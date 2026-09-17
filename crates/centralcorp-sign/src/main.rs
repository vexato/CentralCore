#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use centralcore::trust::{
    provider_signing_payload, transition_signing_payload, KeyTransition, KeyTransitionPayload,
    PublicKey, PublicKeyFile, SignatureEnvelope, KEY_FILE_FORMAT_VERSION, KEY_TRANSITION_VERSION,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(
    name = "ccorp-sign",
    version,
    about = "Offline CentralCore provider signing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair using the operating-system CSPRNG.
    Keygen {
        #[arg(long, default_value = "centralcorp-signing-key.private.json")]
        private_key: PathBuf,
        #[arg(long, default_value = "centralcorp-signing-key.public.json")]
        public_key: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    /// Canonicalize and sign a provider index into a detached .sig file.
    Sign {
        document: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Hash child manifests, emit a publishable tree, and sign its provider index.
    Prepare {
        document: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a detached provider signature with an explicit public-key file.
    Verify {
        document: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// Authorize a replacement public key using the current private key.
    Transition {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        old_private_key: PathBuf,
        #[arg(long)]
        new_public_key: PathBuf,
        #[arg(long)]
        valid_from_revision: u64,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyFile {
    key_format_version: u32,
    algorithm: String,
    private_key: String,
    public_key: PublicKey,
    key_id: centralcore::trust::KeyId,
}

impl Drop for PrivateKeyFile {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    match Cli::parse().command {
        Command::Keygen {
            private_key,
            public_key,
            label,
        } => keygen(&private_key, &public_key, label)?,
        Command::Sign {
            document,
            private_key,
            output,
        } => sign(&document, &private_key, output.as_deref())?,
        Command::Prepare {
            document,
            private_key,
            output_dir,
        } => prepare(&document, &private_key, &output_dir)?,
        Command::Verify {
            document,
            public_key,
            signature,
        } => verify(&document, &public_key, signature.as_deref())?,
        Command::Transition {
            provider,
            old_private_key,
            new_public_key,
            valid_from_revision,
            output,
        } => transition(
            &provider,
            &old_private_key,
            &new_public_key,
            valid_from_revision,
            &output,
        )?,
    }
    Ok(())
}

fn prepare(
    document_path: &Path,
    private_path: &Path,
    output_dir: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let source_root = document_path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_root = std::fs::canonicalize(source_root)?;
    let mut document: serde_json::Value = serde_json::from_slice(&std::fs::read(document_path)?)?;
    if document.get("revision").and_then(serde_json::Value::as_u64) == Some(0)
        || document
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .is_none()
    {
        return Err("provider revision must be a non-zero integer".into());
    }
    let instances = document
        .get_mut("instances")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("provider instances must be an array")?;
    let mut children = Vec::with_capacity(instances.len());
    for instance in instances {
        let object = instance
            .as_object_mut()
            .ok_or("provider instance reference must be an object")?;
        let manifest = object
            .get("manifest")
            .and_then(serde_json::Value::as_str)
            .ok_or("provider instance reference is missing manifest")?;
        let relative = validated_relative_path(manifest)?;
        let source = source_root.join(&relative);
        let metadata = std::fs::symlink_metadata(&source)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("manifest must be a real file: {}", source.display()).into());
        }
        let canonical_source = std::fs::canonicalize(&source)?;
        if !canonical_source.starts_with(&canonical_root) {
            return Err(format!("manifest escapes the provider root: {manifest}").into());
        }
        let bytes = std::fs::read(&canonical_source)?;
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        object.insert("sha256".into(), serde_json::Value::String(digest));
        children.push((relative, bytes));
    }

    std::fs::create_dir_all(output_dir)?;
    for (relative, bytes) in children {
        write_replace(&output_dir.join(relative), &bytes)?;
    }
    let file_name = document_path
        .file_name()
        .ok_or("provider document has no file name")?;
    let destination = output_dir.join(file_name);
    write_replace(&destination, &serde_json::to_vec_pretty(&document)?)?;
    sign(&destination, private_path, None)?;
    println!(
        "Prepared publishable provider tree at {}.",
        output_dir.display()
    );
    Ok(())
}

fn validated_relative_path(value: &str) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    use std::path::Component;

    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("manifest path is not a safe relative path: {value}").into());
    }
    Ok(path.to_path_buf())
}

fn keygen(
    private_path: &Path,
    public_path: &Path,
    label: Option<String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let signing = SigningKey::generate(&mut OsRng);
    let public = PublicKey::from_bytes(signing.verifying_key().to_bytes());
    let public_file = PublicKeyFile::new(public.clone(), label);
    let private_file = PrivateKeyFile {
        key_format_version: KEY_FILE_FORMAT_VERSION,
        algorithm: "ed25519".into(),
        private_key: BASE64.encode(signing.to_bytes()),
        public_key: public,
        key_id: public_file.key_id.clone(),
    };
    let mut private_bytes = serde_json::to_vec_pretty(&private_file)?;
    let private_result = write_new_private(private_path, &private_bytes);
    private_bytes.zeroize();
    private_result?;
    if let Err(error) = write_new(public_path, &serde_json::to_vec_pretty(&public_file)?) {
        let _ = std::fs::remove_file(private_path);
        return Err(error);
    }
    println!("Generated Ed25519 key {}.", public_file.key_id);
    println!(
        "Private key: {} (do not commit or publish)",
        private_path.display()
    );
    println!("Public key:  {}", public_path.display());
    Ok(())
}

fn sign(
    document_path: &Path,
    private_path: &Path,
    output: Option<&Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let document = std::fs::read(document_path)?;
    let private = load_private(private_path)?;
    let signing = signing_key(&private)?;
    let signature = signing.sign(&provider_signing_payload(&document)?);
    let envelope = SignatureEnvelope::ed25519(private.key_id.clone(), signature.to_bytes());
    let destination = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| detached_path(document_path));
    write_replace(&destination, &serde_json::to_vec_pretty(&envelope)?)?;
    println!(
        "Signed {} with {}.",
        document_path.display(),
        private.key_id
    );
    println!("Signature: {}", destination.display());
    Ok(())
}

fn verify(
    document_path: &Path,
    public_path: &Path,
    signature_path: Option<&Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let document = std::fs::read(document_path)?;
    let public: PublicKeyFile = serde_json::from_slice(&std::fs::read(public_path)?)?;
    public.validate()?;
    let path = signature_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| detached_path(document_path));
    let envelope: SignatureEnvelope = serde_json::from_slice(&std::fs::read(&path)?)?;
    if envelope.signature_version != centralcore::trust::SIGNATURE_VERSION
        || envelope.algorithm != "ed25519"
        || envelope.key_id != public.key_id
    {
        return Err("signature envelope does not match the public key or supported format".into());
    }
    let bytes = BASE64.decode(&envelope.signature)?;
    let signature = Signature::from_slice(&bytes)?;
    VerifyingKey::from_bytes(public.public_key.as_bytes())?
        .verify(&provider_signing_payload(&document)?, &signature)?;
    println!(
        "Signature valid for {} using {}.",
        document_path.display(),
        public.key_id
    );
    Ok(())
}

fn transition(
    provider: &str,
    old_private_path: &Path,
    new_public_path: &Path,
    valid_from_revision: u64,
    output: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if provider.is_empty() || valid_from_revision == 0 {
        return Err("provider and a non-zero revision are required".into());
    }
    let old = load_private(old_private_path)?;
    let new: PublicKeyFile = serde_json::from_slice(&std::fs::read(new_public_path)?)?;
    new.validate()?;
    let payload = KeyTransitionPayload {
        transition_version: KEY_TRANSITION_VERSION,
        provider_id: provider.into(),
        from_key_id: old.key_id.clone(),
        to_key: new,
        valid_from_revision,
    };
    let signature = signing_key(&old)?.sign(&transition_signing_payload(&payload)?);
    let transition = KeyTransition {
        payload,
        signature: BASE64.encode(signature.to_bytes()),
    };
    write_replace(output, &serde_json::to_vec_pretty(&transition)?)?;
    println!(
        "Created key transition {} -> {}.",
        transition.payload.from_key_id, transition.payload.to_key.key_id
    );
    Ok(())
}

fn load_private(path: &Path) -> Result<PrivateKeyFile, Box<dyn Error + Send + Sync>> {
    let mut bytes = std::fs::read(path)?;
    let parsed = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let private: PrivateKeyFile = parsed?;
    if private.key_format_version != KEY_FILE_FORMAT_VERSION
        || private.algorithm != "ed25519"
        || private.public_key.key_id() != private.key_id
    {
        return Err("invalid or unsupported private-key file".into());
    }
    Ok(private)
}

fn signing_key(private: &PrivateKeyFile) -> Result<SigningKey, Box<dyn Error + Send + Sync>> {
    let mut bytes = BASE64.decode(&private.private_key)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err("Ed25519 private key must contain 32 bytes".into());
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let signing = SigningKey::from_bytes(&secret);
    secret.zeroize();
    if signing.verifying_key().to_bytes() != *private.public_key.as_bytes() {
        return Err("private and public key do not match".into());
    }
    Ok(signing)
}

fn detached_path(document: &Path) -> PathBuf {
    let mut value = document.as_os_str().to_os_string();
    value.push(".sig");
    PathBuf::from(value)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        eprintln!("Warning: protect the private-key file with OS filesystem permissions.");
        write_new(path, bytes)
    }
}

fn write_replace(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_hashes_children_and_produces_a_valid_signature() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("source");
        let output = temporary.path().join("publish");
        std::fs::create_dir_all(source.join("instances")).expect("source directories");
        let child = br#"{"format_version":1,"id":"demo","name":"Demo","revision":1,"minecraft":{"version":"1.21.1","loader":{"type":"vanilla"}},"files":[]}"#;
        std::fs::write(source.join("instances/demo.json"), child).expect("child manifest");
        std::fs::write(
            source.join("provider.json"),
            br#"{"format_version":1,"revision":1,"provider":{"id":"demo","name":"Demo"},"instances":[{"id":"demo","manifest":"instances/demo.json"}]}"#,
        )
        .expect("provider index");
        let private = temporary.path().join("private.json");
        let public = temporary.path().join("public.json");
        keygen(&private, &public, None).expect("key generation");

        prepare(&source.join("provider.json"), &private, &output).expect("prepare");

        let prepared: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("provider.json")).expect("prepared index"),
        )
        .expect("JSON");
        let expected = Sha256::digest(child)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(prepared["instances"][0]["sha256"], expected);
        assert_eq!(
            std::fs::read(output.join("instances/demo.json")).expect("copied child"),
            child
        );
        verify(&output.join("provider.json"), &public, None).expect("valid signature");
    }

    #[test]
    fn prepare_rejects_parent_manifest_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("source");
        std::fs::create_dir_all(&source).expect("source directory");
        std::fs::write(
            source.join("provider.json"),
            br#"{"format_version":1,"revision":1,"provider":{"id":"demo","name":"Demo"},"instances":[{"id":"demo","manifest":"../escape.json"}]}"#,
        )
        .expect("provider index");
        let private = temporary.path().join("private.json");
        let public = temporary.path().join("public.json");
        keygen(&private, &public, None).expect("key generation");

        let error = prepare(
            &source.join("provider.json"),
            &private,
            &temporary.path().join("publish"),
        )
        .expect_err("unsafe path must fail");
        assert!(error.to_string().contains("safe relative path"));
    }
}
