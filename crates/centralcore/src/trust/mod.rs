//! Public-key trust, detached provider signatures, and explicit key rotation.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use crate::{
    events::{CoreEvent, EventBus},
    Error, Result,
};

const TRUST_STORE_FORMAT_VERSION: u32 = 1;
pub const SIGNATURE_VERSION: u32 = 1;
pub const KEY_FILE_FORMAT_VERSION: u32 = 1;
pub const KEY_TRANSITION_VERSION: u32 = 1;
const PROVIDER_DOMAIN: &[u8] = b"centralcore-provider-signature-v1\0";
const TRANSITION_DOMAIN: &[u8] = b"centralcore-key-transition-v1\0";

/// Signature algorithms understood by the stable CentralCore API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ed25519 => "ed25519",
        })
    }
}

/// Deterministic SHA-256 fingerprint of public-key bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub fn parse(value: impl Into<String>) -> std::result::Result<Self, TrustError> {
        let value = value.into();
        let digest = value.strip_prefix("sha256:").ok_or_else(|| {
            TrustError::InvalidPublicKey("key ID must use the sha256: prefix".into())
        })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(TrustError::InvalidPublicKey(
                "key ID must contain 64 lowercase hexadecimal characters".into(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Validated Ed25519 public-key bytes, independent from the crypto crate API.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PublicKey")
            .field(&self.key_id())
            .finish()
    }
}

impl PublicKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_base64(value: &str) -> std::result::Result<Self, TrustError> {
        let decoded = BASE64
            .decode(value)
            .map_err(|_| TrustError::InvalidPublicKey("public key is not valid base64".into()))?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            TrustError::InvalidPublicKey("Ed25519 public key must be exactly 32 bytes".into())
        })?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| TrustError::InvalidPublicKey("invalid Ed25519 public key".into()))?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId(format!("sha256:{:x}", Sha256::digest(self.0)))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::from_base64(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Portable public-key file accepted by `ccorp trust add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyFile {
    pub key_format_version: u32,
    pub algorithm: SignatureAlgorithm,
    pub public_key: PublicKey,
    pub key_id: KeyId,
    pub label: Option<String>,
}

impl PublicKeyFile {
    pub fn new(public_key: PublicKey, label: Option<String>) -> Self {
        let key_id = public_key.key_id();
        Self {
            key_format_version: KEY_FILE_FORMAT_VERSION,
            algorithm: SignatureAlgorithm::Ed25519,
            public_key,
            key_id,
            label,
        }
    }

    pub fn validate(&self) -> std::result::Result<(), TrustError> {
        if self.key_format_version != KEY_FILE_FORMAT_VERSION {
            return Err(TrustError::UnsupportedKeyFormat(self.key_format_version));
        }
        if self.key_id != self.public_key.key_id() {
            return Err(TrustError::KeyIdMismatch);
        }
        Ok(())
    }
}

/// One local trust decision. Revoked keys remain recorded to make revocation durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKey {
    pub id: KeyId,
    pub algorithm: SignatureAlgorithm,
    pub public_key: PublicKey,
    pub label: Option<String>,
    pub revoked: bool,
    pub added_unix_seconds: u64,
}

/// Detached signature stored beside a provider index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub signature_version: u32,
    pub algorithm: String,
    pub key_id: KeyId,
    pub signature: String,
}

impl SignatureEnvelope {
    pub fn ed25519(key_id: KeyId, signature: [u8; 64]) -> Self {
        Self {
            signature_version: SIGNATURE_VERSION,
            algorithm: "ed25519".into(),
            key_id,
            signature: BASE64.encode(signature),
        }
    }
}

/// Per-provider signature enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePolicy {
    Required,
    #[default]
    Optional,
    Disabled,
}

/// Security state surfaced in snapshots, sync reports, and JSON CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Verified,
    Unsigned,
    Disabled,
}

/// Evidence retained with an accepted provider snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderVerification {
    pub signature_status: SignatureStatus,
    pub algorithm: Option<SignatureAlgorithm>,
    pub key_id: Option<KeyId>,
    pub signature: Option<String>,
    pub content_sha256: String,
    pub verified_unix_seconds: Option<u64>,
    pub revision: Option<u64>,
    /// Exact index bytes cached with the detached envelope for offline audit/revalidation.
    pub document_base64: String,
    pub envelope: Option<SignatureEnvelope>,
}

/// Key transition payload signed by the current key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyTransitionPayload {
    pub transition_version: u32,
    pub provider_id: String,
    pub from_key_id: KeyId,
    pub to_key: PublicKeyFile,
    pub valid_from_revision: u64,
}

/// Self-contained, old-key-signed rotation declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyTransition {
    #[serde(flatten)]
    pub payload: KeyTransitionPayload,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredTransition {
    provider_id: String,
    from_key_id: KeyId,
    to_key_id: KeyId,
    valid_from_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustDocument {
    format_version: u32,
    keys: BTreeMap<KeyId, TrustedKey>,
    transitions: Vec<StoredTransition>,
}

impl Default for TrustDocument {
    fn default() -> Self {
        Self {
            format_version: TRUST_STORE_FORMAT_VERSION,
            keys: BTreeMap::new(),
            transitions: Vec::new(),
        }
    }
}

/// Structured signature/trust failures exposed by the library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    #[error("provider signature is missing")]
    SignatureMissing,
    #[error("provider signature is invalid")]
    SignatureInvalid,
    #[error("unsupported signature algorithm `{0}`")]
    UnsupportedSignatureAlgorithm(String),
    #[error("unsupported signature envelope version {0}")]
    UnsupportedSignatureVersion(u32),
    #[error("unsupported public-key file version {0}")]
    UnsupportedKeyFormat(u32),
    #[error("signing key `{0}` is not trusted")]
    UntrustedSigningKey(KeyId),
    #[error("signing key `{actual}` does not match expected key `{expected}`")]
    SigningKeyMismatch { expected: KeyId, actual: KeyId },
    #[error("manifest rollback detected for `{subject}`: received revision {received}, highest trusted revision is {highest}")]
    ManifestRollbackDetected {
        subject: String,
        received: u64,
        highest: u64,
    },
    #[error("invalid key transition: {0}")]
    InvalidKeyTransition(String),
    #[error("trust store operation failed: {0}")]
    TrustStoreError(String),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("public key fingerprint does not match its key bytes")]
    KeyIdMismatch,
    #[error("JSON canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Persistent local store of approved public keys and scoped rotations.
#[derive(Debug, Clone)]
pub struct TrustStore {
    root: PathBuf,
    events: EventBus,
    mutex: Arc<Mutex<()>>,
}

impl TrustStore {
    pub(crate) fn new(data_directory: &Path, events: EventBus) -> Self {
        Self {
            root: data_directory.join("trust"),
            events,
            mutex: Arc::new(Mutex::new(())),
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn add_key(
        &self,
        public_key: PublicKey,
        label: Option<String>,
    ) -> Result<TrustedKey> {
        let _guard = self.mutex.lock().await;
        let mut document = self.load().await?;
        let id = public_key.key_id();
        let key = TrustedKey {
            id: id.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key,
            label,
            revoked: false,
            added_unix_seconds: unix_seconds(),
        };
        document.keys.insert(id.clone(), key.clone());
        self.save(&document).await?;
        self.events.emit(CoreEvent::SigningKeyTrusted {
            key_id: id.to_string(),
        });
        Ok(key)
    }

    pub async fn add_key_file(&self, file: PublicKeyFile) -> Result<TrustedKey> {
        file.validate()?;
        self.add_key(file.public_key, file.label).await
    }

    pub async fn list(&self) -> Result<Vec<TrustedKey>> {
        Ok(self.load().await?.keys.into_values().collect())
    }

    pub async fn get(&self, id: &KeyId) -> Result<TrustedKey> {
        let key = self
            .load()
            .await?
            .keys
            .remove(id)
            .ok_or_else(|| TrustError::UntrustedSigningKey(id.clone()))?;
        if key.revoked {
            return Err(TrustError::UntrustedSigningKey(id.clone()).into());
        }
        Ok(key)
    }

    pub async fn show(&self, id: &KeyId) -> Result<TrustedKey> {
        self.load()
            .await?
            .keys
            .remove(id)
            .ok_or_else(|| TrustError::UntrustedSigningKey(id.clone()).into())
    }

    /// Revokes a key durably without touching snapshots or installed instances.
    pub async fn remove(&self, id: &KeyId) -> Result<TrustedKey> {
        let _guard = self.mutex.lock().await;
        let mut document = self.load().await?;
        let key = document
            .keys
            .get_mut(id)
            .ok_or_else(|| TrustError::UntrustedSigningKey(id.clone()))?;
        key.revoked = true;
        let removed = key.clone();
        self.save(&document).await?;
        self.events.emit(CoreEvent::SigningKeyRemoved {
            key_id: id.to_string(),
        });
        Ok(removed)
    }

    pub async fn apply_transition(&self, transition: KeyTransition) -> Result<TrustedKey> {
        let _guard = self.mutex.lock().await;
        let mut document = self.load().await?;
        validate_transition(&document, &transition)?;
        let payload = &transition.payload;
        let id = payload.to_key.key_id.clone();
        let key = TrustedKey {
            id: id.clone(),
            algorithm: payload.to_key.algorithm,
            public_key: payload.to_key.public_key.clone(),
            label: payload.to_key.label.clone(),
            revoked: false,
            added_unix_seconds: unix_seconds(),
        };
        document.keys.insert(id.clone(), key.clone());
        let stored = StoredTransition {
            provider_id: payload.provider_id.clone(),
            from_key_id: payload.from_key_id.clone(),
            to_key_id: id.clone(),
            valid_from_revision: payload.valid_from_revision,
        };
        if !document.transitions.contains(&stored) {
            document.transitions.push(stored);
        }
        self.save(&document).await?;
        self.events.emit(CoreEvent::SigningKeyRotated {
            provider_id: payload.provider_id.clone(),
            old_key_id: payload.from_key_id.to_string(),
            new_key_id: id.to_string(),
        });
        Ok(key)
    }

    pub async fn authorize(
        &self,
        expected: &KeyId,
        actual: &KeyId,
        provider_id: &str,
        revision: u64,
    ) -> Result<TrustedKey> {
        let document = self.load().await?;
        let key = document
            .keys
            .get(actual)
            .filter(|key| !key.revoked)
            .cloned()
            .ok_or_else(|| TrustError::UntrustedSigningKey(actual.clone()))?;
        if actual == expected {
            return Ok(key);
        }
        let authorized = document.transitions.iter().any(|transition| {
            transition.provider_id == provider_id
                && &transition.from_key_id == expected
                && &transition.to_key_id == actual
                && revision >= transition.valid_from_revision
        });
        if !authorized {
            return Err(TrustError::SigningKeyMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            }
            .into());
        }
        Ok(key)
    }

    async fn load(&self) -> Result<TrustDocument> {
        let path = self.root.join("trust.json");
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let document: TrustDocument = serde_json::from_slice(&bytes)
                    .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
                if document.format_version != TRUST_STORE_FORMAT_VERSION {
                    return Err(Error::UnsupportedFormat {
                        kind: "trust store",
                        version: document.format_version,
                    });
                }
                Ok(document)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(TrustDocument::default())
            }
            Err(error) => Err(TrustError::TrustStoreError(error.to_string()).into()),
        }
    }

    async fn save(&self, document: &TrustDocument) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
        let path = self.root.join("trust.json");
        let temporary = self.root.join("trust.json.tmp");
        let bytes = serde_json::to_vec_pretty(document)
            .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
        tokio::fs::write(&temporary, bytes)
            .await
            .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
        if tokio::fs::try_exists(&path)
            .await
            .map_err(|error| TrustError::TrustStoreError(error.to_string()))?
        {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
        }
        tokio::fs::rename(temporary, path)
            .await
            .map_err(|error| TrustError::TrustStoreError(error.to_string()))?;
        Ok(())
    }
}

/// Verifies detached signatures without exposing crypto-library types.
#[derive(Debug, Clone)]
pub struct SignatureVerifier {
    trust: TrustStore,
}

impl SignatureVerifier {
    #[must_use]
    pub fn new(trust: TrustStore) -> Self {
        Self { trust }
    }

    pub async fn verify_provider(
        &self,
        document: &[u8],
        envelope: &SignatureEnvelope,
        expected_key: &KeyId,
        provider_id: &str,
        revision: u64,
    ) -> Result<()> {
        validate_envelope(envelope)?;
        let key = self
            .trust
            .authorize(expected_key, &envelope.key_id, provider_id, revision)
            .await?;
        verify_signature(
            &key.public_key,
            &provider_signing_payload(document)?,
            &envelope.signature,
        )
    }
}

/// RFC 8785 canonical JSON used by both runtime verification and signing tools.
pub fn canonicalize_json(document: &[u8]) -> std::result::Result<Vec<u8>, TrustError> {
    let value: serde_json::Value = serde_json::from_slice(document)
        .map_err(|error| TrustError::Canonicalization(error.to_string()))?;
    serde_jcs::to_vec(&value).map_err(|error| TrustError::Canonicalization(error.to_string()))
}

pub fn provider_signing_payload(document: &[u8]) -> std::result::Result<Vec<u8>, TrustError> {
    let canonical = canonicalize_json(document)?;
    let mut payload = Vec::with_capacity(PROVIDER_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(PROVIDER_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

pub fn transition_signing_payload(
    payload: &KeyTransitionPayload,
) -> std::result::Result<Vec<u8>, TrustError> {
    let canonical = serde_jcs::to_vec(payload)
        .map_err(|error| TrustError::Canonicalization(error.to_string()))?;
    let mut output = Vec::with_capacity(TRANSITION_DOMAIN.len() + canonical.len());
    output.extend_from_slice(TRANSITION_DOMAIN);
    output.extend_from_slice(&canonical);
    Ok(output)
}

fn validate_envelope(envelope: &SignatureEnvelope) -> Result<()> {
    if envelope.signature_version != SIGNATURE_VERSION {
        return Err(TrustError::UnsupportedSignatureVersion(envelope.signature_version).into());
    }
    if envelope.algorithm != "ed25519" {
        return Err(TrustError::UnsupportedSignatureAlgorithm(envelope.algorithm.clone()).into());
    }
    Ok(())
}

fn validate_transition(document: &TrustDocument, transition: &KeyTransition) -> Result<()> {
    let payload = &transition.payload;
    if payload.transition_version != KEY_TRANSITION_VERSION {
        return Err(TrustError::InvalidKeyTransition(format!(
            "unsupported version {}",
            payload.transition_version
        ))
        .into());
    }
    if payload.provider_id.is_empty() || payload.valid_from_revision == 0 {
        return Err(TrustError::InvalidKeyTransition(
            "provider ID and non-zero starting revision are required".into(),
        )
        .into());
    }
    payload.to_key.validate()?;
    if payload.from_key_id == payload.to_key.key_id {
        return Err(
            TrustError::InvalidKeyTransition("old and new keys are identical".into()).into(),
        );
    }
    let old = document
        .keys
        .get(&payload.from_key_id)
        .filter(|key| !key.revoked)
        .ok_or_else(|| TrustError::UntrustedSigningKey(payload.from_key_id.clone()))?;
    verify_signature(
        &old.public_key,
        &transition_signing_payload(payload)?,
        &transition.signature,
    )
    .map_err(|_| TrustError::InvalidKeyTransition("transition signature is invalid".into()).into())
}

fn verify_signature(public_key: &PublicKey, message: &[u8], encoded_signature: &str) -> Result<()> {
    let bytes = BASE64
        .decode(encoded_signature)
        .map_err(|_| TrustError::SignatureInvalid)?;
    let signature = DalekSignature::from_slice(&bytes).map_err(|_| TrustError::SignatureInvalid)?;
    let key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| TrustError::InvalidPublicKey("invalid Ed25519 point".into()))?;
    key.verify(message, &signature)
        .map_err(|_| TrustError::SignatureInvalid.into())
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn canonicalization_ignores_formatting_and_object_order() {
        let left = canonicalize_json(br#"{ "b": 2, "a": [true, null] }"#).expect("left");
        let right = canonicalize_json(b"{\n\"a\":[true,null],\"b\":2}\n").expect("right");
        assert_eq!(left, right);
    }

    #[test]
    fn key_id_is_deterministic() {
        let key = PublicKey::from_bytes([7; 32]);
        assert_eq!(key.key_id(), key.key_id());
        assert_eq!(key.key_id().as_str().len(), 71);
    }

    #[test]
    fn deeply_nested_or_truncated_json_is_rejected_without_panicking() {
        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(canonicalize_json(nested.as_bytes()).is_err());
        assert!(canonicalize_json(br#"{"revision":1,"provider":"#).is_err());
    }

    #[tokio::test]
    async fn valid_signature_is_accepted_and_tampering_is_rejected() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let events = EventBus::new(16);
        let trust = TrustStore::new(temporary.path(), events);
        let signing = SigningKey::generate(&mut OsRng);
        let public = PublicKey::from_bytes(signing.verifying_key().to_bytes());
        let trusted = trust.add_key(public, None).await.expect("trust");
        let document = br#"{"revision":1,"provider":"demo"}"#;
        let signature = signing.sign(&provider_signing_payload(document).expect("payload"));
        let envelope = SignatureEnvelope::ed25519(trusted.id.clone(), signature.to_bytes());
        let verifier = SignatureVerifier::new(trust);
        verifier
            .verify_provider(document, &envelope, &trusted.id, "demo", 1)
            .await
            .expect("valid");
        let error = verifier
            .verify_provider(
                br#"{"revision":2,"provider":"demo"}"#,
                &envelope,
                &trusted.id,
                "demo",
                2,
            )
            .await
            .expect_err("tampered");
        assert!(matches!(error, Error::Trust(TrustError::SignatureInvalid)));
    }

    #[tokio::test]
    async fn unknown_and_wrong_keys_are_rejected() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let trust = TrustStore::new(temporary.path(), EventBus::new(16));
        let expected_signing = SigningKey::generate(&mut OsRng);
        let expected = trust
            .add_key(
                PublicKey::from_bytes(expected_signing.verifying_key().to_bytes()),
                None,
            )
            .await
            .expect("expected");
        let other_signing = SigningKey::generate(&mut OsRng);
        let other_public = PublicKey::from_bytes(other_signing.verifying_key().to_bytes());
        let document = br#"{"revision":1}"#;
        let signature = other_signing.sign(&provider_signing_payload(document).expect("payload"));
        let unknown = SignatureEnvelope::ed25519(other_public.key_id(), signature.to_bytes());
        let verifier = SignatureVerifier::new(trust.clone());
        assert!(matches!(
            verifier
                .verify_provider(document, &unknown, &expected.id, "demo", 1)
                .await,
            Err(Error::Trust(TrustError::UntrustedSigningKey(_)))
        ));
        let other = trust.add_key(other_public, None).await.expect("other");
        let wrong = SignatureEnvelope::ed25519(other.id, signature.to_bytes());
        assert!(matches!(
            verifier
                .verify_provider(document, &wrong, &expected.id, "demo", 1)
                .await,
            Err(Error::Trust(TrustError::SigningKeyMismatch { .. }))
        ));
    }

    #[tokio::test]
    async fn valid_rotation_authorizes_only_the_scoped_successor() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let trust = TrustStore::new(temporary.path(), EventBus::new(16));
        let old_signing = SigningKey::generate(&mut OsRng);
        let old = trust
            .add_key(
                PublicKey::from_bytes(old_signing.verifying_key().to_bytes()),
                None,
            )
            .await
            .expect("old");
        let new_signing = SigningKey::generate(&mut OsRng);
        let new_file = PublicKeyFile::new(
            PublicKey::from_bytes(new_signing.verifying_key().to_bytes()),
            Some("new".into()),
        );
        let payload = KeyTransitionPayload {
            transition_version: KEY_TRANSITION_VERSION,
            provider_id: "demo".into(),
            from_key_id: old.id.clone(),
            to_key: new_file,
            valid_from_revision: 2,
        };
        let signature =
            old_signing.sign(&transition_signing_payload(&payload).expect("transition payload"));
        trust
            .apply_transition(KeyTransition {
                payload,
                signature: BASE64.encode(signature.to_bytes()),
            })
            .await
            .expect("rotation");
        let document = br#"{"revision":2}"#;
        let signature =
            new_signing.sign(&provider_signing_payload(document).expect("provider payload"));
        let envelope = SignatureEnvelope::ed25519(
            PublicKey::from_bytes(new_signing.verifying_key().to_bytes()).key_id(),
            signature.to_bytes(),
        );
        SignatureVerifier::new(trust.clone())
            .verify_provider(document, &envelope, &old.id, "demo", 2)
            .await
            .expect("rotated provider");
        assert!(SignatureVerifier::new(trust)
            .verify_provider(document, &envelope, &old.id, "other", 2)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unknown_algorithm_is_rejected_before_signature_parsing() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let trust = TrustStore::new(temporary.path(), EventBus::new(16));
        let signing = SigningKey::generate(&mut OsRng);
        let trusted = trust
            .add_key(
                PublicKey::from_bytes(signing.verifying_key().to_bytes()),
                None,
            )
            .await
            .expect("trust");
        let envelope = SignatureEnvelope {
            signature_version: SIGNATURE_VERSION,
            algorithm: "future-signature".into(),
            key_id: trusted.id.clone(),
            signature: BASE64.encode([0; 64]),
        };
        let error = SignatureVerifier::new(trust)
            .verify_provider(b"{}", &envelope, &trusted.id, "demo", 1)
            .await
            .expect_err("unsupported algorithm");
        assert!(matches!(
            error,
            Error::Trust(TrustError::UnsupportedSignatureAlgorithm(_))
        ));
    }

    #[tokio::test]
    async fn corrupted_rotation_signature_is_rejected() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let trust = TrustStore::new(temporary.path(), EventBus::new(16));
        let old_signing = SigningKey::generate(&mut OsRng);
        let old = trust
            .add_key(
                PublicKey::from_bytes(old_signing.verifying_key().to_bytes()),
                None,
            )
            .await
            .expect("old");
        let new_signing = SigningKey::generate(&mut OsRng);
        let payload = KeyTransitionPayload {
            transition_version: KEY_TRANSITION_VERSION,
            provider_id: "demo".into(),
            from_key_id: old.id,
            to_key: PublicKeyFile::new(
                PublicKey::from_bytes(new_signing.verifying_key().to_bytes()),
                None,
            ),
            valid_from_revision: 2,
        };
        let error = trust
            .apply_transition(KeyTransition {
                payload,
                signature: BASE64.encode([0; 64]),
            })
            .await
            .expect_err("invalid transition");
        assert!(matches!(
            error,
            Error::Trust(TrustError::InvalidKeyTransition(_))
        ));
    }
}
