//! Safe relative paths and provider-neutral file manifests.

use std::{collections::HashSet, fmt, path::Path};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::{Error, Result};

/// A portable relative path that cannot escape its intended root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeRelativePath(String);

impl SafeRelativePath {
    /// Parses and validates a backend-supplied path.
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        validate_relative_path(&path)?;
        Ok(Self(path))
    }

    /// Returns the normalized forward-slash representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Joins this path below a trusted root.
    #[must_use]
    pub fn join_under(&self, root: &Path) -> std::path::PathBuf {
        self.0
            .split('/')
            .fold(root.to_path_buf(), |path, part| path.join(part))
    }
}

impl fmt::Display for SafeRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for SafeRelativePath {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl Serialize for SafeRelativePath {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeRelativePath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

fn validate_relative_path(path: &str) -> Result<()> {
    let invalid = |reason| Error::InvalidRelativePath {
        path: path.to_owned(),
        reason,
    };
    if path.is_empty() {
        return Err(invalid("path is empty"));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(invalid("absolute paths are forbidden"));
    }
    if path.contains('\\') {
        return Err(invalid("backslash separators are forbidden"));
    }
    if path.contains('\0') {
        return Err(invalid("NUL bytes are forbidden"));
    }

    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(
                "empty, current, and parent components are forbidden",
            ));
        }
        if component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        }) {
            return Err(invalid("component contains a non-portable character"));
        }
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(invalid("component has a non-portable suffix"));
        }
        let stem = component.split('.').next().unwrap_or_default();
        let reserved = matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        if reserved {
            return Err(invalid("component is a reserved Windows device name"));
        }
    }
    Ok(())
}

/// Supported content digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

/// A validated hexadecimal content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileHash {
    algorithm: HashAlgorithm,
    value: String,
}

impl<'de> Deserialize<'de> for FileHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedHash {
            algorithm: HashAlgorithm,
            value: String,
        }

        let value = SerializedHash::deserialize(deserializer)?;
        Self::new(value.algorithm, value.value).map_err(D::Error::custom)
    }
}

impl FileHash {
    /// Creates a digest after validating its hexadecimal length.
    pub fn new(algorithm: HashAlgorithm, value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        let expected_len = match algorithm {
            HashAlgorithm::Sha1 => 40,
            HashAlgorithm::Sha256 => 64,
        };
        if value.len() != expected_len || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::InvalidConfig(format!(
                "invalid {algorithm:?} digest"
            )));
        }
        Ok(Self { algorithm, value })
    }

    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One file supplied by an instance provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: SafeRelativePath,
    pub url: Url,
    pub size: Option<u64>,
    pub hash: Option<FileHash>,
}

/// Versioned collection of files belonging to an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub format_version: u32,
    pub files: Vec<FileEntry>,
}

impl FileManifest {
    pub const FORMAT_VERSION: u32 = 1;

    /// Validates the format version and ensures paths are unique.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != Self::FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "file manifest",
                version: self.format_version,
            });
        }
        let mut paths = HashSet::with_capacity(self.files.len());
        for file in &self.files {
            if !paths.insert(file.path.clone()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate manifest path `{}`",
                    file.path
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_and_absolute_paths() {
        for candidate in [
            "../secret",
            "mods/../../secret",
            "/etc/passwd",
            r"C:\\Windows",
            r"mods\\evil.jar",
            "mods/CON.txt",
        ] {
            assert!(
                SafeRelativePath::new(candidate).is_err(),
                "accepted {candidate}"
            );
        }
    }

    #[test]
    fn accepts_portable_nested_paths() {
        let path = SafeRelativePath::new("mods/example-1.0.jar").expect("valid path");
        assert_eq!(path.as_str(), "mods/example-1.0.jar");
    }

    #[test]
    fn validates_hash_length_and_hexadecimal_content() {
        assert!(FileHash::new(HashAlgorithm::Sha1, "a".repeat(40)).is_ok());
        assert!(FileHash::new(HashAlgorithm::Sha256, "z".repeat(64)).is_err());
    }

    #[test]
    fn deserialization_preserves_hash_validation() {
        let invalid = r#"{"algorithm":"sha256","value":"not-a-digest"}"#;
        assert!(serde_json::from_str::<FileHash>(invalid).is_err());
    }

    #[test]
    fn manifest_rejects_duplicate_paths() {
        let path = SafeRelativePath::new("mods/example.jar").expect("path");
        let entry = FileEntry {
            path,
            url: Url::parse("https://example.test/mod.jar").expect("URL"),
            size: None,
            hash: None,
        };
        let manifest = FileManifest {
            format_version: FileManifest::FORMAT_VERSION,
            files: vec![entry.clone(), entry],
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn generated_paths_preserve_containment_invariant() {
        let root = Path::new("sandbox-root");
        for index in 0..1_000 {
            let candidate = format!("mods/group-{}/file-{index}.jar", index % 17);
            let validated = SafeRelativePath::new(&candidate).expect("generated safe path");
            assert!(validated.join_under(root).starts_with(root));
            for hostile in [
                format!("../{candidate}"),
                format!("mods/{index}/../../escape"),
                format!(r"mods\{index}\escape.jar"),
            ] {
                assert!(SafeRelativePath::new(hostile).is_err());
            }
        }
    }
}
