//! Versioned local CentralCore configuration.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use url::Url;

use crate::{download::DownloadConfig, java::JavaPolicy, Error, Result};

/// Current on-disk configuration format.
pub const CONFIG_FORMAT_VERSION: u32 = 1;

/// Local configuration used to construct the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConfig {
    pub format_version: u32,
    pub data_directory: PathBuf,
    #[serde(default)]
    pub download: DownloadConfig,
    #[serde(default)]
    pub java: JavaPolicy,
    #[serde(default)]
    pub minecraft: MinecraftSettings,
    #[serde(default)]
    pub reliability: ReliabilitySettings,
    #[serde(default)]
    pub providers: ProviderSettings,
    #[serde(default = "default_event_capacity")]
    pub event_capacity: usize,
}

impl CoreConfig {
    /// Creates a version-1 configuration rooted at `data_directory`.
    #[must_use]
    pub fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self {
            format_version: CONFIG_FORMAT_VERSION,
            data_directory: data_directory.into(),
            download: DownloadConfig::default(),
            java: JavaPolicy::default(),
            minecraft: MinecraftSettings::default(),
            reliability: ReliabilitySettings::default(),
            providers: ProviderSettings::default(),
            event_capacity: default_event_capacity(),
        }
    }

    /// Checks version and bounded policy values.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != CONFIG_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "configuration",
                version: self.format_version,
            });
        }
        if self.data_directory.as_os_str().is_empty() {
            return Err(Error::InvalidConfig(
                "data_directory cannot be empty".into(),
            ));
        }
        if self.event_capacity == 0 || self.event_capacity > 65_536 {
            return Err(Error::InvalidConfig(
                "event_capacity must be between 1 and 65536".into(),
            ));
        }
        self.download.validate()?;
        self.java.validate()?;
        if self.minecraft.max_metadata_size == 0
            || self.minecraft.max_metadata_size > self.download.max_file_size
        {
            return Err(Error::InvalidConfig(
                "minecraft max_metadata_size must be within the download size limit".into(),
            ));
        }
        if !(1..=16).contains(&self.reliability.verify_concurrency) {
            return Err(Error::InvalidConfig(
                "verification concurrency must be between 1 and 16".into(),
            ));
        }
        self.providers.validate(&self.download)?;
        Ok(())
    }

    /// Loads and validates a JSON configuration file.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = tokio::fs::read(path).await?;
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Saves this configuration with a temporary-file rename.
    pub async fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        tokio::fs::write(&temporary, bytes).await?;
        if tokio::fs::try_exists(path).await? {
            tokio::fs::remove_file(path).await?;
        }
        tokio::fs::rename(&temporary, path).await?;
        Ok(())
    }
}

/// Security and resource limits for static provider documents and URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub max_index_size: u64,
    pub max_instance_manifest_size: u64,
    /// Development escape hatch for loopback/private provider endpoints.
    pub allow_private_networks: bool,
}

impl ProviderSettings {
    fn validate(&self, downloads: &DownloadConfig) -> Result<()> {
        if self.max_index_size == 0
            || self.max_instance_manifest_size == 0
            || self.max_index_size > downloads.max_file_size
            || self.max_instance_manifest_size > downloads.max_file_size
        {
            return Err(Error::InvalidConfig(
                "provider JSON limits must be non-zero and within the download limit".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            max_index_size: 4 * 1024 * 1024,
            max_instance_manifest_size: 4 * 1024 * 1024,
            allow_private_networks: false,
        }
    }
}

/// Bounded disk-verification policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilitySettings {
    pub verify_concurrency: usize,
}

impl Default for ReliabilitySettings {
    fn default() -> Self {
        Self {
            verify_concurrency: 4,
        }
    }
}

/// Official metadata endpoints and bounded JSON policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinecraftSettings {
    pub version_manifest_url: Url,
    pub asset_base_url: Url,
    pub max_metadata_size: u64,
}

impl Default for MinecraftSettings {
    fn default() -> Self {
        Self {
            version_manifest_url: Url::parse(
                "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
            )
            .expect("static official manifest URL is valid"),
            asset_base_url: Url::parse("https://resources.download.minecraft.net/")
                .expect("static official asset URL is valid"),
            max_metadata_size: 16 * 1024 * 1024,
        }
    }
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self::new(".centralcore")
    }
}

const fn default_event_capacity() -> usize {
    512
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_format_version() {
        let config = CoreConfig {
            format_version: 99,
            ..CoreConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(Error::UnsupportedFormat { version: 99, .. })
        ));
    }

    #[tokio::test]
    async fn truncated_configuration_returns_a_parse_error() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let path = temporary.path().join("centralcore.json");
        tokio::fs::write(&path, br#"{"format_version":1,"data_directory":"#)
            .await
            .expect("fixture");
        assert!(matches!(CoreConfig::load(path).await, Err(Error::Json(_))));
    }
}
