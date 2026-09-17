//! Official Minecraft metadata, Vanilla installation, and launch planning.

mod arguments;
mod assets;
mod classpath;
mod error;
mod install;
mod launch;
pub(crate) mod libraries;
mod manifest;
mod natives;
mod recovery;
mod repair;
mod rules;
mod version;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub use arguments::{FeatureSet, LaunchOptions, Resolution};
pub use classpath::Classpath;
pub use error::MinecraftError;
pub use install::{InstallPhase, InstallPlan, InstallProgress, MinecraftManager};
pub(crate) use install::{MinecraftServices, TransactionState};
pub use launch::LaunchPlan;
pub use libraries::{ResolvedArtifact, ResolvedLibrary, ResolvedNative};
pub use manifest::{
    Argument, ArgumentValue, Arguments, AssetIndexReference, DownloadInfo, LatestVersions, Library,
    Rule, RuleAction, VersionManifest, VersionMetadata, VersionReference, VersionType,
};
pub use recovery::{RecoveryError, RecoveryReport};
pub use repair::{
    RepairDownload, RepairError, RepairExtraction, RepairMetrics, RepairOptions, RepairOutcome,
    RepairPlan, VerifyOptions,
};
pub use rules::RuleContext;
pub(crate) use version::required_java_major;

/// Minecraft version requested by an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinecraftConfig {
    version: String,
}

impl MinecraftConfig {
    /// Creates a configuration for an official version identifier.
    pub fn new(version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        let config = Self { version };
        config.validate()?;
        Ok(config)
    }

    /// Validates a version identifier, including values read from JSON.
    pub fn validate(&self) -> Result<()> {
        if self.version.is_empty()
            || self.version.len() > 128
            || !self
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(Error::InvalidConfig(
                "Minecraft version identifier is invalid".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}
