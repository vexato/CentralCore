//! Explicit provider update plans and reports.

use serde::{Deserialize, Serialize};

use crate::{files::FileHash, instance::InstanceId};

use super::{ComponentSelections, ProviderFile, ProviderInstanceId};

/// One visible file action in an update plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateFileAction {
    pub id: String,
    pub path: String,
    pub component_id: Option<String>,
    pub size: u64,
    pub sha256: FileHash,
}

/// One managed file which no longer belongs to the desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateRemoval {
    pub id: String,
    pub path: String,
    pub component_id: Option<String>,
}

/// Effective component activation change represented by an update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OptionalComponentChange {
    pub component_id: String,
    pub enabled: bool,
}

/// Immutable analysis result. Applying it is a separate operation.
#[derive(Debug, Clone, Serialize)]
pub struct UpdatePlan {
    pub(crate) instance: ProviderInstanceId,
    pub(crate) local_instance_id: InstanceId,
    pub(crate) from_revision: u64,
    pub(crate) to_revision: u64,
    pub(crate) keep: Vec<UpdateFileAction>,
    pub(crate) downloads: Vec<UpdateFileAction>,
    pub(crate) replacements: Vec<UpdateFileAction>,
    pub(crate) removals: Vec<UpdateRemoval>,
    pub(crate) optional_changes: Vec<OptionalComponentChange>,
    /// Missing Minecraft/loader cache artifacts when the base definition changes.
    pub(crate) base_downloads: u64,
    pub(crate) base_download_size: Option<u64>,
    pub(crate) download_size: u64,
    pub(crate) base_game_changed: bool,
    #[serde(skip)]
    pub(crate) desired_files: Vec<DesiredProviderFile>,
    #[serde(skip)]
    pub(crate) selections: ComponentSelections,
    #[serde(skip)]
    pub(crate) expected_selections: ComponentSelections,
}

impl UpdatePlan {
    #[must_use]
    pub fn instance(&self) -> &ProviderInstanceId {
        &self.instance
    }

    #[must_use]
    pub fn local_instance_id(&self) -> &InstanceId {
        &self.local_instance_id
    }

    #[must_use]
    pub const fn from_revision(&self) -> u64 {
        self.from_revision
    }

    #[must_use]
    pub const fn to_revision(&self) -> u64 {
        self.to_revision
    }

    #[must_use]
    pub fn kept_files(&self) -> &[UpdateFileAction] {
        &self.keep
    }

    #[must_use]
    pub fn downloads(&self) -> &[UpdateFileAction] {
        &self.downloads
    }

    #[must_use]
    pub fn replacements(&self) -> &[UpdateFileAction] {
        &self.replacements
    }

    #[must_use]
    pub fn removals(&self) -> &[UpdateRemoval] {
        &self.removals
    }

    #[must_use]
    pub fn optional_changes(&self) -> &[OptionalComponentChange] {
        &self.optional_changes
    }

    #[must_use]
    pub const fn base_downloads(&self) -> u64 {
        self.base_downloads
    }

    #[must_use]
    pub const fn base_download_size(&self) -> Option<u64> {
        self.base_download_size
    }

    #[must_use]
    pub const fn download_size(&self) -> u64 {
        self.download_size
    }

    #[must_use]
    pub const fn base_game_changed(&self) -> bool {
        self.base_game_changed
    }

    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.from_revision != self.to_revision
            || self.base_game_changed
            || !self.downloads.is_empty()
            || !self.replacements.is_empty()
            || !self.removals.is_empty()
            || !self.optional_changes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DesiredProviderFile {
    pub file: ProviderFile,
    pub component_id: Option<String>,
}

/// Structured global update progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Preparing,
    Downloading,
    Applying,
    Verifying,
    Finalizing,
}

/// Result and reusable metrics for one committed update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateReport {
    pub instance_id: String,
    pub from_revision: u64,
    pub to_revision: u64,
    pub files_kept: u64,
    pub files_downloaded: u64,
    pub files_replaced: u64,
    pub files_removed: u64,
    pub bytes_reused: u64,
    pub bytes_downloaded: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub duration_millis: u64,
}
