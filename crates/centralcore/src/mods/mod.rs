//! Mod metadata and user selection policy.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::files::FileHash;

/// Installation policy for a mod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModSelection {
    Required,
    Optional,
    Disabled,
}

/// Provider-neutral mod declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModConfig {
    pub id: String,
    pub name: String,
    pub version: String,
    pub url: Url,
    pub hash: Option<FileHash>,
    pub selection: ModSelection,
    pub description: Option<String>,
}

impl ModConfig {
    /// Resolves whether the mod should be installed for a user's selection.
    #[must_use]
    pub fn is_enabled(&self, optional_selected: bool) -> bool {
        match self.selection {
            ModSelection::Required => true,
            ModSelection::Optional => optional_selected,
            ModSelection::Disabled => false,
        }
    }
}
