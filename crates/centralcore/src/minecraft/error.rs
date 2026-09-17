//! Minecraft-specific error categories.

/// Errors produced while resolving, installing, or launching Minecraft.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MinecraftError {
    #[error("Minecraft version `{0}` was not found in the official manifest")]
    VersionNotFound(String),
    #[error("invalid Minecraft manifest ({context}): {message}")]
    InvalidManifest {
        context: &'static str,
        message: String,
    },
    #[error("Minecraft version `{version}` inherits from `{parent}`, which is unavailable")]
    UnsupportedInheritance { version: String, parent: String },
    #[error("could not resolve library `{library}`: {reason}")]
    LibraryResolution { library: String, reason: String },
    #[error("could not resolve asset index `{index}`: {reason}")]
    AssetIndex { index: String, reason: String },
    #[error("native extraction failed for `{archive}`: {reason}")]
    NativeExtraction { archive: String, reason: String },
    #[error("Minecraft {version} requires Java {required}, but no compatible runtime was found")]
    JavaUnavailable { version: String, required: u16 },
    #[error("instance `{0}` is not fully installed")]
    NotInstalled(String),
    #[error("instance `{0}` is already running")]
    AlreadyRunning(String),
    #[error("could not build the launch plan: {0}")]
    LaunchPlan(String),
    #[error("could not launch Minecraft: {0}")]
    Launch(String),
}
