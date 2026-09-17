//! Normalized host platform information.

use serde::{Deserialize, Serialize};

/// Operating systems supported by CentralCore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOs,
    Other,
}

/// CPU architectures understood by CentralCore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Architecture {
    X86,
    X86_64,
    Aarch64,
    Arm,
    Other,
}

/// Information about the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: OperatingSystem,
    pub architecture: Architecture,
}

impl Platform {
    /// Detects the compile target's operating system and architecture.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            os: current_os(),
            architecture: current_architecture(),
        }
    }
}

const fn current_os() -> OperatingSystem {
    if cfg!(target_os = "windows") {
        OperatingSystem::Windows
    } else if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else if cfg!(target_os = "macos") {
        OperatingSystem::MacOs
    } else {
        OperatingSystem::Other
    }
}

const fn current_architecture() -> Architecture {
    if cfg!(target_arch = "x86") {
        Architecture::X86
    } else if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else if cfg!(target_arch = "arm") {
        Architecture::Arm
    } else {
        Architecture::Other
    }
}
