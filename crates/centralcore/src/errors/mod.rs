//! Error types shared by CentralCore services.

use std::path::PathBuf;

/// Result type returned by CentralCore APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error categories exposed by the library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A supplied instance identifier is not portable or safe.
    #[error("invalid instance id `{id}`: {reason}")]
    InvalidInstanceId { id: String, reason: &'static str },

    /// A backend-supplied relative path failed validation.
    #[error("invalid relative path `{path}`: {reason}")]
    InvalidRelativePath { path: String, reason: &'static str },

    /// A value in the local configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The persisted format is newer or otherwise unsupported.
    #[error("unsupported {kind} format version {version}")]
    UnsupportedFormat { kind: &'static str, version: u32 },

    /// The requested entity already exists.
    #[error("{kind} `{id}` already exists")]
    AlreadyExists { kind: &'static str, id: String },

    /// The requested entity does not exist.
    #[error("{kind} `{id}` was not found")]
    NotFound { kind: &'static str, id: String },

    /// A filesystem entry had an unsafe type, such as a symbolic link.
    #[error("unsafe filesystem entry at `{path}`: {reason}")]
    UnsafeFilesystemEntry { path: PathBuf, reason: &'static str },

    /// A provider rejected or could not satisfy an operation.
    #[error("provider `{provider}` failed: {message}")]
    Provider { provider: String, message: String },

    /// A static provider manifest, snapshot, or resource failed validation.
    #[error(transparent)]
    StaticProvider(#[from] crate::providers::ProviderError),

    /// Provider content signature, trust, rotation, or rollback verification failed.
    #[error(transparent)]
    Trust(#[from] crate::trust::TrustError),

    /// An authentication provider rejected an operation.
    #[error("authentication provider `{provider}` failed: {message}")]
    Authentication { provider: String, message: String },

    /// A structured authentication flow, account, or credential-store failure.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// A loader rejected or could not satisfy an operation.
    ///
    /// This legacy-shaped variant remains available for API compatibility with
    /// callers that implement their own loader adapters.
    #[error("loader `{loader}` failed: {message}")]
    Loader { loader: String, message: String },

    /// A built-in loader could not resolve or execute its typed plan.
    #[error(transparent)]
    LoaderPlan(#[from] crate::loaders::LoaderError),

    /// A Java runtime could not be inspected or used.
    #[error("Java runtime error: {0}")]
    Java(String),

    /// A download failed after applying retry and integrity policy.
    #[error(transparent)]
    Download(#[from] crate::download::DownloadError),

    /// Minecraft metadata, installation, or launch failed.
    #[error(transparent)]
    Minecraft(#[from] crate::minecraft::MinecraftError),

    /// Process lifecycle management failed.
    #[error("process error: {0}")]
    Process(String),

    /// A persisted process could not be recovered safely.
    #[error(transparent)]
    ProcessRecovery(#[from] crate::process::ProcessRecoveryError),

    /// Cross-process coordination failed.
    #[error("coordination lock failed")]
    Lock {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Cache inspection or maintenance failed.
    #[error(transparent)]
    Cache(#[from] crate::cache::CacheError),

    /// Instance verification or repair failed.
    #[error(transparent)]
    Repair(#[from] crate::minecraft::RepairError),

    /// An interrupted installation could not be reconciled.
    #[error(transparent)]
    Recovery(#[from] crate::minecraft::RecoveryError),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or parsing failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<crate::lock::LockError> for Error {
    fn from(source: crate::lock::LockError) -> Self {
        Self::Lock {
            source: Box::new(source),
        }
    }
}

impl Error {
    pub(crate) fn is_lock_busy(&self) -> bool {
        matches!(
            self,
            Self::Lock { source }
                if matches!(
                    source.downcast_ref::<crate::lock::LockError>(),
                    Some(crate::lock::LockError::Busy { .. })
                )
        )
    }
}

/// Authentication errors contain categories and non-secret context only.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("authentication provider `{provider}` rejected the credentials")]
    InvalidCredentials { provider: String },
    #[error("authentication provider `{provider}` requires two-factor authentication")]
    TwoFactorRequired { provider: String },
    #[error("authentication flow for `{provider}` was cancelled")]
    Cancelled { provider: String },
    #[error("authentication session or flow for `{provider}` expired")]
    Expired { provider: String },
    #[error("authentication provider `{provider}` is unavailable")]
    ProviderUnavailable { provider: String },
    #[error("authentication provider `{provider}` rate limited the request")]
    RateLimited {
        provider: String,
        retry_after_seconds: Option<u64>,
    },
    #[error("account at authentication provider `{provider}` is restricted ({reason})")]
    AccountRestricted {
        provider: String,
        reason: AccountRestriction,
    },
    #[error("account at authentication provider `{provider}` does not own Minecraft")]
    NoMinecraftOwnership { provider: String },
    #[error("authentication provider `{provider}` returned an invalid Minecraft profile")]
    InvalidMinecraftProfile { provider: String },
    #[error("credential store operation `{operation}` failed")]
    CredentialStore { operation: &'static str },
    #[error("authentication protocol `{provider}` rejected a response")]
    Protocol { provider: String, code: String },
}

impl std::fmt::Debug for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("AuthError");
        debug.field("kind", &self.kind());
        match self {
            Self::InvalidCredentials { provider }
            | Self::TwoFactorRequired { provider }
            | Self::Cancelled { provider }
            | Self::Expired { provider }
            | Self::ProviderUnavailable { provider }
            | Self::NoMinecraftOwnership { provider }
            | Self::InvalidMinecraftProfile { provider }
            | Self::Protocol { provider, .. } => {
                debug.field("provider", provider);
            }
            Self::RateLimited {
                provider,
                retry_after_seconds,
            } => {
                debug
                    .field("provider", provider)
                    .field("retry_after_seconds", retry_after_seconds);
            }
            Self::AccountRestricted { provider, reason } => {
                debug.field("provider", provider).field("reason", reason);
            }
            Self::CredentialStore { operation } => {
                debug.field("operation", operation);
            }
        }
        debug.finish()
    }
}

impl AuthError {
    /// Stable, secret-free category used by generic events and UIs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidCredentials { .. } => "invalid_credentials",
            Self::TwoFactorRequired { .. } => "two_factor_required",
            Self::Cancelled { .. } => "cancelled",
            Self::Expired { .. } => "expired",
            Self::ProviderUnavailable { .. } => "provider_unavailable",
            Self::RateLimited { .. } => "rate_limited",
            Self::AccountRestricted { .. } => "account_restricted",
            Self::NoMinecraftOwnership { .. } => "no_minecraft_ownership",
            Self::InvalidMinecraftProfile { .. } => "invalid_minecraft_profile",
            Self::CredentialStore { .. } => "credential_store",
            Self::Protocol { .. } => "protocol",
        }
    }
}

/// Provider-neutral account restriction reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccountRestriction {
    Banned,
    Disabled,
    ChildAccount,
    RegionRestricted,
    Unknown,
}

impl std::fmt::Display for AccountRestriction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Banned => "banned",
            Self::Disabled => "disabled",
            Self::ChildAccount => "child_account",
            Self::RegionRestricted => "region_restricted",
            Self::Unknown => "unknown",
        })
    }
}
