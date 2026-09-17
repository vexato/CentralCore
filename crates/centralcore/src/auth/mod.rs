//! Extensible, UI-independent authentication flows and normalized identities.
//!
//! Providers return structured challenges and never perform terminal or GUI I/O.
//! Minecraft consumes only [`MinecraftIdentity`], never a concrete provider type.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use url::Url;
use zeroize::Zeroize;

use crate::{
    download::CancellationToken,
    errors::AuthError,
    events::{CoreEvent, EventBus},
    Error, Result,
};

mod azuriom;
mod config;
mod http;
mod microsoft;
mod mock;

pub use azuriom::AzuriomAuthProvider;
pub use config::{AuthProviderConfig, AuthProviderConfigEntry, AUTH_REGISTRY_FORMAT_VERSION};
pub use http::{HttpAuthPolicy, HttpAuthProvider, CENTRALCORP_AUTH_PROTOCOL_VERSION};
pub use microsoft::{MicrosoftAuthConfig, MicrosoftAuthProvider};
pub use mock::{MockAuthProvider, MockAuthScenario};

/// Secret text that is redacted from `Debug` and zeroized when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes a secret only at the boundary that must transmit or consume it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// Non-secret identity asserted by an authentication provider.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthIdentity {
    pub provider_user_id: String,
    pub username: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for AuthIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthIdentity")
            .field("provider_user_id", &self.provider_user_id)
            .field("username", &self.username)
            .field("metadata_keys", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Official Minecraft credentials obtained from Minecraft Services.
#[derive(Clone, PartialEq, Eq)]
pub struct OfficialMinecraftIdentity {
    pub username: String,
    pub uuid: String,
    pub access_token: SecretString,
    pub xuid: Option<String>,
    pub expires_at: Option<u64>,
}

impl fmt::Debug for OfficialMinecraftIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfficialMinecraftIdentity")
            .field("username", &self.username)
            .field("uuid", &self.uuid)
            .field("access_token", &"[REDACTED]")
            .field("xuid", &self.xuid)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Stable offline identity. It never contains an official access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineMinecraftIdentity {
    pub username: String,
    pub uuid: String,
}

impl OfflineMinecraftIdentity {
    pub fn new(username: impl Into<String>) -> Result<Self> {
        let username = username.into();
        validate_minecraft_username(&username)?;
        Ok(Self {
            uuid: offline_uuid(&username),
            username,
        })
    }

    /// Uses a provider-supplied UUID after validating its canonical shape.
    pub fn with_uuid(username: impl Into<String>, uuid: impl Into<String>) -> Result<Self> {
        let username = username.into();
        let uuid = uuid.into();
        validate_minecraft_username(&username)?;
        validate_uuid(&uuid)?;
        Ok(Self { username, uuid })
    }
}

/// Provider-neutral identity consumed by Minecraft launch planning.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MinecraftIdentity {
    Official(OfficialMinecraftIdentity),
    Offline(OfflineMinecraftIdentity),
}

impl fmt::Debug for MinecraftIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Official(identity) => formatter.debug_tuple("Official").field(identity).finish(),
            Self::Offline(identity) => formatter.debug_tuple("Offline").field(identity).finish(),
        }
    }
}

impl MinecraftIdentity {
    #[must_use]
    pub fn username(&self) -> &str {
        match self {
            Self::Official(identity) => &identity.username,
            Self::Offline(identity) => &identity.username,
        }
    }

    #[must_use]
    pub fn uuid(&self) -> &str {
        match self {
            Self::Official(identity) => &identity.uuid,
            Self::Offline(identity) => &identity.uuid,
        }
    }

    #[must_use]
    pub fn access_token(&self) -> Option<&SecretString> {
        match self {
            Self::Official(identity) => Some(&identity.access_token),
            Self::Offline(_) => None,
        }
    }

    #[must_use]
    pub fn xuid(&self) -> Option<&str> {
        match self {
            Self::Official(identity) => identity.xuid.as_deref(),
            Self::Offline(_) => None,
        }
    }

    #[must_use]
    pub fn user_type(&self) -> &'static str {
        match self {
            Self::Official(_) => "msa",
            Self::Offline(_) => "legacy",
        }
    }
}

/// Provider-owned session secrets, kept separate from Minecraft credentials.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProviderSession {
    pub access_token: Option<SecretString>,
    pub refresh_token: Option<SecretString>,
    pub device_secret: Option<SecretString>,
    /// Non-secret provider state that may safely be persisted.
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for ProviderSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSession")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "device_secret",
                &self.device_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("metadata_keys", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A normalized authenticated account.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSession {
    pub account_id: String,
    pub provider_id: String,
    pub identity: AuthIdentity,
    pub provider_session: ProviderSession,
    pub expires_at: Option<u64>,
    pub refreshable: bool,
    pub minecraft: MinecraftIdentity,
}

impl fmt::Debug for AuthSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthSession")
            .field("account_id", &self.account_id)
            .field("provider_id", &self.provider_id)
            .field("identity", &self.identity)
            .field("provider_session", &self.provider_session)
            .field("expires_at", &self.expires_at)
            .field("refreshable", &self.refreshable)
            .field("minecraft", &self.minecraft)
            .finish()
    }
}

impl AuthSession {
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|expires| expires <= now_unix)
    }
}

/// Capabilities declared by a provider. Consumers never inspect concrete types.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCapabilities {
    pub interactive: bool,
    pub refresh: bool,
    pub logout: bool,
    pub verify: bool,
    pub credentials: bool,
    pub two_factor: bool,
    pub browser: bool,
    pub device_code: bool,
    pub official_minecraft_session: bool,
}

/// Public, non-secret description of a registered provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProviderInfo {
    pub id: String,
    pub capabilities: AuthCapabilities,
}

/// Initial hints passed to a provider. No password belongs in this structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    pub account_hint: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

/// Kind-only representation suitable for events and JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthChallengeKind {
    Credentials,
    Browser,
    DeviceCode,
    TwoFactorCode,
}

/// A structured interaction that an application can render in any UI.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthChallenge {
    Credentials {
        username_label: String,
        password_label: String,
        password_required: bool,
    },
    Browser {
        authorization_url: Url,
        callback_url: Url,
    },
    DeviceCode {
        verification_uri: Url,
        user_code: SecretString,
        expires_at: u64,
        poll_interval_seconds: u64,
    },
    TwoFactorCode {
        message: Option<String>,
    },
}

impl AuthChallenge {
    #[must_use]
    pub fn kind(&self) -> AuthChallengeKind {
        match self {
            Self::Credentials { .. } => AuthChallengeKind::Credentials,
            Self::Browser { .. } => AuthChallengeKind::Browser,
            Self::DeviceCode { .. } => AuthChallengeKind::DeviceCode,
            Self::TwoFactorCode { .. } => AuthChallengeKind::TwoFactorCode,
        }
    }
}

impl fmt::Debug for AuthChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials {
                username_label,
                password_label,
                password_required,
            } => formatter
                .debug_struct("Credentials")
                .field("username_label", username_label)
                .field("password_label", password_label)
                .field("password_required", password_required)
                .finish(),
            Self::Browser {
                authorization_url,
                callback_url,
            } => formatter
                .debug_struct("Browser")
                .field("authorization_url", &redact_url(authorization_url))
                .field("callback_url", &redact_url(callback_url))
                .finish(),
            Self::DeviceCode {
                verification_uri,
                expires_at,
                poll_interval_seconds,
                ..
            } => formatter
                .debug_struct("DeviceCode")
                .field("verification_uri", &redact_url(verification_uri))
                .field("user_code", &"[REDACTED]")
                .field("expires_at", expires_at)
                .field("poll_interval_seconds", poll_interval_seconds)
                .finish(),
            Self::TwoFactorCode { message } => formatter
                .debug_struct("TwoFactorCode")
                .field("message", &message.as_ref().map(|_| "[PRESENT]"))
                .finish(),
        }
    }
}

/// User/application response to one challenge. Secret fields are always redacted.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthResponse {
    Credentials {
        username: String,
        password: Option<SecretString>,
    },
    BrowserCallback {
        callback_url: Url,
    },
    PollDeviceCode,
    TwoFactorCode {
        code: SecretString,
    },
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials { username, password } => formatter
                .debug_struct("Credentials")
                .field("username", username)
                .field("password", &password.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            Self::BrowserCallback { callback_url } => formatter
                .debug_struct("BrowserCallback")
                .field("callback_url", &redact_url(callback_url))
                .finish(),
            Self::PollDeviceCode => formatter.write_str("PollDeviceCode"),
            Self::TwoFactorCode { .. } => formatter
                .debug_struct("TwoFactorCode")
                .field("code", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Opaque flow identifier used by applications to continue a challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthFlowId(String);

impl AuthFlowId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuthFlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Public state returned by [`AuthManager::begin`] and `continue_flow`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthFlow {
    Challenge {
        flow_id: AuthFlowId,
        provider_id: String,
        challenge: AuthChallenge,
    },
    Authenticated(AuthSession),
}

impl fmt::Debug for AuthFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Challenge {
                flow_id,
                provider_id,
                challenge,
            } => formatter
                .debug_struct("Challenge")
                .field("flow_id", flow_id)
                .field("provider_id", provider_id)
                .field("challenge", challenge)
                .finish(),
            Self::Authenticated(session) => formatter
                .debug_tuple("Authenticated")
                .field(session)
                .finish(),
        }
    }
}

/// Internal provider result. Opaque state is retained by the manager, not the UI.
#[derive(Clone)]
pub enum AuthProviderStep {
    Challenge {
        challenge: AuthChallenge,
        state: SecretString,
    },
    Authenticated(AuthSession),
}

impl fmt::Debug for AuthProviderStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Challenge { challenge, .. } => formatter
                .debug_struct("Challenge")
                .field("challenge", challenge)
                .field("state", &"[REDACTED]")
                .finish(),
            Self::Authenticated(session) => formatter
                .debug_tuple("Authenticated")
                .field(session)
                .finish(),
        }
    }
}

/// Services available to providers without granting filesystem access.
pub struct AuthContext<'a> {
    pub credentials: &'a dyn CredentialStore,
    pub cancellation: &'a CancellationToken,
}

/// Stable compile-time extension contract for built-in and third-party providers.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> AuthCapabilities;

    async fn begin(
        &self,
        request: AuthRequest,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep>;

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep>;

    async fn refresh(&self, session: &AuthSession, context: AuthContext<'_>)
        -> Result<AuthSession>;

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession>;

    async fn logout(&self, session: AuthSession, context: AuthContext<'_>) -> Result<()>;
}

/// Credential persistence boundary. Implementations should use an OS vault.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn load(&self, key: &str) -> Result<Option<SecretString>>;
    async fn store(&self, key: &str, value: &SecretString) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Volatile credential store intended for tests and ephemeral applications.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCredentialStore {
    values: Arc<RwLock<BTreeMap<String, SecretString>>>,
}

/// Credential store backed by the native operating-system vault.
#[derive(Debug, Clone)]
pub struct SystemCredentialStore {
    service: String,
    known_keys: Arc<RwLock<BTreeSet<String>>>,
}

const CREDENTIAL_INDEX_KEY: &str = "__centralcore_credential_index_v1";

impl SystemCredentialStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            known_keys: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    async fn entry_operation<T: Send + 'static>(
        &self,
        key: &str,
        operation: &'static str,
        callback: impl FnOnce(keyring::Entry) -> std::result::Result<T, keyring::Error> + Send + 'static,
    ) -> Result<T> {
        validate_credential_key(key)?;
        let service = self.service.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &key)
                .map_err(|_| AuthError::CredentialStore { operation })?;
            callback(entry).map_err(|_| AuthError::CredentialStore { operation })
        })
        .await
        .map_err(|_| AuthError::CredentialStore { operation })?
        .map_err(Into::into)
    }

    async fn load_key_index(&self) -> Result<BTreeSet<String>> {
        let serialized = self
            .entry_operation(CREDENTIAL_INDEX_KEY, "list", |entry| {
                match entry.get_password() {
                    Ok(value) => Ok(Some(value)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(error) => Err(error),
                }
            })
            .await?;
        match serialized {
            Some(serialized) => serde_json::from_str(&serialized)
                .map_err(|_| AuthError::CredentialStore { operation: "list" }.into()),
            None => Ok(BTreeSet::new()),
        }
    }

    async fn save_key_index(&self, keys: &BTreeSet<String>) -> Result<()> {
        let serialized = serde_json::to_string(keys)
            .map_err(|_| AuthError::CredentialStore { operation: "list" })?;
        self.entry_operation(CREDENTIAL_INDEX_KEY, "list", move |entry| {
            entry.set_password(&serialized)
        })
        .await
    }

    async fn update_key_index(&self, key: &str, present: bool) -> Result<()> {
        let mut keys = self.load_key_index().await?;
        keys.extend(self.known_keys.read().await.iter().cloned());
        if present {
            keys.insert(key.to_owned());
        } else {
            keys.remove(key);
        }
        self.save_key_index(&keys).await?;
        *self.known_keys.write().await = keys;
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for SystemCredentialStore {
    async fn load(&self, key: &str) -> Result<Option<SecretString>> {
        validate_public_credential_key(key)?;
        let service = self.service.clone();
        let key_owned = key.to_owned();
        let value = tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &key_owned)
                .map_err(|_| AuthError::CredentialStore { operation: "load" })?;
            match entry.get_password() {
                Ok(value) => Ok(Some(SecretString::new(value))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(_) => Err(AuthError::CredentialStore { operation: "load" }),
            }
        })
        .await
        .map_err(|_| AuthError::CredentialStore { operation: "load" })??;
        if value.is_some() {
            self.update_key_index(key, true).await?;
        }
        Ok(value)
    }

    async fn store(&self, key: &str, value: &SecretString) -> Result<()> {
        validate_public_credential_key(key)?;
        let secret = value.expose_secret().to_owned();
        self.entry_operation(key, "store", move |entry| entry.set_password(&secret))
            .await?;
        self.update_key_index(key, true).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        validate_public_credential_key(key)?;
        let service = self.service.clone();
        let key_owned = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &key_owned).map_err(|_| {
                AuthError::CredentialStore {
                    operation: "delete",
                }
            })?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(AuthError::CredentialStore {
                    operation: "delete",
                }),
            }
        })
        .await
        .map_err(|_| AuthError::CredentialStore {
            operation: "delete",
        })??;
        self.update_key_index(key, false).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        validate_credential_prefix(prefix)?;
        let mut keys = self.load_key_index().await?;
        keys.extend(self.known_keys.read().await.iter().cloned());
        *self.known_keys.write().await = keys.clone();
        Ok(keys
            .iter()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn load(&self, key: &str) -> Result<Option<SecretString>> {
        validate_public_credential_key(key)?;
        Ok(self.values.read().await.get(key).cloned())
    }

    async fn store(&self, key: &str, value: &SecretString) -> Result<()> {
        validate_public_credential_key(key)?;
        self.values.write().await.insert(key.into(), value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        validate_public_credential_key(key)?;
        self.values.write().await.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        validate_credential_prefix(prefix)?;
        Ok(self
            .values
            .read()
            .await
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }
}

struct PendingFlow {
    provider_id: String,
    state: SecretString,
    expires_at: u64,
}

const DEFAULT_AUTH_FLOW_TTL_SECONDS: u64 = 15 * 60;

/// Authentication facade, provider registry, active flows, and account sessions.
#[derive(Clone)]
pub struct AuthManager {
    providers: Arc<RwLock<BTreeMap<String, Arc<dyn AuthProvider>>>>,
    flows: Arc<RwLock<BTreeMap<AuthFlowId, PendingFlow>>>,
    sessions: Arc<RwLock<BTreeMap<String, AuthSession>>>,
    credentials: Arc<dyn CredentialStore>,
    events: EventBus,
    next_flow_id: Arc<AtomicU64>,
    registry_path: PathBuf,
    accounts_path: PathBuf,
}

impl fmt::Debug for AuthManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthManager")
            .finish_non_exhaustive()
    }
}

impl AuthManager {
    #[must_use]
    pub fn new(
        data_directory: impl AsRef<Path>,
        credentials: Arc<dyn CredentialStore>,
        events: EventBus,
    ) -> Self {
        Self {
            providers: Arc::new(RwLock::new(BTreeMap::new())),
            flows: Arc::new(RwLock::new(BTreeMap::new())),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            credentials,
            events,
            next_flow_id: Arc::new(AtomicU64::new(1)),
            registry_path: data_directory.as_ref().join("auth").join("providers.json"),
            accounts_path: data_directory.as_ref().join("auth").join("accounts.json"),
        }
    }

    /// Loads and registers locally approved configurable providers.
    pub async fn load_configured(&self) -> Result<()> {
        let registry = config::AuthProviderRegistry::load(&self.registry_path).await?;
        for (id, provider_config) in registry.providers {
            self.register(provider_config.build(id)?).await?;
        }
        Ok(())
    }

    /// Restores public account metadata and obtains secrets from the vault.
    pub async fn load_sessions(&self) -> Result<()> {
        if !tokio::fs::try_exists(&self.accounts_path).await? {
            return Ok(());
        }
        let bytes = tokio::fs::read(&self.accounts_path).await?;
        let document: AccountDocument = serde_json::from_slice(&bytes)?;
        if document.format_version != ACCOUNT_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "authentication accounts",
                version: document.format_version,
            });
        }
        let mut restored = Vec::with_capacity(document.accounts.len());
        for persisted in document.accounts {
            let prefix = credential_prefix(&persisted.account_id);
            let provider_access = self
                .credentials
                .load(&format!("{prefix}provider_access"))
                .await?;
            let provider_refresh = self
                .credentials
                .load(&format!("{prefix}provider_refresh"))
                .await?;
            let device_secret = self
                .credentials
                .load(&format!("{prefix}device_secret"))
                .await?;
            let minecraft = match persisted.minecraft {
                PersistedMinecraftIdentity::Offline(identity) => {
                    MinecraftIdentity::Offline(identity)
                }
                PersistedMinecraftIdentity::Official {
                    username,
                    uuid,
                    xuid,
                    expires_at,
                } => {
                    let token = self
                        .credentials
                        .load(&format!("{prefix}minecraft_access"))
                        .await?
                        .ok_or(AuthError::CredentialStore {
                            operation: "restore_minecraft_access",
                        })?;
                    MinecraftIdentity::Official(OfficialMinecraftIdentity {
                        username,
                        uuid,
                        access_token: token,
                        xuid,
                        expires_at,
                    })
                }
            };
            restored.push((
                persisted.account_id.clone(),
                AuthSession {
                    account_id: persisted.account_id,
                    provider_id: persisted.provider_id,
                    identity: persisted.identity,
                    provider_session: ProviderSession {
                        access_token: provider_access,
                        refresh_token: provider_refresh,
                        device_secret,
                        metadata: persisted.provider_metadata,
                    },
                    expires_at: persisted.expires_at,
                    refreshable: persisted.refreshable,
                    minecraft,
                },
            ));
        }
        let mut sessions = self.sessions.write().await;
        sessions.extend(restored);
        Ok(())
    }

    /// Persists and registers a trusted provider endpoint.
    pub async fn add_configured(
        &self,
        id: impl Into<String>,
        provider_config: AuthProviderConfig,
    ) -> Result<()> {
        let id = id.into();
        validate_provider_id(&id)?;
        if id == "offline" {
            return Err(Error::AlreadyExists {
                kind: "authentication provider",
                id,
            });
        }
        let provider = provider_config.clone().build(id.clone())?;
        let mut registry = config::AuthProviderRegistry::load(&self.registry_path).await?;
        if registry.providers.contains_key(&id) {
            return Err(Error::AlreadyExists {
                kind: "authentication provider",
                id,
            });
        }
        registry.providers.insert(id, provider_config);
        registry.save(&self.registry_path).await?;
        self.register(provider).await
    }

    pub async fn configured(&self) -> Result<Vec<AuthProviderConfigEntry>> {
        let registry = config::AuthProviderRegistry::load(&self.registry_path).await?;
        Ok(registry
            .providers
            .into_iter()
            .map(|(id, config)| AuthProviderConfigEntry { id, config })
            .collect())
    }

    pub async fn configured_provider(&self, id: &str) -> Result<AuthProviderConfigEntry> {
        let registry = config::AuthProviderRegistry::load(&self.registry_path).await?;
        registry
            .providers
            .get(id)
            .cloned()
            .map(|config| AuthProviderConfigEntry {
                id: id.to_owned(),
                config,
            })
            .ok_or_else(|| Error::NotFound {
                kind: "configured authentication provider",
                id: id.to_owned(),
            })
    }

    pub async fn remove_configured(&self, id: &str) -> Result<()> {
        let mut registry = config::AuthProviderRegistry::load(&self.registry_path).await?;
        if registry.providers.remove(id).is_none() {
            return Err(Error::NotFound {
                kind: "configured authentication provider",
                id: id.to_owned(),
            });
        }
        registry.save(&self.registry_path).await?;
        self.providers.write().await.remove(id);
        Ok(())
    }

    /// Registers or replaces a provider. Rust providers are linked at compile time.
    pub async fn register(&self, provider: Arc<dyn AuthProvider>) -> Result<()> {
        validate_provider_id(provider.id())?;
        self.providers
            .write()
            .await
            .insert(provider.id().to_owned(), provider);
        Ok(())
    }

    pub async fn unregister(&self, provider_id: &str) -> Result<bool> {
        if provider_id == "offline" {
            return Err(Error::InvalidConfig(
                "the built-in offline authentication provider cannot be removed".into(),
            ));
        }
        Ok(self.providers.write().await.remove(provider_id).is_some())
    }

    pub async fn providers(&self) -> Vec<AuthProviderInfo> {
        self.providers
            .read()
            .await
            .values()
            .map(|provider| AuthProviderInfo {
                id: provider.id().to_owned(),
                capabilities: provider.capabilities(),
            })
            .collect()
    }

    pub async fn begin(
        &self,
        provider_id: &str,
        request: AuthRequest,
        cancellation: &CancellationToken,
    ) -> Result<AuthFlow> {
        self.prune_expired_flows().await;
        cancellation_check(cancellation, provider_id)?;
        let provider = self.provider(provider_id).await?;
        self.events.emit(CoreEvent::AuthFlowStarted {
            provider_id: provider_id.to_owned(),
        });
        let step = provider
            .begin(
                request,
                AuthContext {
                    credentials: self.credentials.as_ref(),
                    cancellation,
                },
            )
            .await;
        self.finish_step(provider_id, None, step).await
    }

    pub async fn continue_flow(
        &self,
        flow_id: &AuthFlowId,
        response: AuthResponse,
        cancellation: &CancellationToken,
    ) -> Result<AuthFlow> {
        let pending =
            self.flows
                .write()
                .await
                .remove(flow_id)
                .ok_or_else(|| AuthError::Expired {
                    provider: "unknown".into(),
                })?;
        if unix_now() >= pending.expires_at {
            self.events.emit(CoreEvent::AuthFlowFailed {
                provider_id: pending.provider_id.clone(),
                error_kind: "expired".into(),
            });
            return Err(AuthError::Expired {
                provider: pending.provider_id,
            }
            .into());
        }
        cancellation_check(cancellation, &pending.provider_id)?;
        let provider = self.provider(&pending.provider_id).await?;
        let step = provider
            .continue_flow(
                pending.state,
                response,
                AuthContext {
                    credentials: self.credentials.as_ref(),
                    cancellation,
                },
            )
            .await;
        self.finish_step(&pending.provider_id, Some(flow_id.clone()), step)
            .await
    }

    /// Cancels and removes a pending interactive flow. No provider task is kept alive.
    pub async fn cancel_flow(&self, flow_id: &AuthFlowId) -> Result<()> {
        let pending = self
            .flows
            .write()
            .await
            .remove(flow_id)
            .ok_or_else(|| Error::NotFound {
                kind: "authentication flow",
                id: flow_id.to_string(),
            })?;
        self.events.emit(CoreEvent::AuthFlowFailed {
            provider_id: pending.provider_id,
            error_kind: "cancelled".into(),
        });
        Ok(())
    }

    pub async fn sessions(&self) -> Vec<AuthSession> {
        self.sessions.read().await.values().cloned().collect()
    }

    pub async fn session(&self, account_id: &str) -> Result<AuthSession> {
        self.sessions
            .read()
            .await
            .get(account_id)
            .cloned()
            .ok_or_else(|| Error::NotFound {
                kind: "authentication account",
                id: account_id.to_owned(),
            })
    }

    pub async fn refresh(
        &self,
        account_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<AuthSession> {
        let session = self.session(account_id).await?;
        if !session.refreshable {
            return Err(AuthError::Expired {
                provider: session.provider_id,
            }
            .into());
        }
        cancellation_check(cancellation, &session.provider_id)?;
        let provider = self.provider(&session.provider_id).await?;
        let refreshed = provider
            .refresh(
                &session,
                AuthContext {
                    credentials: self.credentials.as_ref(),
                    cancellation,
                },
            )
            .await?;
        validate_session(&session.provider_id, &refreshed)?;
        if refreshed.account_id != account_id {
            return Err(AuthError::Protocol {
                provider: session.provider_id,
                code: "refresh_account_mismatch".into(),
            }
            .into());
        }
        self.persist_secrets(&refreshed).await?;
        self.sessions
            .write()
            .await
            .insert(refreshed.account_id.clone(), refreshed.clone());
        self.save_sessions().await?;
        self.events.emit(CoreEvent::AuthSessionRefreshed {
            provider_id: refreshed.provider_id.clone(),
            account_id: refreshed.account_id.clone(),
        });
        Ok(refreshed)
    }

    pub async fn identity_for_launch(
        &self,
        account_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<MinecraftIdentity> {
        let mut session = self.session(account_id).await?;
        if session.is_expired(unix_now()) {
            self.events.emit(CoreEvent::AuthSessionExpired {
                provider_id: session.provider_id.clone(),
                account_id: session.account_id.clone(),
            });
            session = self.refresh(account_id, cancellation).await?;
        }
        let provider = self.provider(&session.provider_id).await?;
        let verified = provider
            .verify(
                &session,
                AuthContext {
                    credentials: self.credentials.as_ref(),
                    cancellation,
                },
            )
            .await?;
        validate_session(&session.provider_id, &verified)?;
        if verified.account_id != account_id {
            return Err(AuthError::Protocol {
                provider: session.provider_id,
                code: "verification_account_mismatch".into(),
            }
            .into());
        }
        self.persist_secrets(&verified).await?;
        self.sessions
            .write()
            .await
            .insert(account_id.to_owned(), verified.clone());
        self.save_sessions().await?;
        Ok(verified.minecraft)
    }

    pub async fn logout(&self, account_id: &str, cancellation: &CancellationToken) -> Result<()> {
        let session = self.session(account_id).await?;
        let provider = self.provider(&session.provider_id).await?;
        provider
            .logout(
                session.clone(),
                AuthContext {
                    credentials: self.credentials.as_ref(),
                    cancellation,
                },
            )
            .await?;
        self.sessions.write().await.remove(account_id);
        let prefix = credential_prefix(account_id);
        for name in [
            "provider_access",
            "provider_refresh",
            "device_secret",
            "minecraft_access",
        ] {
            self.credentials.delete(&format!("{prefix}{name}")).await?;
        }
        self.save_sessions().await?;
        self.events.emit(CoreEvent::AuthSessionRemoved {
            provider_id: session.provider_id,
            account_id: account_id.to_owned(),
        });
        Ok(())
    }

    async fn finish_step(
        &self,
        provider_id: &str,
        existing_id: Option<AuthFlowId>,
        step: Result<AuthProviderStep>,
    ) -> Result<AuthFlow> {
        match step {
            Ok(AuthProviderStep::Challenge { challenge, state }) => {
                let flow_id = existing_id.unwrap_or_else(|| self.next_id());
                let expires_at = match &challenge {
                    AuthChallenge::DeviceCode { expires_at, .. } => *expires_at,
                    _ => unix_now().saturating_add(DEFAULT_AUTH_FLOW_TTL_SECONDS),
                };
                self.flows.write().await.insert(
                    flow_id.clone(),
                    PendingFlow {
                        provider_id: provider_id.to_owned(),
                        state,
                        expires_at,
                    },
                );
                self.events.emit(CoreEvent::AuthChallengeRequired {
                    provider_id: provider_id.to_owned(),
                    flow_id: flow_id.to_string(),
                    challenge: challenge.kind(),
                });
                Ok(AuthFlow::Challenge {
                    flow_id,
                    provider_id: provider_id.to_owned(),
                    challenge,
                })
            }
            Ok(AuthProviderStep::Authenticated(session)) => {
                validate_session(provider_id, &session)?;
                self.persist_secrets(&session).await?;
                self.sessions
                    .write()
                    .await
                    .insert(session.account_id.clone(), session.clone());
                self.save_sessions().await?;
                self.events.emit(CoreEvent::AuthFlowCompleted {
                    provider_id: provider_id.to_owned(),
                    account_id: session.account_id.clone(),
                });
                self.events.emit(CoreEvent::AuthSessionCreated {
                    provider_id: provider_id.to_owned(),
                    account_id: session.account_id.clone(),
                });
                Ok(AuthFlow::Authenticated(session))
            }
            Err(error) => {
                self.events.emit(CoreEvent::AuthFlowFailed {
                    provider_id: provider_id.to_owned(),
                    error_kind: auth_error_kind(&error).into(),
                });
                Err(error)
            }
        }
    }

    async fn persist_secrets(&self, session: &AuthSession) -> Result<()> {
        let prefix = credential_prefix(&session.account_id);
        for (name, value) in [
            (
                "provider_access",
                session.provider_session.access_token.as_ref(),
            ),
            (
                "provider_refresh",
                session.provider_session.refresh_token.as_ref(),
            ),
            (
                "device_secret",
                session.provider_session.device_secret.as_ref(),
            ),
            ("minecraft_access", session.minecraft.access_token()),
        ] {
            if let Some(value) = value {
                self.credentials
                    .store(&format!("{prefix}{name}"), value)
                    .await?;
            }
        }
        Ok(())
    }

    async fn save_sessions(&self) -> Result<()> {
        let accounts = self
            .sessions
            .read()
            .await
            .values()
            .map(PersistedSession::from)
            .collect();
        let document = AccountDocument {
            format_version: ACCOUNT_FORMAT_VERSION,
            accounts,
        };
        if let Some(parent) = self.accounts_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temporary = self.accounts_path.with_extension("json.tmp");
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(&document)?).await?;
        if tokio::fs::try_exists(&self.accounts_path).await? {
            tokio::fs::remove_file(&self.accounts_path).await?;
        }
        tokio::fs::rename(temporary, &self.accounts_path).await?;
        Ok(())
    }

    async fn provider(&self, provider_id: &str) -> Result<Arc<dyn AuthProvider>> {
        self.providers
            .read()
            .await
            .get(provider_id)
            .cloned()
            .ok_or_else(|| Error::NotFound {
                kind: "authentication provider",
                id: provider_id.to_owned(),
            })
    }

    fn next_id(&self) -> AuthFlowId {
        let sequence = self.next_flow_id.fetch_add(1, Ordering::Relaxed);
        AuthFlowId(format!("flow-{}-{sequence}", unix_now()))
    }

    async fn prune_expired_flows(&self) {
        let now = unix_now();
        let expired = {
            let mut flows = self.flows.write().await;
            let expired = flows
                .iter()
                .filter(|(_, pending)| pending.expires_at <= now)
                .map(|(id, pending)| (id.clone(), pending.provider_id.clone()))
                .collect::<Vec<_>>();
            for (id, _) in &expired {
                flows.remove(id);
            }
            expired
        };
        for (_, provider_id) in expired {
            self.events.emit(CoreEvent::AuthFlowFailed {
                provider_id,
                error_kind: "expired".into(),
            });
        }
    }
}

const ACCOUNT_FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDocument {
    format_version: u32,
    accounts: Vec<PersistedSession>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSession {
    account_id: String,
    provider_id: String,
    identity: AuthIdentity,
    provider_metadata: BTreeMap<String, String>,
    expires_at: Option<u64>,
    refreshable: bool,
    minecraft: PersistedMinecraftIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PersistedMinecraftIdentity {
    Official {
        username: String,
        uuid: String,
        xuid: Option<String>,
        expires_at: Option<u64>,
    },
    Offline(OfflineMinecraftIdentity),
}

impl From<&AuthSession> for PersistedSession {
    fn from(session: &AuthSession) -> Self {
        let minecraft = match &session.minecraft {
            MinecraftIdentity::Official(identity) => PersistedMinecraftIdentity::Official {
                username: identity.username.clone(),
                uuid: identity.uuid.clone(),
                xuid: identity.xuid.clone(),
                expires_at: identity.expires_at,
            },
            MinecraftIdentity::Offline(identity) => {
                PersistedMinecraftIdentity::Offline(identity.clone())
            }
        };
        Self {
            account_id: session.account_id.clone(),
            provider_id: session.provider_id.clone(),
            identity: session.identity.clone(),
            provider_metadata: session.provider_session.metadata.clone(),
            expires_at: session.expires_at,
            refreshable: session.refreshable,
            minecraft,
        }
    }
}

/// Built-in provider for explicitly offline accounts.
#[derive(Debug, Clone, Default)]
pub struct OfflineAuthProvider;

#[async_trait]
impl AuthProvider for OfflineAuthProvider {
    fn id(&self) -> &str {
        "offline"
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            interactive: true,
            credentials: true,
            verify: true,
            logout: true,
            ..AuthCapabilities::default()
        }
    }

    async fn begin(
        &self,
        request: AuthRequest,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, self.id())?;
        match request.account_hint {
            Some(username) => offline_session(username).map(AuthProviderStep::Authenticated),
            None => Ok(AuthProviderStep::Challenge {
                challenge: AuthChallenge::Credentials {
                    username_label: "Minecraft username".into(),
                    password_label: "Password".into(),
                    password_required: false,
                },
                state: SecretString::new("offline-credentials"),
            }),
        }
    }

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, self.id())?;
        if state.expose_secret() != "offline-credentials" {
            return Err(AuthError::Protocol {
                provider: self.id().into(),
                code: "invalid_flow_state".into(),
            }
            .into());
        }
        match response {
            AuthResponse::Credentials { username, .. } => {
                offline_session(username).map(AuthProviderStep::Authenticated)
            }
            _ => Err(AuthError::Protocol {
                provider: self.id().into(),
                code: "unexpected_challenge_response".into(),
            }
            .into()),
        }
    }

    async fn refresh(
        &self,
        session: &AuthSession,
        context: AuthContext<'_>,
    ) -> Result<AuthSession> {
        cancellation_check(context.cancellation, self.id())?;
        Ok(session.clone())
    }

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession> {
        cancellation_check(context.cancellation, self.id())?;
        Ok(session.clone())
    }

    async fn logout(&self, _session: AuthSession, context: AuthContext<'_>) -> Result<()> {
        cancellation_check(context.cancellation, self.id())
    }
}

fn offline_session(username: String) -> Result<AuthSession> {
    let minecraft = OfflineMinecraftIdentity::new(username.clone())?;
    Ok(AuthSession {
        account_id: format!("offline-{username}"),
        provider_id: "offline".into(),
        identity: AuthIdentity {
            provider_user_id: format!("offline:{username}"),
            username,
            metadata: BTreeMap::new(),
        },
        provider_session: ProviderSession::default(),
        expires_at: None,
        refreshable: false,
        minecraft: MinecraftIdentity::Offline(minecraft),
    })
}

fn validate_provider_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::InvalidConfig(
            "authentication provider id is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_session(expected_provider: &str, session: &AuthSession) -> Result<()> {
    if session.provider_id != expected_provider {
        return Err(AuthError::Protocol {
            provider: expected_provider.into(),
            code: "provider_identity_mismatch".into(),
        }
        .into());
    }
    if session.account_id.is_empty()
        || session.account_id.len() > 128
        || session.account_id.chars().any(char::is_control)
    {
        return Err(AuthError::Protocol {
            provider: expected_provider.into(),
            code: "invalid_account_id".into(),
        }
        .into());
    }
    validate_minecraft_username(session.minecraft.username())?;
    validate_uuid(session.minecraft.uuid())
}

fn validate_minecraft_username(username: &str) -> Result<()> {
    if !(3..=16).contains(&username.len())
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(AuthError::InvalidMinecraftProfile {
            provider: "identity".into(),
        }
        .into());
    }
    Ok(())
}

fn validate_uuid(uuid: &str) -> Result<()> {
    let valid = uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err(AuthError::InvalidMinecraftProfile {
            provider: "identity".into(),
        }
        .into());
    }
    Ok(())
}

/// Java-compatible UUID v3 used by the Vanilla server for offline players.
#[must_use]
fn offline_uuid(username: &str) -> String {
    let digest = md5::compute(format!("OfflinePlayer:{username}"));
    let mut bytes = digest.0;
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn validate_credential_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 256
        || key.starts_with('/')
        || key.contains("..")
        || key.chars().any(char::is_control)
    {
        return Err(AuthError::CredentialStore {
            operation: "validate_key",
        }
        .into());
    }
    Ok(())
}

fn validate_public_credential_key(key: &str) -> Result<()> {
    validate_credential_key(key)?;
    if key == CREDENTIAL_INDEX_KEY {
        return Err(AuthError::CredentialStore {
            operation: "validate_key",
        }
        .into());
    }
    Ok(())
}

fn validate_credential_prefix(prefix: &str) -> Result<()> {
    if prefix.len() > 256
        || prefix.contains("..")
        || prefix.chars().any(char::is_control)
        || prefix.starts_with(CREDENTIAL_INDEX_KEY)
    {
        return Err(AuthError::CredentialStore {
            operation: "validate_prefix",
        }
        .into());
    }
    Ok(())
}

fn credential_prefix(account_id: &str) -> String {
    format!("accounts/{account_id}/")
}

fn cancellation_check(token: &CancellationToken, provider: &str) -> Result<()> {
    if token.is_cancelled() {
        Err(AuthError::Cancelled {
            provider: provider.to_owned(),
        }
        .into())
    } else {
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

fn auth_error_kind(error: &Error) -> &'static str {
    match error {
        Error::Auth(error) => error.kind(),
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc as StdArc, Mutex},
    };

    #[derive(Clone, Default)]
    struct LogBuffer(StdArc<Mutex<Vec<u8>>>);

    struct LogWriter(LogBuffer);

    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 .0.lock().expect("log lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogBuffer {
        type Writer = LogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            LogWriter(self.clone())
        }
    }

    #[derive(Debug, Default)]
    struct MockAuthProvider;

    #[async_trait]
    impl AuthProvider for MockAuthProvider {
        fn id(&self) -> &str {
            "mock"
        }

        fn capabilities(&self) -> AuthCapabilities {
            AuthCapabilities {
                interactive: true,
                credentials: true,
                two_factor: true,
                browser: true,
                refresh: true,
                logout: true,
                verify: true,
                ..AuthCapabilities::default()
            }
        }

        async fn begin(
            &self,
            request: AuthRequest,
            _context: AuthContext<'_>,
        ) -> Result<AuthProviderStep> {
            let mode = request.account_hint.as_deref().unwrap_or("credentials");
            let challenge = match mode {
                "browser" => AuthChallenge::Browser {
                    authorization_url: Url::parse("https://login.example/authorize?state=secret")
                        .expect("URL"),
                    callback_url: Url::parse("http://127.0.0.1/callback").expect("URL"),
                },
                _ => AuthChallenge::Credentials {
                    username_label: "Username".into(),
                    password_label: "Password".into(),
                    password_required: true,
                },
            };
            Ok(AuthProviderStep::Challenge {
                challenge,
                state: SecretString::new(mode),
            })
        }

        async fn continue_flow(
            &self,
            state: SecretString,
            response: AuthResponse,
            _context: AuthContext<'_>,
        ) -> Result<AuthProviderStep> {
            if state.expose_secret() == "credentials" {
                if let AuthResponse::Credentials { username, .. } = response {
                    return Ok(AuthProviderStep::Challenge {
                        challenge: AuthChallenge::TwoFactorCode {
                            message: Some("Enter code".into()),
                        },
                        state: SecretString::new(format!("two-factor:{username}")),
                    });
                }
            }
            if let Some(username) = state.expose_secret().strip_prefix("two-factor:") {
                if matches!(response, AuthResponse::TwoFactorCode { .. }) {
                    let mut session = offline_session(username.to_owned())?;
                    session.account_id = "mock-account".into();
                    session.provider_id = self.id().into();
                    session.identity.provider_user_id = "mock-user".into();
                    session.provider_session.access_token =
                        Some(SecretString::new("provider-secret"));
                    session.refreshable = true;
                    return Ok(AuthProviderStep::Authenticated(session));
                }
            }
            Err(AuthError::Protocol {
                provider: self.id().into(),
                code: "unexpected_mock_response".into(),
            }
            .into())
        }

        async fn refresh(
            &self,
            session: &AuthSession,
            _context: AuthContext<'_>,
        ) -> Result<AuthSession> {
            Ok(session.clone())
        }

        async fn verify(
            &self,
            session: &AuthSession,
            _context: AuthContext<'_>,
        ) -> Result<AuthSession> {
            Ok(session.clone())
        }

        async fn logout(&self, _session: AuthSession, _context: AuthContext<'_>) -> Result<()> {
            Ok(())
        }
    }

    fn manager() -> AuthManager {
        let directory = tempfile::tempdir().expect("tempdir").keep();
        AuthManager::new(
            directory,
            Arc::new(InMemoryCredentialStore::default()),
            EventBus::new(32),
        )
    }

    #[test]
    fn secrets_are_redacted_and_offline_uuid_is_stable() {
        let secret = SecretString::new("never-print-me");
        assert!(!format!("{secret:?}").contains(secret.expose_secret()));
        let error = AuthError::Protocol {
            provider: "mock".into(),
            code: "remote-secret-must-not-be-rendered".into(),
        };
        assert!(!format!("{error:?}").contains("remote-secret-must-not-be-rendered"));
        assert!(!error
            .to_string()
            .contains("remote-secret-must-not-be-rendered"));
        let official = AuthSession {
            account_id: "microsoft-account".into(),
            provider_id: "microsoft".into(),
            identity: AuthIdentity {
                provider_user_id: "user-hash".into(),
                username: "Player_1".into(),
                metadata: BTreeMap::from([("private-looking".into(), "metadata-secret".into())]),
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new("oauth-secret")),
                refresh_token: Some(SecretString::new("refresh-secret")),
                device_secret: Some(SecretString::new("device-secret")),
                metadata: BTreeMap::from([("private-looking".into(), "state-secret".into())]),
            },
            expires_at: Some(100),
            refreshable: true,
            minecraft: MinecraftIdentity::Official(OfficialMinecraftIdentity {
                username: "Player_1".into(),
                uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                access_token: SecretString::new("minecraft-secret"),
                xuid: Some("42".into()),
                expires_at: Some(100),
            }),
        };
        let debug = format!("{official:?}");
        for value in [
            "oauth-secret",
            "refresh-secret",
            "device-secret",
            "state-secret",
            "minecraft-secret",
            "metadata-secret",
        ] {
            assert!(!debug.contains(value));
        }
        let persisted =
            serde_json::to_string(&PersistedSession::from(&official)).expect("persisted metadata");
        for value in [
            "oauth-secret",
            "refresh-secret",
            "device-secret",
            "minecraft-secret",
        ] {
            assert!(!persisted.contains(value));
        }
        assert_eq!(
            offline_uuid("Steve"),
            "5627dd98-e6be-3c21-b8a8-e92344183641"
        );
    }

    #[tokio::test]
    async fn offline_provider_uses_generic_challenge_flow() {
        let manager = manager();
        manager
            .register(Arc::new(OfflineAuthProvider))
            .await
            .expect("register");
        let cancellation = CancellationToken::default();
        let flow = manager
            .begin("offline", AuthRequest::default(), &cancellation)
            .await
            .expect("begin");
        let AuthFlow::Challenge { flow_id, .. } = flow else {
            panic!("expected challenge")
        };
        let completed = manager
            .continue_flow(
                &flow_id,
                AuthResponse::Credentials {
                    username: "Player_1".into(),
                    password: None,
                },
                &cancellation,
            )
            .await
            .expect("continue");
        let AuthFlow::Authenticated(session) = completed else {
            panic!("expected session")
        };
        assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
        assert_eq!(manager.sessions().await.len(), 1);
    }

    #[tokio::test]
    async fn in_memory_credential_store_supports_full_lifecycle() {
        let store = InMemoryCredentialStore::default();
        store
            .store("accounts/a/access", &SecretString::new("vault-secret"))
            .await
            .expect("store");
        assert_eq!(store.list("accounts/a/").await.expect("list").len(), 1);
        let loaded = store
            .load("accounts/a/access")
            .await
            .expect("load")
            .expect("secret");
        assert_eq!(loaded.expose_secret(), "vault-secret");
        store.delete("accounts/a/access").await.expect("delete");
        assert!(store
            .load("accounts/a/access")
            .await
            .expect("load after delete")
            .is_none());
    }

    #[tokio::test]
    async fn mock_validates_credentials_then_two_factor_without_leaking_secrets() {
        let directory = tempfile::tempdir().expect("tempdir");
        let events = EventBus::new(32);
        let mut receiver = events.subscribe();
        let manager = AuthManager::new(
            directory.path(),
            Arc::new(InMemoryCredentialStore::default()),
            events,
        );
        manager
            .register(Arc::new(MockAuthProvider))
            .await
            .expect("register");
        let cancellation = CancellationToken::default();
        let flow = manager
            .begin("mock", AuthRequest::default(), &cancellation)
            .await
            .expect("begin");
        let AuthFlow::Challenge { flow_id, .. } = flow else {
            panic!("expected credentials")
        };
        let flow = manager
            .continue_flow(
                &flow_id,
                AuthResponse::Credentials {
                    username: "Player_1".into(),
                    password: Some(SecretString::new("password-secret")),
                },
                &cancellation,
            )
            .await
            .expect("credentials");
        assert!(matches!(
            flow,
            AuthFlow::Challenge {
                challenge: AuthChallenge::TwoFactorCode { .. },
                ..
            }
        ));
        let AuthFlow::Challenge { flow_id, .. } = flow else {
            panic!("expected two-factor")
        };
        let flow = manager
            .continue_flow(
                &flow_id,
                AuthResponse::TwoFactorCode {
                    code: SecretString::new("123456"),
                },
                &cancellation,
            )
            .await
            .expect("two-factor");
        let rendered = format!("{flow:?}");
        assert!(!rendered.contains("password-secret"));
        assert!(!rendered.contains("provider-secret"));
        assert!(!rendered.contains("123456"));

        let mut serialized_events = String::new();
        while let Ok(event) = receiver.try_recv() {
            serialized_events.push_str(&serde_json::to_string(&event).expect("serialize event"));
        }
        for secret in ["password-secret", "provider-secret", "123456"] {
            assert!(!serialized_events.contains(secret));
        }
        let persisted = tokio::fs::read_to_string(directory.path().join("auth/accounts.json"))
            .await
            .expect("account metadata");
        for secret in ["password-secret", "provider-secret", "123456"] {
            assert!(!persisted.contains(secret));
        }

        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(auth_session = ?flow, "authentication completed");
        });
        let logs =
            String::from_utf8(buffer.0.lock().expect("log lock").clone()).expect("UTF-8 logs");
        assert!(!logs.contains("provider-secret"));
    }

    #[tokio::test]
    async fn cancellation_ends_a_flow_without_background_work() {
        let manager = manager();
        manager
            .register(Arc::new(MockAuthProvider))
            .await
            .expect("register");
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = manager
            .begin("mock", AuthRequest::default(), &cancellation)
            .await
            .expect_err("cancelled");
        assert!(matches!(error, Error::Auth(AuthError::Cancelled { .. })));

        let cancellation = CancellationToken::default();
        let AuthFlow::Challenge { flow_id, .. } = manager
            .begin("mock", AuthRequest::default(), &cancellation)
            .await
            .expect("begin pending flow")
        else {
            panic!("challenge")
        };
        manager.cancel_flow(&flow_id).await.expect("cancel flow");
        assert!(manager
            .continue_flow(
                &flow_id,
                AuthResponse::Credentials {
                    username: "Player_1".into(),
                    password: None,
                },
                &cancellation,
            )
            .await
            .is_err());
    }
}
