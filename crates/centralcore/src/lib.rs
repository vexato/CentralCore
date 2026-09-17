//! CentralCore is a UI-independent Minecraft launcher engine.
//!
//! The crate exposes focused services behind [`CentralCore`] and extension
//! contracts for authentication, instance providers, and mod loaders.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod auth;
pub mod cache;
pub mod config;
pub mod download;
pub mod errors;
pub mod events;
pub mod files;
pub mod instance;
pub mod java;
pub mod loaders;
mod lock;
pub mod minecraft;
pub mod mods;
pub mod platform;
pub mod process;
pub mod providers;
pub mod trust;

pub use cache::{CacheManager, CachePolicy};
pub use config::CoreConfig;
pub use errors::{Error, Result};
pub use events::{CoreEvent, EventBus, EventEnvelope, EventId};
pub use instance::{Instance, InstanceId, InstanceService, InstanceSpec, InstanceStatus};
pub use process::{
    DetachedInstance, ProcessExit, ProcessManager, ProcessRecoveryReport, RunningInstance,
};
pub use trust::TrustStore;

use auth::{AuthManager, CredentialStore, OfflineAuthProvider, SystemCredentialStore};
use download::DownloadManager;
use java::JavaManager;
use loaders::LoaderManager;
use minecraft::{MinecraftManager, MinecraftServices};
use providers::ProviderManager;

/// Main entry point for applications embedding CentralCore.
#[derive(Debug, Clone)]
pub struct CentralCore {
    config: CoreConfig,
    events: EventBus,
    instances: InstanceService,
    downloads: DownloadManager,
    java: JavaManager,
    loaders: LoaderManager,
    auth: AuthManager,
    minecraft: MinecraftManager,
    processes: ProcessManager,
    cache: CacheManager,
    providers: ProviderManager,
    trust: TrustStore,
}

impl CentralCore {
    /// Starts construction with safe local defaults.
    #[must_use]
    pub fn builder() -> CentralCoreBuilder {
        CentralCoreBuilder::default()
    }

    /// Returns the validated active configuration.
    #[must_use]
    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    /// Accesses isolated instance storage.
    #[must_use]
    pub fn instances(&self) -> &InstanceService {
        &self.instances
    }

    /// Accesses Java runtime discovery and selection.
    #[must_use]
    pub fn java(&self) -> &JavaManager {
        &self.java
    }

    /// Accesses loader discovery and the generic loader registry.
    #[must_use]
    pub fn loaders(&self) -> &LoaderManager {
        &self.loaders
    }

    /// Accesses download policy, validation, and cancellation primitives.
    #[must_use]
    pub fn downloads(&self) -> &DownloadManager {
        &self.downloads
    }

    /// Accesses the authentication provider registry.
    #[must_use]
    pub fn auth(&self) -> &AuthManager {
        &self.auth
    }

    /// Accesses official Minecraft metadata, installation, and launch.
    #[must_use]
    pub fn minecraft(&self) -> &MinecraftManager {
        &self.minecraft
    }

    /// Accesses the multi-instance process registry.
    #[must_use]
    pub fn processes(&self) -> &ProcessManager {
        &self.processes
    }

    /// Accesses shared-cache status, verification, and pruning.
    #[must_use]
    pub fn cache(&self) -> &CacheManager {
        &self.cache
    }

    /// Accesses the persistent provider registry and static-provider pipeline.
    #[must_use]
    pub fn providers(&self) -> &ProviderManager {
        &self.providers
    }

    /// Accesses locally approved provider-signing public keys.
    #[must_use]
    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    /// Accesses the shared event bus.
    #[must_use]
    pub fn events(&self) -> &EventBus {
        &self.events
    }

    /// Removes a managed Java runtime after proving no tracked Minecraft process uses it.
    pub async fn remove_java_runtime(&self, runtime_id: &str) -> Result<()> {
        let runtime = self.java.managed().verify(runtime_id).await?;
        if self
            .processes
            .is_executable_running(&runtime.runtime.executable)
            .await?
        {
            return Err(Error::Java("Java runtime is currently in use".into()));
        }
        self.java.managed().remove(runtime_id).await
    }
}

/// Builder for [`CentralCore`].
#[derive(Clone)]
pub struct CentralCoreBuilder {
    data_directory: PathBuf,
    config: Option<CoreConfig>,
    credential_store: Option<Arc<dyn CredentialStore>>,
}

impl std::fmt::Debug for CentralCoreBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CentralCoreBuilder")
            .field("data_directory", &self.data_directory)
            .field("config", &self.config)
            .field("custom_credential_store", &self.credential_store.is_some())
            .finish()
    }
}

impl Default for CentralCoreBuilder {
    fn default() -> Self {
        Self {
            data_directory: PathBuf::from(".centralcore"),
            config: None,
            credential_store: None,
        }
    }
}

impl CentralCoreBuilder {
    /// Selects the root used for config, instances, caches, and runtimes.
    #[must_use]
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_directory = path.into();
        self.config = None;
        self
    }

    /// Uses an explicit already-constructed configuration.
    #[must_use]
    pub fn config(mut self, config: CoreConfig) -> Self {
        self.data_directory = config.data_directory.clone();
        self.config = Some(config);
        self
    }

    /// Overrides the native credential vault, primarily for tests or host integration.
    #[must_use]
    pub fn credential_store(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.credential_store = Some(store);
        self
    }

    /// Validates configuration, prepares the data layout, and wires services.
    pub async fn build(self) -> Result<CentralCore> {
        let config_path = self.data_directory.join("centralcore.json");
        let config = match self.config {
            Some(config) => config,
            None if tokio::fs::try_exists(&config_path).await? => {
                CoreConfig::load(&config_path).await?
            }
            None => CoreConfig::new(&self.data_directory),
        };
        config.validate()?;

        for directory in [
            config.data_directory.as_path(),
            &config.data_directory.join("instances"),
            &config.data_directory.join("cache"),
            &config.data_directory.join("runtimes"),
            &config.data_directory.join("minecraft"),
            &config.data_directory.join("processes"),
            &config.data_directory.join("locks"),
            &config.data_directory.join("providers"),
            &config.data_directory.join("auth"),
            &config.data_directory.join("trust"),
        ] {
            tokio::fs::create_dir_all(directory).await?;
        }
        if !tokio::fs::try_exists(&config_path).await? {
            config.save(&config_path).await?;
        }

        let events = EventBus::new(config.event_capacity);
        let trust = TrustStore::new(&config.data_directory, events.clone());
        let locks = lock::LockManager::new(config.data_directory.join("locks"));
        let instances = InstanceService::new(
            config.data_directory.join("instances"),
            events.clone(),
            locks.clone(),
        );
        let downloads = DownloadManager::new(config.download.clone(), events.clone())?
            .with_locks(locks.clone());
        let java = JavaManager::new(
            config.java.clone(),
            config.data_directory.join("runtimes").join("java"),
            config.data_directory.join("cache").join("java"),
            downloads.clone(),
            locks.clone(),
            events.clone(),
        );
        let loaders = LoaderManager::new(
            config.data_directory.join("minecraft"),
            downloads.clone(),
            java.clone(),
            events.clone(),
        );
        let processes =
            ProcessManager::new(config.data_directory.join("processes"), events.clone());
        let cache = CacheManager::new(
            config.data_directory.join("minecraft"),
            instances.clone(),
            locks.clone(),
            events.clone(),
            config.reliability.verify_concurrency,
        );
        let minecraft = MinecraftManager::new(
            &config.data_directory,
            config.minecraft.clone(),
            MinecraftServices {
                downloads: downloads.clone(),
                java: java.clone(),
                instances: instances.clone(),
                processes: processes.clone(),
                cache: cache.clone(),
                locks: locks.clone(),
                events: events.clone(),
                loaders: loaders.clone(),
            },
        );
        let providers = ProviderManager::new(
            &config.data_directory,
            config.providers.clone(),
            downloads.clone(),
            instances.clone(),
            minecraft.clone(),
            cache.clone(),
            locks,
            events.clone(),
            trust.clone(),
        );
        processes.recover().await?;
        minecraft.recover().await?;
        java.managed().recover().await?;
        let credential_store = self.credential_store.unwrap_or_else(|| {
            Arc::new(SystemCredentialStore::new("centralcore")) as Arc<dyn CredentialStore>
        });
        let auth = AuthManager::new(&config.data_directory, credential_store, events.clone());
        auth.register(Arc::new(OfflineAuthProvider)).await?;
        auth.load_configured().await?;
        auth.load_sessions().await?;

        Ok(CentralCore {
            config,
            events,
            instances,
            downloads,
            java,
            loaders,
            auth,
            minecraft,
            processes,
            cache,
            providers,
            trust,
        })
    }
}

/// Returns the conventional config file below a data directory.
#[must_use]
pub fn config_path(data_directory: impl AsRef<Path>) -> PathBuf {
    data_directory.as_ref().join("centralcore.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builder_prepares_a_versioned_layout() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let core = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("core");

        assert!(core.instances().root().is_dir());
        assert!(temporary.path().join("centralcore.json").is_file());
        assert_eq!(core.config().format_version, config::CONFIG_FORMAT_VERSION);
    }

    #[test]
    fn facade_is_clone_send_and_sync() {
        fn assert_traits<T: Clone + Send + Sync>() {}
        assert_traits::<CentralCore>();
        assert_traits::<CentralCoreBuilder>();
    }

    #[tokio::test]
    async fn two_cores_share_one_data_directory_without_duplicate_creation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let first = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("first core");
        let second = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("second core");
        let left = first
            .instances()
            .create(InstanceSpec::vanilla("shared", "Shared", "1.21.1").expect("left spec"));
        let right = second
            .instances()
            .create(InstanceSpec::vanilla("shared", "Shared", "1.21.1").expect("right spec"));
        let (left, right) = tokio::join!(left, right);
        assert_ne!(left.is_ok(), right.is_ok());
        assert_eq!(first.instances().list().await.expect("list").len(), 1);
    }
}
