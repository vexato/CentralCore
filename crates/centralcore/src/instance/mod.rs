//! Isolated instance model and local persistence.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    events::{CoreEvent, EventBus},
    java::JavaInstanceConfig,
    loaders::LoaderConfig,
    lock::LockManager,
    minecraft::MinecraftConfig,
    mods::ModConfig,
    Error, Result,
};

const INSTANCE_FORMAT_VERSION: u32 = 1;

/// Validated, filesystem-safe identifier for an instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(String);

impl InstanceId {
    /// Accepts 1-64 portable ASCII letters, digits, hyphens, and underscores.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(invalid_id(id, "identifier is empty"));
        }
        if id.len() > 64 {
            return Err(invalid_id(id, "identifier exceeds 64 bytes"));
        }
        if !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_id(
                id,
                "only ASCII letters, digits, hyphens, and underscores are allowed",
            ));
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn invalid_id(id: String, reason: &'static str) -> Error {
    Error::InvalidInstanceId { id, reason }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for InstanceId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InstanceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id = String::deserialize(deserializer)?;
        Self::new(id).map_err(D::Error::custom)
    }
}

/// Optional server selected when launching an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// Provider-neutral authentication policy for an instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAuthPolicy {
    #[serde(default)]
    pub required: bool,
    /// IDs only: manifests cannot define credential-bearing endpoints.
    #[serde(default)]
    pub providers: Vec<String>,
}

impl InstanceAuthPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.required && self.providers.is_empty() {
            return Err(Error::InvalidConfig(
                "required instance authentication must list at least one provider".into(),
            ));
        }
        if self.providers.len() > 32 {
            return Err(Error::InvalidConfig(
                "instance authentication policy contains too many providers".into(),
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for id in &self.providers {
            if id.is_empty()
                || id.len() > 64
                || !id.as_bytes()[0].is_ascii_alphanumeric()
                || !id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
                || !unique.insert(id)
            {
                return Err(Error::InvalidConfig(
                    "instance authentication policy contains an invalid provider id".into(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn allows(&self, provider_id: &str) -> bool {
        self.providers.is_empty() || self.providers.iter().any(|id| id == provider_id)
    }
}

/// Serializable definition shared by local storage and remote providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSpec {
    id: InstanceId,
    name: String,
    minecraft: MinecraftConfig,
    #[serde(default)]
    java: JavaInstanceConfig,
    loader: Option<LoaderConfig>,
    #[serde(default)]
    mods: Vec<ModConfig>,
    server: Option<ServerConfig>,
    #[serde(default)]
    authentication: InstanceAuthPolicy,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

impl InstanceSpec {
    /// Creates a Vanilla instance with safe defaults.
    pub fn vanilla(
        id: impl Into<String>,
        name: impl Into<String>,
        minecraft_version: impl Into<String>,
    ) -> Result<Self> {
        let spec = Self {
            id: InstanceId::new(id)?,
            name: name.into(),
            minecraft: MinecraftConfig::new(minecraft_version)?,
            java: JavaInstanceConfig::default(),
            loader: None,
            mods: Vec::new(),
            server: None,
            authentication: InstanceAuthPolicy::default(),
            metadata: BTreeMap::new(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Replaces per-instance Java settings.
    pub fn with_java(mut self, java: JavaInstanceConfig) -> Result<Self> {
        self.java = java;
        self.validate()?;
        Ok(self)
    }

    /// Selects a mod loader.
    pub fn with_loader(mut self, loader: LoaderConfig) -> Result<Self> {
        self.loader = Some(loader);
        self.validate()?;
        Ok(self)
    }

    /// Replaces the provider-neutral mod declarations.
    #[must_use]
    pub fn with_mods(mut self, mods: Vec<ModConfig>) -> Self {
        self.mods = mods;
        self
    }

    /// Selects a default multiplayer server.
    #[must_use]
    pub fn with_server(mut self, server: ServerConfig) -> Self {
        self.server = Some(server);
        self
    }

    pub fn with_authentication(mut self, policy: InstanceAuthPolicy) -> Result<Self> {
        policy.validate()?;
        self.authentication = policy;
        Ok(self)
    }

    /// Adds provider/application metadata without changing the core schema.
    pub fn insert_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Validates values created in code or deserialized by a provider.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err(Error::InvalidConfig(
                "instance name must contain 1-128 characters".into(),
            ));
        }
        self.minecraft.validate()?;
        if self.java.minimum_memory_mib == 0
            || self.java.maximum_memory_mib < self.java.minimum_memory_mib
        {
            return Err(Error::InvalidConfig(
                "Java memory limits are inconsistent".into(),
            ));
        }
        if let Some(loader) = &self.loader {
            loader.validate()?;
        }
        self.authentication.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn id(&self) -> &InstanceId {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn minecraft(&self) -> &MinecraftConfig {
        &self.minecraft
    }

    #[must_use]
    pub fn java(&self) -> &JavaInstanceConfig {
        &self.java
    }

    #[must_use]
    pub fn loader(&self) -> Option<&LoaderConfig> {
        self.loader.as_ref()
    }

    #[must_use]
    pub fn mods(&self) -> &[ModConfig] {
        &self.mods
    }

    #[must_use]
    pub fn server(&self) -> Option<&ServerConfig> {
        self.server.as_ref()
    }

    #[must_use]
    pub fn authentication(&self) -> &InstanceAuthPolicy {
        &self.authentication
    }

    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// A local isolated instance and its trusted root path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    spec: InstanceSpec,
    path: PathBuf,
}

impl Instance {
    #[must_use]
    pub fn id(&self) -> &InstanceId {
        self.spec.id()
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.spec.name()
    }

    #[must_use]
    pub fn spec(&self) -> &InstanceSpec {
        &self.spec
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn minecraft_dir(&self) -> PathBuf {
        self.path.join(".minecraft")
    }

    pub(crate) fn with_spec(&self, spec: InstanceSpec) -> Result<Self> {
        spec.validate()?;
        if spec.id() != self.id() {
            return Err(Error::InvalidConfig(
                "transient instance specification changed the instance id".into(),
            ));
        }
        Ok(Self {
            spec,
            path: self.path.clone(),
        })
    }
}

/// Current locally observable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InstanceStatus {
    /// Retained for API compatibility with Phase 1; new code receives a more
    /// precise installation status.
    #[deprecated(note = "use NotInstalled, Installing, Updating, Installed, Broken, or Running")]
    Available,
    NotFound,
    NotInstalled,
    Installing,
    Updating,
    Recoverable,
    Installed,
    Broken,
    Running,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstanceDocument {
    format_version: u32,
    instance: InstanceSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallStateDocument {
    format_version: u32,
    status: PersistedInstallStatus,
    version_id: String,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedInstallStatus {
    Installing,
    Updating,
    Interrupted,
    Installed,
    Broken,
}

/// CRUD service for isolated local instances.
#[derive(Debug, Clone)]
pub struct InstanceService {
    root: PathBuf,
    events: EventBus,
    locks: LockManager,
}

impl InstanceService {
    pub(crate) fn new(root: PathBuf, events: EventBus, locks: LockManager) -> Self {
        Self {
            root,
            events,
            locks,
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the standard instance layout and persists its definition.
    pub async fn create(&self, spec: InstanceSpec) -> Result<Instance> {
        spec.validate()?;
        let _lock = self
            .locks
            .acquire_exclusive(format!("instance:{}", spec.id()))
            .await?;
        tokio::fs::create_dir_all(&self.root).await?;
        let target = self.root.join(spec.id().as_str());
        match tokio::fs::symlink_metadata(&target).await {
            Ok(_) => {
                return Err(Error::AlreadyExists {
                    kind: "instance",
                    id: spec.id().to_string(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::InvalidConfig("system clock precedes Unix epoch".into()))?
            .as_nanos();
        let staging = self.root.join(format!(".{}.{}.creating", spec.id(), nonce));
        tokio::fs::create_dir(&staging).await?;

        let result = self.write_new_instance(&staging, &spec).await;
        if let Err(error) = result {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(error);
        }
        if let Err(error) = tokio::fs::rename(&staging, &target).await {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(error.into());
        }

        self.events.emit(CoreEvent::InstanceCreated {
            instance_id: spec.id().to_string(),
        });
        Ok(Instance { spec, path: target })
    }

    async fn write_new_instance(&self, directory: &Path, spec: &InstanceSpec) -> Result<()> {
        for child in [".minecraft", "mods", "config", "logs", "runtime"] {
            tokio::fs::create_dir(directory.join(child)).await?;
        }
        let document = InstanceDocument {
            format_version: INSTANCE_FORMAT_VERSION,
            instance: spec.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&document)?;
        tokio::fs::write(directory.join("instance.json"), bytes).await?;
        Ok(())
    }

    /// Loads and validates one persisted instance.
    pub async fn get(&self, id: impl Into<String>) -> Result<Instance> {
        let id = InstanceId::new(id)?;
        let path = self.root.join(id.as_str());
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound {
                    kind: "instance",
                    id: id.to_string(),
                }
            } else {
                error.into()
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::UnsafeFilesystemEntry {
                path,
                reason: "instance root must be a real directory",
            });
        }
        let metadata_path = path.join("instance.json");
        let file_metadata = tokio::fs::symlink_metadata(&metadata_path).await?;
        if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: metadata_path,
                reason: "instance metadata must be a real file",
            });
        }
        let bytes = tokio::fs::read(&metadata_path).await?;
        let document: InstanceDocument = serde_json::from_slice(&bytes)?;
        if document.format_version != INSTANCE_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "instance",
                version: document.format_version,
            });
        }
        if document.instance.id() != &id {
            return Err(Error::InvalidConfig(
                "instance directory and document identifiers differ".into(),
            ));
        }
        document.instance.validate()?;
        Ok(Instance {
            spec: document.instance,
            path,
        })
    }

    /// Atomically replaces trusted instance metadata while retaining its root.
    /// Callers performing a compound operation must already hold the instance lock.
    pub(crate) async fn replace_spec_unlocked(
        &self,
        instance: &Instance,
        spec: InstanceSpec,
    ) -> Result<Instance> {
        spec.validate()?;
        if spec.id() != instance.id() {
            return Err(Error::InvalidConfig(
                "replacement instance specification changed the instance id".into(),
            ));
        }
        let document = InstanceDocument {
            format_version: INSTANCE_FORMAT_VERSION,
            instance: spec.clone(),
        };
        let destination = instance.path().join("instance.json");
        let temporary = instance.path().join("instance.json.tmp");
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(&document)?).await?;
        if tokio::fs::try_exists(&destination).await? {
            tokio::fs::remove_file(&destination).await?;
        }
        tokio::fs::rename(temporary, destination).await?;
        Ok(Instance {
            spec,
            path: instance.path().to_path_buf(),
        })
    }

    /// Lists local instances in deterministic identifier order.
    pub async fn list(&self) -> Result<Vec<Instance>> {
        tokio::fs::create_dir_all(&self.root).await?;
        let mut reader = tokio::fs::read_dir(&self.root).await?;
        let mut ids = Vec::new();
        while let Some(entry) = reader.next_entry().await? {
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if let Ok(id) = InstanceId::new(name) {
                ids.push(id);
            }
        }
        ids.sort();
        let mut instances = Vec::with_capacity(ids.len());
        for id in ids {
            instances.push(self.get(id.to_string()).await?);
        }
        Ok(instances)
    }

    /// Removes exactly one validated instance directory.
    pub async fn delete(&self, id: impl Into<String>) -> Result<()> {
        let id = InstanceId::new(id)?;
        let _lock = self
            .locks
            .try_acquire_exclusive(format!("instance:{id}"))
            .await?;
        let path = self.root.join(id.as_str());
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound {
                    kind: "instance",
                    id: id.to_string(),
                }
            } else {
                error.into()
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::UnsafeFilesystemEntry {
                path,
                reason: "refusing to recursively delete a non-directory or symbolic link",
            });
        }
        tokio::fs::remove_dir_all(&path).await?;
        self.events.emit(CoreEvent::InstanceDeleted {
            instance_id: id.to_string(),
        });
        Ok(())
    }

    /// Reports whether an instance exists without conflating invalid IDs.
    pub async fn status(&self, id: impl Into<String>) -> Result<InstanceStatus> {
        let id = InstanceId::new(id)?;
        let instance_root = self.root.join(id.as_str());
        match tokio::fs::symlink_metadata(&instance_root).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => Err(Error::UnsafeFilesystemEntry {
                path: instance_root.clone(),
                reason: "instance root must be a real directory",
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InstanceStatus::NotFound);
            }
            Err(error) => return Err(error.into()),
        }
        let state_path = instance_root.join("runtime").join("install-state.json");
        let metadata = match tokio::fs::symlink_metadata(&state_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InstanceStatus::NotInstalled);
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: state_path,
                reason: "installation state must be a real file",
            });
        }
        let state: InstallStateDocument =
            serde_json::from_slice(&tokio::fs::read(&state_path).await?)?;
        if state.format_version != 1 {
            return Err(Error::UnsupportedFormat {
                kind: "installation state",
                version: state.format_version,
            });
        }
        Ok(match state.status {
            PersistedInstallStatus::Installing => InstanceStatus::Installing,
            PersistedInstallStatus::Updating => InstanceStatus::Updating,
            PersistedInstallStatus::Interrupted => InstanceStatus::Recoverable,
            PersistedInstallStatus::Installed => InstanceStatus::Installed,
            PersistedInstallStatus::Broken => InstanceStatus::Broken,
        })
    }

    pub(crate) async fn mark_installing(&self, instance: &Instance) -> Result<()> {
        self.write_install_state(
            instance,
            PersistedInstallStatus::Installing,
            instance.spec().minecraft().version(),
            None,
        )
        .await
    }

    pub(crate) async fn mark_installed(&self, instance: &Instance) -> Result<()> {
        self.write_install_state(
            instance,
            PersistedInstallStatus::Installed,
            instance.spec().minecraft().version(),
            None,
        )
        .await
    }

    pub(crate) async fn mark_updating(&self, instance: &Instance) -> Result<()> {
        self.write_install_state(
            instance,
            PersistedInstallStatus::Updating,
            instance.spec().minecraft().version(),
            None,
        )
        .await
    }

    pub(crate) async fn mark_broken(&self, instance: &Instance, error: &str) -> Result<()> {
        self.write_install_state(
            instance,
            PersistedInstallStatus::Broken,
            instance.spec().minecraft().version(),
            Some(error),
        )
        .await
    }

    pub(crate) async fn mark_interrupted(&self, instance: &Instance, error: &str) -> Result<()> {
        self.write_install_state(
            instance,
            PersistedInstallStatus::Interrupted,
            instance.spec().minecraft().version(),
            Some(error),
        )
        .await
    }

    pub(crate) async fn installed_version(&self, instance: &Instance) -> Result<Option<String>> {
        if self.status(instance.id().to_string()).await? != InstanceStatus::Installed {
            return Ok(None);
        }
        let state_path = instance.path().join("runtime").join("install-state.json");
        let state: InstallStateDocument =
            serde_json::from_slice(&tokio::fs::read(state_path).await?)?;
        Ok(Some(state.version_id))
    }

    async fn write_install_state(
        &self,
        instance: &Instance,
        status: PersistedInstallStatus,
        version_id: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let runtime = instance.path().join("runtime");
        match tokio::fs::symlink_metadata(&runtime).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(Error::UnsafeFilesystemEntry {
                    path: runtime,
                    reason: "instance runtime must be a real directory",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir(&runtime).await?;
            }
            Err(error) => return Err(error.into()),
        }
        let state_path = runtime.join("install-state.json");
        let temporary = runtime.join("install-state.json.tmp");
        let document = InstallStateDocument {
            format_version: 1,
            status,
            version_id: version_id.to_owned(),
            error: error.map(str::to_owned),
        };
        if tokio::fs::try_exists(&temporary).await? {
            let metadata = tokio::fs::symlink_metadata(&temporary).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::UnsafeFilesystemEntry {
                    path: temporary,
                    reason: "temporary installation state must be a real file",
                });
            }
        }
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(&document)?).await?;
        if tokio::fs::try_exists(&state_path).await? {
            let metadata = tokio::fs::symlink_metadata(&state_path).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::UnsafeFilesystemEntry {
                    path: state_path,
                    reason: "installation state must be a real file",
                });
            }
            tokio::fs::remove_file(&state_path).await?;
        }
        tokio::fs::rename(temporary, state_path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_instance_ids() {
        assert!(InstanceId::new("survival-01").is_ok());
        for invalid in ["", "../escape", "with space", "slash/name"] {
            assert!(InstanceId::new(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn creates_loads_lists_and_deletes_an_instance() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let events = EventBus::new(8);
        let service = InstanceService::new(
            temporary.path().join("instances"),
            events,
            LockManager::new(temporary.path().join("locks")),
        );
        let spec = InstanceSpec::vanilla("test", "Test", "1.21.1").expect("spec");

        let created = service.create(spec).await.expect("create");
        assert!(created.minecraft_dir().is_dir());
        assert_eq!(service.get("test").await.expect("get").name(), "Test");
        assert_eq!(service.list().await.expect("list").len(), 1);

        service.delete("test").await.expect("delete");
        assert_eq!(
            service.status("test").await.expect("status"),
            InstanceStatus::NotFound
        );
    }
}
