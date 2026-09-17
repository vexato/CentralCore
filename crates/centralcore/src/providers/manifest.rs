//! Versioned wire models and validated static-provider domain types.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    path::PathBuf,
    str::FromStr,
};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use url::Url;

use crate::{
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    instance::{InstanceAuthPolicy, InstanceId, InstanceSpec, ServerConfig},
    java::JavaInstanceConfig,
    loaders::{LoaderConfig, LoaderKind},
    Error, Result,
};

pub const PROVIDER_FORMAT_VERSION: u32 = 1;
pub const INSTANCE_MANIFEST_FORMAT_VERSION: u32 = 1;

/// Stable provider-defined identity for a required or optional component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
            })
        {
            return Err(ProviderError::InvalidComponentId(value).into());
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ComponentId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Validated registry identifier chosen by the local application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'-' | b'_'))
            })
        {
            return Err(ProviderError::InvalidId(value).into());
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// A local file tree or a remote HTTPS provider index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderSource {
    Local(PathBuf),
    Remote(Url),
}

impl ProviderSource {
    /// Parses an HTTP(S) URL as remote; all other input is an explicit local path.
    pub fn parse(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if value.starts_with("https://") || value.starts_with("http://") {
            return Ok(Self::Remote(Url::parse(value).map_err(|error| {
                ProviderError::UrlPolicy {
                    url: value.to_owned(),
                    reason: error.to_string(),
                }
            })?));
        }
        if value.starts_with("file://") {
            let url = Url::parse(value).map_err(|error| ProviderError::UrlPolicy {
                url: value.to_owned(),
                reason: error.to_string(),
            })?;
            return url.to_file_path().map(Self::Local).map_err(|()| {
                ProviderError::UrlPolicy {
                    url: value.to_owned(),
                    reason: "file URL cannot be converted to a local path".into(),
                }
                .into()
            });
        }
        if value.contains("://") {
            return Err(ProviderError::UrlPolicy {
                url: value.to_owned(),
                reason: "only file, HTTP, and HTTPS sources are supported".into(),
            }
            .into());
        }
        Ok(Self::Local(PathBuf::from(value)))
    }
}

/// Collision-free logical identity of an instance exposed by a provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderInstanceId {
    pub provider_id: ProviderId,
    pub instance_id: InstanceId,
}

impl ProviderInstanceId {
    pub fn new(provider_id: ProviderId, instance_id: InstanceId) -> Self {
        Self {
            provider_id,
            instance_id,
        }
    }
}

impl fmt::Display for ProviderInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.provider_id, self.instance_id)
    }
}

impl FromStr for ProviderInstanceId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let (provider, instance) = value
            .split_once(':')
            .ok_or_else(|| ProviderError::InvalidReference(value.to_owned()))?;
        if instance.contains(':') {
            return Err(ProviderError::InvalidReference(value.to_owned()).into());
        }
        Ok(Self::new(
            ProviderId::new(provider)?,
            InstanceId::new(instance)?,
        ))
    }
}

/// Resolved origin of one provider-supplied resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderResource {
    Local { path: PathBuf, root: PathBuf },
    Remote(Url),
}

/// Validated mandatory file declared by an instance manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderFile {
    pub id: String,
    pub path: SafeRelativePath,
    pub source: ProviderResource,
    pub size: u64,
    pub sha256: FileHash,
    pub required: bool,
}

/// Installation policy attached to a provider component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRequirement {
    Required,
    Optional,
}

/// A logical group of files. A component is not necessarily a mod or one JAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderComponent {
    pub id: ComponentId,
    pub name: String,
    pub description: Option<String>,
    pub requirement: ComponentRequirement,
    pub default_enabled: bool,
    #[serde(default)]
    pub requires: Vec<ComponentId>,
    #[serde(default)]
    pub conflicts: Vec<ComponentId>,
    pub files: Vec<ProviderFile>,
}

/// Structured Java memory recommendations. Providers cannot inject arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderJavaMemory {
    pub minimum_mb: u32,
    pub recommended_mb: u32,
    pub maximum_mb: Option<u32>,
}

/// Validated instance declaration, distinct from its local installation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInstanceDefinition {
    pub id: InstanceId,
    pub name: String,
    pub description: Option<String>,
    pub revision: u64,
    pub minecraft_version: String,
    pub loader: Option<LoaderConfig>,
    pub java_memory: Option<ProviderJavaMemory>,
    pub server: Option<ServerConfig>,
    #[serde(default)]
    pub authentication: InstanceAuthPolicy,
    pub files: Vec<ProviderFile>,
    /// Required and optional file groups. Missing in Phase 4 manifests by design.
    #[serde(default)]
    pub components: Vec<ProviderComponent>,
}

impl ProviderInstanceDefinition {
    /// Converts a declaration into an isolated local specification.
    pub fn local_spec(&self, local_id: String, key: &ProviderInstanceId) -> Result<InstanceSpec> {
        let mut spec =
            InstanceSpec::vanilla(local_id, self.name.clone(), self.minecraft_version.clone())?;
        if let Some(loader) = &self.loader {
            spec = spec.with_loader(loader.clone())?;
        }
        if let Some(memory) = &self.java_memory {
            spec = spec.with_java(JavaInstanceConfig {
                executable: None,
                minimum_memory_mib: memory.minimum_mb,
                maximum_memory_mib: memory.recommended_mb,
            })?;
        }
        if let Some(server) = &self.server {
            spec = spec.with_server(server.clone());
        }
        spec = spec.with_authentication(self.authentication.clone())?;
        spec.insert_metadata("centralcore.provider_id", key.provider_id.to_string());
        spec.insert_metadata(
            "centralcore.provider_instance_id",
            key.instance_id.to_string(),
        );
        spec.insert_metadata("centralcore.provider_revision", self.revision.to_string());
        Ok(spec)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProviderManifest {
    pub format_version: u32,
    #[serde(default)]
    pub revision: Option<u64>,
    pub provider: RawProviderIdentity,
    pub instances: Vec<RawProviderInstanceReference>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProviderIdentity {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProviderInstanceReference {
    pub id: String,
    pub manifest: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawInstanceManifest {
    pub format_version: u32,
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub revision: u64,
    pub minecraft: RawMinecraft,
    pub java: Option<RawJava>,
    pub server: Option<RawServer>,
    pub authentication: Option<InstanceAuthPolicy>,
    #[serde(default)]
    pub files: Vec<RawProviderFile>,
    #[serde(default)]
    pub components: Vec<RawProviderComponent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMinecraft {
    pub version: String,
    pub loader: RawLoader,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLoader {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawJava {
    pub memory: Option<ProviderJavaMemory>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawServer {
    pub address: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProviderFile {
    pub id: Option<String>,
    pub path: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default = "required_by_default")]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProviderComponent {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default_enabled: bool,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub files: Vec<RawProviderFile>,
}

impl RawInstanceManifest {
    pub(crate) fn validate(
        self,
        expected_id: &InstanceId,
        resolve: impl Fn(&str) -> Result<ProviderResource>,
        max_file_size: u64,
    ) -> Result<ProviderInstanceDefinition> {
        if self.format_version != INSTANCE_MANIFEST_FORMAT_VERSION {
            return Err(ProviderError::UnsupportedInstanceFormat(self.format_version).into());
        }
        let id = InstanceId::new(self.id)?;
        if &id != expected_id {
            return Err(ProviderError::InstanceIdentity {
                expected: expected_id.to_string(),
                actual: id.to_string(),
            }
            .into());
        }
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err(ProviderError::InvalidManifest(
                "instance name must contain 1-128 characters".into(),
            )
            .into());
        }
        if self.revision == 0 {
            return Err(ProviderError::InvalidManifest(
                "instance revision must be greater than zero".into(),
            )
            .into());
        }
        let loader = if self.minecraft.loader.kind == "vanilla" {
            if self.minecraft.loader.version.is_some() {
                return Err(ProviderError::InvalidManifest(
                    "Vanilla loader must not declare a loader version".into(),
                )
                .into());
            }
            None
        } else {
            let kind = LoaderKind::from_str(&self.minecraft.loader.kind).map_err(|_| {
                ProviderError::UnsupportedLoader(self.minecraft.loader.kind.clone())
            })?;
            let version = self.minecraft.loader.version.ok_or_else(|| {
                ProviderError::InvalidManifest(format!("loader `{kind}` requires an exact version"))
            })?;
            Some(LoaderConfig::new(kind, version)?)
        };
        if self.minecraft.version.is_empty() || self.minecraft.version.len() > 128 {
            return Err(
                ProviderError::InvalidManifest("Minecraft version is invalid".into()).into(),
            );
        }
        let java_memory = self.java.and_then(|java| java.memory);
        if let Some(memory) = &java_memory {
            if memory.minimum_mb < 256
                || memory.recommended_mb < memory.minimum_mb
                || memory
                    .maximum_mb
                    .is_some_and(|maximum| maximum < memory.recommended_mb)
            {
                return Err(ProviderError::InvalidManifest(
                    "Java memory recommendations are inconsistent".into(),
                )
                .into());
            }
        }
        let server = self
            .server
            .map(|server| {
                validate_server_address(&server.address)?;
                Ok::<ServerConfig, Error>(ServerConfig {
                    host: server.address,
                    port: server.port,
                })
            })
            .transpose()?;
        let authentication = self.authentication.unwrap_or_default();
        authentication.validate()?;
        let mut paths = HashSet::with_capacity(self.files.len());
        let mut file_ids = HashSet::with_capacity(self.files.len());
        let mut files = Vec::with_capacity(self.files.len());
        for (index, raw) in self.files.into_iter().enumerate() {
            let path = SafeRelativePath::new(raw.path)?;
            if !paths.insert(path.clone()) {
                return Err(ProviderError::DuplicateFile(path.to_string()).into());
            }
            if raw.size == 0 || raw.size > max_file_size {
                return Err(ProviderError::InvalidFileSize {
                    path: path.to_string(),
                    size: raw.size,
                }
                .into());
            }
            if !raw.required {
                return Err(ProviderError::OptionalFilesUnsupported(path.to_string()).into());
            }
            let id = raw.id.unwrap_or_else(|| format!("file-{index}"));
            if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
                return Err(ProviderError::InvalidManifest(format!(
                    "file id for `{path}` is invalid"
                ))
                .into());
            }
            if !file_ids.insert(id.clone()) {
                return Err(ProviderError::DuplicateFileId(id).into());
            }
            files.push(ProviderFile {
                id,
                path,
                source: resolve(&raw.url)?,
                size: raw.size,
                sha256: FileHash::new(HashAlgorithm::Sha256, raw.sha256)?,
                required: true,
            });
        }
        let mut component_ids = BTreeSet::new();
        let mut components = Vec::with_capacity(self.components.len());
        for raw_component in self.components {
            let component_id = ComponentId::new(raw_component.id)?;
            if !component_ids.insert(component_id.clone()) {
                return Err(ProviderError::DuplicateComponent(component_id.to_string()).into());
            }
            if raw_component.name.trim().is_empty() || raw_component.name.len() > 128 {
                return Err(ProviderError::InvalidManifest(format!(
                    "component `{component_id}` name must contain 1-128 characters"
                ))
                .into());
            }
            if raw_component.files.is_empty() {
                return Err(ProviderError::InvalidManifest(format!(
                    "component `{component_id}` must contain at least one file"
                ))
                .into());
            }
            let requires = raw_component
                .requires
                .into_iter()
                .map(ComponentId::new)
                .collect::<Result<Vec<_>>>()?;
            let conflicts = raw_component
                .conflicts
                .into_iter()
                .map(ComponentId::new)
                .collect::<Result<Vec<_>>>()?;
            let mut component_files = Vec::with_capacity(raw_component.files.len());
            let mut component_file_ids = HashSet::with_capacity(raw_component.files.len());
            for (index, raw) in raw_component.files.into_iter().enumerate() {
                let path = SafeRelativePath::new(raw.path)?;
                if !paths.insert(path.clone()) {
                    return Err(ProviderError::DuplicateFile(path.to_string()).into());
                }
                if raw.size == 0 || raw.size > max_file_size {
                    return Err(ProviderError::InvalidFileSize {
                        path: path.to_string(),
                        size: raw.size,
                    }
                    .into());
                }
                let id = raw.id.unwrap_or_else(|| format!("file-{index}"));
                validate_file_id(&id, &path)?;
                if !component_file_ids.insert(id.clone()) {
                    return Err(ProviderError::DuplicateFileId(id).into());
                }
                component_files.push(ProviderFile {
                    id,
                    path,
                    source: resolve(&raw.url)?,
                    size: raw.size,
                    sha256: FileHash::new(HashAlgorithm::Sha256, raw.sha256)?,
                    required: raw_component.required,
                });
            }
            components.push(ProviderComponent {
                id: component_id,
                name: raw_component.name,
                description: raw_component.description,
                requirement: if raw_component.required {
                    ComponentRequirement::Required
                } else {
                    ComponentRequirement::Optional
                },
                default_enabled: raw_component.required || raw_component.default_enabled,
                requires,
                conflicts,
                files: component_files,
            });
        }
        for component in &components {
            for dependency in component.requires.iter().chain(&component.conflicts) {
                if dependency == &component.id || !component_ids.contains(dependency) {
                    return Err(ProviderError::InvalidComponentReference {
                        component: component.id.to_string(),
                        referenced: dependency.to_string(),
                    }
                    .into());
                }
            }
        }
        Ok(ProviderInstanceDefinition {
            id,
            name: self.name,
            description: self.description,
            revision: self.revision,
            minecraft_version: self.minecraft.version,
            loader,
            java_memory,
            server,
            authentication,
            files,
            components,
        })
    }
}

fn validate_file_id(id: &str, path: &SafeRelativePath) -> Result<()> {
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(
            ProviderError::InvalidManifest(format!("file id for `{path}` is invalid")).into(),
        );
    }
    Ok(())
}

fn validate_server_address(address: &str) -> Result<()> {
    if address.trim() != address
        || address.is_empty()
        || address.len() > 255
        || address.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '/' | '\\' | '@' | '#' | '?')
        })
    {
        return Err(ProviderError::InvalidManifest("server address is invalid".into()).into());
    }
    Ok(())
}

const fn default_server_port() -> u16 {
    25565
}

const fn required_by_default() -> bool {
    true
}

/// Static-provider-specific structured failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    #[error("invalid provider id `{0}`")]
    InvalidId(String),
    #[error("invalid component id `{0}`")]
    InvalidComponentId(String),
    #[error("invalid provider instance reference `{0}`; expected provider:instance")]
    InvalidReference(String),
    #[error("unsupported provider manifest format version: {0}")]
    UnsupportedProviderFormat(u32),
    #[error("unsupported instance manifest format version: {0}")]
    UnsupportedInstanceFormat(u32),
    #[error("provider manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("provider index contains duplicate instance `{0}`")]
    DuplicateInstance(String),
    #[error("instance manifest identity is `{actual}`, expected `{expected}`")]
    InstanceIdentity { expected: String, actual: String },
    #[error("provider manifest contains duplicate file path `{0}`")]
    DuplicateFile(String),
    #[error("provider manifest contains duplicate file id `{0}`")]
    DuplicateFileId(String),
    #[error("provider manifest contains duplicate component `{0}`")]
    DuplicateComponent(String),
    #[error("component `{component}` references unknown or invalid component `{referenced}`")]
    InvalidComponentReference {
        component: String,
        referenced: String,
    },
    #[error("provider file `{path}` has invalid size {size}")]
    InvalidFileSize { path: String, size: u64 },
    #[error(
        "optional provider file `{0}` is declared, but optional selection is not available yet"
    )]
    OptionalFilesUnsupported(String),
    #[error("loader `{0}` is not available in this CentralCore build/version")]
    UnsupportedLoader(String),
    #[error("provider URL `{url}` is forbidden: {reason}")]
    UrlPolicy { url: String, reason: String },
    #[error("provider resource `{0}` escapes its local provider directory")]
    LocalPathEscape(PathBuf),
    #[error("provider document exceeds its {limit}-byte limit")]
    DocumentTooLarge { limit: u64 },
    #[error("provider snapshot is unavailable for `{0}`")]
    MissingSnapshot(String),
    #[error("provider instance `{0}` is ambiguous; use provider:instance")]
    AmbiguousInstance(String),
    #[error("managed path conflict at `{path}` between `{existing}` and `{incoming}`")]
    ManagedPathConflict {
        path: String,
        existing: String,
        incoming: String,
    },
    #[error("components `{left}` and `{right}` cannot be enabled together")]
    ComponentConflict { left: String, right: String },
    #[error("component dependency cycle detected involving {components:?}")]
    ComponentDependencyCycle { components: Vec<String> },
    #[error("component `{component}` cannot be disabled because `{dependent}` requires it")]
    ComponentRequiredBy {
        component: String,
        dependent: String,
    },
    #[error("instance `{0}` is currently running")]
    InstanceRunning(String),
    #[error("update plan targets revision {planned}, but revision {available} is now available")]
    StaleUpdatePlan { planned: u64, available: u64 },
    #[error("update plan starts at revision {planned}, but revision {installed} is installed")]
    StaleInstalledRevision { planned: u64, installed: u64 },
    #[error("component selections changed after the update plan was created")]
    StaleComponentSelections,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_instance(path: &str, sha256: &str, required: bool) -> RawInstanceManifest {
        serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "id": "survival",
            "name": "Survival",
            "revision": 7,
            "minecraft": {"version":"1.20.4", "loader":{"type":"vanilla"}},
            "files": [{
                "path": path,
                "url": "https://cdn.example.test/file",
                "size": 4,
                "sha256": sha256,
                "required": required
            }]
        }))
        .expect("raw instance")
    }

    #[test]
    fn parses_and_validates_instance_v1() {
        let expected = InstanceId::new("survival").expect("id");
        let definition = raw_instance("config/example.json", &"ab".repeat(32), true)
            .validate(
                &expected,
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                1024,
            )
            .expect("definition");
        assert_eq!(definition.revision, 7);
        assert_eq!(definition.files[0].path.as_str(), "config/example.json");
    }

    #[test]
    fn v1_components_are_backward_compatible_and_group_multiple_files() {
        let raw: RawInstanceManifest = serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "id": "survival",
            "name": "Survival",
            "revision": 8,
            "minecraft": {"version":"1.20.4", "loader":{"type":"fabric", "version":"0.15.11"}},
            "components": [{
                "id": "sodium",
                "name": "Sodium",
                "default_enabled": false,
                "files": [
                    {"id":"jar", "path":"mods/sodium.jar", "url":"https://cdn.example.test/sodium", "size":4, "sha256":"abababababababababababababababababababababababababababababababab"},
                    {"id":"config", "path":"config/sodium.json", "url":"https://cdn.example.test/config", "size":4, "sha256":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}
                ]
            }]
        }))
        .expect("raw component manifest");
        let definition = raw
            .validate(
                &InstanceId::new("survival").expect("id"),
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("url"))),
                1024,
            )
            .expect("definition");
        assert_eq!(definition.components.len(), 1);
        assert_eq!(definition.components[0].files.len(), 2);
        assert_eq!(
            definition.components[0].requirement,
            ComponentRequirement::Optional
        );
    }

    #[test]
    fn authentication_policy_cannot_inject_an_endpoint() {
        let mut document = serde_json::json!({
            "format_version": 1,
            "id": "survival",
            "name": "Survival",
            "revision": 1,
            "minecraft": {"version": "1.20.4", "loader": {"type": "vanilla"}},
            "authentication": {
                "required": true,
                "providers": ["community"],
                "auth_url": "https://evil.example/collect"
            },
            "files": []
        });
        assert!(serde_json::from_value::<RawInstanceManifest>(document.take()).is_err());
    }

    #[test]
    fn legacy_provider_snapshot_defaults_authentication_policy() {
        let expected = InstanceId::new("survival").expect("id");
        let definition = raw_instance("config/example.json", &"ab".repeat(32), true)
            .validate(
                &expected,
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                1024,
            )
            .expect("definition");
        let mut value = serde_json::to_value(definition).expect("JSON");
        value
            .as_object_mut()
            .expect("object")
            .remove("authentication");
        let restored: ProviderInstanceDefinition =
            serde_json::from_value(value).expect("legacy snapshot");
        assert_eq!(restored.authentication, InstanceAuthPolicy::default());
    }

    #[test]
    fn rejects_unknown_instance_format() {
        let mut raw = raw_instance("config/example.json", &"ab".repeat(32), true);
        raw.format_version = 42;
        assert!(matches!(
            raw.validate(
                &InstanceId::new("survival").expect("id"),
                |_| unreachable!(),
                1024
            ),
            Err(Error::StaticProvider(
                ProviderError::UnsupportedInstanceFormat(42)
            ))
        ));
    }

    #[test]
    fn rejects_traversal_bad_hash_and_optional_files() {
        let expected = InstanceId::new("survival").expect("id");
        for raw in [
            raw_instance("../evil", &"ab".repeat(32), true),
            raw_instance("config/example.json", "invalid", true),
            raw_instance("config/example.json", &"ab".repeat(32), false),
        ] {
            assert!(raw
                .validate(
                    &expected,
                    |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                    1024,
                )
                .is_err());
        }
    }

    #[test]
    fn provider_and_instance_ids_are_strict() {
        assert!(ProviderId::new("example-network").is_ok());
        for id in ["../foo", "Uppercase", "foo/bar", "", "-bad"] {
            assert!(ProviderId::new(id).is_err(), "accepted {id}");
        }
        assert!("example:survival".parse::<ProviderInstanceId>().is_ok());
        assert!("example:survival:extra"
            .parse::<ProviderInstanceId>()
            .is_err());
    }

    #[test]
    fn rejects_duplicate_provider_file_paths() {
        let mut raw = raw_instance("config/example.json", &"ab".repeat(32), true);
        raw.files.push(raw.files[0].clone());
        assert!(matches!(
            raw.validate(
                &InstanceId::new("survival").expect("id"),
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                1024,
            ),
            Err(Error::StaticProvider(ProviderError::DuplicateFile(_)))
        ));
    }

    #[test]
    fn accepts_exact_fabric_and_forge_loaders() {
        let expected = InstanceId::new("survival").expect("id");
        for (kind, version) in [("fabric", "0.19.5"), ("forge", "47.4.23")] {
            let mut raw = raw_instance("config/example.json", &"ab".repeat(32), true);
            raw.minecraft.loader.kind = kind.to_owned();
            raw.minecraft.loader.version = Some(version.to_owned());
            let definition = raw
                .validate(
                    &expected,
                    |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                    1024,
                )
                .expect("loader definition");
            let loader = definition.loader.expect("loader config");
            assert_eq!(loader.kind.as_str(), kind);
            assert_eq!(loader.version, version);
        }
    }

    #[test]
    fn rejects_missing_or_floating_loader_versions() {
        let expected = InstanceId::new("survival").expect("id");
        for version in [None, Some("latest".to_owned())] {
            let mut raw = raw_instance("config/example.json", &"ab".repeat(32), true);
            raw.minecraft.loader.kind = "fabric".to_owned();
            raw.minecraft.loader.version = version;
            assert!(raw
                .validate(
                    &expected,
                    |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                    1024,
                )
                .is_err());
        }
    }

    #[test]
    fn rejects_version_on_vanilla_loader() {
        let expected = InstanceId::new("survival").expect("id");
        let mut raw = raw_instance("config/example.json", &"ab".repeat(32), true);
        raw.minecraft.loader.version = Some("1.0".to_owned());
        assert!(raw
            .validate(
                &expected,
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                1024,
            )
            .is_err());
    }

    #[test]
    fn parses_and_validates_ten_thousand_managed_files() {
        let files = (0..10_000)
            .map(|index| {
                serde_json::json!({
                    "id": format!("file-{index}"),
                    "path": format!("mods/file-{index}.jar"),
                    "url": format!("https://cdn.example.test/files/{index}"),
                    "size": 1,
                    "sha256": "ab".repeat(32)
                })
            })
            .collect::<Vec<_>>();
        let document = serde_json::to_vec(&serde_json::json!({
            "format_version": 1,
            "id": "survival",
            "name": "Large synthetic instance",
            "revision": 1,
            "minecraft": {"version": "1.21.1", "loader": {"type": "vanilla"}},
            "files": files
        }))
        .expect("serialize fixture");
        let parse_started = std::time::Instant::now();
        let raw: RawInstanceManifest =
            serde_json::from_slice(&document).expect("parse large manifest");
        let parse_elapsed = parse_started.elapsed();
        let validate_started = std::time::Instant::now();
        let definition = raw
            .validate(
                &InstanceId::new("survival").expect("id"),
                |url| Ok(ProviderResource::Remote(Url::parse(url).expect("URL"))),
                1024,
            )
            .expect("validate large manifest");
        eprintln!(
            "large-manifest parse={parse_elapsed:?} validate={:?}",
            validate_started.elapsed()
        );
        assert_eq!(definition.files.len(), 10_000);
    }
}
