//! Persistent provider registry, transactional synchronization, and installation.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::{
    cache::{
        load_managed_index, snapshot_managed_file, verify_index, write_managed_index, CacheManager,
        ManagedFile, ManagedFileKind, ManagedFileLocation, ManagedFileOrigin,
    },
    config::ProviderSettings,
    download::{
        verify_file, CancellationToken, ConditionalFetch, DownloadManager, DownloadRequest,
    },
    events::{CoreEvent, EventBus},
    files::SafeRelativePath,
    instance::{Instance, InstanceId, InstanceService, InstanceStatus},
    lock::LockManager,
    minecraft::{InstallPlan, MinecraftManager},
    trust::{
        canonicalize_json, KeyId, ProviderVerification, SignatureEnvelope, SignaturePolicy,
        SignatureStatus, SignatureVerifier, TrustError, TrustStore,
    },
    Error, Result,
};

use super::{
    components::{initialize_selections, load_selections, resolve_components, write_selections},
    manifest::{RawInstanceManifest, RawProviderManifest},
    ComponentId, ComponentStatus, DesiredProviderFile, OptionalComponentChange, ProviderError,
    ProviderFile, ProviderId, ProviderInstanceDefinition, ProviderInstanceId, ProviderResource,
    ProviderSource, StaticProvider, UpdateFileAction, UpdatePhase, UpdatePlan, UpdateRemoval,
    UpdateReport, PROVIDER_FORMAT_VERSION,
};

const REGISTRY_FORMAT_VERSION: u32 = 1;
const SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// A configured provider, independent from whether it currently has a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistration {
    pub id: ProviderId,
    pub source: ProviderSource,
    pub added_unix_seconds: u64,
    #[serde(default)]
    pub signature_policy: SignaturePolicy,
    #[serde(default)]
    pub trusted_key_id: Option<KeyId>,
}

/// Identity published inside a validated provider index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderIdentity {
    pub id: ProviderId,
    pub name: String,
    pub description: Option<String>,
}

/// HTTP validators retained only to optimize future document retrieval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProviderHttpMetadata {
    pub url: Url,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub retrieved_unix_seconds: u64,
    pub content_sha256: String,
}

/// Completely validated provider state replaced as one filesystem transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSnapshot {
    pub(crate) format_version: u32,
    pub(crate) registration_id: ProviderId,
    pub(crate) provider: ProviderIdentity,
    pub(crate) source: ProviderSource,
    pub(crate) synced_unix_seconds: u64,
    pub(crate) instances: BTreeMap<InstanceId, ProviderInstanceDefinition>,
    pub(crate) index_http: Option<ProviderHttpMetadata>,
    pub(crate) instance_http: BTreeMap<InstanceId, ProviderHttpMetadata>,
    #[serde(default)]
    pub(crate) provider_revision: Option<u64>,
    #[serde(default = "legacy_provider_verification")]
    pub(crate) verification: ProviderVerification,
    #[serde(default)]
    pub(crate) manifest_documents: BTreeMap<InstanceId, CachedManifestDocument>,
}

/// Exact authenticated child-manifest bytes retained for 304 and offline audit paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedManifestDocument {
    pub document_base64: String,
    pub content_sha256: String,
    pub revision: u64,
}

impl ProviderSnapshot {
    /// Local registration identity owning this snapshot.
    #[must_use]
    pub fn registration_id(&self) -> &ProviderId {
        &self.registration_id
    }

    /// Provider identity authenticated by the accepted index.
    #[must_use]
    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    /// Configured local or remote provider source.
    #[must_use]
    pub fn source(&self) -> &ProviderSource {
        &self.source
    }

    /// Unix timestamp of the successful synchronization.
    #[must_use]
    pub const fn synced_unix_seconds(&self) -> u64 {
        self.synced_unix_seconds
    }

    /// Validated instance definitions keyed by provider instance ID.
    #[must_use]
    pub fn instances(&self) -> &BTreeMap<InstanceId, ProviderInstanceDefinition> {
        &self.instances
    }

    /// Signature and root-revision evidence retained with the snapshot.
    #[must_use]
    pub fn verification(&self) -> &ProviderVerification {
        &self.verification
    }

    /// Signed provider revision, absent only for explicitly unsigned legacy indexes.
    #[must_use]
    pub const fn revision(&self) -> Option<u64> {
        self.provider_revision
    }
}

/// Observable provider sync outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSyncReport {
    pub provider_id: ProviderId,
    pub declared_id: ProviderId,
    pub instances: u64,
    pub not_modified: bool,
    pub updated_instances: Vec<InstanceId>,
    pub signature_status: SignatureStatus,
    pub key_id: Option<KeyId>,
    pub revision: Option<u64>,
}

/// Explicit administrative options for one synchronization.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderSyncOptions {
    /// Permit activating an older signed revision without lowering high-water marks.
    pub allow_rollback: bool,
}

/// Relationship between a provider declaration and local installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderInstanceState {
    NotInstalled,
    Installed,
    UpdateAvailable,
    ProviderRemoved,
    Broken,
    Installing,
    Updating,
}

/// One provider catalog row suitable for CLIs and frontends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInstanceEntry {
    pub id: ProviderInstanceId,
    pub name: String,
    pub minecraft_version: String,
    pub revision: u64,
    pub local_instance_id: Option<InstanceId>,
    pub state: ProviderInstanceState,
}

/// Successful provider-backed installation.
#[derive(Debug, Clone)]
pub struct ProviderInstallOutcome {
    pub instance: Instance,
    pub minecraft: InstallPlan,
    pub provider_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryDocument {
    format_version: u32,
    providers: BTreeMap<ProviderId, ProviderRegistration>,
}

impl Default for RegistryDocument {
    fn default() -> Self {
        Self {
            format_version: REGISTRY_FORMAT_VERSION,
            providers: BTreeMap::new(),
        }
    }
}

enum DocumentFetch {
    NotModified,
    Modified {
        bytes: Vec<u8>,
        http: Option<ProviderHttpMetadata>,
    },
}

#[derive(Debug)]
struct VerifiedIndex {
    raw: RawProviderManifest,
    verification: ProviderVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackDocument {
    #[serde(default = "rollback_format_version")]
    format_version: u32,
    #[serde(default)]
    providers: BTreeMap<ProviderId, ProviderHighWater>,
}

impl Default for RollbackDocument {
    fn default() -> Self {
        Self {
            format_version: rollback_format_version(),
            providers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderHighWater {
    revision: u64,
    content_sha256: String,
    instances: BTreeMap<InstanceId, RevisionHighWater>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevisionHighWater {
    revision: u64,
    content_sha256: String,
}

/// Persistent registry and orchestration facade for all instance providers.
#[derive(Debug, Clone)]
pub struct ProviderManager {
    root: PathBuf,
    settings: ProviderSettings,
    downloads: DownloadManager,
    instances: InstanceService,
    minecraft: MinecraftManager,
    cache: CacheManager,
    locks: LockManager,
    events: EventBus,
    trust: TrustStore,
}

impl ProviderManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        data_directory: &Path,
        settings: ProviderSettings,
        downloads: DownloadManager,
        instances: InstanceService,
        minecraft: MinecraftManager,
        cache: CacheManager,
        locks: LockManager,
        events: EventBus,
        trust: TrustStore,
    ) -> Self {
        Self {
            root: data_directory.join("providers"),
            settings,
            downloads,
            instances,
            minecraft,
            cache,
            locks,
            events,
            trust,
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Registers a local provider with legacy-compatible optional signatures.
    ///
    /// Remote providers must use [`Self::add_with_trust`] so their signature
    /// policy cannot be selected accidentally by a convenience default.
    pub async fn add(
        &self,
        id: ProviderId,
        source: ProviderSource,
    ) -> Result<ProviderRegistration> {
        if matches!(source, ProviderSource::Remote(_)) {
            return Err(TrustError::TrustStoreError(
                "remote providers require an explicit signature policy and trusted key".into(),
            )
            .into());
        }
        self.add_with_trust(id, source, SignaturePolicy::Optional, None)
            .await
    }

    /// Registers a provider with an explicit signature policy and expected root key.
    pub async fn add_with_trust(
        &self,
        id: ProviderId,
        source: ProviderSource,
        signature_policy: SignaturePolicy,
        trusted_key_id: Option<KeyId>,
    ) -> Result<ProviderRegistration> {
        if signature_policy == SignaturePolicy::Required && trusted_key_id.is_none() {
            return Err(TrustError::TrustStoreError(
                "required signature policy needs an expected trusted key ID".into(),
            )
            .into());
        }
        if let Some(key_id) = &trusted_key_id {
            self.trust.get(key_id).await?;
        }
        let source = match source {
            ProviderSource::Local(path) => {
                let metadata = tokio::fs::symlink_metadata(&path).await?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(Error::UnsafeFilesystemEntry {
                        path,
                        reason: "provider index must be a real file",
                    });
                }
                ProviderSource::Local(tokio::fs::canonicalize(path).await?)
            }
            ProviderSource::Remote(url) => {
                self.validate_remote_url_syntax(&url)?;
                ProviderSource::Remote(url)
            }
        };
        let _lock = self.locks.acquire_exclusive("providers:registry").await?;
        let mut registry = self.load_registry().await?;
        if registry.providers.contains_key(&id) {
            return Err(Error::AlreadyExists {
                kind: "provider",
                id: id.to_string(),
            });
        }
        let registration = ProviderRegistration {
            id: id.clone(),
            source,
            added_unix_seconds: unix_seconds(),
            signature_policy,
            trusted_key_id,
        };
        registry.providers.insert(id.clone(), registration.clone());
        self.write_registry(&registry).await?;
        self.events.emit(CoreEvent::ProviderAdded {
            provider_id: id.to_string(),
        });
        Ok(registration)
    }

    /// Removes only the configuration. Materialized instances and snapshots remain intact.
    pub async fn remove(&self, id: &ProviderId) -> Result<ProviderRegistration> {
        let _lock = self.locks.acquire_exclusive("providers:registry").await?;
        let mut registry = self.load_registry().await?;
        let registration = registry
            .providers
            .remove(id)
            .ok_or_else(|| Error::NotFound {
                kind: "provider",
                id: id.to_string(),
            })?;
        self.write_registry(&registry).await?;
        self.events.emit(CoreEvent::ProviderRemoved {
            provider_id: id.to_string(),
        });
        Ok(registration)
    }

    pub async fn list(&self) -> Result<Vec<ProviderRegistration>> {
        Ok(self
            .load_registry()
            .await?
            .providers
            .into_values()
            .collect())
    }

    pub async fn get(&self, id: &ProviderId) -> Result<ProviderRegistration> {
        self.load_registry()
            .await?
            .providers
            .remove(id)
            .ok_or_else(|| Error::NotFound {
                kind: "provider",
                id: id.to_string(),
            })
    }

    /// Returns the last committed snapshot without performing network access.
    pub async fn snapshot(&self, id: &ProviderId) -> Result<ProviderSnapshot> {
        let path = self.snapshot_path(id);
        let bytes = read_with_previous(&path)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => {
                    Error::StaticProvider(ProviderError::MissingSnapshot(id.to_string()))
                }
                _ => error.into(),
            })?;
        let snapshot: ProviderSnapshot = serde_json::from_slice(&bytes)?;
        if snapshot.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "provider snapshot",
                version: snapshot.format_version,
            });
        }
        if &snapshot.registration_id != id {
            return Err(ProviderError::InvalidManifest(
                "provider snapshot registry identity mismatch".into(),
            )
            .into());
        }
        Ok(snapshot)
    }

    /// Creates the generic provider-contract view of a committed snapshot.
    pub async fn static_provider(&self, id: &ProviderId) -> Result<StaticProvider> {
        Ok(StaticProvider::new(self.snapshot(id).await?))
    }

    /// Fetches and validates every referenced manifest before replacing the active snapshot.
    pub async fn sync(&self, id: &ProviderId) -> Result<ProviderSyncReport> {
        self.sync_with_cancellation(
            id,
            ProviderSyncOptions::default(),
            &CancellationToken::default(),
        )
        .await
    }

    /// Synchronizes with an explicit local rollback override.
    pub async fn sync_with_options(
        &self,
        id: &ProviderId,
        options: ProviderSyncOptions,
    ) -> Result<ProviderSyncReport> {
        self.sync_with_cancellation(id, options, &CancellationToken::default())
            .await
    }

    /// Synchronizes with explicit rollback and cooperative cancellation policy.
    ///
    /// Cancellation is checked by every remote index, signature, and child
    /// manifest transfer. No partially verified snapshot is committed.
    pub async fn sync_with_cancellation(
        &self,
        id: &ProviderId,
        options: ProviderSyncOptions,
        cancellation: &CancellationToken,
    ) -> Result<ProviderSyncReport> {
        let _lock = self
            .locks
            .try_acquire_exclusive(format!("provider:{id}"))
            .await?;
        self.events.emit(CoreEvent::ProviderSyncStarted {
            provider_id: id.to_string(),
        });
        let result = self.sync_inner(id, options, cancellation).await;
        match &result {
            Ok(report) => self.events.emit(CoreEvent::ProviderSyncCompleted {
                provider_id: id.to_string(),
                instances: report.instances,
            }),
            Err(error) => self.events.emit(CoreEvent::ProviderSyncFailed {
                provider_id: id.to_string(),
                message: error.to_string(),
            }),
        }
        result
    }

    async fn sync_inner(
        &self,
        id: &ProviderId,
        options: ProviderSyncOptions,
        cancellation: &CancellationToken,
    ) -> Result<ProviderSyncReport> {
        let registration = self.get(id).await?;
        let previous = self.snapshot(id).await.ok();
        let index_fetch = self
            .fetch_document(
                &registration.source,
                previous
                    .as_ref()
                    .and_then(|snapshot| snapshot.index_http.as_ref()),
                self.settings.max_index_size,
                cancellation,
            )
            .await?;
        if matches!(index_fetch, DocumentFetch::NotModified) {
            let snapshot =
                previous.ok_or_else(|| ProviderError::MissingSnapshot(id.to_string()))?;
            if registration.signature_policy == SignaturePolicy::Required
                && snapshot.verification.signature_status != SignatureStatus::Verified
            {
                return Err(TrustError::SignatureMissing.into());
            }
            if snapshot.verification.signature_status == SignatureStatus::Verified {
                let expected = registration.trusted_key_id.as_ref().ok_or_else(|| {
                    TrustError::TrustStoreError(
                        "verified provider registration has no expected key".into(),
                    )
                })?;
                let actual = snapshot.verification.key_id.as_ref().ok_or_else(|| {
                    TrustError::TrustStoreError(
                        "verified snapshot has no signing-key fingerprint".into(),
                    )
                })?;
                let revision = snapshot.provider_revision.ok_or_else(|| {
                    ProviderError::InvalidManifest(
                        "verified snapshot has no provider revision".into(),
                    )
                })?;
                self.trust
                    .authorize(expected, actual, id.as_str(), revision)
                    .await?;
            }
            self.events.emit(CoreEvent::ProviderNotModified {
                provider_id: id.to_string(),
            });
            return Ok(ProviderSyncReport {
                provider_id: id.clone(),
                declared_id: snapshot.provider.id,
                instances: snapshot.instances.len() as u64,
                not_modified: true,
                updated_instances: Vec::new(),
                signature_status: snapshot.verification.signature_status,
                key_id: snapshot.verification.key_id,
                revision: snapshot.provider_revision,
            });
        }
        let DocumentFetch::Modified {
            bytes: index_bytes,
            http: index_http,
        } = index_fetch
        else {
            unreachable!("not-modified handled above")
        };
        let raw: RawProviderManifest = serde_json::from_slice(&index_bytes).map_err(|error| {
            ProviderError::InvalidManifest(format!("provider index JSON: {error}"))
        })?;
        let verified_index = self
            .verify_provider_index(id, &registration, raw, &index_bytes, cancellation)
            .await?;
        let raw = verified_index.raw;
        let verification = verified_index.verification;
        if raw.format_version != PROVIDER_FORMAT_VERSION {
            return Err(ProviderError::UnsupportedProviderFormat(raw.format_version).into());
        }
        let declared_id = ProviderId::new(raw.provider.id)?;
        if raw.provider.name.trim().is_empty() || raw.provider.name.len() > 128 {
            return Err(ProviderError::InvalidManifest(
                "provider name must contain 1-128 characters".into(),
            )
            .into());
        }
        let mut seen = BTreeSet::new();
        let mut instances = BTreeMap::new();
        let mut instance_http = BTreeMap::new();
        let mut manifest_documents = BTreeMap::new();
        let signed_root = verification.signature_status == SignatureStatus::Verified;
        let total = raw.instances.len() as u64;
        for (position, reference) in raw.instances.into_iter().enumerate() {
            let instance_id = InstanceId::new(reference.id)?;
            if !seen.insert(instance_id.clone()) {
                return Err(ProviderError::DuplicateInstance(instance_id.to_string()).into());
            }
            let source = self.resolve_reference(&registration.source, &reference.manifest)?;
            let previous_http = previous
                .as_ref()
                .and_then(|snapshot| snapshot.instance_http.get(&instance_id))
                .filter(|metadata| source_remote_url(&source) == Some(&metadata.url));
            let fetched = self
                .fetch_resource_document(
                    &source,
                    previous_http,
                    self.settings.max_instance_manifest_size,
                    cancellation,
                )
                .await?;
            let (definition, manifest_document) = match fetched {
                DocumentFetch::NotModified => {
                    self.events.emit(CoreEvent::ProviderCacheHit {
                        provider_id: id.to_string(),
                        url: source_display(&source),
                    });
                    let previous_snapshot = previous
                        .as_ref()
                        .ok_or_else(|| ProviderError::MissingSnapshot(id.to_string()))?;
                    if let Some(metadata) = previous_http {
                        instance_http.insert(instance_id.clone(), metadata.clone());
                    }
                    let definition = previous_snapshot
                        .instances
                        .get(&instance_id)
                        .cloned()
                        .ok_or_else(|| {
                            ProviderError::InvalidManifest(format!(
                                "server returned 304 for uncached instance `{instance_id}`"
                            ))
                        })?;
                    let document = previous_snapshot
                        .manifest_documents
                        .get(&instance_id)
                        .cloned();
                    if signed_root && document.is_none() {
                        return Err(ProviderError::InvalidManifest(format!(
                            "server returned 304 without cached authenticated bytes for `{instance_id}`"
                        ))
                        .into());
                    }
                    (definition, document)
                }
                DocumentFetch::Modified { bytes, http } => {
                    let content_sha256 = format!("{:x}", Sha256::digest(&bytes));
                    if signed_root {
                        let expected = reference.sha256.as_deref().ok_or_else(|| {
                            ProviderError::InvalidManifest(format!(
                                "signed index omits SHA-256 for instance `{instance_id}`"
                            ))
                        })?;
                        let expected = crate::files::FileHash::new(
                            crate::files::HashAlgorithm::Sha256,
                            expected,
                        )?;
                        if expected.value() != content_sha256 {
                            return Err(TrustError::SignatureInvalid.into());
                        }
                    }
                    let raw: RawInstanceManifest =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            ProviderError::InvalidManifest(format!(
                                "instance `{instance_id}` JSON: {error}"
                            ))
                        })?;
                    let base = source.clone();
                    let definition = raw.validate(
                        &instance_id,
                        |value| self.resolve_reference(&base, value),
                        self.downloads.config().max_file_size,
                    )?;
                    for file in &definition.files {
                        if let ProviderResource::Remote(url) = &file.source {
                            self.validate_remote_url_syntax(url)?;
                        }
                    }
                    for component in &definition.components {
                        for file in &component.files {
                            if let ProviderResource::Remote(url) = &file.source {
                                self.validate_remote_url_syntax(url)?;
                            }
                        }
                    }
                    if let Some(http) = http {
                        instance_http.insert(instance_id.clone(), http);
                    }
                    let cached = CachedManifestDocument {
                        document_base64: BASE64.encode(&bytes),
                        content_sha256,
                        revision: definition.revision,
                    };
                    (definition, Some(cached))
                }
            };
            if signed_root {
                let expected = reference.sha256.as_deref().ok_or_else(|| {
                    ProviderError::InvalidManifest(format!(
                        "signed index omits SHA-256 for instance `{instance_id}`"
                    ))
                })?;
                let cached = manifest_document.as_ref().ok_or_else(|| {
                    ProviderError::InvalidManifest(format!(
                        "authenticated bytes are unavailable for instance `{instance_id}`"
                    ))
                })?;
                if cached.content_sha256 != expected.to_ascii_lowercase() {
                    return Err(TrustError::SignatureInvalid.into());
                }
            }
            if let Some(document) = manifest_document {
                manifest_documents.insert(instance_id.clone(), document);
            }
            instances.insert(instance_id.clone(), definition);
            self.events.emit(CoreEvent::ProviderSyncProgress {
                provider_id: id.to_string(),
                completed_instances: position as u64 + 1,
                total_instances: total,
            });
        }
        let identity = ProviderIdentity {
            id: declared_id.clone(),
            name: raw.provider.name,
            description: raw.provider.description,
        };
        let snapshot = ProviderSnapshot {
            format_version: SNAPSHOT_FORMAT_VERSION,
            registration_id: id.clone(),
            provider: identity,
            source: registration.source,
            synced_unix_seconds: unix_seconds(),
            instances,
            index_http,
            instance_http,
            provider_revision: raw.revision,
            verification,
            manifest_documents,
        };
        if snapshot.verification.signature_status == SignatureStatus::Verified {
            self.enforce_and_record_revisions(id, &snapshot, options.allow_rollback)
                .await?;
        }
        let updated_instances = changed_instances(previous.as_ref(), &snapshot);
        self.write_snapshot(id, &snapshot).await?;
        for instance_id in &updated_instances {
            if let Some(definition) = snapshot.instances.get(instance_id) {
                self.events.emit(CoreEvent::InstanceDefinitionUpdated {
                    provider_id: id.to_string(),
                    instance_id: instance_id.to_string(),
                    revision: definition.revision,
                });
            }
        }
        Ok(ProviderSyncReport {
            provider_id: id.clone(),
            declared_id,
            instances: snapshot.instances.len() as u64,
            not_modified: false,
            updated_instances,
            signature_status: snapshot.verification.signature_status,
            key_id: snapshot.verification.key_id.clone(),
            revision: snapshot.provider_revision,
        })
    }

    /// Lists active declarations and derives state from reconstructible local metadata.
    pub async fn instances(
        &self,
        provider: Option<&ProviderId>,
    ) -> Result<Vec<ProviderInstanceEntry>> {
        let registrations = self.load_registry().await?;
        let selected = registrations
            .providers
            .keys()
            .filter(|id| provider.is_none_or(|selected| selected == *id))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(provider) = provider {
            if !registrations.providers.contains_key(provider) {
                return Err(Error::NotFound {
                    kind: "provider",
                    id: provider.to_string(),
                });
            }
        }
        let mut entries = Vec::new();
        let mut active_keys = BTreeSet::new();
        for provider_id in selected {
            let snapshot = match self.snapshot(&provider_id).await {
                Ok(snapshot) => snapshot,
                Err(Error::StaticProvider(ProviderError::MissingSnapshot(_))) => continue,
                Err(error) => return Err(error),
            };
            for definition in snapshot.instances.values() {
                let key = ProviderInstanceId::new(provider_id.clone(), definition.id.clone());
                active_keys.insert(key.clone());
                let local_id = local_instance_id(&key)?;
                let status = self.instances.status(local_id.to_string()).await?;
                let (local_instance_id, state) = if status == InstanceStatus::NotFound {
                    (None, ProviderInstanceState::NotInstalled)
                } else {
                    let instance = self.instances.get(local_id.to_string()).await?;
                    let installed_revision = instance
                        .spec()
                        .metadata()
                        .get("centralcore.provider_revision")
                        .and_then(|revision| revision.parse::<u64>().ok())
                        .unwrap_or_default();
                    let state = if definition.revision > installed_revision {
                        self.events.emit(CoreEvent::InstanceUpdateAvailable {
                            provider_id: provider_id.to_string(),
                            instance_id: definition.id.to_string(),
                            installed_revision,
                            available_revision: definition.revision,
                        });
                        ProviderInstanceState::UpdateAvailable
                    } else {
                        map_instance_status(status)
                    };
                    (Some(local_id), state)
                };
                entries.push(ProviderInstanceEntry {
                    id: key,
                    name: definition.name.clone(),
                    minecraft_version: definition.minecraft_version.clone(),
                    revision: definition.revision,
                    local_instance_id,
                    state,
                });
            }
        }
        for instance in self.instances.list().await? {
            let metadata = instance.spec().metadata();
            let (Some(provider_text), Some(instance_text)) = (
                metadata.get("centralcore.provider_id"),
                metadata.get("centralcore.provider_instance_id"),
            ) else {
                continue;
            };
            let provider_id = match ProviderId::new(provider_text.clone()) {
                Ok(id) => id,
                Err(_) => continue,
            };
            if provider.is_some_and(|selected| selected != &provider_id) {
                continue;
            }
            let instance_id = match InstanceId::new(instance_text.clone()) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let key = ProviderInstanceId::new(provider_id, instance_id);
            if active_keys.contains(&key) {
                continue;
            }
            let revision = metadata
                .get("centralcore.provider_revision")
                .and_then(|value| value.parse().ok())
                .unwrap_or_default();
            entries.push(ProviderInstanceEntry {
                id: key,
                name: instance.name().to_owned(),
                minecraft_version: instance.spec().minecraft().version().to_owned(),
                revision,
                local_instance_id: Some(instance.id().clone()),
                state: ProviderInstanceState::ProviderRemoved,
            });
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(entries)
    }

    /// Resolves `provider:instance`, or an unambiguous short provider instance ID.
    pub async fn resolve_provider_reference(
        &self,
        reference: &str,
    ) -> Result<Option<ProviderInstanceId>> {
        if reference.contains(':') {
            let key = reference.parse::<ProviderInstanceId>()?;
            self.definition(&key).await?;
            return Ok(Some(key));
        }
        if self.instances.status(reference.to_owned()).await? != InstanceStatus::NotFound {
            return Ok(None);
        }
        let requested = InstanceId::new(reference)?;
        let mut matches = self
            .instances(None)
            .await?
            .into_iter()
            .filter(|entry| entry.id.instance_id == requested)
            .map(|entry| entry.id)
            .collect::<Vec<_>>();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            _ => Err(ProviderError::AmbiguousInstance(reference.to_owned()).into()),
        }
    }

    pub async fn definition(&self, key: &ProviderInstanceId) -> Result<ProviderInstanceDefinition> {
        self.snapshot(&key.provider_id)
            .await?
            .instances
            .remove(&key.instance_id)
            .ok_or_else(|| Error::NotFound {
                kind: "provider instance",
                id: key.to_string(),
            })
    }

    /// Lists required and optional components using persisted local choices.
    pub async fn components(&self, key: &ProviderInstanceId) -> Result<Vec<ComponentStatus>> {
        let definition = self.definition(key).await?;
        let instance = self
            .instances
            .get(local_instance_id(key)?.to_string())
            .await?;
        let mut selections = load_selections(&instance).await?;
        initialize_selections(&definition.components, &mut selections);
        Ok(resolve_components(&definition.components, &selections)?
            .statuses()
            .to_vec())
    }

    /// Computes a pure diff from the installed managed index to the latest snapshot.
    pub async fn plan_update(&self, key: &ProviderInstanceId) -> Result<UpdatePlan> {
        self.plan_update_mode(key, false).await
    }

    /// Computes a diff without resolving new Minecraft/loader metadata over the network.
    pub async fn plan_update_offline(&self, key: &ProviderInstanceId) -> Result<UpdatePlan> {
        self.plan_update_mode(key, true).await
    }

    async fn plan_update_mode(
        &self,
        key: &ProviderInstanceId,
        offline: bool,
    ) -> Result<UpdatePlan> {
        self.events.emit(CoreEvent::InstanceUpdateCheckStarted {
            provider_id: key.provider_id.to_string(),
            instance_id: key.instance_id.to_string(),
        });
        let instance = self
            .instances
            .get(local_instance_id(key)?.to_string())
            .await?;
        let mut selections = load_selections(&instance).await?;
        let definition = self.definition(key).await?;
        initialize_selections(&definition.components, &mut selections);
        self.plan_update_with(
            &instance,
            key,
            &definition,
            selections.clone(),
            selections,
            offline,
        )
        .await
    }

    async fn plan_update_with(
        &self,
        instance: &Instance,
        key: &ProviderInstanceId,
        definition: &ProviderInstanceDefinition,
        selections: super::ComponentSelections,
        expected_selections: super::ComponentSelections,
        offline: bool,
    ) -> Result<UpdatePlan> {
        let index = load_managed_index(instance).await?;
        let resolved = resolve_components(&definition.components, &selections)?;
        let desired_files = desired_provider_files(definition, &resolved)
            .into_iter()
            .map(|(file, origin)| DesiredProviderFile {
                file: file.clone(),
                component_id: component_origin_id(&origin),
            })
            .collect::<Vec<_>>();
        let current = index
            .files
            .iter()
            .filter(|file| {
                file.location == ManagedFileLocation::Instance && is_provider_owned(file, key)
            })
            .map(|file| (file.path.to_string(), file))
            .collect::<BTreeMap<_, _>>();
        let desired_paths = desired_files
            .iter()
            .map(|desired| (format!(".minecraft/{}", desired.file.path), desired))
            .collect::<BTreeMap<_, _>>();
        let mut keep = Vec::new();
        let mut downloads = Vec::new();
        let mut replacements = Vec::new();
        for (path, desired) in &desired_paths {
            let action = update_action(desired, path);
            match current.get(path) {
                Some(existing)
                    if existing.expected_size == Some(desired.file.size)
                        && existing.expected_hash.as_ref() == Some(&desired.file.sha256) =>
                {
                    keep.push(action);
                }
                Some(_) => replacements.push(action),
                None => downloads.push(action),
            }
        }
        let removals = current
            .iter()
            .filter(|(path, _)| !desired_paths.contains_key(*path))
            .map(|(path, file)| UpdateRemoval {
                id: file.id.clone(),
                path: path.clone(),
                component_id: component_origin_id(&file.origin),
            })
            .collect::<Vec<_>>();
        let current_components = current
            .values()
            .filter_map(|file| component_origin_id(&file.origin))
            .collect::<BTreeSet<_>>();
        let desired_components = definition
            .components
            .iter()
            .filter(|component| resolved.is_enabled(&component.id))
            .map(|component| component.id.to_string())
            .collect::<BTreeSet<_>>();
        let optional_changes = current_components
            .symmetric_difference(&desired_components)
            .map(|id| OptionalComponentChange {
                component_id: id.clone(),
                enabled: desired_components.contains(id),
            })
            .collect::<Vec<_>>();
        let from_revision = installed_revision(instance);
        let target_spec = definition.local_spec(instance.id().to_string(), key)?;
        let base_game_changed = instance.spec().minecraft() != target_spec.minecraft()
            || instance.spec().loader() != target_spec.loader();
        let (base_downloads, base_download_size) = if base_game_changed {
            let target_instance = instance.with_spec(target_spec)?;
            let base_plan = if offline {
                self.minecraft
                    .resolve_cached_install_plan(&target_instance)
                    .await?
            } else {
                self.minecraft
                    .resolve_install_plan(&target_instance, &CancellationToken::default())
                    .await?
            };
            let missing = base_plan
                .downloads
                .iter()
                .filter(|download| {
                    !index.files.iter().any(|current| {
                        current.location == ManagedFileLocation::Cache
                            && current.path == download.request.destination
                            && current.expected_size == download.request.expected_size
                            && current.expected_hash == download.request.expected_hash
                    })
                })
                .collect::<Vec<_>>();
            let size = missing
                .iter()
                .map(|download| download.request.expected_size)
                .collect::<Option<Vec<_>>>()
                .map(|sizes| sizes.into_iter().sum());
            (missing.len() as u64, size)
        } else {
            (0, Some(0))
        };
        let provider_download_size = downloads
            .iter()
            .chain(&replacements)
            .map(|action| action.size)
            .sum::<u64>();
        let download_size = provider_download_size.saturating_add(base_download_size.unwrap_or(0));
        let plan = UpdatePlan {
            instance: key.clone(),
            local_instance_id: instance.id().clone(),
            from_revision,
            to_revision: definition.revision,
            keep,
            downloads,
            replacements,
            removals,
            optional_changes,
            base_downloads,
            base_download_size,
            download_size,
            base_game_changed,
            desired_files,
            selections,
            expected_selections,
        };
        self.events.emit(CoreEvent::UpdatePlanCreated {
            instance_id: instance.id().to_string(),
            from_revision: plan.from_revision,
            to_revision: plan.to_revision,
            downloads: plan.downloads.len() as u64,
            replacements: plan.replacements.len() as u64,
            removals: plan.removals.len() as u64,
        });
        Ok(plan)
    }

    /// Returns a local instance for either a local ID or a materialized provider identity.
    pub async fn resolve_local_instance(&self, reference: &str) -> Result<Instance> {
        match self.resolve_provider_reference(reference).await? {
            Some(key) => {
                self.instances
                    .get(local_instance_id(&key)?.to_string())
                    .await
            }
            None => self.instances.get(reference.to_owned()).await,
        }
    }

    /// Materializes one declaration without overwriting an existing local specification.
    pub async fn materialize(&self, key: &ProviderInstanceId) -> Result<Instance> {
        let definition = self.definition(key).await?;
        let local_id = local_instance_id(key)?;
        match self.instances.status(local_id.to_string()).await? {
            InstanceStatus::NotFound => {
                self.instances
                    .create(definition.local_spec(local_id.to_string(), key)?)
                    .await
            }
            _ => {
                let instance = self.instances.get(local_id.to_string()).await?;
                if instance.spec().metadata().get("centralcore.provider_id")
                    != Some(&key.provider_id.to_string())
                    || instance
                        .spec()
                        .metadata()
                        .get("centralcore.provider_instance_id")
                        != Some(&key.instance_id.to_string())
                {
                    return Err(ProviderError::ManagedPathConflict {
                        path: instance.path().display().to_string(),
                        existing: "local instance".into(),
                        incoming: key.to_string(),
                    }
                    .into());
                }
                Ok(instance)
            }
        }
    }

    /// Installs Vanilla through the Phase 2 pipeline, then provider files through the same cache/index.
    pub async fn install(
        &self,
        key: &ProviderInstanceId,
        cancellation: &CancellationToken,
    ) -> Result<ProviderInstallOutcome> {
        self.install_mode(key, cancellation, false).await
    }

    /// Installs exclusively from the last provider snapshot and validated local cache.
    pub async fn install_offline(
        &self,
        key: &ProviderInstanceId,
        cancellation: &CancellationToken,
    ) -> Result<ProviderInstallOutcome> {
        self.install_mode(key, cancellation, true).await
    }

    /// Plans and applies the latest provider revision.
    pub async fn update(
        &self,
        key: &ProviderInstanceId,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<UpdateReport> {
        let plan = if offline {
            self.plan_update_offline(key).await?
        } else {
            self.plan_update(key).await?
        };
        self.apply_update(plan, cancellation, offline).await
    }

    /// Applies an immutable plan under the existing per-instance lock.
    pub async fn apply_update(
        &self,
        plan: UpdatePlan,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<UpdateReport> {
        let instance = self
            .instances
            .get(plan.local_instance_id.to_string())
            .await?;
        let _lock = self
            .locks
            .try_acquire_exclusive(format!("instance:{}", instance.id()))
            .await?;
        if self.minecraft.status(instance.id()).await? == InstanceStatus::Running {
            return Err(ProviderError::InstanceRunning(instance.id().to_string()).into());
        }
        let current_definition = self.definition(&plan.instance).await?;
        if current_definition.revision != plan.to_revision {
            return Err(ProviderError::StaleUpdatePlan {
                planned: plan.to_revision,
                available: current_definition.revision,
            }
            .into());
        }
        if installed_revision(&instance) != plan.from_revision {
            return Err(ProviderError::StaleInstalledRevision {
                planned: plan.from_revision,
                installed: installed_revision(&instance),
            }
            .into());
        }
        let mut current_selections = load_selections(&instance).await?;
        initialize_selections(&current_definition.components, &mut current_selections);
        if current_selections != plan.expected_selections {
            return Err(ProviderError::StaleComponentSelections.into());
        }
        let transaction = provider_transaction_id();
        self.minecraft
            .write_transaction(
                &instance,
                &transaction,
                "update",
                crate::minecraft::TransactionState::Created,
            )
            .await?;
        self.events.emit(CoreEvent::InstanceUpdateProgress {
            instance_id: instance.id().to_string(),
            phase: UpdatePhase::Preparing,
            completed_files: 0,
            total_files: (plan.downloads.len() + plan.replacements.len()) as u64,
            completed_bytes: 0,
            total_bytes: plan.download_size,
        });
        self.instances.mark_updating(&instance).await?;
        self.events.emit(CoreEvent::InstanceUpdateStarted {
            instance_id: instance.id().to_string(),
            from_revision: plan.from_revision,
            to_revision: plan.to_revision,
        });
        let started = Instant::now();
        let result = self
            .apply_update_unlocked(
                &instance,
                &current_definition,
                &plan,
                cancellation,
                offline,
                &transaction,
                started,
            )
            .await;
        match result {
            Ok(report) => {
                let committed = self.instances.get(instance.id().to_string()).await?;
                self.instances.mark_installed(&committed).await?;
                self.minecraft
                    .write_transaction(
                        &instance,
                        &transaction,
                        "update",
                        crate::minecraft::TransactionState::Committed,
                    )
                    .await?;
                self.events.emit(CoreEvent::InstanceUpdateCompleted {
                    instance_id: instance.id().to_string(),
                    from_revision: plan.from_revision,
                    to_revision: plan.to_revision,
                });
                Ok(report)
            }
            Err(error) => {
                let message = error.to_string();
                let _ = self.instances.mark_interrupted(&instance, &message).await;
                let state = if cancellation.is_cancelled() {
                    crate::minecraft::TransactionState::Cancelled
                } else {
                    crate::minecraft::TransactionState::Failed
                };
                let _ = self
                    .minecraft
                    .write_transaction(&instance, &transaction, "update", state)
                    .await;
                self.events.emit(CoreEvent::InstanceUpdateFailed {
                    instance_id: instance.id().to_string(),
                    message,
                });
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_update_unlocked(
        &self,
        original_instance: &Instance,
        definition: &ProviderInstanceDefinition,
        plan: &UpdatePlan,
        cancellation: &CancellationToken,
        offline: bool,
        transaction: &str,
        started: Instant,
    ) -> Result<UpdateReport> {
        self.minecraft
            .write_transaction(
                original_instance,
                transaction,
                "update",
                crate::minecraft::TransactionState::Preparing,
            )
            .await?;
        let total_changed = plan.downloads.len() + plan.replacements.len();
        let changed_paths = plan
            .downloads
            .iter()
            .chain(&plan.replacements)
            .map(|action| action.path.clone())
            .collect::<BTreeSet<_>>();
        let staging = original_instance
            .path()
            .join("runtime")
            .join(format!("update-{transaction}"));
        cleanup_real_directory(&staging).await?;
        tokio::fs::create_dir(&staging).await?;
        let staged_files = staging.join("files");
        let backups = staging.join("backups");
        tokio::fs::create_dir(&staged_files).await?;
        tokio::fs::create_dir(&backups).await?;
        copy_real_file(
            &original_instance.path().join("instance.json"),
            &staging.join("instance.json.previous"),
        )
        .await?;
        copy_real_file(
            &original_instance
                .path()
                .join("runtime")
                .join("managed-files.json"),
            &staging.join("managed-files.json.previous"),
        )
        .await?;
        self.minecraft
            .write_transaction(
                original_instance,
                transaction,
                "update",
                crate::minecraft::TransactionState::Downloading,
            )
            .await?;
        let cache_root = self.minecraft.cache_root();
        let mut cache_hits = 0_u64;
        let mut cache_misses = 0_u64;
        let mut bytes_downloaded = 0_u64;
        let mut completed = 0_u64;
        for desired in &plan.desired_files {
            let path = format!(".minecraft/{}", desired.file.path);
            if !changed_paths.contains(&path) {
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(crate::download::DownloadError::Cancelled.into());
            }
            let reused = self
                .prepare_provider_file_cache(&plan.instance, &desired.file, cancellation, offline)
                .await?;
            if reused {
                cache_hits += 1;
            } else {
                cache_misses += 1;
                bytes_downloaded = bytes_downloaded.saturating_add(desired.file.size);
            }
            let cache_path = provider_cache_path(&desired.file.sha256)?;
            let instance_path = SafeRelativePath::new(path)?;
            copy_verified(
                cache_root,
                &cache_path,
                &staged_files,
                &instance_path,
                desired.file.size,
                &desired.file.sha256,
            )
            .await?;
            completed += 1;
            self.events.emit(CoreEvent::InstanceUpdateProgress {
                instance_id: original_instance.id().to_string(),
                phase: UpdatePhase::Downloading,
                completed_files: completed,
                total_files: total_changed as u64,
                completed_bytes: bytes_downloaded,
                total_bytes: plan.download_size,
            });
        }
        let target_spec =
            definition.local_spec(original_instance.id().to_string(), &plan.instance)?;
        let mut active_instance = original_instance.clone();
        let mut base_removal_paths = BTreeSet::new();
        if plan.base_game_changed {
            let old_index = load_managed_index(original_instance).await?;
            active_instance = self
                .instances
                .replace_spec_unlocked(original_instance, target_spec.clone())
                .await?;
            self.minecraft
                .install_for_provider(&active_instance, cancellation, offline)
                .await?;
            self.instances.mark_updating(&active_instance).await?;
            let new_index = load_managed_index(&active_instance).await?;
            let new_paths = new_index
                .files
                .iter()
                .filter(|file| file.location == ManagedFileLocation::Instance)
                .map(|file| file.path.to_string())
                .collect::<BTreeSet<_>>();
            base_removal_paths.extend(
                old_index
                    .files
                    .iter()
                    .filter(|file| {
                        file.location == ManagedFileLocation::Instance
                            && matches!(
                                &file.origin,
                                ManagedFileOrigin::Minecraft | ManagedFileOrigin::Loader
                            )
                            && !new_paths.contains(&file.path.to_string())
                    })
                    .map(|file| file.path.to_string()),
            );
            self.minecraft
                .write_transaction(
                    &active_instance,
                    transaction,
                    "update",
                    crate::minecraft::TransactionState::Applying,
                )
                .await?;
        } else {
            self.minecraft
                .write_transaction(
                    &active_instance,
                    transaction,
                    "update",
                    crate::minecraft::TransactionState::Applying,
                )
                .await?;
        }
        if cancellation.is_cancelled() {
            return Err(crate::download::DownloadError::Cancelled.into());
        }
        let mut backup_paths = plan
            .removals
            .iter()
            .map(|removal| removal.path.clone())
            .chain(plan.replacements.iter().map(|action| action.path.clone()))
            .collect::<BTreeSet<_>>();
        backup_paths.extend(base_removal_paths);
        self.events.emit(CoreEvent::InstanceUpdateProgress {
            instance_id: active_instance.id().to_string(),
            phase: UpdatePhase::Applying,
            completed_files: 0,
            total_files: (backup_paths.len() + total_changed) as u64,
            completed_bytes: bytes_downloaded,
            total_bytes: plan.download_size,
        });
        for path in &backup_paths {
            if let Err(error) = move_to_backup(&active_instance, &backups, path).await {
                rollback_update_files(&active_instance, &backups, &[], &backup_paths).await?;
                return Err(error);
            }
        }
        let mut applied_paths = Vec::new();
        for action in plan.downloads.iter().chain(&plan.replacements) {
            if let Err(error) =
                move_staged_into_instance(&active_instance, &staged_files, &action.path).await
            {
                rollback_update_files(&active_instance, &backups, &applied_paths, &backup_paths)
                    .await?;
                return Err(error);
            }
            applied_paths.push(action.path.clone());
        }
        self.events.emit(CoreEvent::InstanceUpdateProgress {
            instance_id: active_instance.id().to_string(),
            phase: UpdatePhase::Verifying,
            completed_files: total_changed as u64,
            total_files: total_changed as u64,
            completed_bytes: bytes_downloaded,
            total_bytes: plan.download_size,
        });
        let mut index = load_managed_index(&active_instance).await?;
        index
            .files
            .retain(|file| !is_provider_owned(file, &plan.instance));
        let additions = self
            .snapshot_desired_provider_files(&active_instance, &plan.instance, &plan.desired_files)
            .await?;
        index.files.extend(additions);
        let verification = verify_index(
            &active_instance,
            cache_root,
            &index,
            true,
            self.downloads.config().concurrency,
        )
        .await?;
        if !verification.is_healthy() {
            rollback_update_files(&active_instance, &backups, &applied_paths, &backup_paths)
                .await?;
            return Err(crate::minecraft::RepairError::FinalVerification {
                missing: verification.missing,
                corrupted: verification.corrupted,
            }
            .into());
        }
        self.minecraft
            .write_transaction(
                &active_instance,
                transaction,
                "update",
                crate::minecraft::TransactionState::Finalizing,
            )
            .await?;
        self.events.emit(CoreEvent::InstanceUpdateProgress {
            instance_id: active_instance.id().to_string(),
            phase: UpdatePhase::Finalizing,
            completed_files: total_changed as u64,
            total_files: total_changed as u64,
            completed_bytes: bytes_downloaded,
            total_bytes: plan.download_size,
        });
        write_managed_index(&active_instance, &index).await?;
        self.cache.register(&index).await?;
        write_selections(&active_instance, &plan.selections).await?;
        if !plan.base_game_changed {
            active_instance = self
                .instances
                .replace_spec_unlocked(&active_instance, target_spec)
                .await?;
        }
        cleanup_real_directory(&staging).await?;
        Ok(UpdateReport {
            instance_id: active_instance.id().to_string(),
            from_revision: plan.from_revision,
            to_revision: plan.to_revision,
            files_kept: plan.keep.len() as u64,
            files_downloaded: plan.downloads.len() as u64,
            files_replaced: plan.replacements.len() as u64,
            files_removed: plan.removals.len() as u64,
            bytes_reused: plan
                .keep
                .iter()
                .map(|action| action.size)
                .sum::<u64>()
                .saturating_add(plan.download_size.saturating_sub(bytes_downloaded)),
            bytes_downloaded,
            cache_hits,
            cache_misses,
            duration_millis: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }

    /// Changes one optional component and applies the resulting minimal plan.
    pub async fn set_component_enabled(
        &self,
        key: &ProviderInstanceId,
        component_id: &ComponentId,
        enabled: bool,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<UpdateReport> {
        let definition = self.definition(key).await?;
        let component = definition
            .components
            .iter()
            .find(|component| &component.id == component_id)
            .ok_or_else(|| Error::NotFound {
                kind: "component",
                id: component_id.to_string(),
            })?;
        if component.requirement == super::ComponentRequirement::Required && !enabled {
            return Err(ProviderError::ComponentRequiredBy {
                component: component_id.to_string(),
                dependent: "provider".into(),
            }
            .into());
        }
        let instance = self
            .instances
            .get(local_instance_id(key)?.to_string())
            .await?;
        let mut selections = load_selections(&instance).await?;
        initialize_selections(&definition.components, &mut selections);
        let expected_selections = selections.clone();
        selections.components.insert(component_id.clone(), enabled);
        let resolved = resolve_components(&definition.components, &selections)?;
        if !enabled && resolved.is_enabled(component_id) {
            let dependent = resolved
                .statuses()
                .iter()
                .find(|status| &status.id == component_id)
                .and_then(|status| status.enabled_by.first())
                .map(ToString::to_string)
                .unwrap_or_else(|| "another enabled component".into());
            return Err(ProviderError::ComponentRequiredBy {
                component: component_id.to_string(),
                dependent,
            }
            .into());
        }
        let plan = self
            .plan_update_with(
                &instance,
                key,
                &definition,
                selections,
                expected_selections,
                offline,
            )
            .await?;
        let report = self.apply_update(plan, cancellation, offline).await?;
        self.events.emit(CoreEvent::ComponentSelectionChanged {
            instance_id: instance.id().to_string(),
            component_id: component_id.to_string(),
            enabled,
        });
        self.events.emit(if enabled {
            CoreEvent::ComponentEnabled {
                instance_id: instance.id().to_string(),
                component_id: component_id.to_string(),
            }
        } else {
            CoreEvent::ComponentDisabled {
                instance_id: instance.id().to_string(),
                component_id: component_id.to_string(),
            }
        });
        Ok(report)
    }

    async fn install_mode(
        &self,
        key: &ProviderInstanceId,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<ProviderInstallOutcome> {
        let definition = self.definition(key).await?;
        let instance = self.materialize(key).await?;
        let _lock = self
            .locks
            .try_acquire_exclusive(format!("instance:{}", instance.id()))
            .await?;
        let minecraft = self
            .minecraft
            .install_for_provider(&instance, cancellation, offline)
            .await?;
        self.instances.mark_installing(&instance).await?;
        let provider_result = self
            .install_provider_files(&instance, key, &definition, cancellation, offline)
            .await;
        match provider_result {
            Ok(provider_files) => {
                self.instances.mark_installed(&instance).await?;
                Ok(ProviderInstallOutcome {
                    instance,
                    minecraft,
                    provider_files,
                })
            }
            Err(error) => {
                let _ = self
                    .instances
                    .mark_broken(&instance, &error.to_string())
                    .await;
                Err(error)
            }
        }
    }

    async fn install_provider_files(
        &self,
        instance: &Instance,
        key: &ProviderInstanceId,
        definition: &ProviderInstanceDefinition,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<u64> {
        let mut index = load_managed_index(instance).await?;
        let cache_root = self.minecraft.cache_root();
        let mut selections = load_selections(instance).await?;
        initialize_selections(&definition.components, &mut selections);
        let resolved = resolve_components(&definition.components, &selections)?;
        write_selections(instance, &selections).await?;
        let desired = desired_provider_files(definition, &resolved);
        let mut additions = Vec::with_capacity(desired.len() * 2);
        for (file, origin) in &desired {
            let managed_id = managed_provider_file_id(file, origin);
            if cancellation.is_cancelled() {
                return Err(crate::download::DownloadError::Cancelled.into());
            }
            let cache_path = provider_cache_path(&file.sha256)?;
            match &file.source {
                ProviderResource::Remote(url) => {
                    let request = DownloadRequest {
                        id: format!(
                            "provider:{}:{}:{}",
                            key.provider_id, key.instance_id, managed_id
                        ),
                        source: url.clone(),
                        destination: cache_path.clone(),
                        expected_size: Some(file.size),
                        expected_hash: Some(file.sha256.clone()),
                    };
                    if offline {
                        if !self.downloads.recover_local(cache_root, &request).await? {
                            return Err(crate::minecraft::RepairError::OfflineObjectsUnavailable {
                                count: 1,
                            }
                            .into());
                        }
                    } else {
                        self.validate_remote_access(url).await?;
                        self.downloads
                            .download(cache_root, &request, cancellation)
                            .await?;
                    }
                }
                ProviderResource::Local { path, root } => {
                    validate_local_resource(root, path).await?;
                    self.import_local_file(path, cache_root, &cache_path, file.size, &file.sha256)
                        .await?;
                }
            }
            let instance_path = SafeRelativePath::new(format!(".minecraft/{}", file.path))?;
            reject_managed_conflict(&index.files, &instance_path, key)?;
            copy_verified(
                cache_root,
                &cache_path,
                instance.path(),
                &instance_path,
                file.size,
                &file.sha256,
            )
            .await?;
            let (remote_source, local_source) = match &file.source {
                ProviderResource::Remote(url) => (Some(url.clone()), None),
                ProviderResource::Local { path, .. } => (None, Some(path.clone())),
            };
            additions.push(
                snapshot_managed_file(
                    cache_root,
                    ManagedFile {
                        id: format!(
                            "provider-cache:{}:{}:{}",
                            key.provider_id, key.instance_id, managed_id
                        ),
                        location: ManagedFileLocation::Cache,
                        path: cache_path.clone(),
                        kind: ManagedFileKind::Other,
                        origin: origin.clone(),
                        expected_size: Some(file.size),
                        expected_hash: Some(file.sha256.clone()),
                        source: remote_source,
                        source_path: local_source,
                        repair_from: None,
                        verified_size: 0,
                        verified_modified_unix_nanos: None,
                    },
                )
                .await?,
            );
            additions.push(
                snapshot_managed_file(
                    instance.path(),
                    ManagedFile {
                        id: format!(
                            "provider-file:{}:{}:{}",
                            key.provider_id, key.instance_id, file.id
                        ),
                        location: ManagedFileLocation::Instance,
                        path: instance_path,
                        kind: ManagedFileKind::Other,
                        origin: origin.clone(),
                        expected_size: Some(file.size),
                        expected_hash: Some(file.sha256.clone()),
                        source: None,
                        source_path: None,
                        repair_from: Some(cache_path),
                        verified_size: 0,
                        verified_modified_unix_nanos: None,
                    },
                )
                .await?,
            );
        }
        index.files.retain(|file| !is_provider_owned(file, key));
        index.files.extend(additions);
        let verification = verify_index(
            instance,
            cache_root,
            &index,
            true,
            self.downloads.config().concurrency,
        )
        .await?;
        if !verification.is_healthy() {
            return Err(crate::minecraft::RepairError::FinalVerification {
                missing: verification.missing,
                corrupted: verification.corrupted,
            }
            .into());
        }
        write_managed_index(instance, &index).await?;
        self.cache.register(&index).await?;
        Ok(desired.len() as u64)
    }

    async fn import_local_file(
        &self,
        source: &Path,
        cache_root: &Path,
        destination: &SafeRelativePath,
        size: u64,
        hash: &crate::files::FileHash,
    ) -> Result<()> {
        let _lock = self
            .locks
            .acquire_exclusive(format!("cache:{destination}"))
            .await?;
        let metadata = tokio::fs::symlink_metadata(source).await?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: source.to_path_buf(),
                reason: "local provider file must be a real file",
            });
        }
        let target = destination.join_under(cache_root);
        if tokio::fs::try_exists(&target).await?
            && verify_file(&target, Some(size), Some(hash)).await.is_ok()
        {
            return Ok(());
        }
        copy_absolute_verified(source, cache_root, destination, size, hash).await
    }

    async fn prepare_provider_file_cache(
        &self,
        key: &ProviderInstanceId,
        file: &ProviderFile,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<bool> {
        let cache_root = self.minecraft.cache_root();
        let cache_path = provider_cache_path(&file.sha256)?;
        match &file.source {
            ProviderResource::Remote(url) => {
                let request = DownloadRequest {
                    id: format!(
                        "provider:{}:{}:{}",
                        key.provider_id, key.instance_id, file.id
                    ),
                    source: url.clone(),
                    destination: cache_path,
                    expected_size: Some(file.size),
                    expected_hash: Some(file.sha256.clone()),
                };
                if offline {
                    if !self.downloads.recover_local(cache_root, &request).await? {
                        return Err(crate::minecraft::RepairError::OfflineObjectsUnavailable {
                            count: 1,
                        }
                        .into());
                    }
                    Ok(true)
                } else {
                    self.validate_remote_access(url).await?;
                    Ok(self
                        .downloads
                        .download(cache_root, &request, cancellation)
                        .await?
                        .reused)
                }
            }
            ProviderResource::Local { path, root } => {
                validate_local_resource(root, path).await?;
                let target = cache_path.join_under(cache_root);
                let reused = tokio::fs::try_exists(&target).await?
                    && verify_file(&target, Some(file.size), Some(&file.sha256))
                        .await
                        .is_ok();
                if !reused {
                    self.import_local_file(path, cache_root, &cache_path, file.size, &file.sha256)
                        .await?;
                }
                Ok(reused)
            }
        }
    }

    async fn snapshot_desired_provider_files(
        &self,
        instance: &Instance,
        key: &ProviderInstanceId,
        desired_files: &[DesiredProviderFile],
    ) -> Result<Vec<ManagedFile>> {
        let cache_root = self.minecraft.cache_root();
        let mut additions = Vec::with_capacity(desired_files.len() * 2);
        for desired in desired_files {
            let file = &desired.file;
            let origin = desired
                .component_id
                .as_ref()
                .map(|id| ManagedFileOrigin::Component { id: id.clone() })
                .unwrap_or(ManagedFileOrigin::Provider);
            let managed_id = managed_provider_file_id(file, &origin);
            let cache_path = provider_cache_path(&file.sha256)?;
            let instance_path = SafeRelativePath::new(format!(".minecraft/{}", file.path))?;
            let (remote_source, local_source) = match &file.source {
                ProviderResource::Remote(url) => (Some(url.clone()), None),
                ProviderResource::Local { path, .. } => (None, Some(path.clone())),
            };
            additions.push(
                snapshot_managed_file(
                    cache_root,
                    ManagedFile {
                        id: format!(
                            "provider-cache:{}:{}:{}",
                            key.provider_id, key.instance_id, managed_id
                        ),
                        location: ManagedFileLocation::Cache,
                        path: cache_path.clone(),
                        kind: ManagedFileKind::Other,
                        origin: origin.clone(),
                        expected_size: Some(file.size),
                        expected_hash: Some(file.sha256.clone()),
                        source: remote_source,
                        source_path: local_source,
                        repair_from: None,
                        verified_size: 0,
                        verified_modified_unix_nanos: None,
                    },
                )
                .await?,
            );
            additions.push(
                snapshot_managed_file(
                    instance.path(),
                    ManagedFile {
                        id: format!(
                            "provider-file:{}:{}:{}",
                            key.provider_id, key.instance_id, managed_id
                        ),
                        location: ManagedFileLocation::Instance,
                        path: instance_path,
                        kind: ManagedFileKind::Other,
                        origin,
                        expected_size: Some(file.size),
                        expected_hash: Some(file.sha256.clone()),
                        source: None,
                        source_path: None,
                        repair_from: Some(cache_path),
                        verified_size: 0,
                        verified_modified_unix_nanos: None,
                    },
                )
                .await?,
            );
        }
        Ok(additions)
    }

    async fn verify_provider_index(
        &self,
        id: &ProviderId,
        registration: &ProviderRegistration,
        raw: RawProviderManifest,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<VerifiedIndex> {
        let canonical = canonicalize_json(bytes)?;
        let content_sha256 = format!("{:x}", Sha256::digest(&canonical));
        if registration.signature_policy == SignaturePolicy::Disabled {
            return Ok(VerifiedIndex {
                verification: provider_verification(
                    SignatureStatus::Disabled,
                    raw.revision,
                    content_sha256,
                    bytes,
                    None,
                ),
                raw,
            });
        }

        self.events.emit(CoreEvent::ManifestVerificationStarted {
            provider_id: id.to_string(),
        });
        let signature_source = detached_signature_source(&registration.source)?;
        let envelope_bytes = match self
            .fetch_document(&signature_source, None, 64 * 1024, cancellation)
            .await
        {
            Ok(DocumentFetch::Modified { bytes, .. }) => Some(bytes),
            Ok(DocumentFetch::NotModified) => None,
            Err(error) if signature_not_found(&error) => None,
            Err(error) => return Err(error),
        };
        let Some(envelope_bytes) = envelope_bytes else {
            if registration.signature_policy == SignaturePolicy::Required {
                self.events.emit(CoreEvent::ManifestVerificationFailed {
                    provider_id: id.to_string(),
                    error_kind: "signature_missing".into(),
                });
                return Err(TrustError::SignatureMissing.into());
            }
            return Ok(VerifiedIndex {
                verification: provider_verification(
                    SignatureStatus::Unsigned,
                    raw.revision,
                    content_sha256,
                    bytes,
                    None,
                ),
                raw,
            });
        };
        let result: Result<VerifiedIndex> = async {
            let envelope: SignatureEnvelope = serde_json::from_slice(&envelope_bytes)
                .map_err(|_| TrustError::SignatureInvalid)?;
            let expected = registration
                .trusted_key_id
                .as_ref()
                .ok_or_else(|| TrustError::UntrustedSigningKey(envelope.key_id.clone()))?;
            let revision = raw.revision.ok_or_else(|| {
                ProviderError::InvalidManifest(
                    "signed provider index requires a non-zero revision".into(),
                )
            })?;
            if revision == 0 {
                return Err(ProviderError::InvalidManifest(
                    "signed provider index revision must be greater than zero".into(),
                )
                .into());
            }
            SignatureVerifier::new(self.trust.clone())
                .verify_provider(bytes, &envelope, expected, id.as_str(), revision)
                .await?;
            Ok(VerifiedIndex {
                verification: provider_verification(
                    SignatureStatus::Verified,
                    Some(revision),
                    content_sha256,
                    bytes,
                    Some(envelope),
                ),
                raw,
            })
        }
        .await;
        match &result {
            Ok(index) => self.events.emit(CoreEvent::ManifestVerified {
                provider_id: id.to_string(),
                key_id: index
                    .verification
                    .key_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                revision: index.verification.revision.unwrap_or_default(),
            }),
            Err(error) => self.events.emit(CoreEvent::ManifestVerificationFailed {
                provider_id: id.to_string(),
                error_kind: trust_error_kind(error).into(),
            }),
        }
        result
    }

    async fn enforce_and_record_revisions(
        &self,
        id: &ProviderId,
        snapshot: &ProviderSnapshot,
        allow_rollback: bool,
    ) -> Result<()> {
        let _rollback_lock = self.locks.acquire_exclusive("providers:rollback").await?;
        let revision = snapshot.provider_revision.ok_or_else(|| {
            ProviderError::InvalidManifest("verified snapshot has no provider revision".into())
        })?;
        let mut document = self.load_rollback_state().await?;
        if let Some(highest) = document.providers.get(id) {
            if revision < highest.revision && !allow_rollback {
                self.events.emit(CoreEvent::ProviderRollbackRejected {
                    provider_id: id.to_string(),
                    received_revision: revision,
                    highest_revision: highest.revision,
                });
                return Err(TrustError::ManifestRollbackDetected {
                    subject: id.to_string(),
                    received: revision,
                    highest: highest.revision,
                }
                .into());
            }
            if revision == highest.revision
                && snapshot.verification.content_sha256 != highest.content_sha256
                && !allow_rollback
            {
                return Err(TrustError::SignatureInvalid.into());
            }
            for (instance_id, definition) in &snapshot.instances {
                if let Some(instance_highest) = highest.instances.get(instance_id) {
                    if definition.revision < instance_highest.revision && !allow_rollback {
                        self.events.emit(CoreEvent::ProviderRollbackRejected {
                            provider_id: id.to_string(),
                            received_revision: definition.revision,
                            highest_revision: instance_highest.revision,
                        });
                        return Err(TrustError::ManifestRollbackDetected {
                            subject: format!("{id}:{instance_id}"),
                            received: definition.revision,
                            highest: instance_highest.revision,
                        }
                        .into());
                    }
                    let content = snapshot
                        .manifest_documents
                        .get(instance_id)
                        .map(|document| document.content_sha256.as_str())
                        .unwrap_or_default();
                    if definition.revision == instance_highest.revision
                        && content != instance_highest.content_sha256
                        && !allow_rollback
                    {
                        return Err(TrustError::SignatureInvalid.into());
                    }
                }
            }
        }

        let entry = document
            .providers
            .entry(id.clone())
            .or_insert_with(|| ProviderHighWater {
                revision,
                content_sha256: snapshot.verification.content_sha256.clone(),
                instances: BTreeMap::new(),
            });
        if revision > entry.revision {
            entry.revision = revision;
            entry.content_sha256 = snapshot.verification.content_sha256.clone();
        }
        for (instance_id, definition) in &snapshot.instances {
            let content_sha256 = snapshot
                .manifest_documents
                .get(instance_id)
                .map(|document| document.content_sha256.clone())
                .ok_or_else(|| {
                    ProviderError::InvalidManifest(format!(
                        "verified manifest bytes missing for `{instance_id}`"
                    ))
                })?;
            match entry.instances.get_mut(instance_id) {
                Some(highest) if definition.revision > highest.revision => {
                    highest.revision = definition.revision;
                    highest.content_sha256 = content_sha256;
                }
                None => {
                    entry.instances.insert(
                        instance_id.clone(),
                        RevisionHighWater {
                            revision: definition.revision,
                            content_sha256,
                        },
                    );
                }
                _ => {}
            }
        }
        atomic_json(&self.root, Path::new("rollback.json"), &document).await
    }

    async fn load_rollback_state(&self) -> Result<RollbackDocument> {
        let path = self.root.join("rollback.json");
        match read_with_previous(&path).await {
            Ok(bytes) => {
                let document: RollbackDocument = serde_json::from_slice(&bytes)?;
                if document.format_version != rollback_format_version() {
                    return Err(Error::UnsupportedFormat {
                        kind: "provider rollback state",
                        version: document.format_version,
                    });
                }
                Ok(document)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(RollbackDocument::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn fetch_document(
        &self,
        source: &ProviderSource,
        previous: Option<&ProviderHttpMetadata>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<DocumentFetch> {
        match source {
            ProviderSource::Local(path) => Ok(DocumentFetch::Modified {
                bytes: read_bounded_real_file(path, limit).await?,
                http: None,
            }),
            ProviderSource::Remote(url) => {
                self.fetch_remote_document(url, previous, limit, cancellation)
                    .await
            }
        }
    }

    async fn fetch_resource_document(
        &self,
        source: &ProviderResource,
        previous: Option<&ProviderHttpMetadata>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<DocumentFetch> {
        match source {
            ProviderResource::Local { path, root } => {
                validate_local_resource(root, path).await?;
                Ok(DocumentFetch::Modified {
                    bytes: read_bounded_real_file(path, limit).await?,
                    http: None,
                })
            }
            ProviderResource::Remote(url) => {
                self.fetch_remote_document(url, previous, limit, cancellation)
                    .await
            }
        }
    }

    async fn fetch_remote_document(
        &self,
        url: &Url,
        previous: Option<&ProviderHttpMetadata>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<DocumentFetch> {
        self.validate_remote_access(url).await?;
        match self
            .downloads
            .fetch_conditional(
                url,
                previous.and_then(|metadata| metadata.etag.as_deref()),
                previous.and_then(|metadata| metadata.last_modified.as_deref()),
                limit,
                cancellation,
            )
            .await?
        {
            ConditionalFetch::NotModified => Ok(DocumentFetch::NotModified),
            ConditionalFetch::Modified {
                bytes,
                etag,
                last_modified,
            } => Ok(DocumentFetch::Modified {
                http: Some(ProviderHttpMetadata {
                    url: url.clone(),
                    etag,
                    last_modified,
                    retrieved_unix_seconds: unix_seconds(),
                    content_sha256: format!("{:x}", Sha256::digest(&bytes)),
                }),
                bytes,
            }),
        }
    }

    fn resolve_reference(
        &self,
        base: &impl ResourceBase,
        reference: &str,
    ) -> Result<ProviderResource> {
        base.resolve(reference, self)
    }

    fn validate_remote_url_syntax(&self, url: &Url) -> Result<()> {
        let scheme_allowed = url.scheme() == "https"
            || (url.scheme() == "http" && self.downloads.config().allow_insecure_http);
        if !scheme_allowed {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: "HTTPS is required (HTTP is development-only)".into(),
            }
            .into());
        }
        if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: "userinfo is forbidden and a host is required".into(),
            }
            .into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: "query strings and fragments are forbidden in static provider URLs".into(),
            }
            .into());
        }
        let host = url.host_str().unwrap_or_default();
        if !self.downloads.config().allowed_hosts.is_empty()
            && !self
                .downloads
                .config()
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: format!("host `{host}` is not allowlisted"),
            }
            .into());
        }
        if !self.settings.allow_private_networks
            && (host.eq_ignore_ascii_case("localhost")
                || host.ends_with(".localhost")
                || host.parse::<IpAddr>().is_ok_and(is_private_address))
        {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: "loopback, link-local, and private destinations are forbidden".into(),
            }
            .into());
        }
        Ok(())
    }

    async fn validate_remote_access(&self, url: &Url) -> Result<()> {
        self.validate_remote_url_syntax(url)?;
        if self.settings.allow_private_networks {
            return Ok(());
        }
        let host = url.host_str().unwrap_or_default();
        let port = url.port_or_known_default().unwrap_or(443);
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: format!("host resolution failed: {error}"),
            })?;
        if addresses
            .into_iter()
            .any(|address| is_private_address(address.ip()))
        {
            return Err(ProviderError::UrlPolicy {
                url: safe_url(url),
                reason: "DNS resolved to a loopback, link-local, or private address".into(),
            }
            .into());
        }
        Ok(())
    }

    async fn load_registry(&self) -> Result<RegistryDocument> {
        let path = self.root.join("registry.json");
        match read_with_previous(&path).await {
            Ok(bytes) => {
                let registry: RegistryDocument = serde_json::from_slice(&bytes)?;
                if registry.format_version != REGISTRY_FORMAT_VERSION {
                    return Err(Error::UnsupportedFormat {
                        kind: "provider registry",
                        version: registry.format_version,
                    });
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(RegistryDocument::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn write_registry(&self, registry: &RegistryDocument) -> Result<()> {
        atomic_json(&self.root, Path::new("registry.json"), registry).await
    }

    async fn write_snapshot(&self, id: &ProviderId, snapshot: &ProviderSnapshot) -> Result<()> {
        let relative = PathBuf::from("snapshots").join(format!("{id}.json"));
        atomic_json(&self.root, &relative, snapshot).await
    }

    fn snapshot_path(&self, id: &ProviderId) -> PathBuf {
        self.root.join("snapshots").join(format!("{id}.json"))
    }
}

fn provider_verification(
    status: SignatureStatus,
    revision: Option<u64>,
    content_sha256: String,
    document: &[u8],
    envelope: Option<SignatureEnvelope>,
) -> ProviderVerification {
    ProviderVerification {
        signature_status: status,
        algorithm: envelope
            .as_ref()
            .map(|_| crate::trust::SignatureAlgorithm::Ed25519),
        key_id: envelope.as_ref().map(|value| value.key_id.clone()),
        signature: envelope.as_ref().map(|value| value.signature.clone()),
        content_sha256,
        verified_unix_seconds: (status == SignatureStatus::Verified).then(unix_seconds),
        revision,
        document_base64: BASE64.encode(document),
        envelope,
    }
}

fn legacy_provider_verification() -> ProviderVerification {
    ProviderVerification {
        signature_status: SignatureStatus::Unsigned,
        algorithm: None,
        key_id: None,
        signature: None,
        content_sha256: String::new(),
        verified_unix_seconds: None,
        revision: None,
        document_base64: String::new(),
        envelope: None,
    }
}

fn detached_signature_source(source: &ProviderSource) -> Result<ProviderSource> {
    match source {
        ProviderSource::Local(path) => {
            let mut value = path.as_os_str().to_os_string();
            value.push(".sig");
            Ok(ProviderSource::Local(PathBuf::from(value)))
        }
        ProviderSource::Remote(url) => {
            let mut signature = url.clone();
            signature.set_path(&format!("{}.sig", url.path()));
            Ok(ProviderSource::Remote(signature))
        }
    }
}

fn signature_not_found(error: &Error) -> bool {
    match error {
        Error::Io(error) => error.kind() == std::io::ErrorKind::NotFound,
        Error::Download(crate::download::DownloadError::HttpStatus { status, .. }) => {
            status.as_u16() == 404
        }
        _ => false,
    }
}

fn trust_error_kind(error: &Error) -> &'static str {
    match error {
        Error::Trust(TrustError::SignatureMissing) => "signature_missing",
        Error::Trust(TrustError::SignatureInvalid) => "signature_invalid",
        Error::Trust(TrustError::UnsupportedSignatureAlgorithm(_)) => {
            "unsupported_signature_algorithm"
        }
        Error::Trust(TrustError::UntrustedSigningKey(_)) => "untrusted_signing_key",
        Error::Trust(TrustError::SigningKeyMismatch { .. }) => "signing_key_mismatch",
        Error::Trust(TrustError::ManifestRollbackDetected { .. }) => "manifest_rollback_detected",
        Error::Trust(TrustError::InvalidKeyTransition(_)) => "invalid_key_transition",
        Error::Trust(TrustError::TrustStoreError(_)) => "trust_store_error",
        Error::Trust(_) => "trust_error",
        _ => "manifest_verification_failed",
    }
}

const fn rollback_format_version() -> u32 {
    1
}

trait ResourceBase {
    fn resolve(&self, reference: &str, manager: &ProviderManager) -> Result<ProviderResource>;
}

impl ResourceBase for ProviderSource {
    fn resolve(&self, reference: &str, manager: &ProviderManager) -> Result<ProviderResource> {
        match self {
            ProviderSource::Local(path) => {
                let root = path.parent().ok_or_else(|| {
                    ProviderError::InvalidManifest(
                        "local provider document has no parent directory".into(),
                    )
                })?;
                resolve_local(path, root, reference)
            }
            ProviderSource::Remote(url) => resolve_remote(url, reference, manager),
        }
    }
}

impl ResourceBase for ProviderResource {
    fn resolve(&self, reference: &str, manager: &ProviderManager) -> Result<ProviderResource> {
        match self {
            ProviderResource::Local { path, root } => resolve_local(path, root, reference),
            ProviderResource::Remote(url) => resolve_remote(url, reference, manager),
        }
    }
}

fn resolve_local(base_document: &Path, root: &Path, reference: &str) -> Result<ProviderResource> {
    if let Ok(url) = Url::parse(reference) {
        if matches!(url.scheme(), "http" | "https") {
            return Ok(ProviderResource::Remote(url));
        }
        return Err(ProviderError::UrlPolicy {
            url: url.to_string(),
            reason: "local manifests may only reference local paths or HTTP(S) URLs".into(),
        }
        .into());
    }
    if reference.starts_with('/')
        || reference.starts_with('\\')
        || reference.contains('\\')
        || reference.contains('\0')
    {
        return Err(ProviderError::InvalidManifest(
            "local resource references must use forward slashes".into(),
        )
        .into());
    }
    let parent = base_document.parent().ok_or_else(|| {
        ProviderError::InvalidManifest("local provider document has no parent directory".into())
    })?;
    let base_relative = parent
        .strip_prefix(root)
        .map_err(|_| ProviderError::LocalPathEscape(base_document.to_path_buf()))?;
    let mut components = base_relative
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect::<Vec<_>>();
    for component in reference.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(ProviderError::LocalPathEscape(PathBuf::from(reference)).into());
                }
            }
            value => {
                SafeRelativePath::new(value)?;
                components.push(value.into());
            }
        }
    }
    if components.is_empty() {
        return Err(ProviderError::LocalPathEscape(PathBuf::from(reference)).into());
    }
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
    }
    Ok(ProviderResource::Local {
        path,
        root: root.to_path_buf(),
    })
}

fn resolve_remote(
    base: &Url,
    reference: &str,
    manager: &ProviderManager,
) -> Result<ProviderResource> {
    let resolved = base
        .join(reference)
        .map_err(|error| ProviderError::UrlPolicy {
            url: reference.to_owned(),
            reason: error.to_string(),
        })?;
    manager.validate_remote_url_syntax(&resolved)?;
    Ok(ProviderResource::Remote(resolved))
}

fn source_remote_url(source: &ProviderResource) -> Option<&Url> {
    match source {
        ProviderResource::Remote(url) => Some(url),
        ProviderResource::Local { .. } => None,
    }
}

fn source_display(source: &ProviderResource) -> String {
    match source {
        ProviderResource::Remote(url) => safe_url(url),
        ProviderResource::Local { path, .. } => path.display().to_string(),
    }
}

fn desired_provider_files<'a>(
    definition: &'a ProviderInstanceDefinition,
    resolved: &super::ResolvedComponentSet,
) -> Vec<(&'a ProviderFile, ManagedFileOrigin)> {
    let mut files = definition
        .files
        .iter()
        .map(|file| (file, ManagedFileOrigin::Provider))
        .collect::<Vec<_>>();
    for component in &definition.components {
        if resolved.is_enabled(&component.id) {
            files.extend(component.files.iter().map(|file| {
                (
                    file,
                    ManagedFileOrigin::Component {
                        id: component.id.to_string(),
                    },
                )
            }));
        }
    }
    files
}

fn installed_revision(instance: &Instance) -> u64 {
    instance
        .spec()
        .metadata()
        .get("centralcore.provider_revision")
        .and_then(|revision| revision.parse().ok())
        .unwrap_or_default()
}

fn component_origin_id(origin: &ManagedFileOrigin) -> Option<String> {
    match origin {
        ManagedFileOrigin::Component { id } => Some(id.clone()),
        _ => None,
    }
}

fn managed_provider_file_id(file: &ProviderFile, origin: &ManagedFileOrigin) -> String {
    match origin {
        ManagedFileOrigin::Component { id } => format!("component:{id}:{}", file.id),
        _ => file.id.clone(),
    }
}

fn update_action(desired: &DesiredProviderFile, path: &str) -> UpdateFileAction {
    UpdateFileAction {
        id: desired.file.id.clone(),
        path: path.to_owned(),
        component_id: desired.component_id.clone(),
        size: desired.file.size,
        sha256: desired.file.sha256.clone(),
    }
}

fn provider_transaction_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

async fn cleanup_real_directory(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            tokio::fs::remove_dir_all(path).await?;
        }
        Ok(_) => {
            return Err(Error::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                reason: "update staging must be a real directory",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn copy_real_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(source).await?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::UnsafeFilesystemEntry {
            path: source.to_path_buf(),
            reason: "transaction metadata source must be a real file",
        });
    }
    tokio::fs::copy(source, destination).await?;
    Ok(())
}

async fn move_to_backup(instance: &Instance, backup_root: &Path, path: &str) -> Result<()> {
    let relative = SafeRelativePath::new(path.to_owned())?;
    let source = relative.join_under(instance.path());
    match tokio::fs::symlink_metadata(&source).await {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(Error::UnsafeFilesystemEntry {
                path: source,
                reason: "managed update target must be a real file",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    ensure_real_parents(backup_root, &relative).await?;
    tokio::fs::rename(source, relative.join_under(backup_root)).await?;
    Ok(())
}

async fn move_staged_into_instance(
    instance: &Instance,
    staged_root: &Path,
    path: &str,
) -> Result<()> {
    let relative = SafeRelativePath::new(path.to_owned())?;
    let source = relative.join_under(staged_root);
    let source_metadata = tokio::fs::symlink_metadata(&source).await?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(Error::UnsafeFilesystemEntry {
            path: source,
            reason: "staged update file must be a real file",
        });
    }
    ensure_real_parents(instance.path(), &relative).await?;
    let destination = relative.join_under(instance.path());
    if tokio::fs::try_exists(&destination).await? {
        return Err(ProviderError::ManagedPathConflict {
            path: path.to_owned(),
            existing: "unmanaged local file".into(),
            incoming: "update".into(),
        }
        .into());
    }
    tokio::fs::rename(source, destination).await?;
    Ok(())
}

async fn rollback_update_files(
    instance: &Instance,
    backup_root: &Path,
    applied_paths: &[String],
    backup_paths: &BTreeSet<String>,
) -> Result<()> {
    for path in applied_paths.iter().rev() {
        let relative = SafeRelativePath::new(path.clone())?;
        let destination = relative.join_under(instance.path());
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(destination).await?;
            }
            Ok(_) => {
                return Err(Error::UnsafeFilesystemEntry {
                    path: destination,
                    reason: "update rollback target must be a real file",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    for path in backup_paths {
        let relative = SafeRelativePath::new(path.clone())?;
        let backup = relative.join_under(backup_root);
        if !tokio::fs::try_exists(&backup).await? {
            continue;
        }
        ensure_real_parents(instance.path(), &relative).await?;
        tokio::fs::rename(backup, relative.join_under(instance.path())).await?;
    }
    Ok(())
}

fn is_provider_owned(file: &ManagedFile, key: &ProviderInstanceId) -> bool {
    matches!(
        file.origin,
        ManagedFileOrigin::Provider | ManagedFileOrigin::Component { .. }
    ) && file
        .id
        .contains(&format!(":{}:{}:", key.provider_id, key.instance_id))
}

fn safe_url(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or("<missing-host>"),
        url.path()
    )
}

fn local_instance_id(key: &ProviderInstanceId) -> Result<InstanceId> {
    let digest = Sha256::digest(key.to_string().as_bytes());
    let encoded = format!("{digest:x}");
    InstanceId::new(format!("provider-{}", &encoded[..24]))
}

fn provider_cache_path(hash: &crate::files::FileHash) -> Result<SafeRelativePath> {
    SafeRelativePath::new(format!(
        "provider/objects/sha256/{}/{}",
        &hash.value()[..2],
        hash.value()
    ))
}

fn reject_managed_conflict(
    files: &[ManagedFile],
    path: &SafeRelativePath,
    key: &ProviderInstanceId,
) -> Result<()> {
    if let Some(existing) = files
        .iter()
        .find(|file| file.location == ManagedFileLocation::Instance && file.path == *path)
    {
        let expected_prefix = format!("provider-file:{}:{}:", key.provider_id, key.instance_id);
        if !existing.id.starts_with(&expected_prefix) {
            return Err(ProviderError::ManagedPathConflict {
                path: path.to_string(),
                existing: existing.id.clone(),
                incoming: key.to_string(),
            }
            .into());
        }
    }
    Ok(())
}

async fn read_bounded_real_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            reason: "provider document must be a real file",
        });
    }
    if metadata.len() > limit {
        return Err(ProviderError::DocumentTooLarge { limit }.into());
    }
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(ProviderError::DocumentTooLarge { limit }.into());
    }
    Ok(bytes)
}

async fn validate_local_resource(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ProviderError::LocalPathEscape(path.to_path_buf()))?;
    let root_metadata = tokio::fs::symlink_metadata(root).await?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(Error::UnsafeFilesystemEntry {
            path: root.to_path_buf(),
            reason: "local provider root must be a real directory",
        });
    }
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = tokio::fs::symlink_metadata(&current).await?;
        let is_last = index + 1 == components.len();
        if metadata.file_type().is_symlink()
            || (is_last && !metadata.is_file())
            || (!is_last && !metadata.is_dir())
        {
            return Err(Error::UnsafeFilesystemEntry {
                path: current,
                reason: "local provider resources cannot traverse symbolic links",
            });
        }
    }
    Ok(())
}

async fn copy_absolute_verified(
    source: &Path,
    destination_root: &Path,
    destination: &SafeRelativePath,
    size: u64,
    hash: &crate::files::FileHash,
) -> Result<()> {
    let source_metadata = tokio::fs::symlink_metadata(source).await?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(Error::UnsafeFilesystemEntry {
            path: source.to_path_buf(),
            reason: "provider source must be a real file",
        });
    }
    verify_file(source, Some(size), Some(hash)).await?;
    ensure_real_parents(destination_root, destination).await?;
    let final_path = destination.join_under(destination_root);
    let temporary = final_path.with_extension("centralcore.tmp");
    reject_non_file_or_symlink(&temporary).await?;
    let mut input = tokio::fs::File::open(source).await?;
    let mut output = tokio::fs::File::create(&temporary).await?;
    tokio::io::copy(&mut input, &mut output).await?;
    output.flush().await?;
    verify_file(&temporary, Some(size), Some(hash)).await?;
    replace_file(&temporary, &final_path).await
}

async fn copy_verified(
    source_root: &Path,
    source: &SafeRelativePath,
    destination_root: &Path,
    destination: &SafeRelativePath,
    size: u64,
    hash: &crate::files::FileHash,
) -> Result<()> {
    let source_path = source.join_under(source_root);
    copy_absolute_verified(&source_path, destination_root, destination, size, hash).await
}

async fn ensure_real_parents(root: &Path, relative: &SafeRelativePath) -> Result<()> {
    tokio::fs::create_dir_all(root).await?;
    let metadata = tokio::fs::symlink_metadata(root).await?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::UnsafeFilesystemEntry {
            path: root.to_path_buf(),
            reason: "managed root must be a real directory",
        });
    }
    let parts = relative.as_str().split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current.push(part);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::UnsafeFilesystemEntry {
                    path: current,
                    reason: "managed parent must be a real directory",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir(&current).await?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn reject_non_file_or_symlink(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                reason: "managed destination must be a real file",
            })
        }
        Ok(_) => {
            tokio::fs::remove_file(path).await?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    reject_non_file_or_symlink(destination).await?;
    tokio::fs::rename(temporary, destination).await?;
    Ok(())
}

async fn atomic_json<T: Serialize>(root: &Path, relative: &Path, value: &T) -> Result<()> {
    tokio::fs::create_dir_all(root).await?;
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = destination.with_extension("json.tmp");
    let previous = destination.with_extension("json.previous");
    let bytes = serde_json::to_vec_pretty(value)?;
    tokio::fs::write(&temporary, bytes).await?;
    if tokio::fs::try_exists(&destination).await? {
        let metadata = tokio::fs::symlink_metadata(&destination).await?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: destination,
                reason: "provider metadata destination must be a real file",
            });
        }
        reject_non_file_or_symlink(&previous).await?;
        tokio::fs::rename(&destination, &previous).await?;
    }
    if let Err(error) = tokio::fs::rename(&temporary, &destination).await {
        if tokio::fs::try_exists(&previous).await.unwrap_or(false) {
            let _ = tokio::fs::rename(&previous, &destination).await;
        }
        return Err(error.into());
    }
    if tokio::fs::try_exists(&previous).await? {
        tokio::fs::remove_file(previous).await?;
    }
    Ok(())
}

async fn read_with_previous(path: &Path) -> std::io::Result<Vec<u8>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::read(path.with_extension("json.previous")).await
        }
        Err(error) => Err(error),
    }
}

fn changed_instances(
    previous: Option<&ProviderSnapshot>,
    current: &ProviderSnapshot,
) -> Vec<InstanceId> {
    current
        .instances
        .iter()
        .filter_map(|(id, definition)| {
            let changed = previous
                .and_then(|snapshot| snapshot.instances.get(id))
                .is_none_or(|old| old != definition);
            changed.then(|| id.clone())
        })
        .collect()
}

fn map_instance_status(status: InstanceStatus) -> ProviderInstanceState {
    match status {
        InstanceStatus::Installed | InstanceStatus::Running => ProviderInstanceState::Installed,
        InstanceStatus::Installing | InstanceStatus::Recoverable => {
            ProviderInstanceState::Installing
        }
        InstanceStatus::Updating => ProviderInstanceState::Updating,
        InstanceStatus::Broken => ProviderInstanceState::Broken,
        #[allow(deprecated)]
        InstanceStatus::Available | InstanceStatus::NotFound | InstanceStatus::NotInstalled => {
            ProviderInstanceState::NotInstalled
        }
    }
}

fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_private_v4(address),
        IpAddr::V6(address) => is_private_v6(address),
    }
}

fn is_private_v4(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.octets()[0] == 0
        || address.octets()[0] >= 224
}

fn is_private_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::{write_managed_index, ManagedFileIndex},
        minecraft::{RepairOptions, VerifyOptions},
        providers::InstanceProvider,
        CentralCore,
    };

    #[test]
    fn content_addressed_path_uses_sha256() {
        let hash =
            crate::files::FileHash::new(crate::files::HashAlgorithm::Sha256, "ab".repeat(32))
                .expect("hash");
        assert_eq!(
            provider_cache_path(&hash).expect("path").as_str(),
            format!("provider/objects/sha256/ab/{}", "ab".repeat(32))
        );
    }

    #[test]
    fn private_network_detection_is_conservative() {
        assert!(is_private_address("127.0.0.1".parse().expect("IP")));
        assert!(is_private_address("169.254.169.254".parse().expect("IP")));
        assert!(is_private_address("10.0.0.1".parse().expect("IP")));
        assert!(is_private_address("::1".parse().expect("IP")));
        assert!(!is_private_address("1.1.1.1".parse().expect("IP")));
    }

    async fn write_provider_fixture(root: &Path, revision: u64, format_version: u32) {
        write_provider_fixture_payload(root, revision, format_version, b"provider-payload").await;
    }

    async fn write_provider_fixture_payload(
        root: &Path,
        revision: u64,
        format_version: u32,
        payload: &[u8],
    ) {
        let instances = root.join("instances");
        let files = root.join("files");
        tokio::fs::create_dir_all(&instances)
            .await
            .expect("instances directory");
        tokio::fs::create_dir_all(&files)
            .await
            .expect("files directory");
        tokio::fs::write(files.join("example.json"), payload)
            .await
            .expect("payload");
        let sha256 = format!("{:x}", Sha256::digest(payload));
        let provider = serde_json::json!({
            "format_version": 1,
            "provider": {"id":"fixture", "name":"Fixture Provider"},
            "instances": [{"id":"survival", "manifest":"instances/survival.json"}]
        });
        let instance = serde_json::json!({
            "format_version": format_version,
            "id":"survival",
            "name":"Survival",
            "revision":revision,
            "minecraft":{"version":"1.20.4", "loader":{"type":"vanilla"}},
            "files":[{
                "id":"fixture-config",
                "path":"config/example.json",
                "url":"../files/example.json",
                "size":payload.len(),
                "sha256":sha256
            }]
        });
        tokio::fs::write(
            root.join("provider.json"),
            serde_json::to_vec_pretty(&provider).expect("provider JSON"),
        )
        .await
        .expect("provider index");
        tokio::fs::write(
            instances.join("survival.json"),
            serde_json::to_vec_pretty(&instance).expect("instance JSON"),
        )
        .await
        .expect("instance manifest");
    }

    async fn write_component_fixture(
        root: &Path,
        revision: u64,
        payload: &[u8],
        default_enabled: bool,
    ) {
        let instances = root.join("instances");
        let files = root.join("files");
        tokio::fs::create_dir_all(&instances)
            .await
            .expect("instances");
        tokio::fs::create_dir_all(&files).await.expect("files");
        tokio::fs::write(files.join("sodium.jar"), payload)
            .await
            .expect("component payload");
        let provider = serde_json::json!({
            "format_version":1,
            "provider":{"id":"fixture", "name":"Fixture Provider"},
            "instances":[{"id":"survival", "manifest":"instances/survival.json"}]
        });
        let instance = serde_json::json!({
            "format_version":1,
            "id":"survival",
            "name":"Survival",
            "revision":revision,
            "minecraft":{"version":"1.20.4", "loader":{"type":"vanilla"}},
            "components":[{
                "id":"sodium",
                "name":"Sodium",
                "default_enabled":default_enabled,
                "files":[{
                    "id":"sodium-jar",
                    "path":"mods/sodium.jar",
                    "url":"../files/sodium.jar",
                    "size":payload.len(),
                    "sha256":format!("{:x}", Sha256::digest(payload))
                }]
            }]
        });
        tokio::fs::write(
            root.join("provider.json"),
            serde_json::to_vec_pretty(&provider).expect("provider json"),
        )
        .await
        .expect("provider index");
        tokio::fs::write(
            instances.join("survival.json"),
            serde_json::to_vec_pretty(&instance).expect("instance json"),
        )
        .await
        .expect("instance manifest");
    }

    async fn write_large_update_fixture(root: &Path, revision: u64, changed: bool) {
        let instances = root.join("instances");
        tokio::fs::create_dir_all(&instances)
            .await
            .expect("instances");
        let files = (0..4_000)
            .map(|index| {
                let digest_byte = if changed && index % 2 == 0 {
                    "cd"
                } else {
                    "ab"
                };
                serde_json::json!({
                    "id": format!("file-{index}"),
                    "path": format!("mods/file-{index}.jar"),
                    "url": format!("../files/file-{index}.jar"),
                    "size": 1,
                    "sha256": digest_byte.repeat(32)
                })
            })
            .collect::<Vec<_>>();
        let provider = serde_json::json!({
            "format_version": 1,
            "provider": {"id": "fixture", "name": "Fixture Provider"},
            "instances": [{"id": "survival", "manifest": "instances/survival.json"}]
        });
        let instance = serde_json::json!({
            "format_version": 1,
            "id": "survival",
            "name": "Survival",
            "revision": revision,
            "minecraft": {"version": "1.20.4", "loader": {"type": "vanilla"}},
            "files": files
        });
        tokio::fs::write(
            root.join("provider.json"),
            serde_json::to_vec(&provider).expect("provider JSON"),
        )
        .await
        .expect("provider index");
        tokio::fs::write(
            instances.join("survival.json"),
            serde_json::to_vec(&instance).expect("instance JSON"),
        )
        .await
        .expect("instance manifest");
    }

    #[tokio::test]
    async fn update_plan_applies_minimal_provider_diff_and_preserves_user_files() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture_payload(&source, 1, 1, b"revision-one").await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id.clone(),
            InstanceId::new("survival").expect("instance id"),
        );
        let instance = core
            .providers()
            .materialize(&key)
            .await
            .expect("materialize");
        write_managed_index(
            &instance,
            &ManagedFileIndex::new(instance.id().to_string(), "1.20.4".into(), Vec::new()),
        )
        .await
        .expect("empty index");
        let definition = core.providers().definition(&key).await.expect("definition");
        core.providers()
            .install_provider_files(
                &instance,
                &key,
                &definition,
                &CancellationToken::default(),
                false,
            )
            .await
            .expect("provider install");
        core.instances()
            .mark_installed(&instance)
            .await
            .expect("installed");
        let user_file = instance.path().join(".minecraft/saves/world/test.dat");
        tokio::fs::create_dir_all(user_file.parent().expect("parent"))
            .await
            .expect("save directory");
        tokio::fs::write(&user_file, b"user-world")
            .await
            .expect("user file");

        write_provider_fixture_payload(&source, 2, 1, b"revision-two").await;
        core.providers().sync(&provider_id).await.expect("sync v2");
        let plan = core.providers().plan_update(&key).await.expect("plan");
        assert_eq!(plan.from_revision, 1);
        assert_eq!(plan.to_revision, 2);
        assert_eq!(plan.replacements.len(), 1);
        assert!(plan.downloads.is_empty());
        let serialized = serde_json::to_value(&plan).expect("serializable plan");
        assert_eq!(serialized["from_revision"], 1);
        assert_eq!(serialized["to_revision"], 2);
        let report = core
            .providers()
            .apply_update(plan, &CancellationToken::default(), false)
            .await
            .expect("update");
        assert_eq!(report.files_replaced, 1);
        assert_eq!(
            tokio::fs::read(&user_file).await.expect("save"),
            b"user-world"
        );
        assert_eq!(
            tokio::fs::read(instance.path().join(".minecraft/config/example.json"))
                .await
                .expect("provider file"),
            b"revision-two"
        );
        let updated = core
            .providers()
            .resolve_local_instance("demo:survival")
            .await
            .expect("updated instance");
        assert_eq!(installed_revision(&updated), 2);
    }

    #[tokio::test]
    #[ignore = "advisory large UpdatePlan performance measurement"]
    async fn benchmark_update_plan_diff_four_thousand_files() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_large_update_fixture(&source, 1, false).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id,
            InstanceId::new("survival").expect("instance id"),
        );
        let instance = core
            .providers()
            .materialize(&key)
            .await
            .expect("materialize");
        let current_hash =
            crate::files::FileHash::new(crate::files::HashAlgorithm::Sha256, "ab".repeat(32))
                .expect("hash");
        let current = (0..4_000)
            .map(|index| ManagedFile {
                id: format!("provider-file:demo:survival:file-{index}"),
                location: ManagedFileLocation::Instance,
                path: SafeRelativePath::new(format!(".minecraft/mods/file-{index}.jar"))
                    .expect("path"),
                kind: ManagedFileKind::Other,
                origin: ManagedFileOrigin::Provider,
                expected_size: Some(1),
                expected_hash: Some(current_hash.clone()),
                source: None,
                source_path: None,
                repair_from: None,
                verified_size: 1,
                verified_modified_unix_nanos: None,
            })
            .collect();
        write_managed_index(
            &instance,
            &ManagedFileIndex::new(instance.id().to_string(), "1.20.4".into(), current),
        )
        .await
        .expect("managed index");

        write_large_update_fixture(&source, 2, true).await;
        core.providers()
            .sync(&key.provider_id)
            .await
            .expect("sync v2");
        let started = std::time::Instant::now();
        let plan = core.providers().plan_update(&key).await.expect("plan");
        let elapsed = started.elapsed();
        eprintln!("update-plan-4000 elapsed={elapsed:?}");
        assert_eq!(plan.kept_files().len(), 2_000);
        assert_eq!(plan.replacements().len(), 2_000);
    }

    #[tokio::test]
    async fn component_enable_disable_and_disabled_update_respect_selection() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_component_fixture(&source, 1, b"sodium-one", false).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id.clone(),
            InstanceId::new("survival").expect("instance id"),
        );
        let instance = core
            .providers()
            .materialize(&key)
            .await
            .expect("materialize");
        write_managed_index(
            &instance,
            &ManagedFileIndex::new(instance.id().to_string(), "1.20.4".into(), Vec::new()),
        )
        .await
        .expect("empty index");
        let definition = core.providers().definition(&key).await.expect("definition");
        core.providers()
            .install_provider_files(
                &instance,
                &key,
                &definition,
                &CancellationToken::default(),
                false,
            )
            .await
            .expect("initial provider files");
        core.instances()
            .mark_installed(&instance)
            .await
            .expect("installed");
        let mod_path = instance.path().join(".minecraft/mods/sodium.jar");
        assert!(!mod_path.exists());

        let component = ComponentId::new("sodium").expect("component");
        core.providers()
            .set_component_enabled(&key, &component, true, &CancellationToken::default(), false)
            .await
            .expect("enable");
        assert_eq!(
            tokio::fs::read(&mod_path).await.expect("mod"),
            b"sodium-one"
        );
        core.providers()
            .set_component_enabled(&key, &component, false, &CancellationToken::default(), true)
            .await
            .expect("disable");
        assert!(!mod_path.exists());
        core.providers()
            .set_component_enabled(&key, &component, true, &CancellationToken::default(), true)
            .await
            .expect("offline enable from cache");
        assert_eq!(
            tokio::fs::read(&mod_path).await.expect("cached mod"),
            b"sodium-one"
        );
        core.providers()
            .set_component_enabled(&key, &component, false, &CancellationToken::default(), true)
            .await
            .expect("disable again");

        write_component_fixture(&source, 2, b"sodium-two", true).await;
        core.providers().sync(&provider_id).await.expect("sync v2");
        let plan = core.providers().plan_update(&key).await.expect("plan v2");
        assert!(plan.downloads.is_empty());
        assert!(plan.replacements.is_empty());
        core.providers()
            .apply_update(plan, &CancellationToken::default(), true)
            .await
            .expect("offline update while disabled");
        assert!(!mod_path.exists());
        let status = core.providers().components(&key).await.expect("components");
        assert!(!status[0].enabled);
    }

    #[tokio::test]
    async fn local_provider_syncs_and_implements_generic_contract() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 1, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        let report = core.providers().sync(&id).await.expect("sync");
        assert_eq!(report.instances, 1);
        let provider = core
            .providers()
            .static_provider(&id)
            .await
            .expect("static provider");
        assert_eq!(provider.list_instances().await.expect("list").len(), 1);
        let manifest = provider
            .get_manifest(&InstanceId::new("survival").expect("id"))
            .await
            .expect("manifest");
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(
            core.providers()
                .instances(Some(&id))
                .await
                .expect("catalog")[0]
                .state,
            ProviderInstanceState::NotInstalled
        );
    }

    #[tokio::test]
    async fn remote_provider_requires_an_explicit_signature_policy() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let error = core
            .providers()
            .add(
                ProviderId::new("remote").expect("provider id"),
                ProviderSource::parse("https://cdn.example.test/provider.json")
                    .expect("remote source"),
            )
            .await
            .expect_err("implicit remote policy must fail");
        assert!(matches!(
            error,
            Error::Trust(TrustError::TrustStoreError(_))
        ));
    }

    #[tokio::test]
    async fn invalid_sync_preserves_previous_snapshot() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 3, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&id).await.expect("first sync");
        write_provider_fixture(&source, 4, 42).await;
        assert!(core.providers().sync(&id).await.is_err());
        let retained = core.providers().snapshot(&id).await.expect("retained");
        assert_eq!(
            retained
                .instances
                .values()
                .next()
                .expect("instance")
                .revision,
            3
        );
    }

    #[tokio::test]
    async fn removed_provider_retains_materialized_instance_as_orphan() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 1, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id.clone(),
            InstanceId::new("survival").expect("instance id"),
        );
        let materialized = core
            .providers()
            .materialize(&key)
            .await
            .expect("materialize");
        core.providers().remove(&provider_id).await.expect("remove");
        assert!(tokio::fs::try_exists(materialized.path())
            .await
            .expect("exists"));
        let entries = core.providers().instances(None).await.expect("catalog");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].state, ProviderInstanceState::ProviderRemoved);
    }

    #[tokio::test]
    async fn short_instance_reference_rejects_provider_collision() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 1, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        for name in ["first", "second"] {
            let id = ProviderId::new(name).expect("provider id");
            core.providers()
                .add(
                    id.clone(),
                    ProviderSource::Local(source.join("provider.json")),
                )
                .await
                .expect("add");
            core.providers().sync(&id).await.expect("sync");
        }
        assert!(matches!(
            core.providers()
                .resolve_provider_reference("survival")
                .await,
            Err(Error::StaticProvider(ProviderError::AmbiguousInstance(_)))
        ));
    }

    #[tokio::test]
    async fn newer_revision_is_reported_without_overwriting_local_spec() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 1, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id.clone(),
            InstanceId::new("survival").expect("instance id"),
        );
        core.providers()
            .materialize(&key)
            .await
            .expect("materialize");
        write_provider_fixture(&source, 2, 1).await;
        core.providers()
            .sync(&provider_id)
            .await
            .expect("update sync");
        let entries = core
            .providers()
            .instances(Some(&provider_id))
            .await
            .expect("catalog");
        assert_eq!(entries[0].state, ProviderInstanceState::UpdateAvailable);
        let local = core
            .providers()
            .resolve_local_instance("demo:survival")
            .await
            .expect("local");
        assert_eq!(
            local
                .spec()
                .metadata()
                .get("centralcore.provider_revision")
                .map(String::as_str),
            Some("1")
        );
    }

    #[tokio::test]
    async fn provider_file_verify_and_offline_repair_reuse_cache() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let source = temporary.path().join("source");
        write_provider_fixture(&source, 1, 1).await;
        let core = CentralCore::builder()
            .data_dir(temporary.path().join("data"))
            .build()
            .await
            .expect("core");
        let provider_id = ProviderId::new("demo").expect("provider id");
        core.providers()
            .add(
                provider_id.clone(),
                ProviderSource::Local(source.join("provider.json")),
            )
            .await
            .expect("add");
        core.providers().sync(&provider_id).await.expect("sync");
        let key = ProviderInstanceId::new(
            provider_id,
            InstanceId::new("survival").expect("instance id"),
        );
        let definition = core.providers().definition(&key).await.expect("definition");
        let instance = core
            .providers()
            .materialize(&key)
            .await
            .expect("materialize");
        write_managed_index(
            &instance,
            &ManagedFileIndex::new(instance.id().to_string(), "1.20.4".into(), Vec::new()),
        )
        .await
        .expect("base index");
        core.providers()
            .install_provider_files(
                &instance,
                &key,
                &definition,
                &core.downloads().cancellation_token(),
                false,
            )
            .await
            .expect("provider files");
        let healthy = core
            .minecraft()
            .verify(&instance, VerifyOptions { full: true })
            .await
            .expect("verify");
        assert!(healthy.is_healthy());
        assert_eq!(healthy.valid, 2);

        let installed = instance.minecraft_dir().join("config/example.json");
        tokio::fs::write(&installed, b"corrupted")
            .await
            .expect("corrupt");
        let damaged = core
            .minecraft()
            .verify(&instance, VerifyOptions { full: true })
            .await
            .expect("damaged verify");
        assert_eq!(damaged.corrupted, 1);
        let plan = core
            .minecraft()
            .resolve_repair_plan(
                &instance,
                RepairOptions {
                    full_verification: true,
                    offline: true,
                },
            )
            .await
            .expect("repair plan");
        assert_eq!(plan.downloads.len(), 0);
        assert_eq!(plan.copies.len(), 1);
        let repaired = core
            .minecraft()
            .repair(
                &instance,
                RepairOptions {
                    full_verification: true,
                    offline: true,
                },
                &core.downloads().cancellation_token(),
            )
            .await
            .expect("repair");
        assert!(repaired.verification.is_healthy());
        assert_eq!(
            tokio::fs::read(installed).await.expect("read"),
            b"provider-payload"
        );
    }
}
