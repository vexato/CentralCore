//! Vanilla install-plan resolution and transactional execution.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    auth::MinecraftIdentity,
    cache::{
        snapshot_managed_file, write_managed_index, CacheManager, ManagedExtraction, ManagedFile,
        ManagedFileIndex, ManagedFileKind, ManagedFileLocation, ManagedFileOrigin,
    },
    config::MinecraftSettings,
    download::{compute_hash, CancellationToken, DownloadError, DownloadManager, DownloadRequest},
    events::{CoreEvent, EventBus},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    instance::{Instance, InstanceId, InstanceService, InstanceStatus},
    java::{JavaManager, JavaRequirement},
    loaders::{
        execute_loader_plan, load_loader_plan, write_loader_plan, LoaderFileKind, LoaderManager,
        LoaderPlan,
    },
    lock::LockManager,
    process::{DetachedInstance, ProcessManager, RunningInstance},
    Error, Result,
};

use super::{
    assets::{resolve_assets, AssetIndex, ResolvedAsset},
    launch::{build_launch_plan, LaunchPlan},
    libraries::{resolve_libraries, ResolvedArtifact},
    natives::{extract_natives, NativeArchive},
    required_java_major, LaunchOptions, MinecraftError, RuleContext, VersionManifest,
    VersionMetadata,
};

/// Coarse installation stage suitable for UI-independent progress display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    Metadata,
    Client,
    Libraries,
    Assets,
    Natives,
    Logging,
    Loader,
    Finalizing,
}

/// Aggregate installation progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallProgress {
    pub phase: InstallPhase,
    pub completed_files: u64,
    pub total_files: u64,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub bytes_per_second: u64,
    pub current_file: Option<String>,
}

/// One file in an installation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallDownload {
    pub phase: InstallPhase,
    pub request: DownloadRequest,
}

/// Native archive committed after all file downloads validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlan {
    pub archive: SafeRelativePath,
    pub exclusions: Vec<String>,
}

/// Fully resolved, testable work required for one Vanilla version.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub(crate) version: VersionMetadata,
    pub(crate) downloads: Vec<InstallDownload>,
    pub(crate) native_archives: Vec<NativePlan>,
    pub(crate) total_bytes: Option<u64>,
    /// Optional loader overlay composed with the Vanilla plan.
    pub(crate) loader: Option<LoaderPlan>,
    metadata_files: Vec<InstallDownload>,
    assets: Vec<ResolvedAsset>,
    asset_index: AssetIndex,
}

impl InstallPlan {
    /// Resolved Mojang version metadata used by this plan.
    #[must_use]
    pub fn version(&self) -> &VersionMetadata {
        &self.version
    }

    /// Verified downloads grouped by installation phase.
    #[must_use]
    pub fn downloads(&self) -> &[InstallDownload] {
        &self.downloads
    }

    /// Native archives that will be extracted after download verification.
    #[must_use]
    pub fn native_archives(&self) -> &[NativePlan] {
        &self.native_archives
    }

    /// Total expected network bytes, when all upstream sizes are known.
    #[must_use]
    pub const fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    /// Optional loader overlay resolved by CentralCore.
    #[must_use]
    pub fn loader(&self) -> Option<&LoaderPlan> {
        self.loader.as_ref()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransactionState {
    Created,
    Preparing,
    Downloading,
    Applying,
    Validating,
    Finalizing,
    Committing,
    Committed,
    Cancelled,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionJournal {
    format_version: u32,
    transaction_id: String,
    operation: String,
    state: TransactionState,
    started_unix_seconds: u64,
}

/// Minecraft catalog, installer, launch-plan, and process facade.
#[derive(Debug, Clone)]
pub struct MinecraftManager {
    pub(super) cache_root: PathBuf,
    pub(super) settings: MinecraftSettings,
    pub(super) downloads: DownloadManager,
    pub(super) java: JavaManager,
    pub(super) instances: InstanceService,
    pub(super) processes: ProcessManager,
    pub(super) cache: CacheManager,
    pub(super) locks: LockManager,
    pub(super) events: EventBus,
    pub(super) loaders: LoaderManager,
}

pub(crate) struct MinecraftServices {
    pub downloads: DownloadManager,
    pub java: JavaManager,
    pub instances: InstanceService,
    pub processes: ProcessManager,
    pub cache: CacheManager,
    pub locks: LockManager,
    pub events: EventBus,
    pub loaders: LoaderManager,
}

impl MinecraftManager {
    pub(crate) fn new(
        data_directory: &Path,
        settings: MinecraftSettings,
        services: MinecraftServices,
    ) -> Self {
        Self {
            cache_root: data_directory.join("minecraft"),
            settings,
            downloads: services.downloads,
            java: services.java,
            instances: services.instances,
            processes: services.processes,
            cache: services.cache,
            locks: services.locks,
            events: services.events,
            loaders: services.loaders,
        }
    }

    #[must_use]
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// Fetches the official version catalog through the central HTTP client.
    pub async fn version_manifest(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<VersionManifest> {
        self.events.emit(CoreEvent::VersionManifestDownloadStarted);
        self.downloads
            .fetch_json(
                &self.settings.version_manifest_url,
                None,
                None,
                self.settings.max_metadata_size,
                cancellation,
            )
            .await
    }

    /// Convenience overload that creates a fresh cancellation handle.
    pub async fn versions(&self) -> Result<VersionManifest> {
        self.version_manifest(&self.downloads.cancellation_token())
            .await
    }

    /// Resolves and caches metadata without executing the bulk download plan.
    pub async fn resolve_install_plan(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
    ) -> Result<InstallPlan> {
        let manifest = self.version_manifest(cancellation).await?;
        let requested = instance.spec().minecraft().version();
        let reference = manifest
            .versions
            .iter()
            .find(|version| version.id == requested)
            .ok_or_else(|| MinecraftError::VersionNotFound(requested.to_owned()))?;
        let metadata_hash = reference
            .sha1
            .as_ref()
            .map(|hash| FileHash::new(HashAlgorithm::Sha1, hash.clone()))
            .transpose()?;
        let metadata_request = DownloadRequest {
            id: format!("metadata:{requested}"),
            source: reference.url.clone(),
            destination: SafeRelativePath::new(format!("versions/{requested}/{requested}.json"))?,
            expected_size: None,
            expected_hash: metadata_hash,
        };
        let metadata_outcome = self
            .downloads
            .download(&self.cache_root, &metadata_request, cancellation)
            .await?;
        if metadata_outcome.bytes > self.settings.max_metadata_size {
            return Err(DownloadError::SizeLimit {
                limit: self.settings.max_metadata_size,
            }
            .into());
        }
        let metadata_bytes = tokio::fs::read(&metadata_outcome.path).await?;
        let metadata: VersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| {
                MinecraftError::InvalidManifest {
                    context: "version metadata",
                    message: error.to_string(),
                }
            })?;
        if metadata.id != requested {
            return Err(MinecraftError::InvalidManifest {
                context: "version metadata",
                message: format!(
                    "requested `{requested}` but metadata identifies `{}`",
                    metadata.id
                ),
            }
            .into());
        }
        if let Some(parent) = &metadata.inherits_from {
            return Err(MinecraftError::UnsupportedInheritance {
                version: metadata.id.clone(),
                parent: parent.clone(),
            }
            .into());
        }
        let asset_hash = FileHash::new(HashAlgorithm::Sha1, metadata.asset_index.sha1.clone())?;
        let asset_index_request = DownloadRequest {
            id: format!("asset-index:{}", metadata.asset_index.id),
            source: metadata.asset_index.url.clone(),
            destination: SafeRelativePath::new(format!(
                "assets/indexes/{}.json",
                metadata.asset_index.id
            ))?,
            expected_size: Some(metadata.asset_index.size),
            expected_hash: Some(asset_hash),
        };
        let asset_index_outcome = self
            .downloads
            .download(&self.cache_root, &asset_index_request, cancellation)
            .await?;
        if asset_index_outcome.bytes > self.settings.max_metadata_size {
            return Err(DownloadError::SizeLimit {
                limit: self.settings.max_metadata_size,
            }
            .into());
        }
        let asset_index_bytes = tokio::fs::read(&asset_index_outcome.path).await?;
        let asset_index: AssetIndex =
            serde_json::from_slice(&asset_index_bytes).map_err(|error| {
                MinecraftError::AssetIndex {
                    index: metadata.asset_index.id.clone(),
                    reason: error.to_string(),
                }
            })?;
        let metadata_files = vec![
            InstallDownload {
                phase: InstallPhase::Metadata,
                request: DownloadRequest {
                    expected_size: Some(metadata_bytes.len() as u64),
                    ..metadata_request
                },
            },
            InstallDownload {
                phase: InstallPhase::Metadata,
                request: asset_index_request,
            },
        ];

        let mut plan =
            self.finish_install_plan(requested, metadata, metadata_files, asset_index)?;
        self.attach_loader(instance, &mut plan, cancellation, false)
            .await?;
        Ok(plan)
    }

    /// Resolves an install plan exclusively from already validated shared-cache objects.
    pub async fn resolve_cached_install_plan(&self, instance: &Instance) -> Result<InstallPlan> {
        let requested = instance.spec().minecraft().version();
        let metadata_path =
            SafeRelativePath::new(format!("versions/{requested}/{requested}.json"))?;
        let cached_metadata = self
            .cache
            .object(&metadata_path)
            .await?
            .ok_or(crate::minecraft::RepairError::OfflineObjectsUnavailable { count: 1 })?;
        let metadata_absolute = metadata_path.join_under(&self.cache_root);
        crate::download::verify_file(
            &metadata_absolute,
            cached_metadata.expected_size,
            cached_metadata.expected_hash.as_ref(),
        )
        .await
        .map_err(|_| crate::minecraft::RepairError::OfflineObjectsUnavailable { count: 1 })?;
        let metadata_bytes = tokio::fs::read(&metadata_absolute).await?;
        if metadata_bytes.len() as u64 > self.settings.max_metadata_size {
            return Err(DownloadError::SizeLimit {
                limit: self.settings.max_metadata_size,
            }
            .into());
        }
        let metadata: VersionMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|error| {
                MinecraftError::InvalidManifest {
                    context: "cached version metadata",
                    message: error.to_string(),
                }
            })?;
        validate_cached_version(requested, &metadata)?;
        let metadata_source =
            cached_metadata
                .source
                .ok_or_else(|| crate::minecraft::RepairError::MissingSource {
                    path: metadata_path.to_string(),
                })?;
        let metadata_request = DownloadRequest {
            id: format!("metadata:{requested}"),
            source: metadata_source,
            destination: metadata_path,
            expected_size: Some(metadata_bytes.len() as u64),
            expected_hash: cached_metadata.expected_hash,
        };
        let asset_hash = FileHash::new(HashAlgorithm::Sha1, metadata.asset_index.sha1.clone())?;
        let asset_path =
            SafeRelativePath::new(format!("assets/indexes/{}.json", metadata.asset_index.id))?;
        let asset_index_request = DownloadRequest {
            id: format!("asset-index:{}", metadata.asset_index.id),
            source: metadata.asset_index.url.clone(),
            destination: asset_path.clone(),
            expected_size: Some(metadata.asset_index.size),
            expected_hash: Some(asset_hash),
        };
        let asset_absolute = asset_path.join_under(&self.cache_root);
        crate::download::verify_file(
            &asset_absolute,
            asset_index_request.expected_size,
            asset_index_request.expected_hash.as_ref(),
        )
        .await
        .map_err(|_| crate::minecraft::RepairError::OfflineObjectsUnavailable { count: 1 })?;
        let asset_bytes = tokio::fs::read(asset_absolute).await?;
        let asset_index: AssetIndex =
            serde_json::from_slice(&asset_bytes).map_err(|error| MinecraftError::AssetIndex {
                index: metadata.asset_index.id.clone(),
                reason: error.to_string(),
            })?;
        let metadata_files = vec![
            InstallDownload {
                phase: InstallPhase::Metadata,
                request: metadata_request,
            },
            InstallDownload {
                phase: InstallPhase::Metadata,
                request: asset_index_request,
            },
        ];
        let mut plan =
            self.finish_install_plan(requested, metadata, metadata_files, asset_index)?;
        self.attach_loader(
            instance,
            &mut plan,
            &self.downloads.cancellation_token(),
            true,
        )
        .await?;
        let mut unavailable = 0;
        for task in &plan.downloads {
            let path = task.request.destination.join_under(&self.cache_root);
            if crate::download::verify_file(
                &path,
                task.request.expected_size,
                task.request.expected_hash.as_ref(),
            )
            .await
            .is_err()
            {
                unavailable += 1;
            }
        }
        if unavailable > 0 {
            return Err(crate::minecraft::RepairError::OfflineObjectsUnavailable {
                count: unavailable,
            }
            .into());
        }
        Ok(plan)
    }

    async fn attach_loader(
        &self,
        instance: &Instance,
        plan: &mut InstallPlan,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<()> {
        let Some(config) = instance.spec().loader() else {
            return Ok(());
        };
        let loader = self
            .loaders
            .resolve(config, &plan.version, cancellation, offline)
            .await?;
        for download in &loader.downloads {
            if let Some(existing) = plan
                .downloads
                .iter()
                .find(|task| task.request.destination == download.request.destination)
            {
                if existing.request.source != download.request.source
                    || existing.request.expected_hash != download.request.expected_hash
                {
                    return Err(crate::loaders::LoaderError::DuplicatePath(
                        download.request.destination.to_string(),
                    )
                    .into());
                }
                continue;
            }
            plan.downloads.push(InstallDownload {
                phase: InstallPhase::Loader,
                request: download.request.clone(),
            });
        }
        plan.total_bytes = plan
            .downloads
            .iter()
            .map(|task| task.request.expected_size)
            .collect::<Option<Vec<_>>>()
            .map(|sizes| sizes.into_iter().sum());
        plan.loader = Some(loader);
        Ok(())
    }

    fn finish_install_plan(
        &self,
        requested: &str,
        metadata: VersionMetadata,
        metadata_files: Vec<InstallDownload>,
        asset_index: AssetIndex,
    ) -> Result<InstallPlan> {
        let rules = RuleContext::current(BTreeMap::new());
        let libraries = resolve_libraries(&metadata.libraries, &rules)?;
        let assets = resolve_assets(&asset_index, &self.settings.asset_base_url)?;
        let mut tasks = BTreeMap::<String, InstallDownload>::new();
        insert_task(
            &mut tasks,
            InstallPhase::Client,
            format!("client:{requested}"),
            SafeRelativePath::new(format!("versions/{requested}/{requested}.jar"))?,
            &metadata.downloads.client,
        )?;
        let mut native_archives = Vec::new();
        for library in &libraries {
            if let Some(artifact) = &library.artifact {
                insert_artifact(&mut tasks, InstallPhase::Libraries, &library.name, artifact)?;
            }
            if let Some(native) = &library.native {
                let destination = prefixed_path("libraries", &native.archive.path)?;
                insert_artifact(
                    &mut tasks,
                    InstallPhase::Natives,
                    &library.name,
                    &native.archive,
                )?;
                native_archives.push(NativePlan {
                    archive: destination,
                    exclusions: native.exclusions.clone(),
                });
            }
        }
        for asset in &assets {
            tasks
                .entry(asset.object_path.to_string())
                .or_insert_with(|| InstallDownload {
                    phase: InstallPhase::Assets,
                    request: DownloadRequest {
                        id: format!("asset:{}", asset.hash.value()),
                        source: asset.url.clone(),
                        destination: asset.object_path.clone(),
                        expected_size: Some(asset.size),
                        expected_hash: Some(asset.hash.clone()),
                    },
                });
        }
        if let Some(logging) = metadata
            .logging
            .as_ref()
            .and_then(|logging| logging.client.as_ref())
        {
            insert_task(
                &mut tasks,
                InstallPhase::Logging,
                format!("logging:{}", logging.file.id),
                SafeRelativePath::new(format!("log_configs/{}", logging.file.id))?,
                &super::manifest::DownloadInfo {
                    path: None,
                    sha1: Some(logging.file.sha1.clone()),
                    size: Some(logging.file.size),
                    url: logging.file.url.clone(),
                },
            )?;
        }
        let downloads = tasks.into_values().collect::<Vec<_>>();
        let total_bytes = downloads
            .iter()
            .map(|task| task.request.expected_size)
            .collect::<Option<Vec<_>>>()
            .map(|sizes| sizes.into_iter().sum());
        Ok(InstallPlan {
            version: metadata,
            downloads,
            native_archives,
            total_bytes,
            loader: None,
            metadata_files,
            assets,
            asset_index,
        })
    }

    /// Resolves and executes a Vanilla installation transaction.
    pub async fn install(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
    ) -> Result<InstallPlan> {
        self.install_mode(instance, cancellation, false).await
    }

    /// Installs exclusively from shared-cache objects and never accesses the network.
    pub async fn install_cached(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
    ) -> Result<InstallPlan> {
        self.install_mode(instance, cancellation, true).await
    }

    async fn install_mode(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<InstallPlan> {
        let _instance_lock = self
            .locks
            .try_acquire_exclusive(format!("instance:{}", instance.id()))
            .await?;
        self.install_mode_unlocked(instance, cancellation, offline)
            .await
    }

    pub(crate) async fn install_for_provider(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<InstallPlan> {
        self.install_mode_unlocked(instance, cancellation, offline)
            .await
    }

    async fn install_mode_unlocked(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
        offline: bool,
    ) -> Result<InstallPlan> {
        let transaction_id = transaction_id();
        self.write_transaction(
            instance,
            &transaction_id,
            "install",
            TransactionState::Created,
        )
        .await?;
        self.instances.mark_installing(instance).await?;
        self.events.emit(CoreEvent::MinecraftInstallStarted {
            instance_id: instance.id().to_string(),
            version_id: instance.spec().minecraft().version().to_owned(),
        });
        let result = self
            .install_inner(instance, cancellation, &transaction_id, offline)
            .await;
        match result {
            Ok(plan) => {
                self.persist_managed_index(instance, &plan).await?;
                self.instances.mark_installed(instance).await?;
                self.write_transaction(
                    instance,
                    &transaction_id,
                    "install",
                    TransactionState::Committed,
                )
                .await?;
                self.events.emit(CoreEvent::MinecraftInstallCompleted {
                    instance_id: instance.id().to_string(),
                    version_id: plan.version.id.clone(),
                });
                Ok(plan)
            }
            Err(error) => {
                let message = error.to_string();
                let cancelled = matches!(error, Error::Download(DownloadError::Cancelled));
                if cancelled {
                    let _ = self.instances.mark_interrupted(instance, &message).await;
                } else {
                    let _ = self.instances.mark_broken(instance, &message).await;
                }
                let _ = self
                    .write_transaction(
                        instance,
                        &transaction_id,
                        "install",
                        if cancelled {
                            TransactionState::Cancelled
                        } else {
                            TransactionState::Failed
                        },
                    )
                    .await;
                self.events.emit(CoreEvent::MinecraftInstallFailed {
                    instance_id: instance.id().to_string(),
                    message,
                });
                Err(error)
            }
        }
    }

    async fn install_inner(
        &self,
        instance: &Instance,
        cancellation: &CancellationToken,
        transaction_id: &str,
        offline: bool,
    ) -> Result<InstallPlan> {
        let mut plan = if offline {
            self.resolve_cached_install_plan(instance).await?
        } else {
            self.resolve_install_plan(instance, cancellation).await?
        };
        self.write_transaction(
            instance,
            transaction_id,
            "install",
            TransactionState::Downloading,
        )
        .await?;
        let total_files = plan.downloads.len() as u64;
        let mut completed_files = 0_u64;
        let mut downloaded_bytes = 0_u64;
        let started = Instant::now();
        for phase in [
            InstallPhase::Client,
            InstallPhase::Libraries,
            InstallPhase::Assets,
            InstallPhase::Natives,
            InstallPhase::Logging,
            InstallPhase::Loader,
        ] {
            let phase_tasks = plan
                .downloads
                .iter()
                .filter(|task| task.phase == phase)
                .collect::<Vec<_>>();
            for chunk in phase_tasks.chunks(self.downloads.config().concurrency) {
                if cancellation.is_cancelled() {
                    return Err(crate::download::DownloadError::Cancelled.into());
                }
                for task in chunk {
                    self.emit_kind_started(instance.id(), task);
                }
                let requests = chunk
                    .iter()
                    .map(|task| task.request.clone())
                    .collect::<Vec<_>>();
                if offline {
                    completed_files += requests.len() as u64;
                } else {
                    let outcomes = self
                        .downloads
                        .download_all(&self.cache_root, requests, cancellation)
                        .await?;
                    completed_files += outcomes.len() as u64;
                    downloaded_bytes += outcomes
                        .iter()
                        .filter(|outcome| !outcome.reused)
                        .map(|outcome| outcome.bytes)
                        .sum::<u64>();
                }
                self.events.emit(CoreEvent::MinecraftInstallProgress {
                    instance_id: instance.id().to_string(),
                    progress: InstallProgress {
                        phase,
                        completed_files,
                        total_files,
                        downloaded_bytes,
                        total_bytes: plan.total_bytes,
                        bytes_per_second: (downloaded_bytes as f64
                            / started.elapsed().as_secs_f64().max(0.001))
                            as u64,
                        current_file: chunk
                            .last()
                            .map(|task| task.request.destination.to_string()),
                    },
                });
            }
        }

        self.write_transaction(
            instance,
            transaction_id,
            "install",
            TransactionState::Validating,
        )
        .await?;
        if cancellation.is_cancelled() {
            return Err(DownloadError::Cancelled.into());
        }
        self.write_transaction(
            instance,
            transaction_id,
            "install",
            TransactionState::Committing,
        )
        .await?;
        self.commit_natives(instance, &plan, transaction_id, cancellation)
            .await?;
        self.commit_legacy_assets(instance, &plan).await?;
        if let Some(loader) = &mut plan.loader {
            execute_loader_plan(
                loader,
                instance,
                &self.cache_root,
                self.loaders.java(),
                &self.events,
                cancellation,
            )
            .await?;
            write_loader_plan(instance, loader).await?;
        }
        self.events.emit(CoreEvent::MinecraftInstallProgress {
            instance_id: instance.id().to_string(),
            progress: InstallProgress {
                phase: InstallPhase::Finalizing,
                completed_files: total_files,
                total_files,
                downloaded_bytes,
                total_bytes: plan.total_bytes,
                bytes_per_second: (downloaded_bytes as f64
                    / started.elapsed().as_secs_f64().max(0.001))
                    as u64,
                current_file: None,
            },
        });
        Ok(plan)
    }

    fn emit_kind_started(&self, id: &InstanceId, task: &InstallDownload) {
        let event = match task.phase {
            InstallPhase::Libraries | InstallPhase::Natives => {
                Some(CoreEvent::LibraryDownloadStarted {
                    instance_id: id.to_string(),
                    path: task.request.destination.to_string(),
                })
            }
            InstallPhase::Assets => Some(CoreEvent::AssetDownloadStarted {
                instance_id: id.to_string(),
                path: task.request.destination.to_string(),
            }),
            _ => None,
        };
        if let Some(event) = event {
            self.events.emit(event);
        }
    }

    pub(super) async fn commit_natives(
        &self,
        instance: &Instance,
        plan: &InstallPlan,
        transaction_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let native_archives = plan
            .native_archives
            .iter()
            .map(|native| ManagedExtraction {
                archive: native.archive.clone(),
                exclusions: native.exclusions.clone(),
            })
            .collect::<Vec<_>>();
        self.reextract_managed_natives(instance, &native_archives, transaction_id, cancellation)
            .await
    }

    pub(super) async fn reextract_managed_natives(
        &self,
        instance: &Instance,
        native_archives: &[ManagedExtraction],
        transaction_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.events.emit(CoreEvent::NativeExtractionStarted {
            instance_id: instance.id().to_string(),
            archives: native_archives.len() as u64,
        });
        let runtime = instance.path().join("runtime");
        let runtime_metadata = tokio::fs::symlink_metadata(&runtime).await?;
        if runtime_metadata.file_type().is_symlink() || !runtime_metadata.is_dir() {
            return Err(Error::UnsafeFilesystemEntry {
                path: runtime,
                reason: "instance runtime must be a real directory",
            });
        }
        let staging_root = runtime
            .join(".staging")
            .join(format!("install-{transaction_id}"));
        tokio::fs::create_dir_all(&staging_root).await?;
        let staging = staging_root.join("natives");
        reset_real_directory(&staging).await?;
        let archives = native_archives
            .iter()
            .map(|native| NativeArchive {
                path: native.archive.join_under(&self.cache_root),
                exclusions: native.exclusions.clone(),
            })
            .collect();
        extract_natives(archives, staging.clone()).await?;
        if cancellation.is_cancelled() {
            return Err(DownloadError::Cancelled.into());
        }
        let destination = runtime.join("natives");
        let backup = staging_root.join("natives.previous");
        if tokio::fs::try_exists(&destination).await? {
            remove_real_directory_if_present(&backup).await?;
            tokio::fs::rename(&destination, &backup).await?;
        }
        tokio::fs::rename(staging, destination).await?;
        remove_real_directory_if_present(&backup).await?;
        remove_real_directory_if_present(&staging_root).await?;
        Ok(())
    }

    async fn commit_legacy_assets(&self, instance: &Instance, plan: &InstallPlan) -> Result<()> {
        if plan.asset_index.virtual_ {
            let root = self
                .cache_root
                .join("assets")
                .join("virtual")
                .join(&plan.version.asset_index.id);
            for asset in &plan.assets {
                copy_asset(&self.cache_root, &root, asset).await?;
            }
        }
        if plan.asset_index.map_to_resources {
            let root = instance.minecraft_dir().join("resources");
            for asset in &plan.assets {
                copy_asset(&self.cache_root, &root, asset).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn persist_managed_index(
        &self,
        instance: &Instance,
        plan: &InstallPlan,
    ) -> Result<()> {
        let mut files = Vec::with_capacity(plan.metadata_files.len() + plan.downloads.len() + 32);
        for task in plan.metadata_files.iter().chain(&plan.downloads) {
            let loader_download = if task.phase == InstallPhase::Loader {
                plan.loader.as_ref().and_then(|loader| {
                    loader
                        .downloads
                        .iter()
                        .find(|download| download.request.destination == task.request.destination)
                })
            } else {
                None
            };
            let kind = loader_download
                .map(|download| match download.kind {
                    LoaderFileKind::Library | LoaderFileKind::Processor => ManagedFileKind::Library,
                    LoaderFileKind::Metadata | LoaderFileKind::Installer => {
                        ManagedFileKind::VersionMetadata
                    }
                    LoaderFileKind::Generated => ManagedFileKind::Other,
                })
                .unwrap_or_else(|| managed_kind(task));
            let mut expected_hash = task.request.expected_hash.clone();
            let absolute = task.request.destination.join_under(&self.cache_root);
            if expected_hash.is_none() {
                expected_hash = Some(compute_hash(&absolute, HashAlgorithm::Sha256).await?);
            }
            let file = ManagedFile {
                id: task.request.id.clone(),
                location: ManagedFileLocation::Cache,
                path: task.request.destination.clone(),
                kind,
                origin: if loader_download.is_some() {
                    ManagedFileOrigin::Loader
                } else {
                    ManagedFileOrigin::Minecraft
                },
                expected_size: task
                    .request
                    .expected_size
                    .or(Some(tokio::fs::metadata(&absolute).await?.len())),
                expected_hash,
                source: Some(task.request.source.clone()),
                source_path: None,
                repair_from: None,
                verified_size: 0,
                verified_modified_unix_nanos: None,
            };
            files.push(snapshot_managed_file(&self.cache_root, file).await?);
        }
        if let Some(loader) = &plan.loader {
            for processor in &loader.processors {
                for output in &processor.outputs {
                    if files.iter().any(|file| {
                        file.location == ManagedFileLocation::Cache && file.path == output.path
                    }) {
                        continue;
                    }
                    let file = ManagedFile {
                        id: format!("loader-output:{}:{}", processor.id, output.path),
                        location: ManagedFileLocation::Cache,
                        path: output.path.clone(),
                        kind: ManagedFileKind::Other,
                        origin: ManagedFileOrigin::Loader,
                        expected_size: output.expected_size,
                        expected_hash: output.expected_hash.clone(),
                        source: None,
                        source_path: None,
                        repair_from: None,
                        verified_size: 0,
                        verified_modified_unix_nanos: None,
                    };
                    files.push(snapshot_managed_file(&self.cache_root, file).await?);
                }
            }
            for extraction in &loader.archive_entries {
                let absolute = extraction.destination.join_under(&self.cache_root);
                let file = ManagedFile {
                    id: format!("loader-extraction:{}", extraction.destination),
                    location: ManagedFileLocation::Cache,
                    path: extraction.destination.clone(),
                    kind: ManagedFileKind::Other,
                    origin: ManagedFileOrigin::Loader,
                    expected_size: Some(tokio::fs::metadata(&absolute).await?.len()),
                    expected_hash: Some(compute_hash(&absolute, HashAlgorithm::Sha256).await?),
                    source: None,
                    source_path: None,
                    repair_from: None,
                    verified_size: 0,
                    verified_modified_unix_nanos: None,
                };
                files.push(snapshot_managed_file(&self.cache_root, file).await?);
            }
        }
        for relative in
            regular_files_below(instance.path(), &instance.path().join("runtime/natives")).await?
        {
            let absolute = relative.join_under(instance.path());
            let size = tokio::fs::metadata(&absolute).await?.len();
            let hash = compute_hash(&absolute, HashAlgorithm::Sha256).await?;
            let file = ManagedFile {
                id: format!("native:{}", relative),
                location: ManagedFileLocation::Instance,
                path: relative,
                kind: ManagedFileKind::ExtractedNative,
                origin: ManagedFileOrigin::Minecraft,
                expected_size: Some(size),
                expected_hash: Some(hash),
                source: None,
                source_path: None,
                repair_from: None,
                verified_size: 0,
                verified_modified_unix_nanos: None,
            };
            files.push(snapshot_managed_file(instance.path(), file).await?);
        }
        let mut index =
            ManagedFileIndex::new(instance.id().to_string(), plan.version.id.clone(), files);
        index.native_archives = plan
            .native_archives
            .iter()
            .map(|native| ManagedExtraction {
                archive: native.archive.clone(),
                exclusions: native.exclusions.clone(),
            })
            .collect();
        write_managed_index(instance, &index).await?;
        self.cache.register(&index).await
    }

    pub(crate) async fn write_transaction(
        &self,
        instance: &Instance,
        transaction_id: &str,
        operation: &str,
        state: TransactionState,
    ) -> Result<()> {
        let journal = TransactionJournal {
            format_version: 1,
            transaction_id: transaction_id.to_owned(),
            operation: operation.to_owned(),
            state,
            started_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        atomic_write_under(
            instance.path(),
            &SafeRelativePath::new("runtime/transaction.json")?,
            &serde_json::to_vec_pretty(&journal)?,
        )
        .await
    }

    /// Resolves the combined Minecraft and loader Java requirement from cached metadata.
    pub async fn java_requirement(&self, instance: &Instance) -> Result<JavaRequirement> {
        let metadata_path = self
            .cache_root
            .join("versions")
            .join(instance.spec().minecraft().version())
            .join(format!("{}.json", instance.spec().minecraft().version()));
        let metadata: VersionMetadata =
            serde_json::from_slice(&tokio::fs::read(metadata_path).await?).map_err(|error| {
                MinecraftError::InvalidManifest {
                    context: "cached version metadata",
                    message: error.to_string(),
                }
            })?;
        let loader = load_loader_plan(instance).await?;
        Ok(JavaRequirement::current(required_java_major(&metadata))
            .with_loader_minimum(loader.and_then(|plan| plan.minimum_java_major)))
    }

    /// Builds a launch plan without spawning Java.
    pub async fn build_launch_plan(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
    ) -> Result<LaunchPlan> {
        self.build_launch_plan_with_cancellation(
            instance,
            identity,
            options,
            &CancellationToken::default(),
        )
        .await
    }

    /// Builds a launch plan while allowing managed-Java resolution to be cancelled.
    pub async fn build_launch_plan_with_cancellation(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
        cancellation: &CancellationToken,
    ) -> Result<LaunchPlan> {
        if self.instances.installed_version(instance).await?.as_deref()
            != Some(instance.spec().minecraft().version())
        {
            return Err(MinecraftError::NotInstalled(instance.id().to_string()).into());
        }
        let metadata_path = self
            .cache_root
            .join("versions")
            .join(instance.spec().minecraft().version())
            .join(format!("{}.json", instance.spec().minecraft().version()));
        let metadata: VersionMetadata =
            serde_json::from_slice(&tokio::fs::read(metadata_path).await?).map_err(|error| {
                MinecraftError::InvalidManifest {
                    context: "cached version metadata",
                    message: error.to_string(),
                }
            })?;
        let loader = load_loader_plan(instance).await?;
        match (instance.spec().loader(), loader.as_ref()) {
            (Some(expected), Some(plan))
                if plan.identity.kind == expected.kind
                    && plan.identity.loader_version == expected.version
                    && plan.identity.minecraft_version == metadata.id => {}
            (Some(_), _) => return Err(crate::loaders::LoaderError::OfflinePlanUnavailable.into()),
            (None, Some(_)) => {
                return Err(crate::loaders::LoaderError::InvalidPlan(
                    "a loader plan exists for a Vanilla instance".into(),
                )
                .into())
            }
            (None, None) => {}
        }
        build_launch_plan(
            instance,
            &metadata,
            loader.as_ref(),
            &self.cache_root,
            &self.java,
            super::launch::LaunchContext {
                identity,
                options,
                cancellation,
            },
        )
        .await
    }

    /// Builds a plan and launches Java through the multi-instance process manager.
    pub async fn launch(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
    ) -> Result<RunningInstance> {
        self.launch_with_cancellation(instance, identity, options, &CancellationToken::default())
            .await
    }

    /// Resolves Java and launches Minecraft with cooperative setup cancellation.
    pub async fn launch_with_cancellation(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
        cancellation: &CancellationToken,
    ) -> Result<RunningInstance> {
        self.events.emit(CoreEvent::MinecraftStarting {
            instance_id: instance.id().to_string(),
        });
        let plan = self
            .build_launch_plan_with_cancellation(instance, identity, options, cancellation)
            .await?;
        self.processes.launch(instance.id(), &plan).await
    }

    /// Builds a plan and starts Minecraft independently of the caller runtime.
    pub async fn launch_detached(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
    ) -> Result<DetachedInstance> {
        self.launch_detached_with_cancellation(
            instance,
            identity,
            options,
            &CancellationToken::default(),
        )
        .await
    }

    /// Resolves Java and starts a detached process with cooperative setup cancellation.
    pub async fn launch_detached_with_cancellation(
        &self,
        instance: &Instance,
        identity: &MinecraftIdentity,
        options: &LaunchOptions,
        cancellation: &CancellationToken,
    ) -> Result<DetachedInstance> {
        self.events.emit(CoreEvent::MinecraftStarting {
            instance_id: instance.id().to_string(),
        });
        let plan = self
            .build_launch_plan_with_cancellation(instance, identity, options, cancellation)
            .await?;
        self.processes.launch_detached(instance.id(), &plan).await
    }

    pub async fn stop(&self, instance_id: &InstanceId) -> Result<bool> {
        self.processes.kill(instance_id).await
    }

    pub async fn status(&self, instance_id: &InstanceId) -> Result<InstanceStatus> {
        if self.processes.is_running(instance_id).await? {
            Ok(InstanceStatus::Running)
        } else {
            self.instances.status(instance_id.to_string()).await
        }
    }
}

fn managed_kind(task: &InstallDownload) -> ManagedFileKind {
    if task.request.id.starts_with("metadata:") {
        ManagedFileKind::VersionMetadata
    } else if task.request.id.starts_with("asset-index:") {
        ManagedFileKind::AssetIndex
    } else if task.request.id.starts_with("client:") {
        ManagedFileKind::Client
    } else if task.request.id.starts_with("asset:") {
        ManagedFileKind::Asset
    } else if task.request.id.starts_with("logging:") {
        ManagedFileKind::Logging
    } else if task.phase == InstallPhase::Natives {
        ManagedFileKind::NativeArchive
    } else if task.phase == InstallPhase::Libraries {
        ManagedFileKind::Library
    } else {
        ManagedFileKind::Other
    }
}

fn validate_cached_version(requested: &str, metadata: &VersionMetadata) -> Result<()> {
    if metadata.id != requested {
        return Err(MinecraftError::InvalidManifest {
            context: "cached version metadata",
            message: format!(
                "requested `{requested}` but metadata identifies `{}`",
                metadata.id
            ),
        }
        .into());
    }
    if let Some(parent) = &metadata.inherits_from {
        return Err(MinecraftError::UnsupportedInheritance {
            version: metadata.id.clone(),
            parent: parent.clone(),
        }
        .into());
    }
    Ok(())
}

pub(super) fn transaction_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

async fn regular_files_below(root: &Path, directory: &Path) -> Result<Vec<SafeRelativePath>> {
    let root = root.to_path_buf();
    let directory = directory.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut files = Vec::new();
        let mut pending = vec![directory];
        while let Some(current) = pending.pop() {
            for entry in std::fs::read_dir(current)? {
                let entry = entry?;
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    return Err(Error::UnsafeFilesystemEntry {
                        path: entry.path(),
                        reason: "managed native tree cannot contain symbolic links",
                    });
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() {
                    let relative = entry
                        .path()
                        .strip_prefix(&root)
                        .map_err(|_| Error::UnsafeFilesystemEntry {
                            path: entry.path(),
                            reason: "managed native escaped instance root",
                        })?
                        .to_string_lossy()
                        .replace('\\', "/");
                    files.push(SafeRelativePath::new(relative)?);
                }
            }
        }
        files.sort();
        Ok(files)
    })
    .await
    .map_err(|error| {
        Error::Minecraft(MinecraftError::NativeExtraction {
            archive: "managed native tree".into(),
            reason: error.to_string(),
        })
    })?
}

fn insert_artifact(
    tasks: &mut BTreeMap<String, InstallDownload>,
    phase: InstallPhase,
    id: &str,
    artifact: &ResolvedArtifact,
) -> Result<()> {
    let destination = prefixed_path("libraries", &artifact.path)?;
    tasks
        .entry(destination.to_string())
        .or_insert_with(|| InstallDownload {
            phase,
            request: DownloadRequest {
                id: format!("library:{id}"),
                source: artifact.url.clone(),
                destination,
                expected_size: artifact.size,
                expected_hash: artifact.sha1.clone(),
            },
        });
    Ok(())
}

fn insert_task(
    tasks: &mut BTreeMap<String, InstallDownload>,
    phase: InstallPhase,
    id: String,
    destination: SafeRelativePath,
    info: &super::DownloadInfo,
) -> Result<()> {
    let expected_hash = info
        .sha1
        .as_ref()
        .map(|hash| FileHash::new(HashAlgorithm::Sha1, hash.clone()))
        .transpose()?;
    tasks.insert(
        destination.to_string(),
        InstallDownload {
            phase,
            request: DownloadRequest {
                id,
                source: info.url.clone(),
                destination,
                expected_size: info.size,
                expected_hash,
            },
        },
    );
    Ok(())
}

fn prefixed_path(prefix: &str, path: &SafeRelativePath) -> Result<SafeRelativePath> {
    SafeRelativePath::new(format!("{prefix}/{}", path.as_str()))
}

async fn atomic_write_under(root: &Path, relative: &SafeRelativePath, bytes: &[u8]) -> Result<()> {
    let destination = relative.join_under(root);
    ensure_safe_parent(root, relative).await?;
    let temporary = destination.with_extension("tmp");
    reject_non_file_if_present(&temporary).await?;
    tokio::fs::write(&temporary, bytes).await?;
    if tokio::fs::try_exists(&destination).await? {
        let metadata = tokio::fs::symlink_metadata(&destination).await?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: destination,
                reason: "metadata cache entry must be a real file",
            });
        }
        tokio::fs::remove_file(&destination).await?;
    }
    tokio::fs::rename(temporary, destination).await?;
    Ok(())
}

async fn reset_real_directory(path: &Path) -> Result<()> {
    remove_real_directory_if_present(path).await?;
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

async fn remove_real_directory_if_present(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            tokio::fs::remove_dir_all(path).await?;
        }
        Ok(_) => {
            return Err(Error::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                reason: "expected a real directory",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn copy_asset(
    cache_root: &Path,
    destination_root: &Path,
    asset: &ResolvedAsset,
) -> Result<()> {
    let destination = asset.logical_path.join_under(destination_root);
    ensure_safe_parent(destination_root, &asset.logical_path).await?;
    reject_non_file_if_present(&destination).await?;
    tokio::fs::copy(asset.object_path.join_under(cache_root), destination).await?;
    Ok(())
}

async fn ensure_safe_parent(root: &Path, relative: &SafeRelativePath) -> Result<()> {
    match tokio::fs::symlink_metadata(root).await {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(Error::UnsafeFilesystemEntry {
                path: root.to_path_buf(),
                reason: "destination root must be a real directory",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(root).await?;
        }
        Err(error) => return Err(error.into()),
    }
    let parts = relative.as_str().split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current.push(part);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(Error::UnsafeFilesystemEntry {
                    path: current,
                    reason: "destination parent must be a real directory",
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match tokio::fs::create_dir(&current).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                let metadata = tokio::fs::symlink_metadata(&current).await?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(Error::UnsafeFilesystemEntry {
                        path: current,
                        reason: "created destination parent must be a real directory",
                    });
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn reject_non_file_if_present(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(Error::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            reason: "destination must be a real file",
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
