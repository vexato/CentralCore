//! Instance verification and incremental repair planning/execution.

use std::{path::PathBuf, time::Instant};

use serde::{Deserialize, Serialize};

use crate::{
    cache::{
        load_managed_index, snapshot_managed_file, verify_index, write_managed_index, CacheError,
        FileCheck, FileState, ManagedFileIndex, ManagedFileKind, ManagedFileLocation,
        ManagedFileOrigin, VerificationReport,
    },
    download::{CancellationToken, DownloadRequest},
    events::CoreEvent,
    files::{FileHash, SafeRelativePath},
    instance::{Instance, InstanceId},
    loaders::{load_loader_plan, ArchiveEntryPlan, LoaderPlan, ProcessorPlan},
    Result,
};

use super::{
    install::{transaction_id, TransactionState},
    MinecraftManager,
};

/// Options controlling verification work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Recompute every cryptographic digest instead of using trusted metadata.
    pub full: bool,
}

/// Options controlling incremental repair.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepairOptions {
    pub full_verification: bool,
    pub offline: bool,
}

/// One cache transfer required by a repair.
#[derive(Debug, Clone)]
pub struct RepairDownload {
    pub request: DownloadRequest,
    pub previous_state: FileState,
    pub kind: ManagedFileKind,
}

/// One managed native path that must be regenerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairExtraction {
    pub archive: SafeRelativePath,
    pub exclusions: Vec<String>,
}

/// One verified local copy used for content-addressed/provider recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairCopy {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub expected_size: Option<u64>,
    pub expected_hash: Option<FileHash>,
    pub previous_state: FileState,
    pub kind: ManagedFileKind,
}

/// Metrics produced while executing a repair plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairMetrics {
    pub files_checked: u64,
    pub files_reused: u64,
    pub files_downloaded: u64,
    pub bytes_reused: u64,
    pub bytes_downloaded: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub duration_millis: u64,
}

/// Immutable analysis of the changes required to restore one instance.
#[derive(Debug, Clone)]
pub struct RepairPlan {
    pub(crate) instance_id: InstanceId,
    pub(crate) checks: Vec<FileCheck>,
    pub(crate) downloads: Vec<RepairDownload>,
    pub(crate) copies: Vec<RepairCopy>,
    pub(crate) extractions: Vec<RepairExtraction>,
    pub(crate) loader_archive_entries: Vec<ArchiveEntryPlan>,
    pub(crate) loader_processors: Vec<ProcessorPlan>,
    pub(crate) removals: Vec<PathBuf>,
    pub(crate) total_download_bytes: Option<u64>,
}

impl RepairPlan {
    /// Instance whose managed state was analyzed.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    /// Per-file checks that produced this plan.
    #[must_use]
    pub fn checks(&self) -> &[FileCheck] {
        &self.checks
    }

    /// Network transfers required to repair the instance.
    #[must_use]
    pub fn downloads(&self) -> &[RepairDownload] {
        &self.downloads
    }

    /// Verified local cache copies required by the repair.
    #[must_use]
    pub fn copies(&self) -> &[RepairCopy] {
        &self.copies
    }

    /// Native archives that must be re-extracted.
    #[must_use]
    pub fn extractions(&self) -> &[RepairExtraction] {
        &self.extractions
    }

    /// Paths that no longer belong to managed desired state.
    #[must_use]
    pub fn removals(&self) -> &[PathBuf] {
        &self.removals
    }

    /// Total expected network bytes, when known.
    #[must_use]
    pub const fn total_download_bytes(&self) -> Option<u64> {
        self.total_download_bytes
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.downloads.is_empty()
            && self.copies.is_empty()
            && self.extractions.is_empty()
            && self.loader_archive_entries.is_empty()
            && self.loader_processors.is_empty()
            && self.removals.is_empty()
    }
}

/// Successful repair output including its final health report.
#[derive(Debug, Clone)]
pub struct RepairOutcome {
    pub plan: RepairPlan,
    pub verification: VerificationReport,
    pub metrics: RepairMetrics,
}

/// Structured verification and repair failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepairError {
    #[error("repair requires {count} missing or corrupted cache objects, but network access is disabled")]
    OfflineObjectsUnavailable { count: usize },
    #[error("managed file `{path}` has no trusted repair source")]
    MissingSource { path: String },
    #[error("repair completed but verification still reports {missing} missing and {corrupted} corrupted files")]
    FinalVerification { missing: u64, corrupted: u64 },
}

impl MinecraftManager {
    /// Verifies one instance without changing managed or user files.
    pub async fn verify(
        &self,
        instance: &Instance,
        options: VerifyOptions,
    ) -> Result<VerificationReport> {
        let _lock = self
            .locks
            .acquire_shared(format!("instance:{}", instance.id()))
            .await?;
        self.verify_unlocked(instance, options.full).await
    }

    /// Analyzes one instance and returns an inspectable, non-mutating plan.
    pub async fn resolve_repair_plan(
        &self,
        instance: &Instance,
        options: RepairOptions,
    ) -> Result<RepairPlan> {
        let _lock = self
            .locks
            .acquire_shared(format!("instance:{}", instance.id()))
            .await?;
        self.resolve_repair_plan_unlocked(instance, options).await
    }

    /// Executes only the invalid work in a repair plan and fully verifies it.
    pub async fn repair(
        &self,
        instance: &Instance,
        options: RepairOptions,
        cancellation: &CancellationToken,
    ) -> Result<RepairOutcome> {
        let _lock = self
            .locks
            .try_acquire_exclusive(format!("instance:{}", instance.id()))
            .await?;
        let transaction = transaction_id();
        self.write_transaction(instance, &transaction, "repair", TransactionState::Created)
            .await?;
        self.events.emit(CoreEvent::InstanceRepairStarted {
            instance_id: instance.id().to_string(),
        });
        let started = Instant::now();
        let result = self
            .repair_unlocked(instance, options, cancellation, &transaction)
            .await;
        match result {
            Ok(mut outcome) => {
                outcome.metrics.duration_millis =
                    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                self.instances.mark_installed(instance).await?;
                self.write_transaction(
                    instance,
                    &transaction,
                    "repair",
                    TransactionState::Committed,
                )
                .await?;
                self.events.emit(CoreEvent::InstanceRepairCompleted {
                    instance_id: instance.id().to_string(),
                });
                Ok(outcome)
            }
            Err(error) => {
                let message = error.to_string();
                if cancellation.is_cancelled() {
                    let _ = self.instances.mark_interrupted(instance, &message).await;
                } else {
                    let _ = self.instances.mark_broken(instance, &message).await;
                }
                let _ = self
                    .write_transaction(
                        instance,
                        &transaction,
                        "repair",
                        if cancellation.is_cancelled() {
                            TransactionState::Cancelled
                        } else {
                            TransactionState::Failed
                        },
                    )
                    .await;
                self.events.emit(CoreEvent::InstanceRepairFailed {
                    instance_id: instance.id().to_string(),
                    message,
                });
                Err(error)
            }
        }
    }

    async fn verify_unlocked(&self, instance: &Instance, full: bool) -> Result<VerificationReport> {
        self.events.emit(CoreEvent::InstanceVerificationStarted {
            instance_id: instance.id().to_string(),
            full,
        });
        let index = load_managed_index(instance).await?;
        let report = verify_index(
            instance,
            &self.cache_root,
            &index,
            full,
            self.downloads.config().concurrency,
        )
        .await?;
        self.events.emit(CoreEvent::InstanceVerificationProgress {
            instance_id: instance.id().to_string(),
            checked_files: report.metrics.files_checked,
            total_files: report.metrics.files_checked,
        });
        self.events.emit(CoreEvent::InstanceVerificationCompleted {
            instance_id: instance.id().to_string(),
            report: report.clone(),
        });
        Ok(report)
    }

    async fn resolve_repair_plan_unlocked(
        &self,
        instance: &Instance,
        options: RepairOptions,
    ) -> Result<RepairPlan> {
        let index = load_managed_index(instance).await?;
        let verification = self
            .verify_unlocked(instance, options.full_verification)
            .await?;
        let mut downloads = Vec::new();
        let mut copies = Vec::new();
        let mut removals = Vec::new();
        let loader_plan = load_loader_plan(instance).await?;
        let mut loader_archive_entries = Vec::new();
        let mut loader_processors = Vec::new();
        let mut native_invalid = false;
        for check in verification
            .checks
            .iter()
            .filter(|check| check.state != FileState::Valid)
        {
            if check.state == FileState::Unexpected
                && check.location == ManagedFileLocation::Instance
            {
                let relative = SafeRelativePath::new(&check.path)?;
                removals.push(relative.join_under(instance.path()));
                native_invalid |= check.kind == ManagedFileKind::ExtractedNative;
                continue;
            }
            let file = index
                .files
                .iter()
                .find(|file| file.id == check.id && file.location == check.location)
                .ok_or_else(|| RepairError::MissingSource {
                    path: check.path.clone(),
                })?;
            match file.location {
                ManagedFileLocation::Cache => {
                    native_invalid |= file.kind == ManagedFileKind::NativeArchive;
                    if let Some(source) = file.source.clone() {
                        downloads.push(RepairDownload {
                            request: DownloadRequest {
                                id: format!("repair:{}", file.id),
                                source,
                                destination: file.path.clone(),
                                expected_size: file.expected_size,
                                expected_hash: file.expected_hash.clone(),
                            },
                            previous_state: check.state,
                            kind: file.kind,
                        });
                    } else if let Some(source) = file.source_path.clone() {
                        copies.push(RepairCopy {
                            source,
                            destination: file.path.join_under(&self.cache_root),
                            expected_size: file.expected_size,
                            expected_hash: file.expected_hash.clone(),
                            previous_state: check.state,
                            kind: file.kind,
                        });
                    } else if file.origin == ManagedFileOrigin::Loader {
                        let loader = loader_plan
                            .as_ref()
                            .ok_or(crate::loaders::LoaderError::OfflinePlanUnavailable)?;
                        if let Some(processor) = loader.processors.iter().find(|processor| {
                            processor
                                .outputs
                                .iter()
                                .any(|output| output.path == file.path)
                        }) {
                            if !loader_processors
                                .iter()
                                .any(|queued: &ProcessorPlan| queued.id == processor.id)
                            {
                                loader_processors.push(processor.clone());
                            }
                        } else if let Some(extraction) = loader
                            .archive_entries
                            .iter()
                            .find(|extraction| extraction.destination == file.path)
                        {
                            if !loader_archive_entries
                                .iter()
                                .any(|queued: &ArchiveEntryPlan| {
                                    queued.destination == extraction.destination
                                })
                            {
                                loader_archive_entries.push(extraction.clone());
                            }
                        } else {
                            return Err(RepairError::MissingSource {
                                path: check.path.clone(),
                            }
                            .into());
                        }
                    } else {
                        return Err(RepairError::MissingSource {
                            path: check.path.clone(),
                        }
                        .into());
                    }
                }
                ManagedFileLocation::Instance => {
                    if let Some(source) = &file.repair_from {
                        copies.push(RepairCopy {
                            source: source.join_under(&self.cache_root),
                            destination: file.path.join_under(instance.path()),
                            expected_size: file.expected_size,
                            expected_hash: file.expected_hash.clone(),
                            previous_state: check.state,
                            kind: file.kind,
                        });
                    } else {
                        removals.push(file.path.join_under(instance.path()));
                        native_invalid |= file.kind == ManagedFileKind::ExtractedNative;
                    }
                }
            }
        }
        let extractions = if native_invalid {
            index
                .native_archives
                .iter()
                .map(|native| RepairExtraction {
                    archive: native.archive.clone(),
                    exclusions: native.exclusions.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };
        let total_download_bytes = downloads
            .iter()
            .map(|download| download.request.expected_size)
            .collect::<Option<Vec<_>>>()
            .map(|sizes| sizes.into_iter().sum());
        let plan = RepairPlan {
            instance_id: instance.id().clone(),
            checks: verification.checks,
            downloads,
            copies,
            extractions,
            loader_archive_entries,
            loader_processors,
            removals,
            total_download_bytes,
        };
        self.events.emit(CoreEvent::RepairPlanCreated {
            instance_id: instance.id().to_string(),
            downloads: plan.downloads.len() as u64,
            extractions: plan.extractions.len() as u64,
        });
        Ok(plan)
    }

    async fn repair_unlocked(
        &self,
        instance: &Instance,
        options: RepairOptions,
        cancellation: &CancellationToken,
        transaction: &str,
    ) -> Result<RepairOutcome> {
        if matches!(
            load_managed_index(instance).await,
            Err(crate::Error::Cache(CacheError::MissingManagedIndex(_)))
        ) {
            if options.offline {
                return Err(CacheError::MissingManagedIndex(instance.id().to_string()).into());
            }
            let install_plan = self.resolve_install_plan(instance, cancellation).await?;
            self.persist_managed_index(instance, &install_plan).await?;
        }
        let mut plan = self.resolve_repair_plan_unlocked(instance, options).await?;
        if options.offline && !plan.downloads.is_empty() {
            for download in &plan.downloads {
                let _ = self
                    .downloads
                    .recover_local(&self.cache_root, &download.request)
                    .await?;
            }
            plan = self.resolve_repair_plan_unlocked(instance, options).await?;
            if !plan.downloads.is_empty() {
                return Err(RepairError::OfflineObjectsUnavailable {
                    count: plan.downloads.len(),
                }
                .into());
            }
        }
        self.write_transaction(
            instance,
            transaction,
            "repair",
            TransactionState::Downloading,
        )
        .await?;
        let outcomes = self
            .downloads
            .download_all(
                &self.cache_root,
                plan.downloads
                    .iter()
                    .map(|download| download.request.clone())
                    .collect(),
                cancellation,
            )
            .await?;
        if !plan.loader_archive_entries.is_empty() || !plan.loader_processors.is_empty() {
            let installed = load_loader_plan(instance)
                .await?
                .ok_or(crate::loaders::LoaderError::OfflinePlanUnavailable)?;
            let mut repair_loader = LoaderPlan {
                archive_entries: plan.loader_archive_entries.clone(),
                processors: plan.loader_processors.clone(),
                downloads: Vec::new(),
                classpath_additions: Vec::new(),
                jvm_arguments: Vec::new(),
                game_arguments: Vec::new(),
                main_class: None,
                ..installed
            };
            crate::loaders::execute_loader_plan(
                &mut repair_loader,
                instance,
                &self.cache_root,
                self.loaders.java(),
                &self.events,
                cancellation,
            )
            .await?;
        }
        for copy in plan
            .copies
            .iter()
            .filter(|copy| copy.destination.starts_with(&self.cache_root))
        {
            repair_copy(instance, &self.cache_root, copy).await?;
        }
        for copy in plan
            .copies
            .iter()
            .filter(|copy| !copy.destination.starts_with(&self.cache_root))
        {
            repair_copy(instance, &self.cache_root, copy).await?;
        }
        if plan.extractions.is_empty() {
            for removal in &plan.removals {
                if !removal.starts_with(instance.path()) {
                    return Err(crate::Error::UnsafeFilesystemEntry {
                        path: removal.clone(),
                        reason: "repair removal escaped instance root",
                    });
                }
                match tokio::fs::symlink_metadata(removal).await {
                    Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                        tokio::fs::remove_file(removal).await?;
                    }
                    Ok(_) => {
                        return Err(crate::Error::UnsafeFilesystemEntry {
                            path: removal.clone(),
                            reason: "repair removal must be a real file",
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        self.events.emit(CoreEvent::InstanceRepairProgress {
            instance_id: instance.id().to_string(),
            completed_files: outcomes.len() as u64,
            total_files: plan.downloads.len() as u64,
        });
        if !plan.extractions.is_empty() {
            self.write_transaction(
                instance,
                transaction,
                "repair",
                TransactionState::Committing,
            )
            .await?;
            let native_archives = plan
                .extractions
                .iter()
                .map(|extraction| crate::cache::ManagedExtraction {
                    archive: extraction.archive.clone(),
                    exclusions: extraction.exclusions.clone(),
                })
                .collect::<Vec<_>>();
            self.reextract_managed_natives(instance, &native_archives, transaction, cancellation)
                .await?;
        }
        self.write_transaction(
            instance,
            transaction,
            "repair",
            TransactionState::Validating,
        )
        .await?;
        let mut index = load_managed_index(instance).await?;
        refresh_index(instance, &self.cache_root, &mut index).await?;
        write_managed_index(instance, &index).await?;
        self.cache.register(&index).await?;
        let verification = self.verify_unlocked(instance, true).await?;
        if !verification.is_healthy() {
            return Err(RepairError::FinalVerification {
                missing: verification.missing,
                corrupted: verification.corrupted,
            }
            .into());
        }
        let files_downloaded = outcomes.iter().filter(|outcome| !outcome.reused).count() as u64;
        let bytes_downloaded = outcomes
            .iter()
            .filter(|outcome| !outcome.reused)
            .map(|outcome| outcome.bytes)
            .sum();
        let bytes_reused = index
            .files
            .iter()
            .map(|file| file.verified_size)
            .sum::<u64>()
            .saturating_sub(bytes_downloaded);
        let metrics = RepairMetrics {
            files_checked: plan.checks.len() as u64,
            files_reused: (plan.checks.len() as u64)
                .saturating_sub(plan.downloads.len() as u64)
                .saturating_sub(plan.copies.len() as u64),
            files_downloaded,
            bytes_reused,
            bytes_downloaded,
            cache_hits: outcomes.iter().filter(|outcome| outcome.reused).count() as u64,
            cache_misses: files_downloaded,
            duration_millis: 0,
        };
        Ok(RepairOutcome {
            plan,
            verification,
            metrics,
        })
    }
}

async fn repair_copy(
    instance: &Instance,
    cache_root: &std::path::Path,
    copy: &RepairCopy,
) -> Result<()> {
    if !copy.destination.starts_with(cache_root) && !copy.destination.starts_with(instance.path()) {
        return Err(crate::Error::UnsafeFilesystemEntry {
            path: copy.destination.clone(),
            reason: "repair copy destination escaped managed roots",
        });
    }
    let source_metadata = tokio::fs::symlink_metadata(&copy.source).await?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(crate::Error::UnsafeFilesystemEntry {
            path: copy.source.clone(),
            reason: "repair copy source must be a real file",
        });
    }
    crate::download::verify_file(
        &copy.source,
        copy.expected_size,
        copy.expected_hash.as_ref(),
    )
    .await?;
    let parent = copy
        .destination
        .parent()
        .ok_or_else(|| crate::Error::UnsafeFilesystemEntry {
            path: copy.destination.clone(),
            reason: "repair copy destination has no parent",
        })?;
    ensure_repair_parent(
        if copy.destination.starts_with(cache_root) {
            cache_root
        } else {
            instance.path()
        },
        parent,
    )
    .await?;
    let temporary = copy.destination.with_extension("centralcore-repair.tmp");
    reject_repair_symlink(&temporary).await?;
    tokio::fs::copy(&copy.source, &temporary).await?;
    crate::download::verify_file(&temporary, copy.expected_size, copy.expected_hash.as_ref())
        .await?;
    reject_repair_symlink(&copy.destination).await?;
    if tokio::fs::try_exists(&copy.destination).await? {
        tokio::fs::remove_file(&copy.destination).await?;
    }
    tokio::fs::rename(temporary, &copy.destination).await?;
    Ok(())
}

async fn ensure_repair_parent(root: &std::path::Path, parent: &std::path::Path) -> Result<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| crate::Error::UnsafeFilesystemEntry {
            path: parent.to_path_buf(),
            reason: "repair parent escaped managed root",
        })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(crate::Error::UnsafeFilesystemEntry {
                    path: current,
                    reason: "repair parent must be a real directory",
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

async fn reject_repair_symlink(path: &std::path::Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(crate::Error::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                reason: "repair destination must be a real file",
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn refresh_index(
    instance: &Instance,
    cache_root: &std::path::Path,
    index: &mut ManagedFileIndex,
) -> Result<()> {
    let mut refreshed = Vec::with_capacity(index.files.len());
    for file in index.files.drain(..) {
        let base = match file.location {
            ManagedFileLocation::Cache => cache_root,
            ManagedFileLocation::Instance => instance.path(),
        };
        refreshed.push(snapshot_managed_file(base, file).await?);
    }
    index.files = refreshed;
    Ok(())
}
