//! Versioned shared-cache metadata, verification, and safe pruning.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    download::verify_file,
    events::{CoreEvent, EventBus},
    files::{FileHash, SafeRelativePath},
    instance::{Instance, InstanceService},
    lock::LockManager,
    Error, Result,
};

const CACHE_INDEX_VERSION: u32 = 1;
const MANAGED_INDEX_VERSION: u32 = 1;

/// Logical owner of a managed file, ready for future loader/provider content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFileOrigin {
    Minecraft,
    Loader,
    Provider,
    /// File owned by one provider component. The ID makes disable/remove precise.
    Component {
        id: String,
    },
    /// Retained for persisted Phase 3 indexes.
    UserOptional,
}

/// Root against which a managed relative path is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFileLocation {
    Cache,
    Instance,
}

/// Functional category used by reports and cache policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFileKind {
    VersionMetadata,
    Client,
    Library,
    AssetIndex,
    Asset,
    NativeArchive,
    ExtractedNative,
    Logging,
    Other,
}

/// One file explicitly owned by CentralCore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFile {
    pub id: String,
    pub location: ManagedFileLocation,
    pub path: SafeRelativePath,
    pub kind: ManagedFileKind,
    pub origin: ManagedFileOrigin,
    pub expected_size: Option<u64>,
    pub expected_hash: Option<FileHash>,
    pub source: Option<Url>,
    /// Trusted local source used to rebuild a content-addressed cache object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<PathBuf>,
    /// Cache-relative object used to restore an instance-local managed file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_from: Option<SafeRelativePath>,
    pub verified_size: u64,
    pub verified_modified_unix_nanos: Option<u128>,
}

/// Reconstructible ownership description persisted per instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFileIndex {
    pub format_version: u32,
    pub instance_id: String,
    pub version_id: String,
    pub files: Vec<ManagedFile>,
    #[serde(default)]
    pub native_archives: Vec<ManagedExtraction>,
}

/// Reconstructible native extraction input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedExtraction {
    pub archive: SafeRelativePath,
    pub exclusions: Vec<String>,
}

impl ManagedFileIndex {
    pub fn new(instance_id: String, version_id: String, files: Vec<ManagedFile>) -> Self {
        Self {
            format_version: MANAGED_INDEX_VERSION,
            instance_id,
            version_id,
            files,
            native_archives: Vec::new(),
        }
    }
}

/// Observed state of one expected or unexpected file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Valid,
    Missing,
    Corrupted,
    Unexpected,
}

/// Detailed verification result for one managed path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCheck {
    pub id: String,
    pub path: String,
    pub location: ManagedFileLocation,
    pub kind: ManagedFileKind,
    pub state: FileState,
    pub expected_size: Option<u64>,
    pub actual_size: Option<u64>,
}

/// Reusable verification counters and I/O metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMetrics {
    pub files_checked: u64,
    pub bytes_checked: u64,
    pub duration_millis: u64,
}

/// Structured result of verifying one instance or the shared cache.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub subject: String,
    pub checks: Vec<FileCheck>,
    pub valid: u64,
    pub missing: u64,
    pub corrupted: u64,
    pub unexpected: u64,
    pub metrics: VerificationMetrics,
}

impl VerificationReport {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.missing == 0 && self.corrupted == 0 && self.unexpected == 0
    }
}

/// Size/count pair for one cache category.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheCategoryStats {
    pub files: u64,
    pub bytes: u64,
}

/// Snapshot of cache disk usage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStatus {
    pub versions: CacheCategoryStats,
    pub libraries: CacheCategoryStats,
    pub assets: CacheCategoryStats,
    pub metadata: CacheCategoryStats,
    pub temporary: CacheCategoryStats,
    pub other: CacheCategoryStats,
    pub total_files: u64,
    pub total_bytes: u64,
}

/// Basic eviction policy. References always override eviction limits.
#[derive(Debug, Clone, Default)]
pub struct CachePolicy {
    pub max_size: Option<u64>,
    pub max_age: Option<Duration>,
}

/// One safe removal proposed by cache pruning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePruneEntry {
    pub path: String,
    pub bytes: u64,
    pub temporary: bool,
}

/// Inspectable result of cache-prune analysis or execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePruneReport {
    pub candidates: Vec<CachePruneEntry>,
    pub removed_files: u64,
    pub removed_bytes: u64,
    pub skipped_locked: u64,
    pub dry_run: bool,
}

/// Cache-specific structured failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    #[error("managed-file index is missing for instance `{0}`")]
    MissingManagedIndex(String),
    #[error("managed-file index belongs to `{actual}`, expected `{expected}`")]
    IndexIdentity { expected: String, actual: String },
    #[error("cache metadata is invalid: {0}")]
    InvalidIndex(String),
    #[error("cache object `{path}` is corrupted and network access is disabled")]
    OfflineObjectUnavailable { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheIndex {
    format_version: u32,
    files: BTreeMap<String, ManagedFile>,
}

impl Default for CacheIndex {
    fn default() -> Self {
        Self {
            format_version: CACHE_INDEX_VERSION,
            files: BTreeMap::new(),
        }
    }
}

/// Shared Minecraft cache inspection and maintenance service.
#[derive(Debug, Clone)]
pub struct CacheManager {
    root: PathBuf,
    instances: InstanceService,
    locks: LockManager,
    events: EventBus,
    verify_concurrency: usize,
}

impl CacheManager {
    pub(crate) fn new(
        root: PathBuf,
        instances: InstanceService,
        locks: LockManager,
        events: EventBus,
        verify_concurrency: usize,
    ) -> Self {
        Self {
            root,
            instances,
            locks,
            events,
            verify_concurrency: verify_concurrency.clamp(1, 16),
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Computes cache usage without following symbolic links.
    pub async fn status(&self) -> Result<CacheStatus> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || scan_status(&root))
            .await
            .map_err(|error| Error::Cache(CacheError::InvalidIndex(error.to_string())))?
    }

    /// Verifies every indexed cache object.
    pub async fn verify(&self, full: bool) -> Result<VerificationReport> {
        self.events
            .emit(CoreEvent::CacheVerificationStarted { full });
        let started = std::time::Instant::now();
        let index = self.load_cache_index().await?;
        let indexed = index.files.keys().cloned().collect::<BTreeSet<_>>();
        let mut checks = futures_util::stream::iter(index.files.values().cloned())
            .map(|file| {
                let root = self.root.clone();
                async move { verify_managed_file(&root, &root, &file, full).await }
            })
            .buffer_unordered(self.verify_concurrency)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        checks.extend(find_unindexed_files(&self.root, &indexed).await?);
        let report = build_report("cache".into(), checks, started.elapsed());
        self.events.emit(CoreEvent::CacheVerificationCompleted {
            valid: report.valid,
            missing: report.missing,
            corrupted: report.corrupted,
        });
        Ok(report)
    }

    /// Produces and optionally executes a reference-safe prune operation.
    pub async fn prune(&self, policy: &CachePolicy, dry_run: bool) -> Result<CachePruneReport> {
        let index = self.load_cache_index().await?;
        let referenced = self.referenced_cache_paths().await?;
        let mut candidates = Vec::new();
        let now = SystemTime::now();
        for (path, file) in &index.files {
            if referenced.contains(path) {
                continue;
            }
            let absolute = file.path.join_under(&self.root);
            if let Ok(metadata) = tokio::fs::symlink_metadata(&absolute).await {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    continue;
                }
                if policy.max_age.is_some_and(|age| {
                    metadata
                        .modified()
                        .ok()
                        .and_then(|modified| now.duration_since(modified).ok())
                        .is_some_and(|elapsed| elapsed < age)
                }) {
                    continue;
                }
                candidates.push(CachePruneEntry {
                    path: path.clone(),
                    bytes: metadata.len(),
                    temporary: false,
                });
            }
        }
        candidates.extend(find_temporary_files(&self.root).await?);
        candidates.sort_by(|left, right| left.path.cmp(&right.path));
        candidates.dedup_by(|left, right| left.path == right.path);

        if let Some(max_size) = policy.max_size {
            let status = self.status().await?;
            let mut excess = status.total_bytes.saturating_sub(max_size);
            candidates.retain(|candidate| {
                if candidate.temporary || excess > 0 {
                    excess = excess.saturating_sub(candidate.bytes);
                    true
                } else {
                    false
                }
            });
        }

        let mut report = CachePruneReport {
            candidates,
            dry_run,
            ..CachePruneReport::default()
        };
        if dry_run {
            return Ok(report);
        }
        let mut removed_paths = Vec::new();
        for candidate in &report.candidates {
            let relative = SafeRelativePath::new(&candidate.path)?;
            let resource = cache_lock_key(&candidate.path);
            let Ok(_guard) = self.locks.try_acquire_exclusive(resource).await else {
                report.skipped_locked += 1;
                continue;
            };
            let path = relative.join_under(&self.root);
            match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    tokio::fs::remove_file(path).await?;
                    report.removed_files += 1;
                    report.removed_bytes += metadata.len();
                    if !candidate.temporary {
                        removed_paths.push(candidate.path.clone());
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !removed_paths.is_empty() {
            let _guard = self.locks.acquire_exclusive("cache:index").await?;
            let mut latest = self.load_cache_index().await?;
            for path in removed_paths {
                latest.files.remove(&path);
            }
            self.write_cache_index(&latest).await?;
        }
        Ok(report)
    }

    pub(crate) async fn register(&self, managed: &ManagedFileIndex) -> Result<()> {
        let _guard = self.locks.acquire_exclusive("cache:index").await?;
        let mut index = self.load_cache_index().await?;
        for file in managed
            .files
            .iter()
            .filter(|file| file.location == ManagedFileLocation::Cache)
        {
            index.files.insert(file.path.to_string(), file.clone());
        }
        self.write_cache_index(&index).await
    }

    pub(crate) async fn object(&self, path: &SafeRelativePath) -> Result<Option<ManagedFile>> {
        Ok(self.load_cache_index().await?.files.remove(path.as_str()))
    }

    async fn referenced_cache_paths(&self) -> Result<BTreeSet<String>> {
        let mut paths = BTreeSet::new();
        for instance in self.instances.list().await? {
            if let Ok(index) = load_managed_index(&instance).await {
                paths.extend(
                    index
                        .files
                        .into_iter()
                        .filter(|file| file.location == ManagedFileLocation::Cache)
                        .map(|file| file.path.to_string()),
                );
            }
        }
        Ok(paths)
    }

    async fn load_cache_index(&self) -> Result<CacheIndex> {
        let path = self.root.join("cache-index.json");
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let index: CacheIndex = serde_json::from_slice(&bytes)?;
                if index.format_version != CACHE_INDEX_VERSION {
                    return Err(Error::UnsupportedFormat {
                        kind: "cache index",
                        version: index.format_version,
                    });
                }
                Ok(index)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CacheIndex::default()),
            Err(error) => Err(error.into()),
        }
    }

    async fn write_cache_index(&self, index: &CacheIndex) -> Result<()> {
        atomic_json(&self.root, "cache-index.json", index).await
    }
}

pub(crate) async fn load_managed_index(instance: &Instance) -> Result<ManagedFileIndex> {
    let path = instance.path().join("runtime").join("managed-files.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                Error::Cache(CacheError::MissingManagedIndex(instance.id().to_string()))
            }
            _ => error.into(),
        })?;
    let index: ManagedFileIndex = serde_json::from_slice(&bytes)?;
    if index.format_version != MANAGED_INDEX_VERSION {
        return Err(Error::UnsupportedFormat {
            kind: "managed file index",
            version: index.format_version,
        });
    }
    if index.instance_id != instance.id().as_str() {
        return Err(CacheError::IndexIdentity {
            expected: instance.id().to_string(),
            actual: index.instance_id,
        }
        .into());
    }
    Ok(index)
}

pub(crate) async fn write_managed_index(
    instance: &Instance,
    index: &ManagedFileIndex,
) -> Result<()> {
    atomic_json(
        &instance.path().join("runtime"),
        "managed-files.json",
        index,
    )
    .await
}

pub(crate) async fn snapshot_managed_file(
    base: &Path,
    mut file: ManagedFile,
) -> Result<ManagedFile> {
    let path = file.path.join_under(base);
    let metadata = tokio::fs::symlink_metadata(&path).await?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::UnsafeFilesystemEntry {
            path,
            reason: "managed file must be a real file",
        });
    }
    file.verified_size = metadata.len();
    file.verified_modified_unix_nanos = modified_nanos(&metadata);
    Ok(file)
}

pub(crate) async fn verify_index(
    instance: &Instance,
    cache_root: &Path,
    index: &ManagedFileIndex,
    full: bool,
    concurrency: usize,
) -> Result<VerificationReport> {
    let started = std::time::Instant::now();
    let expected_instance_files = index
        .files
        .iter()
        .filter(|file| file.location == ManagedFileLocation::Instance)
        .map(|file| file.path.to_string())
        .collect::<BTreeSet<_>>();
    let mut checks = futures_util::stream::iter(index.files.iter().cloned())
        .map(|file| {
            let cache_root = cache_root.to_path_buf();
            let instance_root = instance.path().to_path_buf();
            async move { verify_managed_file(&cache_root, &instance_root, &file, full).await }
        })
        .buffer_unordered(concurrency.clamp(1, 16))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    checks
        .extend(find_unindexed_instance_natives(instance.path(), &expected_instance_files).await?);
    Ok(build_report(
        instance.id().to_string(),
        checks,
        started.elapsed(),
    ))
}

async fn find_unindexed_instance_natives(
    instance_root: &Path,
    expected: &BTreeSet<String>,
) -> Result<Vec<FileCheck>> {
    let instance_root = instance_root.to_path_buf();
    let expected = expected.clone();
    tokio::task::spawn_blocking(move || {
        let natives = instance_root.join("runtime").join("natives");
        if !natives.exists() {
            return Ok(Vec::new());
        }
        let mut checks = Vec::new();
        let mut pending = vec![natives];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(&instance_root)
                    .map_err(|_| CacheError::InvalidIndex("native escaped instance root".into()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if expected.contains(&relative) {
                    continue;
                }
                checks.push(FileCheck {
                    id: format!("unexpected-native:{relative}"),
                    path: relative,
                    location: ManagedFileLocation::Instance,
                    kind: ManagedFileKind::ExtractedNative,
                    state: FileState::Unexpected,
                    expected_size: None,
                    actual_size: Some(metadata.len()),
                });
            }
        }
        Ok::<_, Error>(checks)
    })
    .await
    .map_err(|error| Error::Cache(CacheError::InvalidIndex(error.to_string())))?
}

async fn verify_managed_file(
    cache_root: &Path,
    instance_root: &Path,
    file: &ManagedFile,
    full: bool,
) -> Result<FileCheck> {
    let base = match file.location {
        ManagedFileLocation::Cache => cache_root,
        ManagedFileLocation::Instance => instance_root,
    };
    let path = file.path.join_under(base);
    let metadata = match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(check(file, FileState::Missing, None));
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(check(file, FileState::Corrupted, Some(metadata.len())));
    }
    let size = metadata.len();
    if file.expected_size.is_some_and(|expected| expected != size) {
        return Ok(check(file, FileState::Corrupted, Some(size)));
    }
    let metadata_unchanged = file.verified_size == size
        && file.verified_modified_unix_nanos == modified_nanos(&metadata);
    let valid = if !full && metadata_unchanged {
        true
    } else {
        verify_file(&path, file.expected_size, file.expected_hash.as_ref())
            .await
            .is_ok()
    };
    Ok(check(
        file,
        if valid {
            FileState::Valid
        } else {
            FileState::Corrupted
        },
        Some(size),
    ))
}

fn check(file: &ManagedFile, state: FileState, actual_size: Option<u64>) -> FileCheck {
    FileCheck {
        id: file.id.clone(),
        path: file.path.to_string(),
        location: file.location,
        kind: file.kind,
        state,
        expected_size: file.expected_size,
        actual_size,
    }
}

fn build_report(subject: String, checks: Vec<FileCheck>, duration: Duration) -> VerificationReport {
    let mut report = VerificationReport {
        subject,
        metrics: VerificationMetrics {
            files_checked: checks.len() as u64,
            bytes_checked: checks.iter().filter_map(|check| check.actual_size).sum(),
            duration_millis: duration.as_millis().try_into().unwrap_or(u64::MAX),
        },
        checks,
        ..VerificationReport::default()
    };
    for check in &report.checks {
        match check.state {
            FileState::Valid => report.valid += 1,
            FileState::Missing => report.missing += 1,
            FileState::Corrupted => report.corrupted += 1,
            FileState::Unexpected => report.unexpected += 1,
        }
    }
    report
}

fn scan_status(root: &Path) -> Result<CacheStatus> {
    let mut status = CacheStatus::default();
    if !root.exists() {
        return Ok(status);
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| CacheError::InvalidIndex("cache path escaped root".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            let category = if is_temporary(&relative) {
                &mut status.temporary
            } else if relative.starts_with("versions/") {
                &mut status.versions
            } else if relative.starts_with("libraries/") {
                &mut status.libraries
            } else if relative.starts_with("assets/") {
                &mut status.assets
            } else if relative.ends_with(".json") {
                &mut status.metadata
            } else {
                &mut status.other
            };
            category.files += 1;
            category.bytes += metadata.len();
            status.total_files += 1;
            status.total_bytes += metadata.len();
        }
    }
    Ok(status)
}

async fn find_temporary_files(root: &Path) -> Result<Vec<CachePruneEntry>> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        if !root.exists() {
            return Ok(found);
        }
        let mut pending = vec![root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() {
                    let relative = entry
                        .path()
                        .strip_prefix(&root)
                        .map_err(|_| CacheError::InvalidIndex("cache path escaped root".into()))?
                        .to_string_lossy()
                        .replace('\\', "/");
                    if is_temporary(&relative) {
                        found.push(CachePruneEntry {
                            path: relative,
                            bytes: metadata.len(),
                            temporary: true,
                        });
                    }
                }
            }
        }
        Ok::<_, Error>(found)
    })
    .await
    .map_err(|error| Error::Cache(CacheError::InvalidIndex(error.to_string())))?
}

async fn find_unindexed_files(root: &Path, indexed: &BTreeSet<String>) -> Result<Vec<FileCheck>> {
    let root = root.to_path_buf();
    let indexed = indexed.clone();
    tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        if !root.exists() {
            return Ok(found);
        }
        let mut pending = vec![root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(&root)
                    .map_err(|_| CacheError::InvalidIndex("cache path escaped root".into()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative == "cache-index.json" || indexed.contains(&relative) {
                    continue;
                }
                found.push(FileCheck {
                    id: if is_temporary(&relative) {
                        format!("temporary:{relative}")
                    } else {
                        format!("unindexed:{relative}")
                    },
                    path: relative,
                    location: ManagedFileLocation::Cache,
                    kind: ManagedFileKind::Other,
                    state: FileState::Unexpected,
                    expected_size: None,
                    actual_size: Some(metadata.len()),
                });
            }
        }
        Ok::<_, Error>(found)
    })
    .await
    .map_err(|error| Error::Cache(CacheError::InvalidIndex(error.to_string())))?
}

fn is_temporary(path: &str) -> bool {
    path.ends_with(".part") || path.ends_with(".tmp") || path.contains(".staging/")
}

fn cache_lock_key(path: &str) -> String {
    let path = path.strip_suffix(".part").unwrap_or(path);
    format!("cache:{path}")
}

fn modified_nanos(metadata: &std::fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

async fn atomic_json<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<()> {
    tokio::fs::create_dir_all(root).await?;
    let metadata = tokio::fs::symlink_metadata(root).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::UnsafeFilesystemEntry {
            path: root.to_path_buf(),
            reason: "metadata root must be a real directory",
        });
    }
    let destination = root.join(name);
    let temporary = root.join(format!("{name}.{}.tmp", std::process::id()));
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(value)?).await?;
    if tokio::fs::try_exists(&destination).await? {
        let old = tokio::fs::symlink_metadata(&destination).await?;
        if !old.is_file() || old.file_type().is_symlink() {
            return Err(Error::UnsafeFilesystemEntry {
                path: destination,
                reason: "metadata destination must be a real file",
            });
        }
        tokio::fs::remove_file(&destination).await?;
    }
    tokio::fs::rename(temporary, destination).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha1::{Digest, Sha1};

    use super::*;
    use crate::{events::EventBus, files::HashAlgorithm, InstanceSpec};

    #[tokio::test]
    async fn fast_verification_hashes_after_metadata_changes() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let relative = SafeRelativePath::new("libraries/test.jar").expect("path");
        let absolute = relative.join_under(temporary.path());
        tokio::fs::create_dir_all(absolute.parent().expect("parent"))
            .await
            .expect("directory");
        tokio::fs::write(&absolute, b"correct")
            .await
            .expect("write");
        let hash = FileHash::new(
            HashAlgorithm::Sha1,
            format!("{:x}", Sha1::digest(b"correct")),
        )
        .expect("hash");
        let file = snapshot_managed_file(
            temporary.path(),
            ManagedFile {
                id: "test".into(),
                location: ManagedFileLocation::Cache,
                path: relative,
                kind: ManagedFileKind::Library,
                origin: ManagedFileOrigin::Minecraft,
                expected_size: Some(7),
                expected_hash: Some(hash),
                source: None,
                source_path: None,
                repair_from: None,
                verified_size: 0,
                verified_modified_unix_nanos: None,
            },
        )
        .await
        .expect("snapshot");
        tokio::time::sleep(Duration::from_millis(2)).await;
        tokio::fs::write(&absolute, b"invalid")
            .await
            .expect("corrupt");
        let check = verify_managed_file(temporary.path(), temporary.path(), &file, false)
            .await
            .expect("verify");
        assert_eq!(check.state, FileState::Corrupted);
    }

    #[tokio::test]
    async fn prune_never_removes_referenced_cache_files() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let events = EventBus::new(8);
        let locks = LockManager::new(temporary.path().join("locks"));
        let instances = InstanceService::new(
            temporary.path().join("instances"),
            events.clone(),
            locks.clone(),
        );
        let cache = CacheManager::new(
            temporary.path().join("minecraft"),
            instances,
            locks,
            events,
            2,
        );
        let instance = cache
            .instances
            .create(InstanceSpec::vanilla("test", "Test", "1.20.4").expect("spec"))
            .await
            .expect("instance");
        let cache_root = cache.root().to_path_buf();
        let used_path = SafeRelativePath::new("libraries/used.jar").expect("path");
        let unused_path = SafeRelativePath::new("libraries/unused.jar").expect("path");
        tokio::fs::create_dir_all(cache_root.join("libraries"))
            .await
            .expect("directory");
        tokio::fs::write(used_path.join_under(&cache_root), b"used")
            .await
            .expect("used");
        tokio::fs::write(unused_path.join_under(&cache_root), b"unused")
            .await
            .expect("unused");
        let managed = snapshot_managed_file(
            &cache_root,
            ManagedFile {
                id: "used".into(),
                location: ManagedFileLocation::Cache,
                path: used_path.clone(),
                kind: ManagedFileKind::Library,
                origin: ManagedFileOrigin::Minecraft,
                expected_size: Some(4),
                expected_hash: None,
                source: None,
                source_path: None,
                repair_from: None,
                verified_size: 0,
                verified_modified_unix_nanos: None,
            },
        )
        .await
        .expect("managed");
        let unused = snapshot_managed_file(
            &cache_root,
            ManagedFile {
                id: "unused".into(),
                path: unused_path,
                expected_size: Some(6),
                ..managed.clone()
            },
        )
        .await
        .expect("unused");
        let instance_index = ManagedFileIndex::new(
            instance.id().to_string(),
            "1.20.4".into(),
            vec![managed.clone()],
        );
        write_managed_index(&instance, &instance_index)
            .await
            .expect("instance index");
        cache
            .register(&instance_index)
            .await
            .expect("register used");
        cache
            .register(&ManagedFileIndex::new(
                "removed-instance".into(),
                "1.20.4".into(),
                vec![unused],
            ))
            .await
            .expect("register unused");
        tokio::fs::write(cache_root.join("abandoned.part"), b"partial")
            .await
            .expect("temporary");

        let verification = cache.verify(true).await.expect("cache verify");
        assert_eq!(verification.unexpected, 1);

        let report = cache
            .prune(&CachePolicy::default(), true)
            .await
            .expect("prune plan");
        assert!(report
            .candidates
            .iter()
            .all(|candidate| candidate.path != used_path.as_str()));
        assert!(report
            .candidates
            .iter()
            .any(|candidate| candidate.path == "libraries/unused.jar"));
        let executed = cache
            .prune(&CachePolicy::default(), false)
            .await
            .expect("prune");
        assert_eq!(executed.removed_files, 2);
        assert!(used_path.join_under(&cache_root).is_file());
        assert!(!cache_root.join("libraries/unused.jar").exists());
        assert!(cache
            .verify(true)
            .await
            .expect("verify after prune")
            .is_healthy());
    }

    #[tokio::test]
    #[ignore = "advisory real-filesystem performance measurement"]
    async fn benchmark_quick_and_full_verify_four_thousand_files() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let events = EventBus::new(8);
        let locks = LockManager::new(temporary.path().join("locks"));
        let instances =
            InstanceService::new(temporary.path().join("instances"), events.clone(), locks);
        let instance = instances
            .create(InstanceSpec::vanilla("benchmark", "Benchmark", "1.21.1").expect("spec"))
            .await
            .expect("instance");
        let root = instance.path().to_path_buf();
        let files = tokio::task::spawn_blocking(move || {
            let hash = FileHash::new(
                HashAlgorithm::Sha1,
                format!("{:x}", Sha1::digest(b"benchmark-payload")),
            )
            .expect("hash");
            let mut files = Vec::with_capacity(4_000);
            for index in 0..4_000 {
                let relative = SafeRelativePath::new(format!(".minecraft/bench/file-{index}.bin"))
                    .expect("path");
                let absolute = relative.join_under(&root);
                std::fs::create_dir_all(absolute.parent().expect("parent")).expect("directory");
                std::fs::write(&absolute, b"benchmark-payload").expect("file");
                let metadata = std::fs::metadata(&absolute).expect("metadata");
                files.push(ManagedFile {
                    id: format!("benchmark-{index}"),
                    location: ManagedFileLocation::Instance,
                    path: relative,
                    kind: ManagedFileKind::Other,
                    origin: ManagedFileOrigin::Provider,
                    expected_size: Some(metadata.len()),
                    expected_hash: Some(hash.clone()),
                    source: None,
                    source_path: None,
                    repair_from: None,
                    verified_size: metadata.len(),
                    verified_modified_unix_nanos: modified_nanos(&metadata),
                });
            }
            files
        })
        .await
        .expect("fixture worker");
        let index = ManagedFileIndex::new("benchmark".into(), "1.21.1".into(), files);
        let quick = verify_index(&instance, temporary.path(), &index, false, 8)
            .await
            .expect("quick verify");
        let full = verify_index(&instance, temporary.path(), &index, true, 8)
            .await
            .expect("full verify");
        eprintln!(
            "verify-4000 quick={}ms full={}ms",
            quick.metrics.duration_millis, full.metrics.duration_millis
        );
        assert_eq!(quick.valid, 4_000);
        assert_eq!(full.valid, 4_000);
    }
}
