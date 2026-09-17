//! Transactional installation of shared, managed Java runtimes.

use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use super::{
    JavaArchiveKind, JavaDistribution, JavaDistributionProvider, JavaDistributionRequest,
    JavaRequirement, JavaRuntime, JavaSource, SystemJavaProvider,
};
use crate::{
    download::{verify_file, CancellationToken, DownloadManager, DownloadRequest},
    events::{CoreEvent, EventBus},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    lock::LockManager,
    platform::Platform,
    Error, Result,
};

pub const RUNTIME_MANIFEST_FORMAT_VERSION: u32 = 1;
const MAX_EXTRACTED_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

/// Versioned identity and integrity record for one committed runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifest {
    pub format_version: u32,
    pub runtime_id: String,
    pub distribution: JavaDistribution,
    pub executable: SafeRelativePath,
    pub installed_at: u64,
}

/// Runtime returned by managed-runtime listing and verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedJavaRuntime {
    pub id: String,
    pub directory: PathBuf,
    pub runtime: JavaRuntime,
    pub manifest: RuntimeManifest,
}

#[derive(Clone)]
pub struct ManagedJavaProvider {
    root: PathBuf,
    cache_root: PathBuf,
    downloads: DownloadManager,
    locks: LockManager,
    events: EventBus,
    providers: Arc<RwLock<BTreeMap<String, Arc<dyn JavaDistributionProvider>>>>,
    inspector: SystemJavaProvider,
}

impl std::fmt::Debug for ManagedJavaProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedJavaProvider")
            .field("root", &self.root)
            .field("cache_root", &self.cache_root)
            .finish_non_exhaustive()
    }
}

impl ManagedJavaProvider {
    pub(super) fn new(
        root: PathBuf,
        cache_root: PathBuf,
        downloads: DownloadManager,
        locks: LockManager,
        events: EventBus,
        default_provider: Arc<dyn JavaDistributionProvider>,
    ) -> Self {
        let providers = BTreeMap::from([(default_provider.id().to_owned(), default_provider)]);
        Self {
            root,
            cache_root,
            downloads,
            locks,
            inspector: SystemJavaProvider::new(events.clone()),
            events,
            providers: Arc::new(RwLock::new(providers)),
        }
    }

    /// Registers or replaces a locally trusted, compile-time provider.
    pub async fn register(&self, provider: Arc<dyn JavaDistributionProvider>) -> Result<()> {
        validate_provider_id(provider.id())?;
        self.providers
            .write()
            .await
            .insert(provider.id().to_owned(), provider);
        Ok(())
    }

    pub async fn provider_ids(&self) -> Vec<String> {
        self.providers.read().await.keys().cloned().collect()
    }

    pub async fn available(
        &self,
        requirement: JavaRequirement,
        cancellation: &CancellationToken,
    ) -> Result<Vec<JavaDistribution>> {
        let providers = self
            .providers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut available = Vec::new();
        let mut last_error = None;
        let request = JavaDistributionRequest {
            requirement,
            operating_system: Platform::current().os,
        };
        for provider in providers {
            if cancellation.is_cancelled() {
                return Err(crate::download::DownloadError::Cancelled.into());
            }
            match provider.resolve(request, cancellation).await {
                Ok(distribution) => {
                    validate_distribution(provider.id(), request, &distribution)?;
                    available.push(distribution);
                }
                Err(error) => {
                    tracing::debug!(provider = provider.id(), %error, "Java distribution unavailable");
                    last_error = Some(error);
                }
            }
        }
        if available.is_empty() {
            if let Some(error) = last_error {
                return Err(error);
            }
        }
        Ok(available)
    }

    pub async fn install(
        &self,
        requirement: JavaRequirement,
        cancellation: &CancellationToken,
    ) -> Result<ManagedJavaRuntime> {
        if let Some(distribution) = self
            .cached_distributions(requirement)
            .await?
            .into_iter()
            .next()
        {
            return self
                .install_distribution(distribution, requirement, cancellation)
                .await;
        }
        let remote = self.available(requirement, cancellation).await;
        let distribution = match remote {
            Ok(distributions) => distributions.into_iter().next(),
            Err(error) => {
                if cancellation.is_cancelled() {
                    return Err(crate::download::DownloadError::Cancelled.into());
                }
                tracing::debug!(%error, "Java provider metadata unavailable; checking local cache");
                None
            }
        };
        let distribution = match distribution {
            Some(distribution) => distribution,
            None => self
                .cached_distributions(requirement)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::Java(format!(
                        "Java {} is required but no compatible runtime is installed or available in the local cache",
                        requirement.major_version
                    ))
                })?,
        };
        self.install_distribution(distribution, requirement, cancellation)
            .await
    }

    /// Installs a previously downloaded archive without resolving remote metadata.
    pub async fn install_cached(
        &self,
        requirement: JavaRequirement,
        cancellation: &CancellationToken,
    ) -> Result<ManagedJavaRuntime> {
        let distribution = self
            .cached_distributions(requirement)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                Error::Java(format!(
                    "Java {} is required but no compatible runtime is installed or available in the local cache",
                    requirement.major_version
                ))
            })?;
        self.install_distribution(distribution, requirement, cancellation)
            .await
    }

    async fn install_distribution(
        &self,
        distribution: JavaDistribution,
        requirement: JavaRequirement,
        cancellation: &CancellationToken,
    ) -> Result<ManagedJavaRuntime> {
        let request = JavaDistributionRequest {
            requirement,
            operating_system: Platform::current().os,
        };
        validate_distribution(&distribution.provider, request, &distribution)?;
        if !self
            .providers
            .read()
            .await
            .contains_key(&distribution.provider)
        {
            return Err(Error::Java(format!(
                "Java distribution provider `{}` is not locally trusted",
                distribution.provider
            )));
        }
        let runtime_id = runtime_id(&distribution);
        let _lock = self
            .locks
            .acquire_exclusive_for(
                format!("java-runtime:{runtime_id}"),
                Duration::from_secs(15 * 60),
            )
            .await?;
        if let Ok(runtime) = self.verify(&runtime_id).await {
            return Ok(runtime);
        }

        tokio::fs::create_dir_all(&self.root).await?;
        tokio::fs::create_dir_all(&self.cache_root).await?;
        let hash = FileHash::new(HashAlgorithm::Sha256, &distribution.archive_sha256)?;
        let extension = match distribution.archive_kind {
            JavaArchiveKind::Zip => "zip",
            JavaArchiveKind::TarGz => "tar.gz",
        };
        let archive_relative = SafeRelativePath::new(format!(
            "objects/sha256/{}/{}.{}",
            &distribution.archive_sha256[..2],
            distribution.archive_sha256,
            extension
        ))?;
        self.events.emit(CoreEvent::JavaRuntimeDownloadStarted {
            provider: distribution.provider.clone(),
            major_version: distribution.major_version,
        });
        let download_id = format!("java-{runtime_id}");
        let mut progress = self.events.subscribe();
        let progress_events = self.events.clone();
        let progress_provider = distribution.provider.clone();
        let observed_download = download_id.clone();
        let progress_task = tokio::spawn(async move {
            while let Ok(event) = progress.recv().await {
                match event {
                    CoreEvent::FileDownloadProgress {
                        download_id,
                        downloaded_bytes,
                        expected_bytes,
                        bytes_per_second,
                        ..
                    } if download_id == observed_download => {
                        progress_events.emit(CoreEvent::JavaRuntimeDownloadProgress {
                            provider: progress_provider.clone(),
                            downloaded_bytes,
                            expected_bytes,
                            bytes_per_second,
                        });
                    }
                    CoreEvent::FileDownloadCompleted { download_id, .. }
                    | CoreEvent::FileDownloadFailed { download_id, .. }
                        if download_id == observed_download =>
                    {
                        break
                    }
                    _ => {}
                }
            }
        });
        let outcome = self
            .downloads
            .download(
                &self.cache_root,
                &DownloadRequest {
                    id: download_id,
                    source: distribution.archive_url.clone(),
                    destination: archive_relative,
                    expected_size: distribution.archive_size,
                    expected_hash: Some(hash),
                },
                cancellation,
            )
            .await;
        progress_task.abort();
        let outcome = outcome?;
        self.persist_cached_distribution(&runtime_id, &distribution)
            .await?;
        self.events.emit(CoreEvent::JavaRuntimeDownloaded {
            provider: distribution.provider.clone(),
            major_version: distribution.major_version,
        });

        self.events.emit(CoreEvent::JavaRuntimeInstallStarted {
            provider: distribution.provider.clone(),
            major_version: distribution.major_version,
        });
        let staging = self.staging_path(&runtime_id);
        tokio::fs::create_dir_all(&staging).await?;
        let archive = outcome.path;
        let kind = distribution.archive_kind;
        let extraction_root = staging.join("payload");
        let extraction_token = cancellation.clone();
        let extraction_root_worker = extraction_root.clone();
        let extraction = tokio::task::spawn_blocking(move || {
            extract_archive(&archive, kind, &extraction_root_worker, &extraction_token)
        })
        .await
        .map_err(|error| Error::Java(format!("Java extraction worker failed: {error}")))?;
        if let Err(error) = extraction {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(error);
        }
        if cancellation.is_cancelled() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(crate::download::DownloadError::Cancelled.into());
        }

        let executable = find_java_executable(&extraction_root)?;
        ensure_executable(&executable)?;
        let inspected = self
            .inspector
            .inspect(&executable, JavaSource::Managed)
            .await?;
        if inspected.version.major < requirement.major_version
            || inspected.architecture != requirement.architecture
        {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(Error::Java(
                "downloaded Java runtime is incompatible".into(),
            ));
        }
        let executable_relative = executable
            .strip_prefix(&staging)
            .map_err(|_| Error::Java("runtime executable escaped staging".into()))?;
        let executable_relative = SafeRelativePath::new(
            executable_relative
                .to_str()
                .ok_or_else(|| Error::Java("runtime path is not Unicode".into()))?
                .replace('\\', "/"),
        )?;
        let manifest = RuntimeManifest {
            format_version: RUNTIME_MANIFEST_FORMAT_VERSION,
            runtime_id: runtime_id.clone(),
            distribution: distribution.clone(),
            executable: executable_relative,
            installed_at: unix_now(),
        };
        tokio::fs::write(
            staging.join("runtime.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )
        .await?;
        let destination = self.runtime_directory(distribution.major_version, &runtime_id)?;
        if tokio::fs::try_exists(&destination).await? {
            tokio::fs::remove_dir_all(&destination).await?;
        }
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&staging, &destination).await?;
        let installed = self.verify(&runtime_id).await?;
        self.events.emit(CoreEvent::JavaRuntimeInstalled {
            provider: distribution.provider,
            major_version: distribution.major_version,
        });
        Ok(installed)
    }

    pub async fn list(&self) -> Result<Vec<ManagedJavaRuntime>> {
        if !tokio::fs::try_exists(&self.root).await? {
            return Ok(Vec::new());
        }
        let mut runtimes = Vec::new();
        let mut majors = tokio::fs::read_dir(&self.root).await?;
        while let Some(major) = majors.next_entry().await? {
            if !major.file_type().await?.is_dir()
                || major.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            let mut entries = tokio::fs::read_dir(major.path()).await?;
            while let Some(entry) = entries.next_entry().await? {
                if !entry.file_type().await?.is_dir() {
                    continue;
                }
                if let Some(id) = entry.file_name().to_str() {
                    if let Ok(runtime) = self.verify(id).await {
                        runtimes.push(runtime);
                    }
                }
            }
        }
        runtimes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(runtimes)
    }

    pub async fn verify(&self, runtime_id: &str) -> Result<ManagedJavaRuntime> {
        validate_runtime_id(runtime_id)?;
        let directory = self.find_runtime_directory(runtime_id).await?;
        let manifest_path = directory.join("runtime.json");
        let bytes = tokio::fs::read(&manifest_path).await?;
        let manifest: RuntimeManifest = serde_json::from_slice(&bytes)?;
        if manifest.format_version != RUNTIME_MANIFEST_FORMAT_VERSION
            || manifest.runtime_id != runtime_id
            || super::managed::runtime_id(&manifest.distribution) != runtime_id
        {
            return Err(Error::Java("invalid managed Java manifest".into()));
        }
        validate_distribution(
            &manifest.distribution.provider,
            JavaDistributionRequest {
                requirement: JavaRequirement::new(
                    manifest.distribution.major_version,
                    manifest.distribution.architecture,
                ),
                operating_system: Platform::current().os,
            },
            &manifest.distribution,
        )?;
        let executable = manifest.executable.join_under(&directory);
        self.events.emit(CoreEvent::JavaRuntimeVerificationStarted {
            executable: executable.display().to_string(),
        });
        let inspected = self
            .inspector
            .inspect(&executable, JavaSource::Managed)
            .await?;
        if inspected.version.major != manifest.distribution.major_version
            || inspected.architecture != manifest.distribution.architecture
        {
            return Err(Error::Java(
                "managed Java manifest does not match executable".into(),
            ));
        }
        let runtime = JavaRuntime::from(&inspected);
        self.events
            .emit(CoreEvent::JavaRuntimeVerificationCompleted {
                executable: runtime.executable.display().to_string(),
                major_version: runtime.major_version,
            });
        Ok(ManagedJavaRuntime {
            id: runtime_id.to_owned(),
            directory,
            runtime,
            manifest,
        })
    }

    /// Reinstalls a damaged runtime transactionally, reusing its verified archive cache.
    pub async fn repair(
        &self,
        runtime_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<ManagedJavaRuntime> {
        validate_runtime_id(runtime_id)?;
        let directory = self.find_runtime_directory(runtime_id).await?;
        let manifest: RuntimeManifest =
            serde_json::from_slice(&tokio::fs::read(directory.join("runtime.json")).await?)?;
        if manifest.format_version != RUNTIME_MANIFEST_FORMAT_VERSION
            || manifest.runtime_id != runtime_id
            || super::managed::runtime_id(&manifest.distribution) != runtime_id
        {
            return Err(Error::Java("invalid managed Java manifest".into()));
        }
        let requirement = JavaRequirement::new(
            manifest.distribution.major_version,
            manifest.distribution.architecture,
        );
        self.install_distribution(manifest.distribution, requirement, cancellation)
            .await
    }

    pub(crate) async fn remove(&self, runtime_id: &str) -> Result<()> {
        validate_runtime_id(runtime_id)?;
        let _lock = self
            .locks
            .acquire_exclusive(format!("java-runtime:{runtime_id}"))
            .await?;
        let directory = self.find_runtime_directory(runtime_id).await?;
        tokio::fs::remove_dir_all(directory).await?;
        Ok(())
    }

    pub async fn recover(&self) -> Result<()> {
        if !tokio::fs::try_exists(&self.root).await? {
            return Ok(());
        }
        let mut entries = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir()
                && entry.file_name().to_string_lossy().starts_with(".install-")
            {
                tokio::fs::remove_dir_all(entry.path()).await?;
            }
        }
        Ok(())
    }

    async fn cached_distributions(
        &self,
        requirement: JavaRequirement,
    ) -> Result<Vec<JavaDistribution>> {
        let root = self.cache_root.join("distributions");
        if !tokio::fs::try_exists(&root).await? {
            return Ok(Vec::new());
        }
        let request = JavaDistributionRequest {
            requirement,
            operating_system: Platform::current().os,
        };
        let trusted = self
            .providers
            .read()
            .await
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut entries = tokio::fs::read_dir(root).await?;
        let mut distributions = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(entry.path()).await else {
                continue;
            };
            let Ok(distribution) = serde_json::from_slice::<JavaDistribution>(&bytes) else {
                continue;
            };
            if !trusted.contains(&distribution.provider) {
                continue;
            }
            if validate_distribution(&distribution.provider, request, &distribution).is_err() {
                continue;
            }
            let Ok(path) = self.archive_path(&distribution) else {
                continue;
            };
            let Ok(hash) = FileHash::new(HashAlgorithm::Sha256, &distribution.archive_sha256)
            else {
                continue;
            };
            if verify_file(&path, distribution.archive_size, Some(&hash))
                .await
                .is_ok()
            {
                distributions.push(distribution);
            }
        }
        distributions.sort_by(|left, right| {
            left.major_version
                .cmp(&right.major_version)
                .then_with(|| left.provider.cmp(&right.provider))
        });
        Ok(distributions)
    }

    async fn persist_cached_distribution(
        &self,
        runtime_id: &str,
        distribution: &JavaDistribution,
    ) -> Result<()> {
        let root = self.cache_root.join("distributions");
        tokio::fs::create_dir_all(&root).await?;
        let destination = root.join(format!("{runtime_id}.json"));
        let temporary = root.join(format!(".{runtime_id}.{}.tmp", std::process::id()));
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(distribution)?).await?;
        if tokio::fs::try_exists(&destination).await? {
            tokio::fs::remove_file(&destination).await?;
        }
        tokio::fs::rename(temporary, destination).await?;
        Ok(())
    }

    fn archive_path(&self, distribution: &JavaDistribution) -> Result<PathBuf> {
        let extension = match distribution.archive_kind {
            JavaArchiveKind::Zip => "zip",
            JavaArchiveKind::TarGz => "tar.gz",
        };
        let relative = SafeRelativePath::new(format!(
            "objects/sha256/{}/{}.{}",
            &distribution.archive_sha256[..2],
            distribution.archive_sha256,
            extension
        ))?;
        Ok(relative.join_under(&self.cache_root))
    }

    fn staging_path(&self, runtime_id: &str) -> PathBuf {
        self.root.join(format!(
            ".install-{runtime_id}-{}-{}",
            std::process::id(),
            unix_now()
        ))
    }

    fn runtime_directory(&self, major: u16, runtime_id: &str) -> Result<PathBuf> {
        validate_runtime_id(runtime_id)?;
        Ok(self.root.join(major.to_string()).join(runtime_id))
    }

    async fn find_runtime_directory(&self, runtime_id: &str) -> Result<PathBuf> {
        let mut majors = tokio::fs::read_dir(&self.root)
            .await
            .map_err(|_| Error::NotFound {
                kind: "managed Java runtime",
                id: runtime_id.to_owned(),
            })?;
        while let Some(major) = majors.next_entry().await? {
            let candidate = major.path().join(runtime_id);
            if tokio::fs::try_exists(candidate.join("runtime.json")).await? {
                return Ok(candidate);
            }
        }
        Err(Error::NotFound {
            kind: "managed Java runtime",
            id: runtime_id.to_owned(),
        })
    }
}

fn validate_distribution(
    provider_id: &str,
    request: JavaDistributionRequest,
    distribution: &JavaDistribution,
) -> Result<()> {
    validate_provider_id(provider_id)?;
    if distribution.provider != provider_id
        || distribution.major_version < request.requirement.major_version
        || distribution.architecture != request.requirement.architecture
        || distribution.operating_system != request.operating_system
        || distribution.vendor.is_empty()
        || distribution.version.is_empty()
    {
        return Err(Error::Java(
            "distribution metadata does not satisfy request".into(),
        ));
    }
    FileHash::new(HashAlgorithm::Sha256, &distribution.archive_sha256)?;
    Ok(())
}

fn validate_provider_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::InvalidConfig("invalid Java provider id".into()));
    }
    Ok(())
}

fn validate_runtime_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "invalid managed Java runtime id".into(),
        ));
    }
    Ok(())
}

fn runtime_id(distribution: &JavaDistribution) -> String {
    let identity = format!(
        "{}|{}|{}|{:?}|{:?}",
        distribution.provider,
        distribution.vendor,
        distribution.version,
        distribution.operating_system,
        distribution.architecture
    );
    let suffix = format!("{:x}", Sha256::digest(identity.as_bytes()));
    let version = distribution
        .version
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("{}-{version}-{}", distribution.provider, &suffix[..12])
}

fn extract_archive(
    archive: &Path,
    kind: JavaArchiveKind,
    destination: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    fs::create_dir_all(destination)?;
    match kind {
        JavaArchiveKind::Zip => extract_zip(archive, destination, cancellation),
        JavaArchiveKind::TarGz => extract_tar_gz(archive, destination, cancellation),
    }
}

fn extract_zip(
    archive_path: &Path,
    destination: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    let file = fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| Error::Java(format!("invalid Java ZIP archive: {error}")))?;
    if archive.len() > MAX_ENTRIES {
        return Err(Error::Java("Java archive has too many entries".into()));
    }
    let mut total = 0_u64;
    for index in 0..archive.len() {
        if cancellation.is_cancelled() {
            return Err(crate::download::DownloadError::Cancelled.into());
        }
        let mut entry = archive
            .by_index(index)
            .map_err(|error| Error::Java(format!("invalid Java ZIP entry: {error}")))?;
        let name = entry.name().replace('\\', "/");
        let name = name.trim_end_matches('/');
        if name.is_empty() {
            continue;
        }
        let relative = SafeRelativePath::new(name.to_owned())?;
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(Error::Java(
                "symbolic links are forbidden in Java archives".into(),
            ));
        }
        if entry.size() > MAX_ENTRY_SIZE {
            return Err(Error::Java("Java archive entry exceeds size limit".into()));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_EXTRACTED_SIZE {
            return Err(Error::Java("Java archive exceeds extraction limit".into()));
        }
        let output = relative.join_under(destination);
        if entry.is_dir() {
            fs::create_dir_all(output)?;
            continue;
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut target = fs::File::create(&output)?;
        io::copy(&mut entry, &mut target)?;
        restore_archive_permissions(&output, entry.unix_mode())?;
    }
    Ok(())
}

fn extract_tar_gz(
    archive_path: &Path,
    destination: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    let file = fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0_usize;
    let mut total = 0_u64;
    for entry in archive.entries()? {
        if cancellation.is_cancelled() {
            return Err(crate::download::DownloadError::Cancelled.into());
        }
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(Error::Java("Java archive has too many entries".into()));
        }
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(Error::Java("links are forbidden in Java archives".into()));
        }
        if !entry_type.is_file() && !entry_type.is_dir() {
            continue;
        }
        let size = entry.header().size()?;
        let mode = entry.header().mode().ok();
        if size > MAX_ENTRY_SIZE {
            return Err(Error::Java("Java archive entry exceeds size limit".into()));
        }
        total = total.saturating_add(size);
        if total > MAX_EXTRACTED_SIZE {
            return Err(Error::Java("Java archive exceeds extraction limit".into()));
        }
        let path = entry.path()?;
        let relative = SafeRelativePath::new(
            path.to_str()
                .ok_or_else(|| Error::Java("Java archive path is not Unicode".into()))?
                .replace('\\', "/"),
        )?;
        let output = relative.join_under(destination);
        if entry_type.is_dir() {
            fs::create_dir_all(output)?;
            continue;
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut target = fs::File::create(&output)?;
        io::copy(&mut entry, &mut target)?;
        restore_archive_permissions(&output, mode)?;
    }
    Ok(())
}

fn find_java_executable(root: &Path) -> Result<PathBuf> {
    let expected = if cfg!(windows) { "java.exe" } else { "java" };
    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    let mut candidates = Vec::new();
    while let Some((directory, depth)) = stack.pop() {
        if depth > 8 {
            continue;
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(Error::Java(
                    "symbolic links are forbidden in Java runtime".into(),
                ));
            }
            if metadata.is_dir() {
                stack.push((entry.path(), depth + 1));
            } else if entry.file_name() == expected
                && entry.path().parent().and_then(Path::file_name)
                    == Some(std::ffi::OsStr::new("bin"))
            {
                candidates.push(entry.path());
            }
        }
    }
    candidates.sort_by_key(|path| path.components().count());
    candidates
        .into_iter()
        .next()
        .ok_or_else(|| Error::Java("Java archive contains no executable".into()))
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn restore_archive_permissions(path: &Path, archive_mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = archive_mode {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600 | (mode & 0o111));
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_archive_permissions(_path: &Path, _archive_mode: Option<u32>) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable(path: &Path) -> Result<()> {
    if fs::metadata(path)?.is_file() {
        Ok(())
    } else {
        Err(Error::Java("Java executable is not a file".into()))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct UnavailableProvider;

    #[async_trait::async_trait]
    impl JavaDistributionProvider for UnavailableProvider {
        fn id(&self) -> &str {
            "unavailable"
        }

        async fn resolve(
            &self,
            _request: JavaDistributionRequest,
            _cancellation: &CancellationToken,
        ) -> Result<JavaDistribution> {
            Err(Error::Java("offline".into()))
        }
    }

    fn distribution(checksum: String, size: u64) -> JavaDistribution {
        JavaDistribution {
            provider: "unavailable".into(),
            vendor: "Test".into(),
            version: "21.0.4+7".into(),
            major_version: 21,
            operating_system: Platform::current().os,
            architecture: Platform::current().architecture,
            archive_url: url::Url::parse("https://example.test/java.zip").expect("URL"),
            archive_sha256: checksum,
            archive_size: Some(size),
            archive_kind: JavaArchiveKind::Zip,
        }
    }

    fn manager(root: &Path) -> ManagedJavaProvider {
        let events = EventBus::new(32);
        let downloads =
            DownloadManager::new(Default::default(), events.clone()).expect("download manager");
        ManagedJavaProvider::new(
            root.join("runtimes"),
            root.join("cache"),
            downloads,
            LockManager::new(root.join("locks")),
            events,
            Arc::new(UnavailableProvider),
        )
    }

    #[test]
    fn runtime_identity_is_stable_and_archive_rejects_traversal() {
        let distribution = distribution("ab".repeat(32), 1);
        assert_eq!(runtime_id(&distribution), runtime_id(&distribution));

        let temporary = tempfile::tempdir().expect("temporary");
        let archive_path = temporary.path().join("bad.zip");
        let file = fs::File::create(&archive_path).expect("archive");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("../../evil.exe", zip::write::SimpleFileOptions::default())
            .expect("entry");
        zip.write_all(b"bad").expect("write");
        zip.finish().expect("finish");
        assert!(extract_zip(
            &archive_path,
            &temporary.path().join("out"),
            &CancellationToken::default()
        )
        .is_err());
        assert!(!temporary.path().join("evil.exe").exists());
    }

    #[test]
    fn cancelled_extraction_does_not_create_payload_files() {
        let temporary = tempfile::tempdir().expect("temporary");
        let archive_path = temporary.path().join("runtime.zip");
        let file = fs::File::create(&archive_path).expect("archive");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("runtime/bin/java", zip::write::SimpleFileOptions::default())
            .expect("entry");
        zip.write_all(b"java").expect("write");
        zip.finish().expect("finish");
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let destination = temporary.path().join("out");
        assert!(extract_zip(&archive_path, &destination, &cancellation).is_err());
        assert!(!destination.join("runtime/bin/java").exists());
    }

    #[tokio::test]
    async fn verified_archive_metadata_is_available_offline_and_corruption_is_rejected() {
        let temporary = tempfile::tempdir().expect("temporary");
        let manager = manager(temporary.path());
        let bytes = b"verified archive";
        let checksum = format!("{:x}", Sha256::digest(bytes));
        let distribution = distribution(checksum, bytes.len() as u64);
        let id = runtime_id(&distribution);
        let archive = manager.archive_path(&distribution).expect("archive path");
        tokio::fs::create_dir_all(archive.parent().expect("parent"))
            .await
            .expect("cache directory");
        tokio::fs::write(&archive, bytes).await.expect("archive");
        manager
            .persist_cached_distribution(&id, &distribution)
            .await
            .expect("metadata");

        let requirement = JavaRequirement::current(21);
        assert_eq!(
            manager
                .cached_distributions(requirement)
                .await
                .expect("cached")
                .len(),
            1
        );
        tokio::fs::write(&archive, b"corrupt")
            .await
            .expect("corrupt archive");
        assert!(manager
            .cached_distributions(requirement)
            .await
            .expect("cached")
            .is_empty());
    }

    #[tokio::test]
    async fn recovery_removes_only_interrupted_staging_directories() {
        let temporary = tempfile::tempdir().expect("temporary");
        let manager = manager(temporary.path());
        tokio::fs::create_dir_all(manager.root.join(".install-interrupted"))
            .await
            .expect("staging");
        tokio::fs::create_dir_all(manager.root.join("21/valid-runtime"))
            .await
            .expect("valid");
        manager.recover().await.expect("recover");
        assert!(!manager.root.join(".install-interrupted").exists());
        assert!(manager.root.join("21/valid-runtime").exists());
    }
}
