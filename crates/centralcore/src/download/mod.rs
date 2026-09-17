//! Central HTTP client, resumable downloads, integrity checks, and cancellation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::{header, Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use url::Url;

use crate::{
    events::{CoreEvent, EventBus},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    lock::LockManager,
    Error, Result,
};

/// Limits and retry behavior shared by all downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadConfig {
    pub concurrency: usize,
    pub timeout_seconds: u64,
    pub retries: u8,
    pub max_file_size: u64,
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

impl DownloadConfig {
    /// Validates bounded resource settings.
    pub fn validate(&self) -> Result<()> {
        if !(1..=64).contains(&self.concurrency) {
            return Err(Error::InvalidConfig(
                "download concurrency must be between 1 and 64".into(),
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > 3_600 {
            return Err(Error::InvalidConfig(
                "download timeout must be between 1 and 3600 seconds".into(),
            ));
        }
        if self.retries > 20 {
            return Err(Error::InvalidConfig(
                "download retries cannot exceed 20".into(),
            ));
        }
        if self.max_file_size == 0 {
            return Err(Error::InvalidConfig(
                "download max_file_size must be non-zero".into(),
            ));
        }
        if self
            .allowed_hosts
            .iter()
            .any(|host| host.is_empty() || host.contains('/'))
        {
            return Err(Error::InvalidConfig(
                "download allowed_hosts contains an invalid host".into(),
            ));
        }
        Ok(())
    }
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            timeout_seconds: 30,
            retries: 3,
            max_file_size: 2 * 1024 * 1024 * 1024,
            allow_insecure_http: false,
            allowed_hosts: Vec::new(),
        }
    }
}

/// One validated file transfer requested by a core subsystem.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRequest {
    pub id: String,
    pub source: Url,
    pub destination: SafeRelativePath,
    pub expected_size: Option<u64>,
    pub expected_hash: Option<FileHash>,
}

impl fmt::Debug for DownloadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DownloadRequest")
            .field("id", &self.id)
            .field("source", &redacted_url(&self.source))
            .field("destination", &self.destination)
            .field("expected_size", &self.expected_size)
            .field("expected_hash", &self.expected_hash)
            .finish()
    }
}

/// Cooperative cancellation handle for one operation or operation group.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notification: Arc<Notify>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notification: Arc::new(Notify::new()),
        }
    }
}

impl CancellationToken {
    /// Requests cancellation. Repeated calls are harmless.
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notification.notify_waiters();
        }
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Completes as soon as cancellation is requested, including if already cancelled.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notification.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// Result of a completed or cache-hit transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadOutcome {
    pub path: PathBuf,
    pub bytes: u64,
    pub reused: bool,
}

/// Result of a bounded conditional HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConditionalFetch {
    /// The server confirmed that the caller's cached representation is current.
    NotModified,
    /// A new, bounded representation and its cache validators were returned.
    Modified {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Failures produced by the central HTTP/download layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DownloadError {
    #[error("download was cancelled")]
    Cancelled,
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("HTTP server returned status {status} for {url}")]
    HttpStatus { status: StatusCode, url: String },
    #[error("download exceeded the configured size limit of {limit} bytes")]
    SizeLimit { limit: u64 },
    #[error("size mismatch for `{path}`: expected {expected}, got {actual}")]
    SizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("checksum mismatch for `{path}`")]
    ChecksumMismatch { path: PathBuf },
    #[error("unsafe download destination `{path}`: {reason}")]
    UnsafeDestination { path: PathBuf, reason: &'static str },
    #[error("I/O error while downloading: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

/// Shared download service with one pooled HTTP client.
#[derive(Debug, Clone)]
pub struct DownloadManager {
    config: DownloadConfig,
    events: EventBus,
    client: Client,
    locks: Option<LockManager>,
}

impl DownloadManager {
    pub(crate) fn new(config: DownloadConfig, events: EventBus) -> Result<Self> {
        config.validate()?;
        let redirects_allow_http = config.allow_insecure_http;
        let redirect_hosts = config.allowed_hosts.clone();
        let client = Client::builder()
            .user_agent(format!("CentralCore/{}", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(config.timeout_seconds))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("too many redirects");
                }
                let target = attempt.url();
                let previous_https = attempt
                    .previous()
                    .last()
                    .is_some_and(|url| url.scheme() == "https");
                if previous_https && target.scheme() != "https" {
                    return attempt.error("HTTPS redirect downgrade is forbidden");
                }
                if target.scheme() != "https"
                    && !(redirects_allow_http && target.scheme() == "http")
                {
                    return attempt.error("redirect target scheme is forbidden");
                }
                let Some(host) = target.host_str() else {
                    return attempt.error("redirect target has no host");
                };
                if !redirects_allow_http && redirect_host_is_private(host) {
                    return attempt.error("redirect target is a private network address");
                }
                if !redirect_hosts.is_empty()
                    && !redirect_hosts
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(host))
                {
                    return attempt.error("redirect target host is not allowed");
                }
                attempt.follow()
            }))
            .https_only(!config.allow_insecure_http)
            .build()
            .map_err(DownloadError::from)?;
        Ok(Self {
            config,
            events,
            client,
            locks: None,
        })
    }

    pub(crate) fn with_locks(mut self, locks: LockManager) -> Self {
        self.locks = Some(locks);
        self
    }

    #[must_use]
    pub fn config(&self) -> &DownloadConfig {
        &self.config
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        CancellationToken::default()
    }

    pub fn validate_request(&self, request: &DownloadRequest) -> Result<()> {
        if request.id.is_empty()
            || request.id.len() > 128
            || request.id.chars().any(char::is_control)
        {
            return Err(Error::InvalidConfig("download id is invalid".into()));
        }
        self.validate_url(&request.source)?;
        if request
            .expected_size
            .is_some_and(|size| size > self.config.max_file_size)
        {
            return Err(DownloadError::SizeLimit {
                limit: self.config.max_file_size,
            }
            .into());
        }
        Ok(())
    }

    /// Fetches a bounded response into memory and verifies optional metadata.
    pub async fn fetch_bytes(
        &self,
        url: &Url,
        expected_size: Option<u64>,
        expected_hash: Option<&FileHash>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>> {
        self.validate_url(url)?;
        if limit == 0 || limit > self.config.max_file_size {
            return Err(Error::InvalidConfig(
                "invalid in-memory download limit".into(),
            ));
        }
        let mut last_error = None;
        for attempt in 0..=self.config.retries {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled.into());
            }
            match self.fetch_bytes_once(url, limit, cancellation).await {
                Ok(bytes) => {
                    match verify_bytes(
                        &bytes,
                        expected_size,
                        expected_hash,
                        Path::new("HTTP response"),
                    ) {
                        Ok(()) => return Ok(bytes),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
            if attempt < self.config.retries {
                tokio::time::sleep(retry_delay(attempt)).await;
            }
        }
        Err(last_error.unwrap_or(DownloadError::Cancelled).into())
    }

    /// Fetches and deserializes a bounded JSON document.
    pub async fn fetch_json<T: DeserializeOwned>(
        &self,
        url: &Url,
        expected_size: Option<u64>,
        expected_hash: Option<&FileHash>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<T> {
        let bytes = self
            .fetch_bytes(url, expected_size, expected_hash, limit, cancellation)
            .await?;
        serde_json::from_slice(&bytes)
            .map_err(DownloadError::from)
            .map_err(Error::from)
    }

    /// Fetches a bounded document using standard HTTP cache validators.
    pub(crate) async fn fetch_conditional(
        &self,
        url: &Url,
        etag: Option<&str>,
        last_modified: Option<&str>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> Result<ConditionalFetch> {
        self.validate_url(url)?;
        if limit == 0 || limit > self.config.max_file_size {
            return Err(Error::InvalidConfig(
                "invalid in-memory download limit".into(),
            ));
        }
        let mut last_error = None;
        for attempt in 0..=self.config.retries {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled.into());
            }
            match self
                .fetch_conditional_once(url, etag, last_modified, limit, cancellation)
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
            if attempt < self.config.retries {
                tokio::time::sleep(retry_delay(attempt)).await;
            }
        }
        Err(last_error.unwrap_or(DownloadError::Cancelled).into())
    }

    /// Downloads one file below `root`, resuming a `.part` file when supported.
    pub async fn download(
        &self,
        root: &Path,
        request: &DownloadRequest,
        cancellation: &CancellationToken,
    ) -> Result<DownloadOutcome> {
        self.validate_request(request)?;
        let _resource_lock = if let Some(locks) = &self.locks {
            Some(
                locks
                    .acquire_exclusive(format!("cache:{}", request.destination))
                    .await?,
            )
        } else {
            None
        };
        let destination = request.destination.join_under(root);
        ensure_safe_parent(root, &request.destination).await?;

        if tokio::fs::try_exists(&destination).await?
            && verify_file(
                &destination,
                request.expected_size,
                request.expected_hash.as_ref(),
            )
            .await
            .is_ok()
        {
            let bytes = tokio::fs::metadata(&destination).await?.len();
            return Ok(DownloadOutcome {
                path: destination,
                bytes,
                reused: true,
            });
        }
        reject_symlink_if_present(&destination).await?;
        if tokio::fs::try_exists(&destination).await? {
            tokio::fs::remove_file(&destination).await?;
        }

        self.events.emit(CoreEvent::FileDownloadStarted {
            download_id: request.id.clone(),
            path: request.destination.to_string(),
            expected_bytes: request.expected_size,
        });

        let part = part_path(&destination)?;
        reject_symlink_if_present(&part).await?;
        let mut last_error = None;
        for attempt in 0..=self.config.retries {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled.into());
            }
            match self.download_once(request, &part, cancellation).await {
                Ok(()) => {
                    match verify_file(&part, request.expected_size, request.expected_hash.as_ref())
                        .await
                    {
                        Ok(bytes) => {
                            tokio::fs::rename(&part, &destination).await?;
                            self.events.emit(CoreEvent::FileDownloadCompleted {
                                download_id: request.id.clone(),
                                path: request.destination.to_string(),
                            });
                            return Ok(DownloadOutcome {
                                path: destination,
                                bytes,
                                reused: false,
                            });
                        }
                        Err(error) => {
                            let _ = tokio::fs::remove_file(&part).await;
                            last_error = Some(error);
                        }
                    }
                }
                Err(error) => last_error = Some(error),
            }
            if attempt < self.config.retries {
                tokio::time::sleep(retry_delay(attempt)).await;
            }
        }
        let error = last_error.unwrap_or(DownloadError::Cancelled);
        self.events.emit(CoreEvent::FileDownloadFailed {
            download_id: request.id.clone(),
            message: error.to_string(),
        });
        Err(error.into())
    }

    /// Downloads a bounded batch without creating an unbounded number of tasks.
    pub async fn download_all(
        &self,
        root: &Path,
        requests: Vec<DownloadRequest>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<DownloadOutcome>> {
        let concurrency = self.config.concurrency;
        let results = futures_util::stream::iter(
            requests
                .iter()
                .map(|request| async move { self.download(root, request, cancellation).await }),
        )
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
        results.into_iter().collect()
    }

    /// Finalizes an already complete `.part` file without making a network
    /// request. This is used during crash recovery and offline repair.
    pub async fn recover_local(&self, root: &Path, request: &DownloadRequest) -> Result<bool> {
        self.validate_request(request)?;
        let _resource_lock = if let Some(locks) = &self.locks {
            Some(
                locks
                    .acquire_exclusive(format!("cache:{}", request.destination))
                    .await?,
            )
        } else {
            None
        };
        ensure_safe_parent(root, &request.destination).await?;
        let destination = request.destination.join_under(root);
        reject_symlink_if_present(&destination).await?;
        if tokio::fs::try_exists(&destination).await?
            && verify_file(
                &destination,
                request.expected_size,
                request.expected_hash.as_ref(),
            )
            .await
            .is_ok()
        {
            return Ok(true);
        }
        let part = part_path(&destination)?;
        reject_symlink_if_present(&part).await?;
        if !tokio::fs::try_exists(&part).await?
            || verify_file(&part, request.expected_size, request.expected_hash.as_ref())
                .await
                .is_err()
        {
            return Ok(false);
        }
        if tokio::fs::try_exists(&destination).await? {
            tokio::fs::remove_file(&destination).await?;
        }
        tokio::fs::rename(part, destination).await?;
        Ok(true)
    }

    #[must_use]
    pub fn events(&self) -> &EventBus {
        &self.events
    }

    fn validate_url(&self, url: &Url) -> Result<()> {
        let scheme_allowed =
            url.scheme() == "https" || (url.scheme() == "http" && self.config.allow_insecure_http);
        if !scheme_allowed {
            return Err(Error::InvalidConfig(format!(
                "URL scheme `{}` is not allowed",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidConfig(
                "download URL user information is forbidden".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidConfig("download URL has no host".into()))?;
        if !self.config.allowed_hosts.is_empty()
            && !self
                .config
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(Error::InvalidConfig(format!(
                "download host `{host}` is not allowed"
            )));
        }
        Ok(())
    }

    async fn fetch_bytes_once(
        &self,
        url: &Url,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Vec<u8>, DownloadError> {
        let response = self.client.get(url.clone()).send().await?;
        if !response.status().is_success() {
            return Err(DownloadError::HttpStatus {
                status: response.status(),
                url: redacted_url(url),
            });
        }
        if response.content_length().is_some_and(|size| size > limit) {
            return Err(DownloadError::SizeLimit { limit });
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled);
            }
            let chunk = chunk?;
            if bytes.len() as u64 + chunk.len() as u64 > limit {
                return Err(DownloadError::SizeLimit { limit });
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn fetch_conditional_once(
        &self,
        url: &Url,
        etag: Option<&str>,
        last_modified: Option<&str>,
        limit: u64,
        cancellation: &CancellationToken,
    ) -> std::result::Result<ConditionalFetch, DownloadError> {
        let mut request = self.client.get(url.clone());
        if let Some(value) = etag {
            request = request.header(header::IF_NONE_MATCH, value);
        }
        if let Some(value) = last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, value);
        }
        let response = request.send().await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(ConditionalFetch::NotModified);
        }
        if !response.status().is_success() {
            return Err(DownloadError::HttpStatus {
                status: response.status(),
                url: redacted_url(url),
            });
        }
        if response.content_length().is_some_and(|size| size > limit) {
            return Err(DownloadError::SizeLimit { limit });
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled);
            }
            let chunk = chunk?;
            if bytes.len() as u64 + chunk.len() as u64 > limit {
                return Err(DownloadError::SizeLimit { limit });
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(ConditionalFetch::Modified {
            bytes,
            etag,
            last_modified,
        })
    }

    async fn download_once(
        &self,
        request: &DownloadRequest,
        part: &Path,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), DownloadError> {
        let existing = match tokio::fs::metadata(part).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let mut http = self.client.get(request.source.clone());
        if existing > 0 {
            http = http.header(header::RANGE, format!("bytes={existing}-"));
        }
        let response = http.send().await?;
        if response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
            return Ok(());
        }
        if !response.status().is_success() {
            return Err(DownloadError::HttpStatus {
                status: response.status(),
                url: redacted_url(&request.source),
            });
        }
        let append = existing > 0 && response.status() == StatusCode::PARTIAL_CONTENT;
        if append {
            let expected_prefix = format!("bytes {existing}-");
            let content_range = response
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok());
            if !content_range.is_some_and(|value| value.starts_with(&expected_prefix)) {
                return Err(DownloadError::Io(std::io::Error::other(
                    "server returned an invalid Content-Range",
                )));
            }
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(part)
            .await?;
        let initial = if append { existing } else { 0 };
        let mut downloaded = initial;
        let started = Instant::now();
        let mut last_event = Instant::now();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if cancellation.is_cancelled() {
                return Err(DownloadError::Cancelled);
            }
            let chunk = chunk?;
            downloaded = downloaded.saturating_add(chunk.len() as u64);
            if downloaded > self.config.max_file_size {
                return Err(DownloadError::SizeLimit {
                    limit: self.config.max_file_size,
                });
            }
            file.write_all(&chunk).await?;
            if last_event.elapsed() >= Duration::from_millis(200) {
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                self.events.emit(CoreEvent::FileDownloadProgress {
                    download_id: request.id.clone(),
                    downloaded_bytes: downloaded,
                    expected_bytes: request.expected_size,
                    bytes_per_second: ((downloaded - initial) as f64 / elapsed) as u64,
                    completed_files: 0,
                    total_files: 1,
                });
                last_event = Instant::now();
            }
        }
        file.flush().await?;
        Ok(())
    }
}

fn retry_delay(attempt: u8) -> Duration {
    Duration::from_millis(200 * 2_u64.pow(u32::from(attempt.min(5))))
}

fn redacted_url(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or("<missing-host>"),
        url.path()
    )
}

fn redirect_host_is_private(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(address) => private_v4(address),
        IpAddr::V6(address) => private_v6(address),
    })
}

fn private_v4(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.octets()[0] == 0
        || address.octets()[0] >= 224
}

fn private_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    address.is_loopback()
        || address.is_unspecified()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

fn part_path(destination: &Path) -> std::result::Result<PathBuf, DownloadError> {
    let name = destination
        .file_name()
        .ok_or_else(|| DownloadError::UnsafeDestination {
            path: destination.to_path_buf(),
            reason: "destination has no file name",
        })?;
    let mut part_name = name.to_os_string();
    part_name.push(".part");
    Ok(destination.with_file_name(part_name))
}

async fn reject_symlink_if_present(path: &Path) -> std::result::Result<(), DownloadError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(DownloadError::UnsafeDestination {
                path: path.to_path_buf(),
                reason: "existing destination must be a regular file",
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn ensure_safe_parent(
    root: &Path,
    relative: &SafeRelativePath,
) -> std::result::Result<(), DownloadError> {
    tokio::fs::create_dir_all(root).await?;
    let root_metadata = tokio::fs::symlink_metadata(root).await?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(DownloadError::UnsafeDestination {
            path: root.to_path_buf(),
            reason: "download root must be a real directory",
        });
    }
    let parts = relative.as_str().split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current.push(part);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(DownloadError::UnsafeDestination {
                    path: current,
                    reason: "download parent must be a real directory",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match tokio::fs::create_dir(&current).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = tokio::fs::symlink_metadata(&current).await?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(DownloadError::UnsafeDestination {
                                path: current,
                                reason: "concurrently created parent is not a real directory",
                            });
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Verifies a file without loading it into memory and returns its size.
pub async fn verify_file(
    path: &Path,
    expected_size: Option<u64>,
    expected_hash: Option<&FileHash>,
) -> std::result::Result<u64, DownloadError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        sha1.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    if expected_size.is_some_and(|expected| expected != total) {
        return Err(DownloadError::SizeMismatch {
            path: path.to_path_buf(),
            expected: expected_size.unwrap_or_default(),
            actual: total,
        });
    }
    if let Some(expected) = expected_hash {
        let actual = match expected.algorithm() {
            HashAlgorithm::Sha1 => format!("{:x}", sha1.finalize()),
            HashAlgorithm::Sha256 => format!("{:x}", sha256.finalize()),
        };
        if actual != expected.value() {
            return Err(DownloadError::ChecksumMismatch {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(total)
}

/// Computes a supported digest without loading the file into memory.
pub async fn compute_hash(
    path: &Path,
    algorithm: HashAlgorithm,
) -> std::result::Result<FileHash, DownloadError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        match algorithm {
            HashAlgorithm::Sha1 => sha1.update(&buffer[..read]),
            HashAlgorithm::Sha256 => sha256.update(&buffer[..read]),
        }
    }
    let value = match algorithm {
        HashAlgorithm::Sha1 => format!("{:x}", sha1.finalize()),
        HashAlgorithm::Sha256 => format!("{:x}", sha256.finalize()),
    };
    FileHash::new(algorithm, value)
        .map_err(|error| DownloadError::Io(std::io::Error::other(error.to_string())))
}

fn verify_bytes(
    bytes: &[u8],
    expected_size: Option<u64>,
    expected_hash: Option<&FileHash>,
    path: &Path,
) -> std::result::Result<(), DownloadError> {
    if expected_size.is_some_and(|expected| expected != bytes.len() as u64) {
        return Err(DownloadError::SizeMismatch {
            path: path.to_path_buf(),
            expected: expected_size.unwrap_or_default(),
            actual: bytes.len() as u64,
        });
    }
    if let Some(expected) = expected_hash {
        let actual = match expected.algorithm() {
            HashAlgorithm::Sha1 => format!("{:x}", Sha1::digest(bytes)),
            HashAlgorithm::Sha256 => format!("{:x}", Sha256::digest(bytes)),
        };
        if actual != expected.value() {
            return Err(DownloadError::ChecksumMismatch {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_urls_are_required_by_default() {
        let manager =
            DownloadManager::new(DownloadConfig::default(), EventBus::new(8)).expect("manager");
        let request = DownloadRequest {
            id: "test".into(),
            source: Url::parse("http://example.test/file").expect("URL"),
            destination: SafeRelativePath::new("file.bin").expect("path"),
            expected_size: None,
            expected_hash: None,
        };
        assert!(manager.validate_request(&request).is_err());
    }

    #[tokio::test]
    async fn verifies_sha1_and_size() {
        let temporary = tempfile::NamedTempFile::new().expect("temporary file");
        tokio::fs::write(temporary.path(), b"centralcore")
            .await
            .expect("write");
        let hash = FileHash::new(
            HashAlgorithm::Sha1,
            format!("{:x}", Sha1::digest(b"centralcore")),
        )
        .expect("hash");
        assert_eq!(
            verify_file(temporary.path(), Some(11), Some(&hash))
                .await
                .expect("verify"),
            11
        );
    }

    #[tokio::test]
    async fn finalizes_a_complete_partial_file_without_network() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let manager =
            DownloadManager::new(DownloadConfig::default(), EventBus::new(8)).expect("manager");
        let request = DownloadRequest {
            id: "recovery".into(),
            source: Url::parse("https://example.test/recovery.bin").expect("URL"),
            destination: SafeRelativePath::new("objects/recovery.bin").expect("path"),
            expected_size: Some(8),
            expected_hash: Some(
                FileHash::new(
                    HashAlgorithm::Sha1,
                    format!("{:x}", Sha1::digest(b"complete")),
                )
                .expect("hash"),
            ),
        };
        let destination = request.destination.join_under(temporary.path());
        tokio::fs::create_dir_all(destination.parent().expect("parent"))
            .await
            .expect("directory");
        tokio::fs::write(part_path(&destination).expect("part"), b"complete")
            .await
            .expect("partial file");
        assert!(manager
            .recover_local(temporary.path(), &request)
            .await
            .expect("recovery"));
        assert_eq!(
            tokio::fs::read(destination).await.expect("final file"),
            b"complete"
        );
    }
}
