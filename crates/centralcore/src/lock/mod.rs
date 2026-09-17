//! Cross-process, resource-scoped filesystem locks.

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Failures produced while coordinating work with another process.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum LockError {
    #[error("resource `{resource}` is locked by another CentralCore process")]
    Busy { resource: String },
    #[error("lock resource key is invalid")]
    InvalidKey,
    #[error("lock filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("lock worker failed: {0}")]
    Worker(String),
}

#[derive(Debug, Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

/// Factory for granular operating-system file locks.
#[derive(Debug, Clone)]
pub(crate) struct LockManager {
    root: PathBuf,
    wait_timeout: Duration,
    held: Arc<Mutex<HashSet<String>>>,
}

impl LockManager {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            wait_timeout: Duration::from_secs(30),
            held: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Acquires an exclusive resource lock, waiting for a bounded duration.
    pub async fn acquire_exclusive(&self, resource: impl Into<String>) -> Result<ResourceLock> {
        self.acquire(resource.into(), LockMode::Exclusive, self.wait_timeout)
            .await
    }

    /// Acquires an exclusive lock with an operation-specific bounded wait.
    pub(crate) async fn acquire_exclusive_for(
        &self,
        resource: impl Into<String>,
        timeout: Duration,
    ) -> Result<ResourceLock> {
        self.acquire(resource.into(), LockMode::Exclusive, timeout)
            .await
    }

    /// Acquires a shared resource lock, waiting for a bounded duration.
    pub async fn acquire_shared(&self, resource: impl Into<String>) -> Result<ResourceLock> {
        self.acquire(resource.into(), LockMode::Shared, self.wait_timeout)
            .await
    }

    /// Attempts an exclusive lock without waiting.
    pub async fn try_acquire_exclusive(&self, resource: impl Into<String>) -> Result<ResourceLock> {
        self.acquire(resource.into(), LockMode::Exclusive, Duration::ZERO)
            .await
    }

    async fn acquire(
        &self,
        resource: String,
        mode: LockMode,
        timeout: Duration,
    ) -> Result<ResourceLock> {
        validate_resource(&resource)?;
        let root = self.root.clone();
        let held = self.held.clone();
        tokio::task::spawn_blocking(move || acquire_blocking(root, resource, mode, timeout, held))
            .await
            .map_err(|error| LockError::Worker(error.to_string()))?
            .map_err(Error::from)
    }
}

/// An acquired lock. Dropping it releases the OS lock even after cancellation.
#[derive(Debug)]
pub(crate) struct ResourceLock {
    file: File,
    resource: String,
    held: Arc<Mutex<HashSet<String>>>,
}

impl Drop for ResourceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
        if let Ok(mut held) = self.held.lock() {
            held.remove(&self.resource);
        }
    }
}

#[derive(Serialize)]
struct LockOwner<'a> {
    format_version: u32,
    resource: &'a str,
    pid: u32,
    acquired_unix_seconds: u64,
}

fn acquire_blocking(
    root: PathBuf,
    resource: String,
    mode: LockMode,
    timeout: Duration,
    held: Arc<Mutex<HashSet<String>>>,
) -> std::result::Result<ResourceLock, LockError> {
    prepare_root(&root)?;
    let digest = format!("{:x}", Sha256::digest(resource.as_bytes()));
    let path = root.join(format!("{digest}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    let started = Instant::now();
    loop {
        let reserved = held
            .lock()
            .map_err(|_| std::io::Error::other("in-process lock registry was poisoned"))?
            .insert(resource.clone());
        if reserved {
            break;
        }
        if started.elapsed() >= timeout {
            return Err(LockError::Busy { resource });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    loop {
        let acquired = match mode {
            LockMode::Shared => FileExt::try_lock_shared(&file),
            LockMode::Exclusive => FileExt::try_lock_exclusive(&file),
        };
        match acquired {
            Ok(()) => break,
            Err(error) if is_busy_error(&error) => {
                if started.elapsed() >= timeout {
                    if let Ok(mut held) = held.lock() {
                        held.remove(&resource);
                    }
                    return Err(LockError::Busy { resource });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                if let Ok(mut held) = held.lock() {
                    held.remove(&resource);
                }
                return Err(error.into());
            }
        }
    }
    let mut guard = ResourceLock {
        file,
        resource,
        held,
    };
    if matches!(mode, LockMode::Exclusive) {
        let owner = LockOwner {
            format_version: 1,
            resource: &guard.resource,
            pid: std::process::id(),
            acquired_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        guard.file.set_len(0)?;
        guard.file.seek(SeekFrom::Start(0))?;
        serde_json::to_writer(&mut guard.file, &owner).map_err(std::io::Error::other)?;
        guard.file.flush()?;
    }
    Ok(guard)
}

fn is_busy_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
    ) || (cfg!(windows) && error.raw_os_error() == Some(33))
}

fn prepare_root(root: &Path) -> std::result::Result<(), LockError> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(std::io::Error::other("lock root is not a real directory").into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(root)?;
            let metadata = std::fs::symlink_metadata(root)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(std::io::Error::other("lock root is not a real directory").into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_resource(resource: &str) -> std::result::Result<(), LockError> {
    if resource.is_empty() || resource.len() > 1_024 || resource.chars().any(char::is_control) {
        return Err(LockError::InvalidKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[tokio::test]
    async fn coordinates_exclusive_locks_between_managers() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let first = LockManager::new(temporary.path().to_path_buf());
        let second = first.clone();
        let guard = first
            .try_acquire_exclusive("instance:test")
            .await
            .expect("first lock");
        assert!(matches!(
            second.try_acquire_exclusive("instance:test").await,
            Err(Error::Lock { .. })
        ));
        drop(guard);
        second
            .try_acquire_exclusive("instance:test")
            .await
            .expect("released lock");
    }

    #[tokio::test]
    async fn operating_system_lock_blocks_another_process() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let marker = temporary.path().join("ready");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "lock::tests::lock_holder_child",
                "--ignored",
                "--nocapture",
            ])
            .env("CENTRALCORE_LOCK_TEST_ROOT", temporary.path())
            .env("CENTRALCORE_LOCK_TEST_MARKER", &marker)
            .spawn()
            .expect("lock holder");
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(marker.exists(), "lock holder did not become ready");
        let manager = LockManager::new(temporary.path().to_path_buf());
        let blocked = manager.try_acquire_exclusive("cross-process").await;
        child.kill().expect("kill holder");
        child.wait().expect("wait holder");
        assert!(
            matches!(blocked, Err(Error::Lock { .. })),
            "unexpected lock result: {blocked:?}"
        );
        manager
            .try_acquire_exclusive("cross-process")
            .await
            .expect("OS released lock after process exit");
    }

    #[tokio::test]
    #[ignore = "helper process spawned by operating_system_lock_blocks_another_process"]
    async fn lock_holder_child() {
        let root = PathBuf::from(std::env::var_os("CENTRALCORE_LOCK_TEST_ROOT").expect("root"));
        let marker =
            PathBuf::from(std::env::var_os("CENTRALCORE_LOCK_TEST_MARKER").expect("marker"));
        let manager = LockManager::new(root);
        let _guard = manager
            .acquire_exclusive("cross-process")
            .await
            .expect("holder lock");
        std::fs::write(marker, b"ready").expect("marker");
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
