//! Recovery of installation states left behind by an interrupted process.

use serde::{Deserialize, Serialize};

use crate::{
    cache::{load_managed_index, verify_index},
    events::CoreEvent,
    instance::InstanceStatus,
    Error, Result,
};

use super::MinecraftManager;

/// Startup reconciliation result for interrupted instance transactions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub recovered: u64,
    pub recoverable: u64,
    pub active_elsewhere: u64,
}

/// Structured transaction recovery failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    #[error("could not inspect interrupted instance `{instance_id}`: {reason}")]
    Inspection { instance_id: String, reason: String },
}

impl MinecraftManager {
    /// Reconciles abandoned `Installing` states without disturbing operations
    /// that still hold their instance lock in another process.
    pub async fn recover(&self) -> Result<RecoveryReport> {
        self.events.emit(CoreEvent::RecoveryStarted);
        let mut report = RecoveryReport::default();
        for instance in self.instances.list().await? {
            if !matches!(
                self.instances.status(instance.id().to_string()).await?,
                InstanceStatus::Installing | InstanceStatus::Updating | InstanceStatus::Recoverable
            ) {
                continue;
            }
            let lock = match self
                .locks
                .try_acquire_exclusive(format!("instance:{}", instance.id()))
                .await
            {
                Ok(lock) => lock,
                Err(error) if error.is_lock_busy() => {
                    report.active_elsewhere += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            restore_abandoned_update(instance.path()).await?;
            let instance = self.instances.get(instance.id().to_string()).await?;
            let recovered = match load_managed_index(&instance).await {
                Ok(index) => verify_index(
                    &instance,
                    &self.cache_root,
                    &index,
                    true,
                    self.downloads.config().concurrency,
                )
                .await
                .map(|verification| verification.is_healthy())
                .unwrap_or(false),
                Err(_) => false,
            };
            if recovered {
                self.instances.mark_installed(&instance).await?;
                report.recovered += 1;
            } else {
                self.instances
                    .mark_interrupted(&instance, "previous installation was interrupted")
                    .await?;
                report.recoverable += 1;
            }
            cleanup_abandoned_staging(instance.path()).await?;
            drop(lock);
        }
        self.events.emit(CoreEvent::RecoveryCompleted {
            recovered_instances: report.recovered,
            recoverable_instances: report.recoverable,
        });
        Ok(report)
    }
}

async fn cleanup_abandoned_staging(instance_root: &std::path::Path) -> Result<()> {
    let staging = instance_root.join("runtime").join(".staging");
    let metadata = match tokio::fs::symlink_metadata(&staging).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::UnsafeFilesystemEntry {
            path: staging,
            reason: "transaction staging root must be a real directory",
        });
    }
    let mut entries = tokio::fs::read_dir(&staging).await?;
    while let Some(entry) = entries.next_entry().await? {
        let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::UnsafeFilesystemEntry {
                path: entry.path(),
                reason: "transaction staging entry must be a real directory",
            });
        }
        tokio::fs::remove_dir_all(entry.path()).await?;
    }
    Ok(())
}

async fn restore_abandoned_update(instance_root: &std::path::Path) -> Result<()> {
    let runtime = instance_root.join("runtime");
    let mut entries = match tokio::fs::read_dir(&runtime).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("update-") {
            continue;
        }
        let staging = entry.path();
        let metadata = tokio::fs::symlink_metadata(&staging).await?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::UnsafeFilesystemEntry {
                path: staging,
                reason: "update recovery staging must be a real directory",
            });
        }
        let backup_root = staging.join("backups");
        if tokio::fs::try_exists(&backup_root).await? {
            restore_backup_tree(instance_root, &backup_root).await?;
        }
        restore_metadata_file(
            &staging.join("instance.json.previous"),
            &instance_root.join("instance.json"),
        )
        .await?;
        restore_metadata_file(
            &staging.join("managed-files.json.previous"),
            &runtime.join("managed-files.json"),
        )
        .await?;
        tokio::fs::remove_dir_all(staging).await?;
    }
    Ok(())
}

async fn restore_backup_tree(
    instance_root: &std::path::Path,
    backup_root: &std::path::Path,
) -> Result<()> {
    let mut directories = vec![backup_root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let metadata = tokio::fs::symlink_metadata(&directory).await?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::UnsafeFilesystemEntry {
                path: directory,
                reason: "update backup entry must be a real directory",
            });
        }
        let mut entries = tokio::fs::read_dir(&directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if metadata.file_type().is_symlink() {
                return Err(Error::UnsafeFilesystemEntry {
                    path,
                    reason: "symbolic links are forbidden in update backups",
                });
            }
            if metadata.is_dir() {
                directories.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(Error::UnsafeFilesystemEntry {
                    path,
                    reason: "update backup entry must be a regular file",
                });
            }
            let relative =
                path.strip_prefix(backup_root)
                    .map_err(|_| Error::UnsafeFilesystemEntry {
                        path: path.clone(),
                        reason: "update backup escaped its root",
                    })?;
            let destination = instance_root.join(relative);
            ensure_recovery_parents(instance_root, destination.parent().unwrap_or(instance_root))
                .await?;
            if tokio::fs::try_exists(&destination).await? {
                let existing = tokio::fs::symlink_metadata(&destination).await?;
                if existing.file_type().is_symlink() || !existing.is_file() {
                    return Err(Error::UnsafeFilesystemEntry {
                        path: destination,
                        reason: "update recovery destination must be a real file",
                    });
                }
                tokio::fs::remove_file(&destination).await?;
            }
            tokio::fs::rename(path, destination).await?;
        }
    }
    Ok(())
}

async fn restore_metadata_file(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<()> {
    if !tokio::fs::try_exists(source).await? {
        return Ok(());
    }
    let metadata = tokio::fs::symlink_metadata(source).await?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::UnsafeFilesystemEntry {
            path: source.to_path_buf(),
            reason: "update recovery metadata must be a real file",
        });
    }
    if tokio::fs::try_exists(destination).await? {
        let existing = tokio::fs::symlink_metadata(destination).await?;
        if existing.file_type().is_symlink() || !existing.is_file() {
            return Err(Error::UnsafeFilesystemEntry {
                path: destination.to_path_buf(),
                reason: "metadata recovery destination must be a real file",
            });
        }
        tokio::fs::remove_file(destination).await?;
    }
    tokio::fs::rename(source, destination).await?;
    Ok(())
}

async fn ensure_recovery_parents(root: &std::path::Path, parent: &std::path::Path) -> Result<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| Error::UnsafeFilesystemEntry {
            path: parent.to_path_buf(),
            reason: "update recovery parent escaped instance root",
        })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::UnsafeFilesystemEntry {
                    path: current,
                    reason: "update recovery parent must be a real directory",
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

#[cfg(test)]
mod tests {
    use crate::{
        cache::{write_managed_index, ManagedFileIndex},
        CentralCore, InstanceSpec,
    };

    use super::*;

    #[tokio::test]
    async fn abandoned_install_becomes_recoverable_on_restart() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let core = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("core");
        let instance = core
            .instances()
            .create(InstanceSpec::vanilla("recovery", "Recovery", "1.20.4").expect("spec"))
            .await
            .expect("instance");
        core.instances()
            .mark_installing(&instance)
            .await
            .expect("installing");
        let abandoned = instance.path().join("runtime/.staging/install-abandoned");
        tokio::fs::create_dir_all(&abandoned)
            .await
            .expect("staging");
        drop(core);

        let recovered = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("restart");
        assert_eq!(
            recovered
                .instances()
                .status("recovery")
                .await
                .expect("status"),
            InstanceStatus::Recoverable
        );
        assert!(!abandoned.exists());
    }

    #[tokio::test]
    async fn abandoned_update_restores_backups_before_verification() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let core = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("core");
        let instance = core
            .instances()
            .create(InstanceSpec::vanilla("update-recovery", "Recovery", "1.20.4").expect("spec"))
            .await
            .expect("instance");
        write_managed_index(
            &instance,
            &ManagedFileIndex::new(instance.id().to_string(), "1.20.4".into(), Vec::new()),
        )
        .await
        .expect("index");
        let target = instance.path().join(".minecraft/config/managed.json");
        tokio::fs::create_dir_all(target.parent().expect("parent"))
            .await
            .expect("config");
        tokio::fs::write(&target, b"new").await.expect("new file");
        let backup = instance
            .path()
            .join("runtime/update-abandoned/backups/.minecraft/config/managed.json");
        tokio::fs::create_dir_all(backup.parent().expect("backup parent"))
            .await
            .expect("backup directory");
        tokio::fs::write(&backup, b"old").await.expect("backup");
        core.instances()
            .mark_updating(&instance)
            .await
            .expect("updating");
        drop(core);

        let recovered = CentralCore::builder()
            .data_dir(temporary.path())
            .build()
            .await
            .expect("restart");
        assert_eq!(tokio::fs::read(&target).await.expect("restored"), b"old");
        assert_eq!(
            recovered
                .instances()
                .status("update-recovery")
                .await
                .expect("status"),
            InstanceStatus::Installed
        );
    }
}
