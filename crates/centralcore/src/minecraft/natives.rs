//! Safe extraction of downloaded native archives.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{files::SafeRelativePath, Result};

use super::MinecraftError;

const MAX_NATIVE_ENTRY_SIZE: u64 = 256 * 1024 * 1024;
const MAX_NATIVE_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeArchive {
    pub path: PathBuf,
    pub exclusions: Vec<String>,
}

pub(crate) async fn extract_natives(
    archives: Vec<NativeArchive>,
    destination: PathBuf,
) -> Result<()> {
    tokio::task::spawn_blocking(move || extract_natives_blocking(&archives, &destination))
        .await
        .map_err(|error| MinecraftError::NativeExtraction {
            archive: "native worker".into(),
            reason: error.to_string(),
        })??;
    Ok(())
}

fn extract_natives_blocking(archives: &[NativeArchive], destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let mut total_size = 0_u64;
    for native in archives {
        let file = fs::File::open(&native.path)?;
        let mut archive =
            zip::ZipArchive::new(file).map_err(|error| native_error(&native.path, error))?;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| native_error(&native.path, error))?;
            let name = entry.name().replace('\\', "/");
            if native
                .exclusions
                .iter()
                .any(|excluded| name.starts_with(excluded))
            {
                continue;
            }
            if entry.is_dir() {
                continue;
            }
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err(MinecraftError::NativeExtraction {
                    archive: native.path.display().to_string(),
                    reason: format!("symbolic-link entry `{name}` is forbidden"),
                }
                .into());
            }
            if entry.size() > MAX_NATIVE_ENTRY_SIZE {
                return Err(MinecraftError::NativeExtraction {
                    archive: native.path.display().to_string(),
                    reason: format!("entry `{name}` exceeds the size limit"),
                }
                .into());
            }
            total_size = total_size.saturating_add(entry.size());
            if total_size > MAX_NATIVE_TOTAL_SIZE {
                return Err(MinecraftError::NativeExtraction {
                    archive: native.path.display().to_string(),
                    reason: "native archives exceed the total extraction limit".into(),
                }
                .into());
            }
            let safe = SafeRelativePath::new(name.clone()).map_err(|error| {
                MinecraftError::NativeExtraction {
                    archive: native.path.display().to_string(),
                    reason: error.to_string(),
                }
            })?;
            let output = safe.join_under(destination);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output_file = fs::File::create(&output)?;
            io::copy(&mut entry, &mut output_file)?;
        }
    }
    Ok(())
}

fn native_error(path: &Path, error: zip::result::ZipError) -> crate::Error {
    MinecraftError::NativeExtraction {
        archive: path.display().to_string(),
        reason: error.to_string(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn rejects_zip_slip_entries() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let archive_path = temporary.path().join("native.zip");
        let file = fs::File::create(&archive_path).expect("archive");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("../../evil.dll", zip::write::SimpleFileOptions::default())
            .expect("entry");
        zip.write_all(b"bad").expect("write");
        zip.finish().expect("finish");

        let result = extract_natives_blocking(
            &[NativeArchive {
                path: archive_path,
                exclusions: Vec::new(),
            }],
            &temporary.path().join("out"),
        );
        assert!(result.is_err());
        assert!(!temporary.path().join("evil.dll").exists());
    }
}
