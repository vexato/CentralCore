use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use tokio::process::Command;

use crate::{
    download::{compute_hash, verify_file, CancellationToken},
    events::{CoreEvent, EventBus},
    files::HashAlgorithm,
    instance::Instance,
    java::{JavaManager, JavaRequirement},
    Result,
};

use super::{LoaderError, LoaderPlan, ProcessorArgument, ProcessorPlan};

const PLAN_FILE: &str = "runtime/loader-plan.json";

pub(crate) async fn write_loader_plan(instance: &Instance, plan: &LoaderPlan) -> Result<()> {
    plan.validate()?;
    let runtime = instance.path().join("runtime");
    tokio::fs::create_dir_all(&runtime).await?;
    let bytes = serde_json::to_vec_pretty(plan)?;
    let temporary = runtime.join("loader-plan.json.tmp");
    tokio::fs::write(&temporary, bytes).await?;
    let target = instance.path().join(PLAN_FILE);
    if tokio::fs::try_exists(&target).await? {
        tokio::fs::remove_file(&target).await?;
    }
    tokio::fs::rename(temporary, target).await?;
    Ok(())
}

pub(crate) async fn load_loader_plan(instance: &Instance) -> Result<Option<LoaderPlan>> {
    let path = instance.path().join(PLAN_FILE);
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let plan: LoaderPlan = serde_json::from_slice(&bytes)?;
    plan.validate()?;
    Ok(Some(plan))
}

pub(crate) async fn execute_loader_plan(
    plan: &mut LoaderPlan,
    instance: &Instance,
    cache_root: &Path,
    java: &JavaManager,
    events: &EventBus,
    cancellation: &CancellationToken,
) -> Result<()> {
    let cache_root = normalize_path(tokio::fs::canonicalize(cache_root).await?);
    for extraction in &plan.archive_entries {
        if cancellation.is_cancelled() {
            return Err(crate::download::DownloadError::Cancelled.into());
        }
        let archive = extraction.archive.join_under(&cache_root);
        let destination = extraction.destination.join_under(&cache_root);
        extract_exact_entry(archive, extraction.entry.clone(), destination.clone()).await?;
        verify_file(&destination, None, extraction.expected_hash.as_ref()).await?;
    }

    if plan.processors.is_empty() {
        return Ok(());
    }
    let java_executable = java
        .resolve_runtime(
            instance.spec().java().executable.as_deref(),
            JavaRequirement::current(plan.minimum_java_major.unwrap_or(8)),
            cancellation,
        )
        .await?
        .executable;
    for processor in &mut plan.processors {
        if cancellation.is_cancelled() {
            return Err(crate::download::DownloadError::Cancelled.into());
        }
        if outputs_are_valid(&cache_root, processor).await {
            continue;
        }
        events.emit(CoreEvent::LoaderProcessorStarted {
            instance_id: instance.id().to_string(),
            processor_id: processor.id.clone(),
        });
        execute_processor(&cache_root, &java_executable, processor).await?;
        snapshot_outputs(&cache_root, processor).await?;
        events.emit(CoreEvent::LoaderProcessorCompleted {
            instance_id: instance.id().to_string(),
            processor_id: processor.id.clone(),
        });
    }
    Ok(())
}

fn normalize_path(path: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return path;
    }
    let value = path.to_string_lossy();
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{path}"))
    } else if let Some(path) = value.strip_prefix(r"\\?\") {
        PathBuf::from(path)
    } else {
        path
    }
}

async fn outputs_are_valid(root: &Path, processor: &ProcessorPlan) -> bool {
    if processor.outputs.is_empty() {
        return false;
    }
    for output in &processor.outputs {
        if output.expected_size.is_none() && output.expected_hash.is_none() {
            return false;
        }
        if verify_file(
            &output.path.join_under(root),
            output.expected_size,
            output.expected_hash.as_ref(),
        )
        .await
        .is_err()
        {
            return false;
        }
    }
    true
}

async fn execute_processor(root: &Path, java: &Path, processor: &ProcessorPlan) -> Result<()> {
    let jar = processor.jar.join_under(root);
    let main_class = processor_main_class(jar.clone()).await?;
    let mut entries = Vec::with_capacity(processor.classpath.len() + 1);
    entries.push(jar);
    entries.extend(processor.classpath.iter().map(|path| path.join_under(root)));
    let classpath = std::env::join_paths(entries)
        .map_err(|error| LoaderError::InvalidPlan(error.to_string()))?;
    let arguments = processor
        .arguments
        .iter()
        .map(|argument| match argument {
            ProcessorArgument::Literal(value) => OsString::from(value),
            ProcessorArgument::CacheRoot => root.as_os_str().to_owned(),
            ProcessorArgument::CachePath(path) => path.join_under(root).into_os_string(),
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        processor = %processor.id,
        java = %java.display(),
        classpath = %classpath.to_string_lossy(),
        "executing loader processor"
    );
    let status = Command::new(java)
        .arg("-cp")
        .arg(classpath)
        .arg(main_class)
        .args(arguments)
        .current_dir(root)
        .status()
        .await?;
    if !status.success() {
        return Err(LoaderError::ProcessorFailed {
            id: processor.id.clone(),
            code: status.code(),
        }
        .into());
    }
    Ok(())
}

async fn snapshot_outputs(root: &Path, processor: &mut ProcessorPlan) -> Result<()> {
    for output in &mut processor.outputs {
        let path = output.path.join_under(root);
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|_| {
            LoaderError::InvalidProcessorOutput {
                id: processor.id.clone(),
                path: output.path.to_string(),
            }
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(LoaderError::InvalidProcessorOutput {
                id: processor.id.clone(),
                path: output.path.to_string(),
            }
            .into());
        }
        output.expected_size = Some(metadata.len());
        match &output.expected_hash {
            Some(hash) => {
                verify_file(&path, Some(metadata.len()), Some(hash)).await?;
            }
            None => {
                output.expected_hash = Some(compute_hash(&path, HashAlgorithm::Sha256).await?);
            }
        }
    }
    Ok(())
}

async fn processor_main_class(jar: PathBuf) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(jar)?;
        let mut archive = zip::ZipArchive::new(file).map_err(|error| {
            LoaderError::InvalidMetadata(format!("invalid processor archive: {error}"))
        })?;
        let mut manifest = archive.by_name("META-INF/MANIFEST.MF").map_err(|error| {
            LoaderError::InvalidMetadata(format!("processor manifest is missing: {error}"))
        })?;
        let mut text = String::new();
        manifest.read_to_string(&mut text)?;
        text.lines()
            .find_map(|line| line.strip_prefix("Main-Class:").map(str::trim))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                LoaderError::InvalidMetadata("processor Main-Class is missing".into()).into()
            })
    })
    .await
    .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?
}

async fn extract_exact_entry(archive: PathBuf, entry: String, destination: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let parent = destination
            .parent()
            .ok_or_else(|| LoaderError::InvalidPlan("archive destination has no parent".into()))?;
        std::fs::create_dir_all(parent)?;
        let file = std::fs::File::open(archive)?;
        let mut zip = zip::ZipArchive::new(file)
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        let entry = entry.trim_start_matches('/');
        let mut source = zip
            .by_name(entry)
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        if source.is_dir() {
            return Err(LoaderError::InvalidPlan("archive entry is a directory".into()).into());
        }
        let temporary = destination.with_extension("loader.tmp");
        let mut target = std::fs::File::create(&temporary)?;
        std::io::copy(&mut source, &mut target)?;
        target.flush()?;
        drop(target);
        if destination.exists() {
            std::fs::remove_file(&destination)?;
        }
        std::fs::rename(temporary, destination)?;
        Ok(())
    })
    .await
    .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?
}
