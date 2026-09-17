use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use crate::{
    download::{verify_file, DownloadRequest},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    minecraft::{
        libraries::{maven_path, resolve_libraries},
        required_java_major, Arguments, Library, RuleContext,
    },
    Result,
};

use super::{
    ArchiveEntryPlan, Loader, LoaderConfig, LoaderDownload, LoaderError, LoaderFileKind,
    LoaderIdentity, LoaderKind, LoaderPlan, LoaderResolveContext, LoaderVersion, ProcessorArgument,
    ProcessorOutput, ProcessorPlan,
};

const FORGE_MAVEN: &str = "https://maven.minecraftforge.net/";
const METADATA_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ForgeLoader;

#[derive(Debug, Deserialize)]
struct MavenMetadata {
    versioning: MavenVersioning,
}

#[derive(Debug, Deserialize)]
struct MavenVersioning {
    versions: MavenVersions,
}

#[derive(Debug, Deserialize)]
struct MavenVersions {
    #[serde(rename = "version", default)]
    values: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ForgeInstallProfile {
    spec: u32,
    minecraft: String,
    version: String,
    #[serde(default)]
    libraries: Vec<Library>,
    #[serde(default)]
    processors: Vec<RawProcessor>,
    #[serde(default)]
    data: BTreeMap<String, SidedValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForgeVersionProfile {
    id: String,
    inherits_from: String,
    main_class: String,
    #[serde(default)]
    libraries: Vec<Library>,
    #[serde(default)]
    arguments: Arguments,
}

#[derive(Debug, Deserialize)]
struct RawProcessor {
    #[serde(default)]
    sides: Vec<String>,
    jar: String,
    #[serde(default)]
    classpath: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    outputs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SidedValue {
    client: String,
    #[allow(dead_code)]
    server: String,
}

struct ParsedInstaller {
    install: ForgeInstallProfile,
    version: ForgeVersionProfile,
}

#[async_trait]
impl Loader for ForgeLoader {
    fn kind(&self) -> LoaderKind {
        LoaderKind::Forge
    }

    async fn versions(
        &self,
        minecraft_version: &str,
        context: &LoaderResolveContext<'_>,
    ) -> Result<Vec<LoaderVersion>> {
        let url = Url::parse(&format!(
            "{FORGE_MAVEN}net/minecraftforge/forge/maven-metadata.xml"
        ))
        .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        let bytes = context
            .downloads
            .fetch_bytes(&url, None, None, METADATA_LIMIT, context.cancellation)
            .await?;
        let metadata: MavenMetadata = quick_xml::de::from_reader(bytes.as_slice())
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        let prefix = format!("{minecraft_version}-");
        let mut versions = metadata
            .versioning
            .versions
            .values
            .into_iter()
            .filter_map(|version| version.strip_prefix(&prefix).map(str::to_owned))
            .map(|version| LoaderVersion {
                version,
                stable: true,
            })
            .collect::<Vec<_>>();
        versions.reverse();
        Ok(versions)
    }

    async fn resolve(
        &self,
        config: &LoaderConfig,
        minecraft_version: &str,
        context: &LoaderResolveContext<'_>,
    ) -> Result<LoaderPlan> {
        let full_version = forge_coordinate_version(minecraft_version, &config.version);
        let installer_relative =
            format!("net/minecraftforge/forge/{full_version}/forge-{full_version}-installer.jar");
        let installer_url = normalized_forge_maven()?
            .join(&installer_relative)
            .map_err(|error| {
                LoaderError::InvalidMetadata(format!("invalid Forge installer URL: {error}"))
            })?;
        let installer_path = SafeRelativePath::new(format!(
            "loaders/forge/installers/{full_version}/installer.jar"
        ))?;
        let sha1 = forge_sha1(context, &installer_url, &full_version).await?;
        let installer_request = DownloadRequest {
            id: format!("forge-installer:{full_version}"),
            source: installer_url,
            destination: installer_path.clone(),
            expected_size: None,
            expected_hash: Some(sha1),
        };
        let installer_absolute = installer_path.join_under(context.cache_root);
        if context.offline {
            verify_file(
                &installer_absolute,
                installer_request.expected_size,
                installer_request.expected_hash.as_ref(),
            )
            .await
            .map_err(|_| LoaderError::OfflinePlanUnavailable)?;
        } else {
            context
                .downloads
                .download(context.cache_root, &installer_request, context.cancellation)
                .await?;
        }
        let parsed = parse_installer(installer_absolute).await?;
        if parsed.install.spec != 1 {
            return Err(LoaderError::UnsupportedForgeSpec(parsed.install.spec).into());
        }
        if parsed.install.minecraft != minecraft_version
            || parsed.version.inherits_from != minecraft_version
            || parsed.install.version != parsed.version.id
        {
            return Err(LoaderError::VersionNotFound {
                loader: LoaderKind::Forge,
                minecraft: minecraft_version.to_owned(),
                version: config.version.clone(),
            }
            .into());
        }

        let rules = RuleContext::current(BTreeMap::new());
        let install_libraries = resolve_libraries(&parsed.install.libraries, &rules)?;
        let launch_libraries = resolve_libraries(&parsed.version.libraries, &rules)?;
        let mut downloads = vec![LoaderDownload {
            request: installer_request,
            kind: LoaderFileKind::Installer,
            classpath: false,
        }];
        for library in install_libraries.iter().chain(&launch_libraries) {
            if let Some(artifact) = &library.artifact {
                downloads.push(LoaderDownload {
                    request: DownloadRequest {
                        id: format!("forge-library:{}", library.name),
                        source: artifact.url.clone(),
                        destination: SafeRelativePath::new(format!("libraries/{}", artifact.path))?,
                        expected_size: artifact.size,
                        expected_hash: artifact.sha1.clone(),
                    },
                    kind: LoaderFileKind::Library,
                    classpath: false,
                });
            }
        }
        let classpath_additions = launch_libraries
            .iter()
            .filter_map(|library| library.artifact.as_ref())
            .map(|artifact| SafeRelativePath::new(format!("libraries/{}", artifact.path)))
            .collect::<Result<Vec<_>>>()?;

        let mut archive_entries = Vec::new();
        let mut variables = builtin_variables(&installer_path, minecraft_version)?;
        for (name, value) in parsed.install.data {
            let resolved = resolve_data_value(
                &value.client,
                &full_version,
                &installer_path,
                &mut archive_entries,
            )?;
            variables.insert(name, resolved);
        }
        add_mojang_mappings_download(context, &variables, &mut downloads)?;
        let processors = parsed
            .install
            .processors
            .into_iter()
            .enumerate()
            .filter(|(_, processor)| {
                processor.sides.is_empty() || processor.sides.iter().any(|side| side == "client")
            })
            .map(|(index, processor)| resolve_processor(index, processor, &variables))
            .collect::<Result<Vec<_>>>()?;
        deduplicate_downloads(&mut downloads)?;

        Ok(LoaderPlan {
            format_version: LoaderPlan::FORMAT_VERSION,
            identity: LoaderIdentity {
                kind: LoaderKind::Forge,
                minecraft_version: minecraft_version.to_owned(),
                loader_version: config.version.clone(),
            },
            version_id: parsed.version.id,
            downloads,
            archive_entries,
            processors,
            classpath_additions,
            main_class: Some(parsed.version.main_class),
            jvm_arguments: parsed.version.arguments.jvm,
            game_arguments: parsed.version.arguments.game,
            minimum_java_major: Some(required_java_major(base_version(context)?)),
        })
    }
}

fn forge_coordinate_version(minecraft: &str, loader: &str) -> String {
    if loader.starts_with(&format!("{minecraft}-")) {
        loader.to_owned()
    } else {
        format!("{minecraft}-{loader}")
    }
}

async fn forge_sha1(
    context: &LoaderResolveContext<'_>,
    installer_url: &Url,
    full_version: &str,
) -> Result<FileHash> {
    let sidecar_path = SafeRelativePath::new(format!(
        "loaders/forge/installers/{full_version}/installer.jar.sha1"
    ))?;
    let absolute = sidecar_path.join_under(context.cache_root);
    if context.offline {
        if !tokio::fs::try_exists(&absolute).await? {
            return Err(LoaderError::OfflinePlanUnavailable.into());
        }
    } else {
        let url = Url::parse(&format!("{}.sha1", installer_url.as_str()))
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        context
            .downloads
            .download(
                context.cache_root,
                &DownloadRequest {
                    id: format!("forge-installer-sha1:{full_version}"),
                    source: url,
                    destination: sidecar_path,
                    expected_size: None,
                    expected_hash: None,
                },
                context.cancellation,
            )
            .await?;
    }
    let value = tokio::fs::read_to_string(absolute).await?;
    let value = value.split_whitespace().next().ok_or_else(|| {
        LoaderError::InvalidMetadata("empty Forge installer SHA-1 sidecar".into())
    })?;
    FileHash::new(HashAlgorithm::Sha1, value)
}

async fn parse_installer(path: std::path::PathBuf) -> Result<ParsedInstaller> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path)?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        let install: ForgeInstallProfile = {
            let reader = archive
                .by_name("install_profile.json")
                .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
            serde_json::from_reader(reader)
                .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?
        };
        let version: ForgeVersionProfile = {
            let reader = archive
                .by_name("version.json")
                .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
            serde_json::from_reader(reader)
                .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?
        };
        Ok(ParsedInstaller { install, version })
    })
    .await
    .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?
}

fn builtin_variables(
    installer: &SafeRelativePath,
    minecraft: &str,
) -> Result<BTreeMap<String, ProcessorArgument>> {
    Ok(BTreeMap::from([
        ("SIDE".into(), ProcessorArgument::Literal("client".into())),
        (
            "MINECRAFT_VERSION".into(),
            ProcessorArgument::Literal(minecraft.into()),
        ),
        ("ROOT".into(), ProcessorArgument::CacheRoot),
        (
            "LIBRARY_DIR".into(),
            ProcessorArgument::CachePath(SafeRelativePath::new("libraries")?),
        ),
        (
            "MINECRAFT_JAR".into(),
            ProcessorArgument::CachePath(SafeRelativePath::new(format!(
                "versions/{minecraft}/{minecraft}.jar"
            ))?),
        ),
        (
            "INSTALLER".into(),
            ProcessorArgument::CachePath(installer.clone()),
        ),
    ]))
}

fn resolve_data_value(
    raw: &str,
    full_version: &str,
    installer: &SafeRelativePath,
    archive_entries: &mut Vec<ArchiveEntryPlan>,
) -> Result<ProcessorArgument> {
    if let Some(coordinate) = bracketed(raw) {
        return Ok(ProcessorArgument::CachePath(SafeRelativePath::new(
            format!("libraries/{}", maven_path(coordinate, None)?),
        )?));
    }
    if let Some(literal) = quoted(raw) {
        return Ok(ProcessorArgument::Literal(literal.to_owned()));
    }
    if raw.starts_with('/') {
        let entry = raw.trim_start_matches('/');
        let destination =
            SafeRelativePath::new(format!("loaders/forge/data/{full_version}/{entry}"))?;
        archive_entries.push(ArchiveEntryPlan {
            archive: installer.clone(),
            entry: entry.to_owned(),
            destination: destination.clone(),
            expected_hash: None,
        });
        return Ok(ProcessorArgument::CachePath(destination));
    }
    Ok(ProcessorArgument::Literal(raw.to_owned()))
}

fn resolve_processor(
    index: usize,
    raw: RawProcessor,
    variables: &BTreeMap<String, ProcessorArgument>,
) -> Result<ProcessorPlan> {
    let jar = coordinate_cache_path(&raw.jar)?;
    let classpath = raw
        .classpath
        .iter()
        .map(|coordinate| coordinate_cache_path(coordinate))
        .collect::<Result<Vec<_>>>()?;
    let arguments = raw
        .args
        .iter()
        .map(|argument| resolve_processor_argument(argument, variables))
        .collect::<Result<Vec<_>>>()?;
    let mut outputs = raw
        .outputs
        .iter()
        .map(|(path, hash)| {
            let path = processor_path(path, variables)?;
            let hash = resolve_hash(hash, variables)?;
            Ok(ProcessorOutput {
                path,
                expected_size: None,
                expected_hash: hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for flag in ["--output", "--slim", "--extra", "--out-jar"] {
        if let Some(position) = raw.args.iter().position(|argument| argument == flag) {
            if let Some(ProcessorArgument::CachePath(path)) = arguments.get(position + 1) {
                if !outputs.iter().any(|output| output.path == *path) {
                    outputs.push(ProcessorOutput {
                        path: path.clone(),
                        expected_size: None,
                        expected_hash: None,
                    });
                }
            }
        }
    }
    Ok(ProcessorPlan {
        id: format!("forge-processor-{index}"),
        jar,
        classpath,
        arguments,
        outputs,
    })
}

fn resolve_processor_argument(
    value: &str,
    variables: &BTreeMap<String, ProcessorArgument>,
) -> Result<ProcessorArgument> {
    if let Some(coordinate) = bracketed(value) {
        return Ok(ProcessorArgument::CachePath(coordinate_cache_path(
            coordinate,
        )?));
    }
    if let Some(name) = token(value) {
        return variables.get(name).cloned().ok_or_else(|| {
            LoaderError::InvalidMetadata(format!("unknown Forge data token {{{name}}}")).into()
        });
    }
    if let Some(suffix) = value.strip_prefix("{ROOT}/") {
        return Ok(ProcessorArgument::CachePath(SafeRelativePath::new(suffix)?));
    }
    if let Some(suffix) = value.strip_prefix("{LIBRARY_DIR}/") {
        return Ok(ProcessorArgument::CachePath(SafeRelativePath::new(
            format!("libraries/{suffix}"),
        )?));
    }
    let mut rendered = value.to_owned();
    for (name, replacement) in variables {
        if let ProcessorArgument::Literal(replacement) = replacement {
            rendered = rendered.replace(&format!("{{{name}}}"), replacement);
        }
    }
    if rendered.contains('{') {
        return Err(LoaderError::InvalidMetadata(format!(
            "unresolved Forge processor argument `{value}`"
        ))
        .into());
    }
    Ok(ProcessorArgument::Literal(rendered))
}

fn processor_path(
    value: &str,
    variables: &BTreeMap<String, ProcessorArgument>,
) -> Result<SafeRelativePath> {
    match resolve_processor_argument(value, variables)? {
        ProcessorArgument::CachePath(path) => Ok(path),
        _ => Err(LoaderError::InvalidMetadata(format!(
            "Forge processor output `{value}` is not a cache path"
        ))
        .into()),
    }
}

fn resolve_hash(
    value: &str,
    variables: &BTreeMap<String, ProcessorArgument>,
) -> Result<Option<FileHash>> {
    let value = if let Some(name) = token(value) {
        match variables.get(name) {
            Some(ProcessorArgument::Literal(value)) => value.as_str(),
            _ => return Ok(None),
        }
    } else {
        quoted(value).unwrap_or(value)
    };
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(FileHash::new(HashAlgorithm::Sha1, value)?))
    }
}

fn add_mojang_mappings_download(
    context: &LoaderResolveContext<'_>,
    variables: &BTreeMap<String, ProcessorArgument>,
    downloads: &mut Vec<LoaderDownload>,
) -> Result<()> {
    let base = base_version(context)?;
    let Some(info) = &base.downloads.client_mappings else {
        return Ok(());
    };
    let Some(ProcessorArgument::CachePath(destination)) = variables.get("MOJMAPS") else {
        return Ok(());
    };
    downloads.push(LoaderDownload {
        request: DownloadRequest {
            id: format!("forge-mojmaps:{}", base.id),
            source: info.url.clone(),
            destination: destination.clone(),
            expected_size: info.size,
            expected_hash: info
                .sha1
                .as_ref()
                .map(|hash| FileHash::new(HashAlgorithm::Sha1, hash.clone()))
                .transpose()?,
        },
        kind: LoaderFileKind::Generated,
        classpath: false,
    });
    Ok(())
}

fn base_version<'a>(
    context: &'a LoaderResolveContext<'_>,
) -> Result<&'a crate::minecraft::VersionMetadata> {
    context.base_version.ok_or_else(|| {
        LoaderError::InvalidPlan("base Minecraft metadata is unavailable".into()).into()
    })
}

fn coordinate_cache_path(coordinate: &str) -> Result<SafeRelativePath> {
    SafeRelativePath::new(format!("libraries/{}", maven_path(coordinate, None)?))
}

fn bracketed(value: &str) -> Option<&str> {
    value.strip_prefix('[')?.strip_suffix(']')
}

fn quoted(value: &str) -> Option<&str> {
    value.strip_prefix('\'')?.strip_suffix('\'')
}

fn token(value: &str) -> Option<&str> {
    value.strip_prefix('{')?.strip_suffix('}')
}

fn normalized_forge_maven() -> Result<Url> {
    Url::parse(FORGE_MAVEN).map_err(|error| LoaderError::InvalidMetadata(error.to_string()).into())
}

fn deduplicate_downloads(downloads: &mut Vec<LoaderDownload>) -> Result<()> {
    let mut unique = BTreeMap::<String, LoaderDownload>::new();
    for download in downloads.drain(..) {
        let key = download.request.destination.to_string();
        if let Some(previous) = unique.get(&key) {
            if previous.request.source != download.request.source
                || previous.request.expected_hash != download.request.expected_hash
            {
                return Err(LoaderError::DuplicatePath(key).into());
            }
        } else {
            unique.insert(key, download);
        }
    }
    downloads.extend(unique.into_values());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_install_profile_and_client_processors() {
        let json = r#"{
          "spec":1,"minecraft":"1.20.1","version":"1.20.1-forge-47.2.0",
          "libraries":[],"data":{"PATCHED":{"client":"[net.minecraftforge:forge:1.20.1-47.2.0:client]","server":"x"}},
          "processors":[{"sides":["client"],"jar":"net.minecraftforge:tool:1.0","args":["--output","{PATCHED}"],"outputs":{"{PATCHED}":"'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"}}]
        }"#;
        let profile: ForgeInstallProfile = serde_json::from_str(json).expect("profile");
        assert_eq!(profile.spec, 1);
        assert_eq!(profile.processors.len(), 1);
        assert_eq!(
            profile.data["PATCHED"].client,
            "[net.minecraftforge:forge:1.20.1-47.2.0:client]"
        );
    }

    #[test]
    fn resolves_processor_paths_without_shell_strings() {
        let variables = BTreeMap::from([(
            "OUT".into(),
            ProcessorArgument::CachePath(
                SafeRelativePath::new("libraries/example/out.jar").expect("path"),
            ),
        )]);
        assert!(matches!(
            resolve_processor_argument("{OUT}", &variables).expect("argument"),
            ProcessorArgument::CachePath(_)
        ));
        assert!(resolve_processor_argument("{UNKNOWN}", &variables).is_err());
    }

    #[test]
    fn filters_forge_versions_by_minecraft_prefix() {
        assert_eq!(
            forge_coordinate_version("1.20.1", "47.4.23"),
            "1.20.1-47.4.23"
        );
        assert_eq!(
            forge_coordinate_version("1.20.1", "1.20.1-47.4.23"),
            "1.20.1-47.4.23"
        );
    }
}
