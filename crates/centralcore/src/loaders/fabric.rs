use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use crate::{
    download::{compute_hash, verify_file, DownloadRequest},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    minecraft::{libraries::maven_path, Arguments},
    Result,
};

use super::{
    Loader, LoaderConfig, LoaderDownload, LoaderError, LoaderFileKind, LoaderIdentity, LoaderKind,
    LoaderPlan, LoaderResolveContext, LoaderVersion,
};

const FABRIC_META: &str = "https://meta.fabricmc.net/v2/versions/loader/";
const METADATA_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct FabricLoader;

#[derive(Debug, Clone, Deserialize)]
struct FabricVersionEntry {
    loader: FabricArtifact,
}

#[derive(Debug, Clone, Deserialize)]
struct FabricArtifact {
    version: String,
    stable: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FabricProfile {
    id: String,
    inherits_from: String,
    main_class: String,
    #[serde(default)]
    libraries: Vec<FabricLibrary>,
    #[serde(default)]
    arguments: Arguments,
}

#[derive(Debug, Clone, Deserialize)]
struct FabricLibrary {
    name: String,
    url: Url,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

#[async_trait]
impl Loader for FabricLoader {
    fn kind(&self) -> LoaderKind {
        LoaderKind::Fabric
    }

    async fn versions(
        &self,
        minecraft_version: &str,
        context: &LoaderResolveContext<'_>,
    ) -> Result<Vec<LoaderVersion>> {
        let url = fabric_url(minecraft_version, None, false)?;
        let entries: Vec<FabricVersionEntry> = context
            .downloads
            .fetch_json(&url, None, None, METADATA_LIMIT, context.cancellation)
            .await?;
        Ok(entries
            .into_iter()
            .map(|entry| LoaderVersion {
                version: entry.loader.version,
                stable: entry.loader.stable,
            })
            .collect())
    }

    async fn resolve(
        &self,
        config: &LoaderConfig,
        minecraft_version: &str,
        context: &LoaderResolveContext<'_>,
    ) -> Result<LoaderPlan> {
        let profile_url = fabric_url(minecraft_version, Some(&config.version), true)?;
        let profile_path = SafeRelativePath::new(format!(
            "loaders/fabric/{minecraft_version}/{}/profile.json",
            config.version
        ))?;
        let (profile_bytes, profile_download) = cached_document(
            context,
            format!("fabric-profile:{minecraft_version}:{}", config.version),
            profile_url,
            profile_path,
        )
        .await?;
        let profile: FabricProfile = serde_json::from_slice(&profile_bytes)
            .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
        if profile.inherits_from != minecraft_version
            || profile.id != format!("fabric-loader-{}-{minecraft_version}", config.version)
        {
            return Err(LoaderError::VersionNotFound {
                loader: LoaderKind::Fabric,
                minecraft: minecraft_version.to_owned(),
                version: config.version.clone(),
            }
            .into());
        }

        let mut downloads = vec![profile_download];
        let mut classpath = Vec::new();
        for library in profile.libraries {
            let maven = maven_path(&library.name, None)?;
            let destination = SafeRelativePath::new(format!("libraries/{maven}"))?;
            let source = normalized_base(&library.url)?
                .join(&maven)
                .map_err(|error| {
                    LoaderError::InvalidMetadata(format!("invalid Fabric library URL: {error}"))
                })?;
            let hash = match library.sha1 {
                Some(hash) => FileHash::new(HashAlgorithm::Sha1, hash)?,
                None => {
                    fetch_sha1(context, &source, minecraft_version, &config.version, &maven).await?
                }
            };
            classpath.push(destination.clone());
            downloads.push(LoaderDownload {
                request: DownloadRequest {
                    id: format!("fabric-library:{}", library.name),
                    source,
                    destination,
                    expected_size: library.size,
                    expected_hash: Some(hash),
                },
                kind: LoaderFileKind::Library,
                classpath: true,
            });
        }
        deduplicate_downloads(&mut downloads)?;
        Ok(LoaderPlan {
            format_version: LoaderPlan::FORMAT_VERSION,
            identity: LoaderIdentity {
                kind: LoaderKind::Fabric,
                minecraft_version: minecraft_version.to_owned(),
                loader_version: config.version.clone(),
            },
            version_id: profile.id,
            downloads,
            archive_entries: Vec::new(),
            processors: Vec::new(),
            classpath_additions: classpath,
            main_class: Some(profile.main_class),
            jvm_arguments: profile.arguments.jvm,
            game_arguments: profile.arguments.game,
            minimum_java_major: None,
        })
    }
}

async fn cached_document(
    context: &LoaderResolveContext<'_>,
    id: String,
    source: Url,
    destination: SafeRelativePath,
) -> Result<(Vec<u8>, LoaderDownload)> {
    let absolute = destination.join_under(context.cache_root);
    if !context.offline {
        context
            .downloads
            .download(
                context.cache_root,
                &DownloadRequest {
                    id: id.clone(),
                    source: source.clone(),
                    destination: destination.clone(),
                    expected_size: None,
                    expected_hash: None,
                },
                context.cancellation,
            )
            .await?;
    } else if verify_file(&absolute, None, None).await.is_err() {
        return Err(LoaderError::OfflinePlanUnavailable.into());
    }
    let bytes = tokio::fs::read(&absolute).await?;
    if bytes.len() as u64 > METADATA_LIMIT {
        return Err(LoaderError::InvalidMetadata("Fabric profile is oversized".into()).into());
    }
    let hash = compute_hash(&absolute, HashAlgorithm::Sha256).await?;
    Ok((
        bytes.clone(),
        LoaderDownload {
            request: DownloadRequest {
                id,
                source,
                destination,
                expected_size: Some(bytes.len() as u64),
                expected_hash: Some(hash),
            },
            kind: LoaderFileKind::Metadata,
            classpath: false,
        },
    ))
}

async fn fetch_sha1(
    context: &LoaderResolveContext<'_>,
    artifact: &Url,
    minecraft_version: &str,
    loader_version: &str,
    maven_path: &str,
) -> Result<FileHash> {
    let sidecar_url = Url::parse(&format!("{}.sha1", artifact.as_str()))
        .map_err(|error| LoaderError::InvalidMetadata(error.to_string()))?;
    let sidecar_path = SafeRelativePath::new(format!(
        "loaders/fabric/{minecraft_version}/{loader_version}/sha1/{maven_path}.sha1"
    ))?;
    let absolute = sidecar_path.join_under(context.cache_root);
    if context.offline {
        if !tokio::fs::try_exists(&absolute).await? {
            return Err(LoaderError::OfflinePlanUnavailable.into());
        }
    } else {
        context
            .downloads
            .download(
                context.cache_root,
                &DownloadRequest {
                    id: format!("fabric-sha1:{maven_path}"),
                    source: sidecar_url,
                    destination: sidecar_path,
                    expected_size: None,
                    expected_hash: None,
                },
                context.cancellation,
            )
            .await?;
    }
    let value = tokio::fs::read_to_string(absolute).await?;
    let hash = value.split_whitespace().next().ok_or_else(|| {
        LoaderError::InvalidMetadata(format!("empty SHA-1 sidecar for {maven_path}"))
    })?;
    FileHash::new(HashAlgorithm::Sha1, hash)
}

fn normalized_base(url: &Url) -> Result<Url> {
    Url::parse(&format!("{}/", url.as_str().trim_end_matches('/')))
        .map_err(|error| LoaderError::InvalidMetadata(error.to_string()).into())
}

fn fabric_url(minecraft_version: &str, loader_version: Option<&str>, profile: bool) -> Result<Url> {
    let mut value = format!("{FABRIC_META}{minecraft_version}");
    if let Some(loader) = loader_version {
        value.push('/');
        value.push_str(loader);
    }
    if profile {
        value.push_str("/profile/json");
    }
    Url::parse(&value).map_err(|error| LoaderError::InvalidMetadata(error.to_string()).into())
}

fn deduplicate_downloads(downloads: &mut Vec<LoaderDownload>) -> Result<()> {
    let mut unique = std::collections::BTreeMap::new();
    for download in downloads.drain(..) {
        let path = download.request.destination.to_string();
        if let Some(previous) = unique.get(&path) {
            if previous != &download {
                return Err(LoaderError::DuplicatePath(path).into());
            }
        } else {
            unique.insert(path, download);
        }
    }
    downloads.extend(unique.into_values());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_profile_shape() {
        let json = r#"{
          "id":"fabric-loader-0.16.14-1.20.4","inheritsFrom":"1.20.4",
          "mainClass":"net.fabricmc.loader.impl.launch.knot.KnotClient",
          "libraries":[{"name":"net.fabricmc:intermediary:1.20.4","url":"https://maven.fabricmc.net/","sha1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":12}],
          "arguments":{"game":[],"jvm":["-DFabricMcEmu= net.minecraft.client.main.Main "]}
        }"#;
        let profile: FabricProfile = serde_json::from_str(json).expect("profile");
        assert_eq!(profile.inherits_from, "1.20.4");
        assert_eq!(profile.libraries.len(), 1);
        assert_eq!(profile.arguments.jvm.len(), 1);
    }

    #[test]
    fn rejects_latest_loader_version() {
        assert!(LoaderConfig::new(LoaderKind::Fabric, "latest").is_err());
    }
}
