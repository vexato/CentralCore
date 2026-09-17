//! Rule-aware Maven library and native-classifier resolution.

use std::path::Path;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    platform::{Architecture, Platform},
    Result,
};

use super::{manifest::DownloadInfo, rules::os_name, Library, MinecraftError, RuleContext};

const DEFAULT_LIBRARY_BASE: &str = "https://libraries.minecraft.net/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedArtifact {
    pub path: SafeRelativePath,
    pub url: Url,
    pub size: Option<u64>,
    pub sha1: Option<FileHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNative {
    pub archive: ResolvedArtifact,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedLibrary {
    pub name: String,
    pub artifact: Option<ResolvedArtifact>,
    pub native: Option<ResolvedNative>,
}

pub(crate) fn resolve_libraries(
    libraries: &[Library],
    context: &RuleContext,
) -> Result<Vec<ResolvedLibrary>> {
    libraries
        .iter()
        .filter(|library| context.allows(&library.rules))
        .map(|library| resolve_library(library, context.platform))
        .collect()
}

fn resolve_library(library: &Library, platform: Platform) -> Result<ResolvedLibrary> {
    let native_classifier = library
        .natives
        .get(os_name(platform.os))
        .map(|classifier| classifier.replace("${arch}", native_arch(platform.architecture)));
    let coordinate_classifier = coordinate_parts(&library.name)
        .ok()
        .and_then(|parts| parts.classifier.map(str::to_owned));
    let coordinate_is_native = coordinate_classifier
        .as_deref()
        .is_some_and(|classifier| classifier.starts_with("natives-"));

    let artifact_info = library
        .downloads
        .as_ref()
        .and_then(|downloads| downloads.artifact.as_ref());
    let resolved_main = match artifact_info {
        Some(info) => Some(resolve_download_info(info, &library.name, None)?),
        None if !coordinate_is_native => Some(resolve_legacy_artifact(library, None)?),
        None => None,
    };

    let native_artifact = if let Some(classifier) = native_classifier.as_deref() {
        if let Some(info) = library
            .downloads
            .as_ref()
            .and_then(|downloads| downloads.classifiers.get(classifier))
        {
            Some(resolve_download_info(
                info,
                &library.name,
                Some(classifier),
            )?)
        } else {
            Some(resolve_legacy_artifact(library, Some(classifier))?)
        }
    } else if coordinate_is_native {
        artifact_info
            .map(|info| {
                resolve_download_info(info, &library.name, coordinate_classifier.as_deref())
            })
            .transpose()?
            .or_else(|| resolve_legacy_artifact(library, coordinate_classifier.as_deref()).ok())
    } else {
        None
    };

    let artifact = if coordinate_is_native {
        None
    } else {
        resolved_main
    };
    let native = native_artifact.map(|archive| ResolvedNative {
        archive,
        exclusions: library
            .extract
            .as_ref()
            .map(|extract| extract.exclude.clone())
            .unwrap_or_else(|| vec!["META-INF/".into()]),
    });
    Ok(ResolvedLibrary {
        name: library.name.clone(),
        artifact,
        native,
    })
}

fn resolve_download_info(
    info: &DownloadInfo,
    coordinate: &str,
    classifier: Option<&str>,
) -> Result<ResolvedArtifact> {
    let path = match &info.path {
        Some(path) => SafeRelativePath::new(path.clone())?,
        None => SafeRelativePath::new(maven_path(coordinate, classifier)?)?,
    };
    let sha1 = info
        .sha1
        .as_ref()
        .map(|hash| FileHash::new(HashAlgorithm::Sha1, hash.clone()))
        .transpose()?;
    Ok(ResolvedArtifact {
        path,
        url: info.url.clone(),
        size: info.size,
        sha1,
    })
}

fn resolve_legacy_artifact(
    library: &Library,
    classifier: Option<&str>,
) -> Result<ResolvedArtifact> {
    let path = SafeRelativePath::new(maven_path(&library.name, classifier)?)?;
    let base = match &library.url {
        Some(url) => url.clone(),
        None => {
            Url::parse(DEFAULT_LIBRARY_BASE).map_err(|error| MinecraftError::LibraryResolution {
                library: library.name.clone(),
                reason: error.to_string(),
            })?
        }
    };
    let base =
        Url::parse(&format!("{}/", base.as_str().trim_end_matches('/'))).map_err(|error| {
            MinecraftError::LibraryResolution {
                library: library.name.clone(),
                reason: error.to_string(),
            }
        })?;
    let url = base
        .join(path.as_str())
        .map_err(|error| MinecraftError::LibraryResolution {
            library: library.name.clone(),
            reason: error.to_string(),
        })?;
    Ok(ResolvedArtifact {
        path,
        url,
        size: None,
        sha1: if classifier.is_none() {
            library
                .checksums
                .iter()
                .find(|checksum| checksum.len() == 40)
                .map(|checksum| FileHash::new(HashAlgorithm::Sha1, checksum.clone()))
                .transpose()?
        } else {
            None
        },
    })
}

struct Coordinate<'a> {
    group: &'a str,
    artifact: &'a str,
    version: &'a str,
    classifier: Option<&'a str>,
    extension: &'a str,
}

fn coordinate_parts(coordinate: &str) -> Result<Coordinate<'_>> {
    let (coordinate, extension) = coordinate
        .split_once('@')
        .map_or((coordinate, "jar"), |(coordinate, extension)| {
            (coordinate, extension)
        });
    let parts = coordinate.split(':').collect::<Vec<_>>();
    if !(3..=4).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
        return Err(MinecraftError::LibraryResolution {
            library: coordinate.to_owned(),
            reason: "expected group:artifact:version[:classifier][@extension]".into(),
        }
        .into());
    }
    Ok(Coordinate {
        group: parts[0],
        artifact: parts[1],
        version: parts[2],
        classifier: parts.get(3).copied(),
        extension,
    })
}

pub(crate) fn maven_path(coordinate: &str, classifier: Option<&str>) -> Result<String> {
    let parts = coordinate_parts(coordinate)?;
    let classifier = classifier.or(parts.classifier);
    let classifier_suffix = classifier.map_or(String::new(), |value| format!("-{value}"));
    Ok(format!(
        "{}/{}/{}/{}-{}{}.{}",
        parts.group.replace('.', "/"),
        parts.artifact,
        parts.version,
        parts.artifact,
        parts.version,
        classifier_suffix,
        parts.extension
    ))
}

fn native_arch(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86 => "32",
        Architecture::X86_64 => "64",
        Architecture::Aarch64 => "arm64",
        Architecture::Arm => "arm32",
        Architecture::Other => "unknown",
    }
}

pub(crate) fn cache_path(cache_root: &Path, artifact: &ResolvedArtifact) -> std::path::PathBuf {
    artifact.path.join_under(&cache_root.join("libraries"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::platform::{OperatingSystem, Platform};

    use super::*;

    #[test]
    fn builds_maven_paths_with_classifier_and_extension() {
        assert_eq!(
            maven_path("org.lwjgl:lwjgl:3.3.3", Some("natives-windows")).expect("path"),
            "org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3-natives-windows.jar"
        );
        assert_eq!(
            maven_path("com.example:demo:1.0:all@zip", None).expect("path"),
            "com/example/demo/1.0/demo-1.0-all.zip"
        );
    }

    #[test]
    fn selects_native_classifier_for_platform() {
        let library = Library {
            name: "org.example:native:1.0".into(),
            checksums: Vec::new(),
            downloads: None,
            rules: Vec::new(),
            natives: BTreeMap::from([("windows".into(), "natives-windows-${arch}".into())]),
            extract: None,
            url: None,
        };
        let context = RuleContext {
            platform: Platform {
                os: OperatingSystem::Windows,
                architecture: Architecture::X86_64,
            },
            os_version: String::new(),
            features: BTreeMap::new(),
        };
        let resolved = resolve_libraries(&[library], &context).expect("resolve");
        assert!(resolved[0]
            .native
            .as_ref()
            .expect("native")
            .archive
            .path
            .as_str()
            .ends_with("natives-windows-64.jar"));
    }
}
