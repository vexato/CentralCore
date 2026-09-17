//! Asset-index parsing and content-addressed asset planning.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    Result,
};

use super::MinecraftError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AssetIndex {
    pub objects: BTreeMap<String, AssetObject>,
    #[serde(default, rename = "virtual")]
    pub virtual_: bool,
    #[serde(default, rename = "map_to_resources")]
    pub map_to_resources: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AssetObject {
    pub hash: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedAsset {
    pub logical_path: SafeRelativePath,
    pub object_path: SafeRelativePath,
    pub url: Url,
    pub size: u64,
    pub hash: FileHash,
}

pub(crate) fn resolve_assets(index: &AssetIndex, base_url: &Url) -> Result<Vec<ResolvedAsset>> {
    index
        .objects
        .iter()
        .map(|(logical, object)| {
            if object.hash.len() != 40 || !object.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(MinecraftError::AssetIndex {
                    index: "objects".into(),
                    reason: format!("invalid SHA-1 for `{logical}`"),
                }
                .into());
            }
            let prefix = &object.hash[..2];
            let object_path =
                SafeRelativePath::new(format!("assets/objects/{prefix}/{}", object.hash))?;
            let url = base_url
                .join(&format!("{prefix}/{}", object.hash))
                .map_err(|error| MinecraftError::AssetIndex {
                    index: "objects".into(),
                    reason: error.to_string(),
                })?;
            Ok(ResolvedAsset {
                logical_path: SafeRelativePath::new(logical.clone())?,
                object_path,
                url,
                size: object.size,
                hash: FileHash::new(HashAlgorithm::Sha1, object.hash.clone())?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_content_addressed_asset_paths() {
        let hash = "abcdef0123456789abcdef0123456789abcdef01";
        let index = AssetIndex {
            objects: BTreeMap::from([(
                "minecraft/sounds/test.ogg".into(),
                AssetObject {
                    hash: hash.into(),
                    size: 12,
                },
            )]),
            virtual_: false,
            map_to_resources: false,
        };
        let assets = resolve_assets(
            &index,
            &Url::parse("https://resources.download.minecraft.net/").expect("URL"),
        )
        .expect("assets");
        assert_eq!(
            assets[0].object_path.as_str(),
            format!("assets/objects/ab/{hash}")
        );
        assert!(assets[0].url.as_str().ends_with(&format!("ab/{hash}")));
    }
}
