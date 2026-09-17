//! `InstanceProvider` adapter backed by one validated local snapshot.

use async_trait::async_trait;
use url::Url;

use crate::{
    files::{FileEntry, FileManifest},
    instance::InstanceId,
    providers::{InstanceProvider, RemoteInstance, RemoteInstanceSummary},
    Error, Result,
};

use super::{ComponentRequirement, ProviderResource, ProviderSnapshot};

/// Immutable provider implementation created from a committed snapshot.
#[derive(Debug, Clone)]
pub struct StaticProvider {
    snapshot: ProviderSnapshot,
}

impl StaticProvider {
    pub(crate) fn new(snapshot: ProviderSnapshot) -> Self {
        Self { snapshot }
    }

    #[must_use]
    pub fn snapshot(&self) -> &ProviderSnapshot {
        &self.snapshot
    }
}

#[async_trait]
impl InstanceProvider for StaticProvider {
    fn id(&self) -> &str {
        self.snapshot.registration_id.as_str()
    }

    async fn list_instances(&self) -> Result<Vec<RemoteInstanceSummary>> {
        Ok(self
            .snapshot
            .instances
            .values()
            .map(|definition| RemoteInstanceSummary {
                id: definition.id.clone(),
                name: definition.name.clone(),
                description: definition.description.clone(),
            })
            .collect())
    }

    async fn get_instance(&self, id: &InstanceId) -> Result<RemoteInstance> {
        let definition = self
            .snapshot
            .instances
            .get(id)
            .ok_or_else(|| Error::NotFound {
                kind: "provider instance",
                id: id.to_string(),
            })?;
        let key = super::ProviderInstanceId::new(self.snapshot.registration_id.clone(), id.clone());
        Ok(RemoteInstance {
            spec: definition.local_spec(id.to_string(), &key)?,
            description: definition.description.clone(),
        })
    }

    async fn get_manifest(&self, id: &InstanceId) -> Result<FileManifest> {
        let definition = self
            .snapshot
            .instances
            .get(id)
            .ok_or_else(|| Error::NotFound {
                kind: "provider instance",
                id: id.to_string(),
            })?;
        let files = definition
            .files
            .iter()
            .chain(
                definition
                    .components
                    .iter()
                    .filter(|component| {
                        component.requirement == ComponentRequirement::Required
                            || component.default_enabled
                    })
                    .flat_map(|component| component.files.iter()),
            )
            .map(|file| {
                let url = match &file.source {
                    ProviderResource::Remote(url) => url.clone(),
                    ProviderResource::Local { path, .. } => {
                        Url::from_file_path(path).map_err(|()| {
                            Error::InvalidConfig(format!(
                                "local provider path `{}` cannot be represented as a file URL",
                                path.display()
                            ))
                        })?
                    }
                };
                Ok(FileEntry {
                    path: file.path.clone(),
                    url,
                    size: Some(file.size),
                    hash: Some(file.sha256.clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let manifest = FileManifest {
            format_version: FileManifest::FORMAT_VERSION,
            files,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}
