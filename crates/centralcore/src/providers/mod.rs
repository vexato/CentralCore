//! Backend-neutral instance providers and the static JSON implementation.

mod components;
mod manifest;
mod service;
mod static_provider;
mod update;

pub use components::{
    resolve_components, ComponentSelections, ComponentStatus, ResolvedComponentSet,
};
pub use manifest::{
    ComponentId, ComponentRequirement, ProviderComponent, ProviderError, ProviderFile, ProviderId,
    ProviderInstanceDefinition, ProviderInstanceId, ProviderJavaMemory, ProviderResource,
    ProviderSource, INSTANCE_MANIFEST_FORMAT_VERSION, PROVIDER_FORMAT_VERSION,
};
pub use service::{
    ProviderIdentity, ProviderInstallOutcome, ProviderInstanceEntry, ProviderInstanceState,
    ProviderManager, ProviderRegistration, ProviderSnapshot, ProviderSyncOptions,
    ProviderSyncReport,
};
pub use static_provider::StaticProvider;
pub(crate) use update::DesiredProviderFile;
pub use update::{
    OptionalComponentChange, UpdateFileAction, UpdatePhase, UpdatePlan, UpdateRemoval, UpdateReport,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    files::FileManifest,
    instance::{InstanceId, InstanceSpec},
    Result,
};

/// Lightweight catalog item shown before loading a full definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteInstanceSummary {
    pub id: InstanceId,
    pub name: String,
    pub description: Option<String>,
}

/// Complete provider response used to create or update a local instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteInstance {
    pub spec: InstanceSpec,
    pub description: Option<String>,
}

/// Source of instance definitions and file manifests.
#[async_trait]
pub trait InstanceProvider: Send + Sync {
    fn id(&self) -> &str;
    async fn list_instances(&self) -> Result<Vec<RemoteInstanceSummary>>;
    async fn get_instance(&self, id: &InstanceId) -> Result<RemoteInstance>;
    async fn get_manifest(&self, id: &InstanceId) -> Result<FileManifest>;
}
