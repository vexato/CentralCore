//! Trusted local authentication-provider registry.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    AuthProvider, AzuriomAuthProvider, HttpAuthPolicy, HttpAuthProvider, MicrosoftAuthConfig,
    MicrosoftAuthProvider,
};
use crate::{Error, Result};

pub const AUTH_REGISTRY_FORMAT_VERSION: u32 = 1;

/// Non-secret configuration for one locally trusted provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum AuthProviderConfig {
    Microsoft {
        client_id: String,
        redirect_url: Url,
        #[serde(default = "default_microsoft_tenant")]
        tenant: String,
    },
    Azuriom {
        base_url: Url,
        #[serde(default)]
        allow_insecure_loopback: bool,
    },
    Http {
        base_url: Url,
        #[serde(default)]
        allow_insecure_loopback: bool,
    },
}

impl AuthProviderConfig {
    pub(super) fn build(&self, id: String) -> Result<Arc<dyn AuthProvider>> {
        let policy = HttpAuthPolicy {
            allow_insecure_loopback: self.allow_insecure_loopback(),
            ..HttpAuthPolicy::default()
        };
        match self {
            Self::Microsoft {
                client_id,
                redirect_url,
                tenant,
            } => Ok(Arc::new(MicrosoftAuthProvider::new(
                id,
                MicrosoftAuthConfig {
                    client_id: client_id.clone(),
                    redirect_url: redirect_url.clone(),
                    tenant: tenant.clone(),
                },
            )?)),
            Self::Azuriom { base_url, .. } => Ok(Arc::new(AzuriomAuthProvider::with_policy(
                id,
                base_url.clone(),
                policy,
            )?)),
            Self::Http { base_url, .. } => Ok(Arc::new(HttpAuthProvider::with_policy(
                id,
                base_url.clone(),
                policy,
            )?)),
        }
    }

    fn allow_insecure_loopback(&self) -> bool {
        match self {
            Self::Microsoft { .. } => false,
            Self::Azuriom {
                allow_insecure_loopback,
                ..
            }
            | Self::Http {
                allow_insecure_loopback,
                ..
            } => *allow_insecure_loopback,
        }
    }
}

fn default_microsoft_tenant() -> String {
    "consumers".into()
}

/// Serializable view used by CLI and applications without exposing secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProviderConfigEntry {
    pub id: String,
    #[serde(flatten)]
    pub config: AuthProviderConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthProviderRegistry {
    pub format_version: u32,
    pub providers: BTreeMap<String, AuthProviderConfig>,
}

impl Default for AuthProviderRegistry {
    fn default() -> Self {
        Self {
            format_version: AUTH_REGISTRY_FORMAT_VERSION,
            providers: BTreeMap::new(),
        }
    }
}

impl AuthProviderRegistry {
    pub async fn load(path: &Path) -> Result<Self> {
        if !tokio::fs::try_exists(path).await? {
            return Ok(Self::default());
        }
        let bytes = tokio::fs::read(path).await?;
        let registry: Self = serde_json::from_slice(&bytes)?;
        if registry.format_version != AUTH_REGISTRY_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                kind: "authentication provider registry",
                version: registry.format_version,
            });
        }
        for (id, provider) in &registry.providers {
            super::validate_provider_id(id)?;
            provider.clone().build(id.clone())?;
        }
        Ok(registry)
    }

    pub async fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temporary = path.with_extension("json.tmp");
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(self)?).await?;
        if tokio::fs::try_exists(path).await? {
            tokio::fs::remove_file(path).await?;
        }
        tokio::fs::rename(temporary, path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_contains_no_secret_fields_and_rejects_unknown_versions() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("providers.json");
        let registry = AuthProviderRegistry {
            format_version: AUTH_REGISTRY_FORMAT_VERSION,
            providers: BTreeMap::from([(
                "community".into(),
                AuthProviderConfig::Azuriom {
                    base_url: Url::parse("https://community.example/").expect("URL"),
                    allow_insecure_loopback: false,
                },
            )]),
        };
        registry.save(&path).await.expect("save");
        let text = tokio::fs::read_to_string(&path).await.expect("read");
        assert!(!text.contains("token"));
        assert!(!text.contains("password"));
        assert_eq!(
            AuthProviderRegistry::load(&path)
                .await
                .expect("load")
                .providers
                .len(),
            1
        );

        tokio::fs::write(&path, br#"{"format_version":99,"providers":{}}"#)
            .await
            .expect("write");
        assert!(matches!(
            AuthProviderRegistry::load(&path).await,
            Err(Error::UnsupportedFormat { version: 99, .. })
        ));
    }
}
