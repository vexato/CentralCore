use std::sync::Arc;

use async_trait::async_trait;
use centralcore::{
    auth::{
        AuthCapabilities, AuthContext, AuthProvider, AuthProviderStep, AuthRequest, AuthResponse,
        AuthSession, SecretString,
    },
    errors::AuthError,
    CentralCore, Result,
};

struct CompanyAuth;

#[async_trait]
impl AuthProvider for CompanyAuth {
    fn id(&self) -> &str {
        "company"
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities::default()
    }

    async fn begin(&self, _: AuthRequest, _: AuthContext<'_>) -> Result<AuthProviderStep> {
        Err(AuthError::Protocol {
            provider: self.id().into(),
            code: "example_only".into(),
        }
        .into())
    }

    async fn continue_flow(
        &self,
        _: SecretString,
        _: AuthResponse,
        _: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        Err(AuthError::Protocol {
            provider: self.id().into(),
            code: "example_only".into(),
        }
        .into())
    }

    async fn refresh(&self, session: &AuthSession, _: AuthContext<'_>) -> Result<AuthSession> {
        Ok(session.clone())
    }

    async fn verify(&self, session: &AuthSession, _: AuthContext<'_>) -> Result<AuthSession> {
        Ok(session.clone())
    }

    async fn logout(&self, _: AuthSession, _: AuthContext<'_>) -> Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    core.auth().register(Arc::new(CompanyAuth)).await?;
    Ok(())
}
