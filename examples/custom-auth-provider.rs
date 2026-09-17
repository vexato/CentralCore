use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use centralcore::{
    auth::{
        AuthCapabilities, AuthContext, AuthIdentity, AuthProvider, AuthProviderStep, AuthRequest,
        AuthResponse, AuthSession, MinecraftIdentity, OfflineMinecraftIdentity, ProviderSession,
        SecretString,
    },
    errors::AuthError,
    minecraft::LaunchOptions,
    CentralCore, Result,
};

struct DemoAuthProvider;

#[async_trait]
impl AuthProvider for DemoAuthProvider {
    fn id(&self) -> &str {
        "demo-auth"
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            interactive: true,
            credentials: true,
            verify: true,
            ..AuthCapabilities::default()
        }
    }

    async fn begin(
        &self,
        request: AuthRequest,
        _context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        let username = request
            .account_hint
            .ok_or_else(|| AuthError::InvalidCredentials {
                provider: self.id().into(),
            })?;
        let minecraft = OfflineMinecraftIdentity::new(&username)?;
        Ok(AuthProviderStep::Authenticated(AuthSession {
            account_id: format!("demo-{username}"),
            provider_id: self.id().into(),
            identity: AuthIdentity {
                provider_user_id: username.clone(),
                username,
                metadata: BTreeMap::new(),
            },
            provider_session: ProviderSession::default(),
            expires_at: None,
            refreshable: false,
            minecraft: MinecraftIdentity::Offline(minecraft),
        }))
    }

    async fn continue_flow(
        &self,
        _state: SecretString,
        _response: AuthResponse,
        _context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        Err(AuthError::Protocol {
            provider: self.id().into(),
            code: "no_interactive_step".into(),
        }
        .into())
    }

    async fn refresh(&self, session: &AuthSession, _: AuthContext<'_>) -> Result<AuthSession> {
        Ok(session.clone())
    }

    async fn verify(&self, session: &AuthSession, _: AuthContext<'_>) -> Result<AuthSession> {
        Ok(session.clone())
    }

    async fn logout(&self, _session: AuthSession, _: AuthContext<'_>) -> Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir =
        std::env::var("CENTRALCORE_DATA_DIR").unwrap_or_else(|_| ".custom-auth-demo".into());
    let core = CentralCore::builder().data_dir(data_dir).build().await?;
    core.auth().register(Arc::new(DemoAuthProvider)).await?;
    let cancellation = core.downloads().cancellation_token();
    let flow = core
        .auth()
        .begin(
            "demo-auth",
            AuthRequest {
                account_hint: Some("Developer".into()),
                ..AuthRequest::default()
            },
            &cancellation,
        )
        .await?;
    let centralcore::auth::AuthFlow::Authenticated(session) = flow else {
        unreachable!("the demo provider authenticates without a challenge")
    };
    let identity = core
        .auth()
        .identity_for_launch(&session.account_id, &cancellation)
        .await?;
    if let Ok(instance_id) = std::env::var("CENTRALCORE_DEMO_INSTANCE") {
        let instance = core.instances().get(instance_id).await?;
        let plan = core
            .minecraft()
            .build_launch_plan(&instance, &identity, &LaunchOptions::default())
            .await?;
        println!("prepared launch plan: {plan:?}");
    } else {
        println!("authenticated session: {session:?}");
    }
    core.auth()
        .logout(&session.account_id, &cancellation)
        .await?;
    Ok(())
}
