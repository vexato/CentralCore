//! Deterministic no-network provider for application and integration tests.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use url::Url;

use super::{
    cancellation_check, unix_now, AuthCapabilities, AuthChallenge, AuthContext, AuthIdentity,
    AuthProvider, AuthProviderStep, AuthRequest, AuthResponse, AuthSession, MinecraftIdentity,
    OfflineMinecraftIdentity, ProviderSession, SecretString,
};
use crate::{errors::AuthError, Result};

/// Flow shape selected for a [`MockAuthProvider`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MockAuthScenario {
    Success,
    Credentials,
    TwoFactor,
    Browser,
    DeviceCode,
    ExpiredThenRefresh,
    Failure,
}

/// Fully deterministic provider covering every generic challenge and lifecycle action.
#[derive(Debug, Clone)]
pub struct MockAuthProvider {
    id: String,
    username: String,
    scenario: MockAuthScenario,
    refreshes: Arc<AtomicUsize>,
    logouts: Arc<AtomicUsize>,
}

impl MockAuthProvider {
    pub fn new(
        id: impl Into<String>,
        username: impl Into<String>,
        scenario: MockAuthScenario,
    ) -> Result<Self> {
        let id = id.into();
        super::validate_provider_id(&id)?;
        let username = username.into();
        OfflineMinecraftIdentity::new(&username)?;
        Ok(Self {
            id,
            username,
            scenario,
            refreshes: Arc::new(AtomicUsize::new(0)),
            logouts: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[must_use]
    pub fn refresh_count(&self) -> usize {
        self.refreshes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn logout_count(&self) -> usize {
        self.logouts.load(Ordering::Relaxed)
    }

    fn session(&self, expired: bool) -> Result<AuthSession> {
        Ok(AuthSession {
            account_id: format!("{}-account", self.id),
            provider_id: self.id.clone(),
            identity: AuthIdentity {
                provider_user_id: "mock-user".into(),
                username: self.username.clone(),
                metadata: BTreeMap::new(),
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new("mock-provider-token")),
                refresh_token: Some(SecretString::new("mock-refresh-token")),
                device_secret: None,
                metadata: BTreeMap::new(),
            },
            expires_at: Some(if expired { 1 } else { unix_now() + 3600 }),
            refreshable: true,
            minecraft: MinecraftIdentity::Offline(OfflineMinecraftIdentity::new(&self.username)?),
        })
    }

    fn authenticated(&self) -> Result<AuthProviderStep> {
        self.session(self.scenario == MockAuthScenario::ExpiredThenRefresh)
            .map(AuthProviderStep::Authenticated)
    }
}

#[async_trait]
impl AuthProvider for MockAuthProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            interactive: true,
            refresh: true,
            logout: true,
            verify: true,
            credentials: true,
            two_factor: true,
            browser: true,
            device_code: true,
            ..AuthCapabilities::default()
        }
    }

    async fn begin(
        &self,
        _request: AuthRequest,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, &self.id)?;
        match self.scenario {
            MockAuthScenario::Success | MockAuthScenario::ExpiredThenRefresh => {
                self.authenticated()
            }
            MockAuthScenario::Credentials | MockAuthScenario::TwoFactor => {
                Ok(AuthProviderStep::Challenge {
                    challenge: AuthChallenge::Credentials {
                        username_label: "Username".into(),
                        password_label: "Password".into(),
                        password_required: true,
                    },
                    state: SecretString::new("credentials"),
                })
            }
            MockAuthScenario::Browser => Ok(AuthProviderStep::Challenge {
                challenge: AuthChallenge::Browser {
                    authorization_url: Url::parse("https://auth.example/authorize")
                        .expect("static URL"),
                    callback_url: Url::parse("http://127.0.0.1/callback").expect("static URL"),
                },
                state: SecretString::new("browser"),
            }),
            MockAuthScenario::DeviceCode => Ok(AuthProviderStep::Challenge {
                challenge: AuthChallenge::DeviceCode {
                    verification_uri: Url::parse("https://auth.example/device")
                        .expect("static URL"),
                    user_code: SecretString::new("MOCK-CODE"),
                    expires_at: unix_now() + 600,
                    poll_interval_seconds: 1,
                },
                state: SecretString::new("device"),
            }),
            MockAuthScenario::Failure => Err(AuthError::InvalidCredentials {
                provider: self.id.clone(),
            }
            .into()),
        }
    }

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, &self.id)?;
        match (state.expose_secret(), response) {
            ("credentials", AuthResponse::Credentials { .. })
                if self.scenario == MockAuthScenario::TwoFactor =>
            {
                Ok(AuthProviderStep::Challenge {
                    challenge: AuthChallenge::TwoFactorCode {
                        message: Some("Mock two-factor authentication".into()),
                    },
                    state: SecretString::new("two-factor"),
                })
            }
            ("credentials", AuthResponse::Credentials { .. })
            | ("two-factor", AuthResponse::TwoFactorCode { .. })
            | ("browser", AuthResponse::BrowserCallback { .. })
            | ("device", AuthResponse::PollDeviceCode) => self.authenticated(),
            _ => Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "unexpected_mock_response".into(),
            }
            .into()),
        }
    }

    async fn refresh(
        &self,
        _session: &AuthSession,
        context: AuthContext<'_>,
    ) -> Result<AuthSession> {
        cancellation_check(context.cancellation, &self.id)?;
        self.refreshes.fetch_add(1, Ordering::Relaxed);
        self.session(false)
    }

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession> {
        cancellation_check(context.cancellation, &self.id)?;
        Ok(session.clone())
    }

    async fn logout(&self, _session: AuthSession, context: AuthContext<'_>) -> Result<()> {
        cancellation_check(context.cancellation, &self.id)?;
        self.logouts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{AuthFlow, AuthManager, InMemoryCredentialStore},
        download::CancellationToken,
        events::EventBus,
    };

    #[tokio::test]
    async fn expired_session_refreshes_before_launch_and_logout_is_observable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let provider = MockAuthProvider::new(
            "mock-expired",
            "Player_1",
            MockAuthScenario::ExpiredThenRefresh,
        )
        .expect("provider");
        let observer = provider.clone();
        let manager = AuthManager::new(
            directory.path(),
            Arc::new(InMemoryCredentialStore::default()),
            EventBus::new(16),
        );
        manager
            .register(Arc::new(provider))
            .await
            .expect("register");
        let cancellation = CancellationToken::default();
        let AuthFlow::Authenticated(session) = manager
            .begin("mock-expired", AuthRequest::default(), &cancellation)
            .await
            .expect("begin")
        else {
            panic!("session")
        };
        manager
            .identity_for_launch(&session.account_id, &cancellation)
            .await
            .expect("identity");
        assert_eq!(observer.refresh_count(), 1);
        manager
            .logout(&session.account_id, &cancellation)
            .await
            .expect("logout");
        assert_eq!(observer.logout_count(), 1);
    }

    #[tokio::test]
    async fn browser_and_device_code_scenarios_use_the_same_flow_contract() {
        for (id, scenario, response) in [
            (
                "mock-browser",
                MockAuthScenario::Browser,
                AuthResponse::BrowserCallback {
                    callback_url: Url::parse("https://auth.example/callback").expect("URL"),
                },
            ),
            (
                "mock-device",
                MockAuthScenario::DeviceCode,
                AuthResponse::PollDeviceCode,
            ),
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let manager = AuthManager::new(
                directory.path(),
                Arc::new(InMemoryCredentialStore::default()),
                EventBus::new(16),
            );
            manager
                .register(Arc::new(
                    MockAuthProvider::new(id, "Player_1", scenario).expect("provider"),
                ))
                .await
                .expect("register");
            let cancellation = CancellationToken::default();
            let AuthFlow::Challenge {
                flow_id, challenge, ..
            } = manager
                .begin(id, AuthRequest::default(), &cancellation)
                .await
                .expect("begin")
            else {
                panic!("challenge")
            };
            assert_eq!(
                challenge.kind(),
                match scenario {
                    MockAuthScenario::Browser => super::super::AuthChallengeKind::Browser,
                    MockAuthScenario::DeviceCode => super::super::AuthChallengeKind::DeviceCode,
                    _ => unreachable!(),
                }
            );
            assert!(matches!(
                manager
                    .continue_flow(&flow_id, response, &cancellation)
                    .await,
                Ok(AuthFlow::Authenticated(_))
            ));
        }
    }
}
