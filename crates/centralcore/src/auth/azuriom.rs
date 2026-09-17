//! Official Azuriom AzAuth provider.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    cancellation_check,
    http::{validate_auth_base_url, AuthHttpClient},
    AuthCapabilities, AuthChallenge, AuthContext, AuthIdentity, AuthProvider, AuthProviderStep,
    AuthRequest, AuthResponse, AuthSession, HttpAuthPolicy, MinecraftIdentity,
    OfflineMinecraftIdentity, ProviderSession, SecretString,
};
use crate::{errors::AuthError, Result};

/// Direct Rust client for Azuriom's `/api/auth` API.
#[derive(Debug, Clone)]
pub struct AzuriomAuthProvider {
    id: String,
    api_url: Url,
    client: AuthHttpClient,
}

impl AzuriomAuthProvider {
    pub fn new(id: impl Into<String>, base_url: Url) -> Result<Self> {
        Self::with_policy(id, base_url, HttpAuthPolicy::default())
    }

    pub fn with_policy(
        id: impl Into<String>,
        base_url: Url,
        policy: HttpAuthPolicy,
    ) -> Result<Self> {
        let id = id.into();
        super::validate_provider_id(&id)?;
        let base_url = validate_auth_base_url(base_url, policy.allow_insecure_loopback)?;
        let api_url = base_url
            .join("api/auth/")
            .map_err(|_| AuthError::Protocol {
                provider: id.clone(),
                code: "invalid_endpoint".into(),
            })?;
        Ok(Self {
            id,
            api_url,
            client: AuthHttpClient::new(policy)?,
        })
    }

    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &impl Serialize,
        context: &AuthContext<'_>,
    ) -> Result<T> {
        cancellation_check(context.cancellation, &self.id)?;
        let url = self
            .api_url
            .join(endpoint)
            .map_err(|_| AuthError::Protocol {
                provider: self.id.clone(),
                code: "invalid_endpoint".into(),
            })?;
        self.client
            .post_json(&self.id, url, body, context.cancellation)
            .await
    }

    fn session(&self, user: AzuriomUser) -> Result<AuthSession> {
        let provider_user_id = json_identifier(user.id).ok_or_else(|| AuthError::Protocol {
            provider: self.id.clone(),
            code: "invalid_user_id".into(),
        })?;
        let minecraft = OfflineMinecraftIdentity::with_uuid(&user.name, &user.game_id)?;
        Ok(AuthSession {
            account_id: format!("{}-{provider_user_id}", self.id),
            provider_id: self.id.clone(),
            identity: AuthIdentity {
                provider_user_id,
                username: user.name,
                metadata: BTreeMap::new(),
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new(user.access_token)),
                refresh_token: None,
                device_secret: None,
                metadata: BTreeMap::new(),
            },
            expires_at: None,
            refreshable: false,
            minecraft: MinecraftIdentity::Offline(minecraft),
        })
    }

    fn handle_authenticate(
        &self,
        response: AzuriomResponse,
        credentials: Option<(&str, &SecretString)>,
    ) -> Result<AuthProviderStep> {
        match response {
            AzuriomResponse::User(user) => self.session(user).map(AuthProviderStep::Authenticated),
            AzuriomResponse::Status(status)
                if status.status == "pending" && status.reason.as_deref() == Some("2fa") =>
            {
                let (email, password) = credentials.ok_or_else(|| AuthError::Protocol {
                    provider: self.id.clone(),
                    code: "missing_two_factor_state".into(),
                })?;
                Ok(AuthProviderStep::Challenge {
                    challenge: AuthChallenge::TwoFactorCode {
                        message: status.message,
                    },
                    state: SecretString::new(
                        serde_json::to_string(&AzuriomFlowState::TwoFactor {
                            email: email.to_owned(),
                            password: password.expose_secret().to_owned(),
                        })
                        .map_err(|_| AuthError::Protocol {
                            provider: self.id.clone(),
                            code: "invalid_flow_state".into(),
                        })?,
                    ),
                })
            }
            AzuriomResponse::Status(status) => {
                Err(map_azuriom_error(&self.id, status.reason.as_deref()).into())
            }
        }
    }
}

#[async_trait]
impl AuthProvider for AzuriomAuthProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            interactive: true,
            logout: true,
            verify: true,
            credentials: true,
            two_factor: true,
            ..AuthCapabilities::default()
        }
    }

    async fn begin(
        &self,
        _request: AuthRequest,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, &self.id)?;
        Ok(AuthProviderStep::Challenge {
            challenge: AuthChallenge::Credentials {
                username_label: "Username or email".into(),
                password_label: "Password".into(),
                password_required: true,
            },
            state: SecretString::new(
                serde_json::to_string(&AzuriomFlowState::Credentials).map_err(|_| {
                    AuthError::Protocol {
                        provider: self.id.clone(),
                        code: "invalid_flow_state".into(),
                    }
                })?,
            ),
        })
    }

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        let state: AzuriomFlowState =
            serde_json::from_str(state.expose_secret()).map_err(|_| AuthError::Protocol {
                provider: self.id.clone(),
                code: "invalid_flow_state".into(),
            })?;
        match (state, response) {
            (
                AzuriomFlowState::Credentials,
                AuthResponse::Credentials {
                    username,
                    password: Some(password),
                },
            ) => {
                let response = self
                    .request(
                        "authenticate",
                        &AzuriomLoginRequest {
                            email: &username,
                            password: password.expose_secret(),
                            code: None,
                        },
                        &context,
                    )
                    .await?;
                self.handle_authenticate(response, Some((&username, &password)))
            }
            (
                AzuriomFlowState::TwoFactor { email, password },
                AuthResponse::TwoFactorCode { code },
            ) => {
                let response = self
                    .request(
                        "authenticate",
                        &AzuriomLoginRequest {
                            email: &email,
                            password: &password,
                            code: Some(code.expose_secret()),
                        },
                        &context,
                    )
                    .await?;
                self.handle_authenticate(response, None)
            }
            _ => Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "unexpected_challenge_response".into(),
            }
            .into()),
        }
    }

    async fn refresh(
        &self,
        _session: &AuthSession,
        _context: AuthContext<'_>,
    ) -> Result<AuthSession> {
        Err(AuthError::Expired {
            provider: self.id.clone(),
        }
        .into())
    }

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession> {
        let token = session
            .provider_session
            .access_token
            .as_ref()
            .ok_or_else(|| AuthError::Expired {
                provider: self.id.clone(),
            })?;
        let response: AzuriomResponse = self
            .request(
                "verify",
                &AzuriomTokenRequest {
                    access_token: token.expose_secret(),
                },
                &context,
            )
            .await?;
        match response {
            AzuriomResponse::User(user) => self.session(user),
            AzuriomResponse::Status(status) => {
                Err(map_azuriom_error(&self.id, status.reason.as_deref()).into())
            }
        }
    }

    async fn logout(&self, session: AuthSession, context: AuthContext<'_>) -> Result<()> {
        let Some(token) = session.provider_session.access_token else {
            return Ok(());
        };
        let response: AzuriomStatus = self
            .request(
                "logout",
                &AzuriomTokenRequest {
                    access_token: token.expose_secret(),
                },
                &context,
            )
            .await?;
        if response.status == "success" {
            Ok(())
        } else {
            Err(map_azuriom_error(&self.id, response.reason.as_deref()).into())
        }
    }
}

fn map_azuriom_error(provider: &str, reason: Option<&str>) -> AuthError {
    match reason {
        Some("invalid_credentials" | "invalid_2fa") => AuthError::InvalidCredentials {
            provider: provider.into(),
        },
        Some("invalid_token") => AuthError::Expired {
            provider: provider.into(),
        },
        Some("user_banned") => AuthError::AccountRestricted {
            provider: provider.into(),
            reason: crate::errors::AccountRestriction::Banned,
        },
        Some("account_disabled" | "user_disabled") => AuthError::AccountRestricted {
            provider: provider.into(),
            reason: crate::errors::AccountRestriction::Disabled,
        },
        _ => AuthError::Protocol {
            provider: provider.into(),
            code: "azuriom_error".into(),
        },
    }
}

fn json_identifier(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) if !value.is_empty() => Some(value),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
enum AzuriomFlowState {
    Credentials,
    TwoFactor { email: String, password: String },
}

#[derive(Serialize)]
struct AzuriomLoginRequest<'a> {
    email: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
}

#[derive(Serialize)]
struct AzuriomTokenRequest<'a> {
    access_token: &'a str,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AzuriomResponse {
    Status(AzuriomStatus),
    User(AzuriomUser),
}

#[derive(Deserialize)]
struct AzuriomStatus {
    status: String,
    reason: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct AzuriomUser {
    id: serde_json::Value,
    name: String,
    game_id: String,
    access_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azuriom_token_is_provider_only_and_never_official() {
        let provider = AzuriomAuthProvider::new(
            "community",
            Url::parse("https://community.example/").expect("URL"),
        )
        .expect("provider");
        let session = provider
            .session(AzuriomUser {
                id: serde_json::json!(42),
                name: "Player_1".into(),
                game_id: super::super::offline_uuid("Player_1"),
                access_token: "azuriom-secret".into(),
            })
            .expect("session");
        assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
        assert!(session.minecraft.access_token().is_none());
        assert!(!format!("{session:?}").contains("azuriom-secret"));
    }
}
