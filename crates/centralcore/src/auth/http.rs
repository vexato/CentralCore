//! CentralCorp Auth Protocol v1 client.

use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{header, Client, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use super::{
    cancellation_check, AuthCapabilities, AuthChallenge, AuthContext, AuthIdentity, AuthProvider,
    AuthProviderStep, AuthRequest, AuthResponse, AuthSession, MinecraftIdentity,
    OfflineMinecraftIdentity, ProviderSession, SecretString,
};
use crate::{errors::AuthError, Result};

pub const CENTRALCORP_AUTH_PROTOCOL_VERSION: u32 = 1;
const MAX_AUTH_RESPONSE_SIZE: usize = 1024 * 1024;

/// Explicit HTTP security policy. HTTPS remains mandatory by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAuthPolicy {
    pub timeout_seconds: u64,
    pub max_response_size: usize,
    /// Intended only for explicitly trusted loopback development servers.
    pub allow_insecure_loopback: bool,
}

impl Default for HttpAuthPolicy {
    fn default() -> Self {
        Self {
            timeout_seconds: 15,
            max_response_size: MAX_AUTH_RESPONSE_SIZE,
            allow_insecure_loopback: false,
        }
    }
}

/// Provider for servers implementing CentralCorp Auth Protocol v1.
#[derive(Debug, Clone)]
pub struct HttpAuthProvider {
    id: String,
    base_url: Url,
    client: AuthHttpClient,
}

impl HttpAuthProvider {
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
        Ok(Self {
            id,
            base_url,
            client: AuthHttpClient::new(policy)?,
        })
    }

    async fn request<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &impl Serialize,
        context: &AuthContext<'_>,
    ) -> Result<T> {
        cancellation_check(context.cancellation, &self.id)?;
        let url = self
            .base_url
            .join(endpoint)
            .map_err(|_| AuthError::Protocol {
                provider: self.id.clone(),
                code: "invalid_endpoint".into(),
            })?;
        self.client
            .post_json(&self.id, url, body, context.cancellation)
            .await
    }

    fn session_from_success(&self, success: ProtocolSuccess) -> Result<AuthSession> {
        let username = success.account.username;
        let refreshable = success.session.refresh_token.is_some();
        let minecraft = match success.account.uuid {
            Some(uuid) => OfflineMinecraftIdentity::with_uuid(username.clone(), uuid)?,
            None => OfflineMinecraftIdentity::new(username.clone())?,
        };
        Ok(AuthSession {
            account_id: format!("{}-{}", self.id, success.account.id),
            provider_id: self.id.clone(),
            identity: AuthIdentity {
                provider_user_id: success.account.id,
                username,
                metadata: success.account.metadata,
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new(success.session.access_token)),
                refresh_token: success.session.refresh_token.map(SecretString::new),
                device_secret: None,
                metadata: BTreeMap::new(),
            },
            expires_at: success.session.expires_at,
            refreshable,
            minecraft: MinecraftIdentity::Offline(minecraft),
        })
    }

    fn handle_login_response(&self, response: ProtocolResponse) -> Result<AuthProviderStep> {
        match response {
            ProtocolResponse::Success(success) => self
                .session_from_success(success)
                .map(AuthProviderStep::Authenticated),
            ProtocolResponse::Challenge {
                challenge,
                continuation_token,
                message,
            } if challenge == "two_factor" => Ok(AuthProviderStep::Challenge {
                challenge: AuthChallenge::TwoFactorCode { message },
                state: SecretString::new(
                    serde_json::to_string(&HttpFlowState::TwoFactor { continuation_token })
                        .map_err(|_| AuthError::Protocol {
                            provider: self.id.clone(),
                            code: "invalid_challenge".into(),
                        })?,
                ),
            }),
            ProtocolResponse::Challenge { .. } => Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "unsupported_challenge".into(),
            }
            .into()),
            ProtocolResponse::Error {
                code,
                retry_after_seconds,
            } => Err(protocol_error(&self.id, &code, retry_after_seconds).into()),
        }
    }
}

#[async_trait]
impl AuthProvider for HttpAuthProvider {
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
            state: SecretString::new(serde_json::to_string(&HttpFlowState::Credentials).map_err(
                |_| AuthError::Protocol {
                    provider: self.id.clone(),
                    code: "invalid_flow_state".into(),
                },
            )?),
        })
    }

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        let state: HttpFlowState =
            serde_json::from_str(state.expose_secret()).map_err(|_| AuthError::Protocol {
                provider: self.id.clone(),
                code: "invalid_flow_state".into(),
            })?;
        let result: ProtocolResponse = match (state, response) {
            (
                HttpFlowState::Credentials,
                AuthResponse::Credentials {
                    username,
                    password: Some(password),
                },
            ) => {
                self.request(
                    "login",
                    &LoginRequest {
                        protocol_version: CENTRALCORP_AUTH_PROTOCOL_VERSION,
                        username,
                        password: password.expose_secret(),
                    },
                    &context,
                )
                .await?
            }
            (
                HttpFlowState::TwoFactor { continuation_token },
                AuthResponse::TwoFactorCode { code },
            ) => {
                self.request(
                    "login",
                    &TwoFactorRequest {
                        protocol_version: CENTRALCORP_AUTH_PROTOCOL_VERSION,
                        continuation_token: &continuation_token,
                        code: code.expose_secret(),
                    },
                    &context,
                )
                .await?
            }
            _ => {
                return Err(AuthError::Protocol {
                    provider: self.id.clone(),
                    code: "unexpected_challenge_response".into(),
                }
                .into())
            }
        };
        self.handle_login_response(result)
    }

    async fn refresh(
        &self,
        session: &AuthSession,
        context: AuthContext<'_>,
    ) -> Result<AuthSession> {
        let token = session
            .provider_session
            .refresh_token
            .as_ref()
            .ok_or_else(|| AuthError::Expired {
                provider: self.id.clone(),
            })?;
        let response: ProtocolResponse = self
            .request(
                "refresh",
                &TokenRequest {
                    protocol_version: CENTRALCORP_AUTH_PROTOCOL_VERSION,
                    token: token.expose_secret(),
                },
                &context,
            )
            .await?;
        match self.handle_login_response(response)? {
            AuthProviderStep::Authenticated(session) => Ok(session),
            AuthProviderStep::Challenge { .. } => Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "refresh_requires_interaction".into(),
            }
            .into()),
        }
    }

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession> {
        let token = session
            .provider_session
            .access_token
            .as_ref()
            .ok_or_else(|| AuthError::Expired {
                provider: self.id.clone(),
            })?;
        let response: ProtocolResponse = self
            .request(
                "session",
                &TokenRequest {
                    protocol_version: CENTRALCORP_AUTH_PROTOCOL_VERSION,
                    token: token.expose_secret(),
                },
                &context,
            )
            .await?;
        match self.handle_login_response(response)? {
            AuthProviderStep::Authenticated(session) => Ok(session),
            AuthProviderStep::Challenge { .. } => Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "verification_requires_interaction".into(),
            }
            .into()),
        }
    }

    async fn logout(&self, session: AuthSession, context: AuthContext<'_>) -> Result<()> {
        let Some(token) = session.provider_session.access_token else {
            return Ok(());
        };
        let response: LogoutResponse = self
            .request(
                "logout",
                &TokenRequest {
                    protocol_version: CENTRALCORP_AUTH_PROTOCOL_VERSION,
                    token: token.expose_secret(),
                },
                &context,
            )
            .await?;
        if response.status == "success" {
            Ok(())
        } else {
            Err(AuthError::Protocol {
                provider: self.id.clone(),
                code: "logout_rejected".into(),
            }
            .into())
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct AuthHttpClient {
    client: Client,
    max_response_size: usize,
}

impl AuthHttpClient {
    pub(super) fn new(policy: HttpAuthPolicy) -> Result<Self> {
        if policy.timeout_seconds == 0
            || policy.timeout_seconds > 300
            || policy.max_response_size == 0
            || policy.max_response_size > 4 * 1024 * 1024
        {
            return Err(AuthError::Protocol {
                provider: "http".into(),
                code: "invalid_http_policy".into(),
            }
            .into());
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(policy.timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AuthError::ProviderUnavailable {
                provider: "http".into(),
            })?;
        Ok(Self {
            client,
            max_response_size: policy.max_response_size,
        })
    }

    pub(super) async fn post_json<T: DeserializeOwned>(
        &self,
        provider: &str,
        url: Url,
        body: &impl Serialize,
        cancellation: &crate::download::CancellationToken,
    ) -> Result<T> {
        let request = self
            .client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .json(body);
        self.send_json(provider, request, cancellation).await
    }

    pub(super) async fn post_form<T: DeserializeOwned>(
        &self,
        provider: &str,
        url: Url,
        body: &[(&str, &str)],
        cancellation: &crate::download::CancellationToken,
    ) -> Result<T> {
        let request = self
            .client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .form(body);
        self.send_json(provider, request, cancellation).await
    }

    pub(super) async fn get_bearer<T: DeserializeOwned>(
        &self,
        provider: &str,
        url: Url,
        token: &str,
        cancellation: &crate::download::CancellationToken,
    ) -> Result<T> {
        let request = self
            .client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .bearer_auth(token);
        self.send_json(provider, request, cancellation).await
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        provider: &str,
        request: RequestBuilder,
        cancellation: &crate::download::CancellationToken,
    ) -> Result<T> {
        cancellation_check(cancellation, provider)?;
        let response = tokio::select! {
            result = request.send() => result.map_err(|_| AuthError::ProviderUnavailable {
                provider: provider.to_owned(),
            })?,
            () = cancellation.cancelled() => {
                return Err(AuthError::Cancelled {
                    provider: provider.to_owned(),
                }
                .into());
            }
        };
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_seconds = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            return Err(AuthError::RateLimited {
                provider: provider.to_owned(),
                retry_after_seconds,
            }
            .into());
        }
        if response.status().is_server_error() {
            return Err(AuthError::ProviderUnavailable {
                provider: provider.to_owned(),
            }
            .into());
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_size as u64)
        {
            return Err(AuthError::Protocol {
                provider: provider.to_owned(),
                code: "oversized_response".into(),
            }
            .into());
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        loop {
            let chunk = tokio::select! {
                chunk = stream.next() => chunk,
                () = cancellation.cancelled() => {
                    return Err(AuthError::Cancelled {
                        provider: provider.to_owned(),
                    }
                    .into());
                }
            };
            let Some(chunk) = chunk else {
                break;
            };
            cancellation_check(cancellation, provider)?;
            let chunk = chunk.map_err(|_| AuthError::ProviderUnavailable {
                provider: provider.to_owned(),
            })?;
            if bytes.len().saturating_add(chunk.len()) > self.max_response_size {
                return Err(AuthError::Protocol {
                    provider: provider.to_owned(),
                    code: "oversized_response".into(),
                }
                .into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            AuthError::Protocol {
                provider: provider.to_owned(),
                code: "invalid_json".into(),
            }
            .into()
        })
    }
}

pub(super) fn validate_auth_base_url(mut url: Url, allow_insecure_loopback: bool) -> Result<Url> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AuthError::Protocol {
            provider: "http".into(),
            code: "unsafe_base_url".into(),
        }
        .into());
    }
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(allow_insecure_loopback && url.scheme() == "http" && loopback) {
        return Err(AuthError::Protocol {
            provider: "http".into(),
            code: "https_required".into(),
        }
        .into());
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn protocol_error(provider: &str, code: &str, retry_after_seconds: Option<u64>) -> AuthError {
    match code {
        "invalid_credentials" => AuthError::InvalidCredentials {
            provider: provider.into(),
        },
        "account_banned" | "user_banned" => AuthError::AccountRestricted {
            provider: provider.into(),
            reason: crate::errors::AccountRestriction::Banned,
        },
        "account_disabled" => AuthError::AccountRestricted {
            provider: provider.into(),
            reason: crate::errors::AccountRestriction::Disabled,
        },
        "expired" | "invalid_token" => AuthError::Expired {
            provider: provider.into(),
        },
        "rate_limited" => AuthError::RateLimited {
            provider: provider.into(),
            retry_after_seconds,
        },
        "server_error" => AuthError::ProviderUnavailable {
            provider: provider.into(),
        },
        _ => AuthError::Protocol {
            provider: provider.into(),
            code: sanitize_code(code),
        },
    }
}

fn sanitize_code(code: &str) -> String {
    if !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        code.to_owned()
    } else {
        "invalid_error_code".into()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
enum HttpFlowState {
    Credentials,
    TwoFactor { continuation_token: String },
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    protocol_version: u32,
    username: String,
    password: &'a str,
}

#[derive(Serialize)]
struct TwoFactorRequest<'a> {
    protocol_version: u32,
    continuation_token: &'a str,
    code: &'a str,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    protocol_version: u32,
    token: &'a str,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ProtocolResponse {
    Success(ProtocolSuccess),
    Challenge {
        challenge: String,
        continuation_token: String,
        message: Option<String>,
    },
    Error {
        code: String,
        retry_after_seconds: Option<u64>,
    },
}

#[derive(Deserialize)]
struct ProtocolSuccess {
    account: ProtocolAccount,
    session: ProtocolSession,
}

#[derive(Deserialize)]
struct ProtocolAccount {
    id: String,
    username: String,
    uuid: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ProtocolSession {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct LogoutResponse {
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::offline_uuid;

    #[test]
    fn requires_https_and_rejects_url_credentials() {
        let insecure = Url::parse("http://example.com/auth/v1/").expect("URL");
        assert!(HttpAuthProvider::new("network", insecure).is_err());
        let credentials = Url::parse("https://user:pass@example.com/auth/v1/").expect("URL");
        assert!(HttpAuthProvider::new("network", credentials).is_err());
        let query = Url::parse("https://example.com/auth/v1/?token=secret").expect("URL");
        assert!(HttpAuthProvider::new("network", query).is_err());
        let fragment = Url::parse("https://example.com/auth/v1/#secret").expect("URL");
        assert!(HttpAuthProvider::new("network", fragment).is_err());
    }

    #[test]
    fn custom_protocol_can_only_create_offline_identity() {
        let provider = HttpAuthProvider::new(
            "network",
            Url::parse("https://auth.example/auth/v1/").expect("URL"),
        )
        .expect("provider");
        let session = provider
            .session_from_success(ProtocolSuccess {
                account: ProtocolAccount {
                    id: "42".into(),
                    username: "Player_1".into(),
                    uuid: Some(offline_uuid("Player_1")),
                    metadata: BTreeMap::new(),
                },
                session: ProtocolSession {
                    access_token: "provider-token".into(),
                    refresh_token: None,
                    expires_at: None,
                },
            })
            .expect("session");
        assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
        assert!(session.minecraft.access_token().is_none());
        assert!(!format!("{session:?}").contains("provider-token"));
    }
}
