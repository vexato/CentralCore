//! Microsoft public-client OAuth, Xbox, and Minecraft Services authentication.

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use super::{
    cancellation_check, http::AuthHttpClient, AuthCapabilities, AuthChallenge, AuthContext,
    AuthIdentity, AuthProvider, AuthProviderStep, AuthRequest, AuthResponse, AuthSession,
    HttpAuthPolicy, MinecraftIdentity, OfficialMinecraftIdentity, ProviderSession, SecretString,
};
use crate::{
    errors::{AccountRestriction, AuthError},
    Result,
};

const MICROSOFT_SCOPE: &str = "XboxLive.signin offline_access";

/// Public desktop application configuration. A client secret is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrosoftAuthConfig {
    pub client_id: String,
    pub redirect_url: Url,
    pub tenant: String,
}

/// Authorization Code + PKCE provider producing official Minecraft identities.
#[derive(Debug, Clone)]
pub struct MicrosoftAuthProvider {
    id: String,
    config: MicrosoftAuthConfig,
    endpoints: MicrosoftEndpoints,
    client: AuthHttpClient,
}

impl MicrosoftAuthProvider {
    pub fn new(id: impl Into<String>, config: MicrosoftAuthConfig) -> Result<Self> {
        let id = id.into();
        super::validate_provider_id(&id)?;
        validate_config(&config)?;
        let endpoints = MicrosoftEndpoints::production(&config)?;
        Ok(Self {
            id,
            config,
            endpoints,
            client: AuthHttpClient::new(HttpAuthPolicy::default())?,
        })
    }

    #[cfg(test)]
    fn with_endpoints(
        id: impl Into<String>,
        config: MicrosoftAuthConfig,
        endpoints: MicrosoftEndpoints,
    ) -> Result<Self> {
        let mut provider = Self::new(id, config)?;
        provider.endpoints = endpoints;
        Ok(provider)
    }

    fn browser_flow(&self) -> Result<AuthProviderStep> {
        let verifier = random_urlsafe(32)?;
        let csrf = random_urlsafe(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorization_url = self.endpoints.authorize.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", self.config.redirect_url.as_str())
            .append_pair("response_mode", "query")
            .append_pair("scope", MICROSOFT_SCOPE)
            .append_pair("state", &csrf)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(AuthProviderStep::Challenge {
            challenge: AuthChallenge::Browser {
                authorization_url,
                callback_url: self.config.redirect_url.clone(),
            },
            state: SecretString::new(
                serde_json::to_string(&MicrosoftFlowState { verifier, csrf })
                    .map_err(|_| protocol(&self.id, "invalid_flow_state"))?,
            ),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        context: &AuthContext<'_>,
    ) -> Result<OAuthToken> {
        let response: OAuthResponse = self
            .client
            .post_form(
                &self.id,
                self.endpoints.token.clone(),
                &[
                    ("client_id", self.config.client_id.as_str()),
                    ("scope", MICROSOFT_SCOPE),
                    ("code", code),
                    ("redirect_uri", self.config.redirect_url.as_str()),
                    ("grant_type", "authorization_code"),
                    ("code_verifier", verifier),
                ],
                context.cancellation,
            )
            .await?;
        oauth_result(&self.id, response)
    }

    async fn exchange_refresh(
        &self,
        refresh_token: &str,
        context: &AuthContext<'_>,
    ) -> Result<OAuthToken> {
        let response: OAuthResponse = self
            .client
            .post_form(
                &self.id,
                self.endpoints.token.clone(),
                &[
                    ("client_id", self.config.client_id.as_str()),
                    ("scope", MICROSOFT_SCOPE),
                    ("refresh_token", refresh_token),
                    ("grant_type", "refresh_token"),
                ],
                context.cancellation,
            )
            .await?;
        oauth_result(&self.id, response)
    }

    async fn create_session(
        &self,
        oauth: OAuthToken,
        context: &AuthContext<'_>,
    ) -> Result<AuthSession> {
        cancellation_check(context.cancellation, &self.id)?;
        let user_reply: XboxResponse = self
            .client
            .post_json(
                &self.id,
                self.endpoints.xbox_user_auth.clone(),
                &XboxUserRequest {
                    properties: XboxUserProperties {
                        auth_method: "RPS",
                        site_name: "user.auth.xboxlive.com",
                        rps_ticket: format!("d={}", oauth.access_token),
                    },
                    relying_party: "http://auth.xboxlive.com",
                    token_type: "JWT",
                },
                context.cancellation,
            )
            .await?;
        let user = xbox_result(&self.id, user_reply)?;
        let user_hash = first_xbox_claim(&self.id, &user)?.uhs.clone();

        let xsts_reply: XboxResponse = self
            .client
            .post_json(
                &self.id,
                self.endpoints.xsts.clone(),
                &XstsRequest {
                    properties: XstsProperties {
                        sandbox_id: "RETAIL",
                        user_tokens: vec![user.token],
                    },
                    relying_party: "rp://api.minecraftservices.com/",
                    token_type: "JWT",
                },
                context.cancellation,
            )
            .await?;
        let xsts = xbox_result(&self.id, xsts_reply)?;
        let xsts_claim = first_xbox_claim(&self.id, &xsts)?;
        if xsts_claim.uhs != user_hash {
            return Err(protocol(&self.id, "xbox_user_hash_mismatch").into());
        }

        let login_reply: MinecraftLoginResponse = self
            .client
            .post_json(
                &self.id,
                self.endpoints.minecraft_login.clone(),
                &MinecraftLoginRequest {
                    identity_token: format!("XBL3.0 x={user_hash};{}", xsts.token),
                },
                context.cancellation,
            )
            .await?;
        let minecraft_token = match login_reply {
            MinecraftLoginResponse::Success(token) => token,
            MinecraftLoginResponse::Error { .. } => {
                return Err(protocol(&self.id, "minecraft_login_rejected").into())
            }
        };

        let entitlements: Entitlements = self
            .client
            .get_bearer(
                &self.id,
                self.endpoints.entitlements.clone(),
                &minecraft_token.access_token,
                context.cancellation,
            )
            .await?;
        ensure_minecraft_ownership(&self.id, &entitlements)?;
        let profile: MinecraftProfileResponse = self
            .client
            .get_bearer(
                &self.id,
                self.endpoints.profile.clone(),
                &minecraft_token.access_token,
                context.cancellation,
            )
            .await?;
        let profile = minecraft_profile(&self.id, profile)?;
        let uuid =
            canonical_uuid(&profile.id).ok_or_else(|| AuthError::InvalidMinecraftProfile {
                provider: self.id.clone(),
            })?;
        let expires_at = unix_now().saturating_add(minecraft_token.expires_in.saturating_sub(60));
        let refreshable = oauth.refresh_token.is_some();
        let official = OfficialMinecraftIdentity {
            username: profile.name.clone(),
            uuid,
            access_token: SecretString::new(minecraft_token.access_token),
            xuid: xsts_claim.xid.clone(),
            expires_at: Some(expires_at),
        };
        Ok(AuthSession {
            account_id: format!("{}-{user_hash}", self.id),
            provider_id: self.id.clone(),
            identity: AuthIdentity {
                provider_user_id: user_hash,
                username: profile.name,
                metadata: BTreeMap::new(),
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new(oauth.access_token)),
                refresh_token: oauth.refresh_token.map(SecretString::new),
                device_secret: None,
                metadata: BTreeMap::new(),
            },
            expires_at: Some(expires_at),
            refreshable,
            minecraft: MinecraftIdentity::Official(official),
        })
    }
}

#[async_trait]
impl AuthProvider for MicrosoftAuthProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            interactive: true,
            refresh: true,
            logout: true,
            verify: true,
            browser: true,
            official_minecraft_session: true,
            ..AuthCapabilities::default()
        }
    }

    async fn begin(
        &self,
        _request: AuthRequest,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, &self.id)?;
        self.browser_flow()
    }

    async fn continue_flow(
        &self,
        state: SecretString,
        response: AuthResponse,
        context: AuthContext<'_>,
    ) -> Result<AuthProviderStep> {
        cancellation_check(context.cancellation, &self.id)?;
        let state: MicrosoftFlowState = serde_json::from_str(state.expose_secret())
            .map_err(|_| protocol(&self.id, "invalid_flow_state"))?;
        let AuthResponse::BrowserCallback { callback_url } = response else {
            return Err(protocol(&self.id, "unexpected_challenge_response").into());
        };
        validate_callback_origin(&self.config.redirect_url, &callback_url)
            .map_err(|code| protocol(&self.id, code))?;
        let query = callback_url.query_pairs().collect::<BTreeMap<_, _>>();
        if query.get("state").map(|value| value.as_ref()) != Some(state.csrf.as_str()) {
            return Err(protocol(&self.id, "state_mismatch").into());
        }
        if query.contains_key("error") {
            return Err(AuthError::AccountRestricted {
                provider: self.id.clone(),
                reason: AccountRestriction::Unknown,
            }
            .into());
        }
        let code = query
            .get("code")
            .filter(|code| !code.is_empty())
            .ok_or_else(|| protocol(&self.id, "authorization_code_missing"))?;
        let oauth = self.exchange_code(code, &state.verifier, &context).await?;
        self.create_session(oauth, &context)
            .await
            .map(AuthProviderStep::Authenticated)
    }

    async fn refresh(
        &self,
        session: &AuthSession,
        context: AuthContext<'_>,
    ) -> Result<AuthSession> {
        cancellation_check(context.cancellation, &self.id)?;
        let refresh_token = session
            .provider_session
            .refresh_token
            .as_ref()
            .ok_or_else(|| AuthError::Expired {
                provider: self.id.clone(),
            })?;
        let oauth = self
            .exchange_refresh(refresh_token.expose_secret(), &context)
            .await?;
        self.create_session(oauth, &context).await
    }

    async fn verify(&self, session: &AuthSession, context: AuthContext<'_>) -> Result<AuthSession> {
        cancellation_check(context.cancellation, &self.id)?;
        let MinecraftIdentity::Official(identity) = &session.minecraft else {
            return Err(AuthError::InvalidMinecraftProfile {
                provider: self.id.clone(),
            }
            .into());
        };
        let profile: MinecraftProfileResponse = self
            .client
            .get_bearer(
                &self.id,
                self.endpoints.profile.clone(),
                identity.access_token.expose_secret(),
                context.cancellation,
            )
            .await?;
        let profile = minecraft_profile(&self.id, profile)?;
        if canonical_uuid(&profile.id).as_deref() != Some(identity.uuid.as_str()) {
            return Err(AuthError::InvalidMinecraftProfile {
                provider: self.id.clone(),
            }
            .into());
        }
        let mut verified = session.clone();
        verified.identity.username = profile.name.clone();
        if let MinecraftIdentity::Official(identity) = &mut verified.minecraft {
            identity.username = profile.name;
        }
        Ok(verified)
    }

    async fn logout(&self, _session: AuthSession, context: AuthContext<'_>) -> Result<()> {
        cancellation_check(context.cancellation, &self.id)
    }
}

#[derive(Debug, Clone)]
struct MicrosoftEndpoints {
    authorize: Url,
    token: Url,
    xbox_user_auth: Url,
    xsts: Url,
    minecraft_login: Url,
    entitlements: Url,
    profile: Url,
}

impl MicrosoftEndpoints {
    fn production(config: &MicrosoftAuthConfig) -> Result<Self> {
        let base = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/",
            config.tenant
        );
        Ok(Self {
            authorize: parse_endpoint(&(base.clone() + "authorize"))?,
            token: parse_endpoint(&(base + "token"))?,
            xbox_user_auth: parse_endpoint("https://user.auth.xboxlive.com/user/authenticate")?,
            xsts: parse_endpoint("https://xsts.auth.xboxlive.com/xsts/authorize")?,
            minecraft_login: parse_endpoint(
                "https://api.minecraftservices.com/authentication/login_with_xbox",
            )?,
            entitlements: parse_endpoint("https://api.minecraftservices.com/entitlements/mcstore")?,
            profile: parse_endpoint("https://api.minecraftservices.com/minecraft/profile")?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct MicrosoftFlowState {
    verifier: String,
    csrf: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OAuthResponse {
    Success(OAuthToken),
    Error(OAuthFailure),
}

#[derive(Deserialize)]
struct OAuthToken {
    access_token: String,
    refresh_token: Option<String>,
    #[serde(rename = "expires_in")]
    _expires_in: u64,
}

#[derive(Deserialize)]
struct OAuthFailure {
    error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct XboxUserRequest {
    properties: XboxUserProperties,
    relying_party: &'static str,
    token_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct XboxUserProperties {
    auth_method: &'static str,
    site_name: &'static str,
    rps_ticket: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct XstsRequest {
    properties: XstsProperties,
    relying_party: &'static str,
    token_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct XstsProperties {
    sandbox_id: &'static str,
    user_tokens: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum XboxResponse {
    Success(XboxToken),
    Error(XboxFailure),
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxToken {
    token: String,
    display_claims: XboxDisplayClaims,
}

#[derive(Deserialize)]
struct XboxDisplayClaims {
    xui: Vec<XboxClaim>,
}

#[derive(Deserialize)]
struct XboxClaim {
    uhs: String,
    #[serde(default)]
    xid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxFailure {
    x_err: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MinecraftLoginRequest {
    identity_token: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MinecraftLoginResponse {
    Success(MinecraftToken),
    Error {
        #[serde(rename = "error")]
        _error: String,
    },
}

#[derive(Deserialize)]
struct MinecraftToken {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct Entitlements {
    #[serde(default)]
    items: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct MinecraftProfile {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MinecraftProfileResponse {
    Success(MinecraftProfile),
    Error {
        #[serde(flatten)]
        _fields: BTreeMap<String, serde_json::Value>,
    },
}

fn minecraft_profile(
    provider: &str,
    response: MinecraftProfileResponse,
) -> Result<MinecraftProfile> {
    match response {
        MinecraftProfileResponse::Success(profile) => Ok(profile),
        MinecraftProfileResponse::Error { .. } => Err(AuthError::InvalidMinecraftProfile {
            provider: provider.into(),
        }
        .into()),
    }
}

fn ensure_minecraft_ownership(provider: &str, entitlements: &Entitlements) -> Result<()> {
    if entitlements.items.is_empty() {
        Err(AuthError::NoMinecraftOwnership {
            provider: provider.into(),
        }
        .into())
    } else {
        Ok(())
    }
}

fn oauth_result(provider: &str, response: OAuthResponse) -> Result<OAuthToken> {
    match response {
        OAuthResponse::Success(token) => Ok(token),
        OAuthResponse::Error(error) => Err(match error.error.as_str() {
            "invalid_grant" => AuthError::Expired {
                provider: provider.into(),
            },
            "authorization_pending" => AuthError::Protocol {
                provider: provider.into(),
                code: "authorization_pending".into(),
            },
            "slow_down" => AuthError::RateLimited {
                provider: provider.into(),
                retry_after_seconds: None,
            },
            _ => protocol(provider, "oauth_rejected"),
        }
        .into()),
    }
}

fn xbox_result(provider: &str, response: XboxResponse) -> Result<XboxToken> {
    match response {
        XboxResponse::Success(token) => Ok(token),
        XboxResponse::Error(error) => Err(match error.x_err {
            2_148_916_233 => AuthError::InvalidMinecraftProfile {
                provider: provider.into(),
            },
            2_148_916_235 | 2_148_916_236 => AuthError::AccountRestricted {
                provider: provider.into(),
                reason: AccountRestriction::RegionRestricted,
            },
            2_148_916_237 | 2_148_916_238 => AuthError::AccountRestricted {
                provider: provider.into(),
                reason: AccountRestriction::ChildAccount,
            },
            _ => protocol(provider, "xsts_denied"),
        }
        .into()),
    }
}

fn first_xbox_claim<'a>(provider: &str, token: &'a XboxToken) -> Result<&'a XboxClaim> {
    token
        .display_claims
        .xui
        .first()
        .filter(|claim| !claim.uhs.is_empty())
        .ok_or_else(|| protocol(provider, "xbox_profile_missing").into())
}

fn validate_config(config: &MicrosoftAuthConfig) -> Result<()> {
    if config.client_id.is_empty()
        || config.client_id.len() > 128
        || !config
            .client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !matches!(config.tenant.as_str(), "consumers" | "common")
    {
        return Err(protocol("microsoft", "invalid_public_client_config").into());
    }
    if config.redirect_url.scheme() != "http"
        || !matches!(
            config.redirect_url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        )
        || config.redirect_url.query().is_some()
        || config.redirect_url.fragment().is_some()
        || !config.redirect_url.username().is_empty()
        || config.redirect_url.password().is_some()
    {
        return Err(protocol("microsoft", "loopback_redirect_required").into());
    }
    Ok(())
}

fn validate_callback_origin(expected: &Url, actual: &Url) -> std::result::Result<(), &'static str> {
    if expected.scheme() != actual.scheme()
        || expected.host_str() != actual.host_str()
        || expected.port_or_known_default() != actual.port_or_known_default()
        || expected.path() != actual.path()
        || actual.fragment().is_some()
        || !actual.username().is_empty()
        || actual.password().is_some()
    {
        Err("callback_origin_mismatch")
    } else {
        Ok(())
    }
}

fn canonical_uuid(value: &str) -> Option<String> {
    let compact = value.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &compact[0..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..32]
    ))
}

fn random_urlsafe(length: usize) -> Result<String> {
    let mut bytes = vec![0_u8; length];
    getrandom::fill(&mut bytes).map_err(|_| protocol("microsoft", "secure_random_failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn parse_endpoint(value: &str) -> Result<Url> {
    Url::parse(value).map_err(|_| protocol("microsoft", "invalid_endpoint").into())
}

fn protocol(provider: &str, code: &'static str) -> AuthError {
    AuthError::Protocol {
        provider: provider.into(),
        code: code.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auth::InMemoryCredentialStore, download::CancellationToken};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn config() -> MicrosoftAuthConfig {
        MicrosoftAuthConfig {
            client_id: "00001111-aaaa-2222-bbbb-3333cccc4444".into(),
            redirect_url: Url::parse("http://127.0.0.1:32123/callback").expect("URL"),
            tenant: "consumers".into(),
        }
    }

    #[tokio::test]
    async fn browser_challenge_uses_pkce_and_keeps_verifier_secret() {
        let provider = MicrosoftAuthProvider::new("microsoft", config()).expect("provider");
        let store = Arc::new(InMemoryCredentialStore::default());
        let cancellation = CancellationToken::default();
        let step = provider
            .begin(
                AuthRequest::default(),
                AuthContext {
                    credentials: store.as_ref(),
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("begin");
        let rendered = format!("{step:?}");
        assert!(!rendered.contains("verifier"));
        assert!(!rendered.contains("code_challenge="));
        assert!(!rendered.contains("state="));
        let AuthProviderStep::Challenge { challenge, .. } = step else {
            panic!("browser challenge")
        };
        let AuthChallenge::Browser {
            authorization_url, ..
        } = challenge
        else {
            panic!("browser challenge")
        };
        let query = authorization_url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            query.get("code_challenge_method").map(|v| v.as_ref()),
            Some("S256")
        );
        assert!(query.contains_key("code_challenge"));
        assert!(query.contains_key("state"));
    }

    #[tokio::test]
    async fn browser_callback_rejects_state_and_origin_mismatch_before_network() {
        let provider = MicrosoftAuthProvider::new("microsoft", config()).expect("provider");
        let store = InMemoryCredentialStore::default();
        let cancellation = CancellationToken::default();
        let AuthProviderStep::Challenge { state, .. } = provider
            .begin(
                AuthRequest::default(),
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("begin")
        else {
            panic!("browser challenge")
        };
        let callback =
            Url::parse("http://127.0.0.1:32123/callback?code=code&state=wrong").expect("callback");
        let error = provider
            .continue_flow(
                state,
                AuthResponse::BrowserCallback {
                    callback_url: callback,
                },
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect_err("state mismatch");
        assert!(matches!(
            error,
            crate::Error::Auth(AuthError::Protocol { .. })
        ));
    }

    #[test]
    fn validates_loopback_and_profile_uuid() {
        let mut invalid = config();
        invalid.redirect_url = Url::parse("https://evil.example/callback").expect("URL");
        assert!(MicrosoftAuthProvider::new("microsoft", invalid).is_err());
        assert_eq!(
            canonical_uuid("0123456789abcdef0123456789abcdef"),
            Some("01234567-89ab-cdef-0123-456789abcdef".into())
        );
        assert!(canonical_uuid("not-a-uuid").is_none());
    }

    #[test]
    fn parses_structured_xsts_restrictions() {
        let Err(error) = xbox_result(
            "microsoft",
            XboxResponse::Error(XboxFailure {
                x_err: 2_148_916_238,
            }),
        ) else {
            panic!("expected restriction")
        };
        assert!(matches!(
            error,
            crate::Error::Auth(AuthError::AccountRestricted {
                reason: AccountRestriction::ChildAccount,
                ..
            })
        ));
    }

    #[test]
    fn maps_oauth_expiry_and_missing_minecraft_profile() {
        let Err(oauth) = oauth_result(
            "microsoft",
            OAuthResponse::Error(OAuthFailure {
                error: "invalid_grant".into(),
            }),
        ) else {
            panic!("expected expired refresh token")
        };
        assert!(matches!(
            oauth,
            crate::Error::Auth(AuthError::Expired { .. })
        ));

        let Err(profile) = minecraft_profile(
            "microsoft",
            MinecraftProfileResponse::Error {
                _fields: BTreeMap::from([(
                    "error".into(),
                    serde_json::Value::String("NOT_FOUND".into()),
                )]),
            },
        ) else {
            panic!("expected missing profile")
        };
        assert!(matches!(
            profile,
            crate::Error::Auth(AuthError::InvalidMinecraftProfile { .. })
        ));

        let ownership =
            ensure_minecraft_ownership("microsoft", &Entitlements { items: Vec::new() })
                .expect_err("missing ownership");
        assert!(matches!(
            ownership,
            crate::Error::Auth(AuthError::NoMinecraftOwnership { .. })
        ));
    }

    #[test]
    fn injectable_endpoints_exist_only_for_mocked_unit_tests() {
        let endpoints = MicrosoftEndpoints::production(&config()).expect("endpoints");
        let provider = MicrosoftAuthProvider::with_endpoints("microsoft", config(), endpoints)
            .expect("provider");
        assert_eq!(provider.id(), "microsoft");
    }

    #[tokio::test]
    async fn mocked_oauth_xbox_xsts_minecraft_profile_and_refresh_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 16 * 1024];
                    let Ok(read) = socket.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = match path {
                        "/token" => serde_json::json!({
                            "access_token":"microsoft-oauth-secret",
                            "refresh_token":"microsoft-refresh-secret",
                            "expires_in":3600
                        }),
                        "/xbox-user" => serde_json::json!({
                            "Token":"xbox-user-secret",
                            "DisplayClaims":{"xui":[{"uhs":"user-hash"}]}
                        }),
                        "/xsts" => serde_json::json!({
                            "Token":"xsts-secret",
                            "DisplayClaims":{"xui":[{"uhs":"user-hash","xid":"123456"}]}
                        }),
                        "/minecraft-login" => serde_json::json!({
                            "access_token":"minecraft-access-secret",
                            "expires_in":86400
                        }),
                        "/entitlements" => serde_json::json!({"items":[{"name":"game_minecraft"}]}),
                        "/profile" => serde_json::json!({
                            "id":"0123456789abcdef0123456789abcdef",
                            "name":"MinecraftUser"
                        }),
                        _ => serde_json::json!({"error":"missing"}),
                    }
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        let endpoint =
            |path: &str| Url::parse(&format!("http://{address}{path}")).expect("endpoint URL");
        let endpoints = MicrosoftEndpoints {
            authorize: endpoint("/authorize"),
            token: endpoint("/token"),
            xbox_user_auth: endpoint("/xbox-user"),
            xsts: endpoint("/xsts"),
            minecraft_login: endpoint("/minecraft-login"),
            entitlements: endpoint("/entitlements"),
            profile: endpoint("/profile"),
        };
        let provider = MicrosoftAuthProvider::with_endpoints("microsoft", config(), endpoints)
            .expect("provider");
        let store = InMemoryCredentialStore::default();
        let cancellation = CancellationToken::default();
        let step = provider
            .begin(
                AuthRequest::default(),
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("begin");
        let AuthProviderStep::Challenge { challenge, state } = step else {
            panic!("browser challenge")
        };
        let AuthChallenge::Browser {
            authorization_url, ..
        } = challenge
        else {
            panic!("browser challenge")
        };
        let csrf = authorization_url
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .expect("state");
        let callback = Url::parse(&format!(
            "http://127.0.0.1:32123/callback?code=auth-code-secret&state={csrf}"
        ))
        .expect("callback");
        let step = provider
            .continue_flow(
                state,
                AuthResponse::BrowserCallback {
                    callback_url: callback,
                },
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("complete chain");
        let AuthProviderStep::Authenticated(session) = step else {
            panic!("session")
        };
        assert!(matches!(session.minecraft, MinecraftIdentity::Official(_)));
        assert_eq!(session.identity.username, "MinecraftUser");
        let debug = format!("{session:?}");
        for secret in [
            "microsoft-oauth-secret",
            "microsoft-refresh-secret",
            "xbox-user-secret",
            "xsts-secret",
            "minecraft-access-secret",
            "auth-code-secret",
        ] {
            assert!(!debug.contains(secret));
        }
        let refreshed = provider
            .refresh(
                &session,
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("refresh chain");
        assert!(matches!(
            refreshed.minecraft,
            MinecraftIdentity::Official(_)
        ));
        provider
            .verify(
                &refreshed,
                AuthContext {
                    credentials: &store,
                    cancellation: &cancellation,
                },
            )
            .await
            .expect("verify profile");
        server.abort();
    }
}
