use std::sync::Arc;

use centralcore::{
    auth::{
        AuthFlow, AuthManager, AuthProvider, AuthRequest, AuthResponse, AzuriomAuthProvider,
        HttpAuthPolicy, InMemoryCredentialStore, MinecraftIdentity, SecretString,
    },
    download::CancellationToken,
    errors::{AccountRestriction, AuthError},
    events::EventBus,
    Error,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

struct AzuriomServer {
    base: Url,
    task: tokio::task::JoinHandle<()>,
}

impl AzuriomServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(handle(socket));
            }
        });
        Self {
            base: Url::parse(&format!("http://{address}/")).expect("URL"),
            task,
        }
    }
}

impl Drop for AzuriomServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(mut socket: TcpStream) {
    let mut bytes = vec![0_u8; 16 * 1024];
    let Ok(read) = socket.read(&mut bytes).await else {
        return;
    };
    let request = String::from_utf8_lossy(&bytes[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    if body.contains("timeout") {
        tokio::time::sleep(std::time::Duration::from_millis(1_250)).await;
    }
    let access_token = if body.contains("expired-session") {
        "expired-token"
    } else {
        "azuriom-access-secret"
    };
    let user = serde_json::json!({
        "id":42,
        "name":"Player_1",
        "game_id":"5627dd98-e6be-3c21-b8a8-e92344183641",
        "access_token":access_token
    })
    .to_string();
    let (status, response, extra) = match path {
        "/api/auth/authenticate" if body.contains("rate-limited") =>
            ("429 Too Many Requests", "{}".into(), "Retry-After: 9\r\n"),
        "/api/auth/authenticate" if body.contains("server-error") =>
            ("500 Internal Server Error", "{}".into(), ""),
        "/api/auth/authenticate" if body.contains("invalid") =>
            ("422 Unprocessable Entity", serde_json::json!({"status":"error","reason":"invalid_credentials","message":"Invalid credentials"}).to_string(), ""),
        "/api/auth/authenticate" if body.contains("banned") =>
            ("403 Forbidden", serde_json::json!({"status":"error","reason":"user_banned","message":"User banned"}).to_string(), ""),
        "/api/auth/authenticate" if body.contains("disabled") =>
            ("403 Forbidden", serde_json::json!({"status":"error","reason":"account_disabled","message":"Account disabled"}).to_string(), ""),
        "/api/auth/authenticate" if body.contains("bad-json") =>
            ("200 OK", "{".into(), ""),
        "/api/auth/authenticate" if body.contains("oversized") =>
            ("200 OK", format!("\"{}\"", "x".repeat(2_048)), ""),
        "/api/auth/authenticate" if body.contains("two-factor") && !body.contains("\"code\"") =>
            ("422 Unprocessable Entity", serde_json::json!({"status":"pending","reason":"2fa","message":"Missing 2FA code"}).to_string(), ""),
        "/api/auth/verify" if body.contains("expired-token") =>
            ("401 Unauthorized", serde_json::json!({"status":"error","reason":"invalid_token"}).to_string(), ""),
        "/api/auth/authenticate" | "/api/auth/verify" => ("200 OK", user, ""),
        "/api/auth/logout" => ("200 OK", serde_json::json!({"status":"success"}).to_string(), ""),
        _ => ("404 Not Found", "{}".into(), ""),
    };
    let response = format!("HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len());
    let _ = socket.write_all(response.as_bytes()).await;
}

async fn manager(server: &AzuriomServer) -> AuthManager {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let manager = AuthManager::new(
        directory,
        Arc::new(InMemoryCredentialStore::default()),
        EventBus::new(32),
    );
    let provider = AzuriomAuthProvider::with_policy(
        "az-test",
        server.base.clone(),
        HttpAuthPolicy {
            timeout_seconds: 1,
            max_response_size: 1024,
            allow_insecure_loopback: true,
        },
    )
    .expect("provider");
    manager
        .register(Arc::new(provider) as Arc<dyn AuthProvider>)
        .await
        .expect("register");
    manager
}

async fn login(manager: &AuthManager, username: &str) -> centralcore::Result<AuthFlow> {
    let cancellation = CancellationToken::default();
    let AuthFlow::Challenge { flow_id, .. } = manager
        .begin("az-test", AuthRequest::default(), &cancellation)
        .await?
    else {
        panic!("credentials")
    };
    manager
        .continue_flow(
            &flow_id,
            AuthResponse::Credentials {
                username: username.into(),
                password: Some(SecretString::new("password-secret")),
            },
            &cancellation,
        )
        .await
}

#[tokio::test]
async fn azauth_two_factor_verify_and_logout_remain_offline_identity() {
    let server = AzuriomServer::start().await;
    let manager = manager(&server).await;
    let AuthFlow::Challenge { flow_id, .. } = login(&manager, "two-factor").await.expect("2FA")
    else {
        panic!("2FA")
    };
    let cancellation = CancellationToken::default();
    let flow = manager
        .continue_flow(
            &flow_id,
            AuthResponse::TwoFactorCode {
                code: SecretString::new("123456"),
            },
            &cancellation,
        )
        .await
        .expect("2FA success");
    let AuthFlow::Authenticated(session) = flow else {
        panic!("session")
    };
    assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
    assert!(session.minecraft.access_token().is_none());
    let debug = format!("{session:?}");
    assert!(!debug.contains("azuriom-access-secret"));
    assert!(!debug.contains("password-secret"));
    manager
        .identity_for_launch(&session.account_id, &cancellation)
        .await
        .expect("verify");
    manager
        .logout(&session.account_id, &cancellation)
        .await
        .expect("logout");
}

#[tokio::test]
async fn azauth_maps_credentials_ban_rate_limit_and_server_error() {
    let server = AzuriomServer::start().await;
    let manager = manager(&server).await;
    assert!(matches!(
        login(&manager, "invalid").await,
        Err(Error::Auth(AuthError::InvalidCredentials { .. }))
    ));
    assert!(matches!(
        login(&manager, "banned").await,
        Err(Error::Auth(AuthError::AccountRestricted {
            reason: AccountRestriction::Banned,
            ..
        }))
    ));
    assert!(matches!(
        login(&manager, "disabled").await,
        Err(Error::Auth(AuthError::AccountRestricted {
            reason: AccountRestriction::Disabled,
            ..
        }))
    ));
    assert!(matches!(
        login(&manager, "rate-limited").await,
        Err(Error::Auth(AuthError::RateLimited {
            retry_after_seconds: Some(9),
            ..
        }))
    ));
    assert!(matches!(
        login(&manager, "server-error").await,
        Err(Error::Auth(AuthError::ProviderUnavailable { .. }))
    ));
    assert!(matches!(
        login(&manager, "bad-json").await,
        Err(Error::Auth(AuthError::Protocol { .. }))
    ));
    assert!(matches!(
        login(&manager, "oversized").await,
        Err(Error::Auth(AuthError::Protocol { .. }))
    ));
    assert!(matches!(
        login(&manager, "timeout").await,
        Err(Error::Auth(AuthError::ProviderUnavailable { .. }))
    ));

    let AuthFlow::Authenticated(expired) = login(&manager, "expired-session")
        .await
        .expect("expired session login")
    else {
        panic!("session")
    };
    let cancellation = CancellationToken::default();
    assert!(matches!(
        manager
            .identity_for_launch(&expired.account_id, &cancellation)
            .await,
        Err(Error::Auth(AuthError::Expired { .. }))
    ));
}
