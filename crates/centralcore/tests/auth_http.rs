use std::{sync::Arc, time::Duration};

use centralcore::{
    auth::{
        AuthFlow, AuthManager, AuthProvider, AuthRequest, AuthResponse, HttpAuthPolicy,
        HttpAuthProvider, InMemoryCredentialStore, MinecraftIdentity, SecretString,
    },
    download::CancellationToken,
    errors::AuthError,
    events::EventBus,
    Error,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

struct MockAuthHttp {
    base: Url,
    task: tokio::task::JoinHandle<()>,
}

impl MockAuthHttp {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(handle(socket));
            }
        });
        Self {
            base: Url::parse(&format!("http://{address}/auth/v1/")).expect("URL"),
            task,
        }
    }
}

impl Drop for MockAuthHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(mut socket: TcpStream) {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok(read) = socket.read(&mut buffer).await else {
            return;
        };
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&buffer[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if bytes.len() >= header_end + 4 + content_length {
            break;
        }
    }
    let request = String::from_utf8_lossy(&bytes);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    if body.contains("timeout") {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let (status, response) = match path {
        "/auth/v1/login" if body.contains("bad-json") => ("200 OK", "{".into()),
        "/auth/v1/login" if body.contains("oversized") => ("200 OK", "x".repeat(2048)),
        "/auth/v1/login" if body.contains("typed-server-error") => ("200 OK", serde_json::json!({"status":"error","code":"server_error"}).to_string()),
        "/auth/v1/login" if body.contains("server-error") => ("500 Internal Server Error", "{}".into()),
        "/auth/v1/login" if body.contains("rate-limited") => {
            let response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            let _ = socket.write_all(response.as_bytes()).await;
            return;
        }
        "/auth/v1/login" if body.contains("invalid") => ("422 Unprocessable Entity", serde_json::json!({"status":"error","code":"invalid_credentials"}).to_string()),
        "/auth/v1/login" if body.contains("two-factor") && !body.contains("continuation_token") => ("422 Unprocessable Entity", serde_json::json!({"status":"challenge","challenge":"two_factor","continuation_token":"continuation-secret","message":"2FA required"}).to_string()),
        "/auth/v1/login" => ("200 OK", success("access-secret", Some("refresh-secret"))),
        "/auth/v1/session" => ("200 OK", success("access-secret", Some("refresh-secret"))),
        "/auth/v1/refresh" => ("200 OK", success("new-access-secret", Some("new-refresh-secret"))),
        "/auth/v1/logout" => ("200 OK", serde_json::json!({"status":"success"}).to_string()),
        _ => ("404 Not Found", "{}".into()),
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len());
    let _ = socket.write_all(response.as_bytes()).await;
}

fn success(access: &str, refresh: Option<&str>) -> String {
    serde_json::json!({
        "status":"success",
        "account":{"id":"42","username":"Player_1","metadata":{"rank":"member"}},
        "session":{"access_token":access,"refresh_token":refresh,"expires_at":4_000_000_000_u64}
    })
    .to_string()
}

async fn manager(server: &MockAuthHttp, max_response_size: usize) -> AuthManager {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let manager = AuthManager::new(
        directory,
        Arc::new(InMemoryCredentialStore::default()),
        EventBus::new(32),
    );
    let provider = HttpAuthProvider::with_policy(
        "network",
        server.base.clone(),
        HttpAuthPolicy {
            timeout_seconds: 1,
            max_response_size,
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

async fn credentials(manager: &AuthManager, username: &str) -> centralcore::Result<AuthFlow> {
    let cancellation = CancellationToken::default();
    let flow = manager
        .begin("network", AuthRequest::default(), &cancellation)
        .await?;
    let AuthFlow::Challenge { flow_id, .. } = flow else {
        panic!("credentials challenge")
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
async fn protocol_v1_supports_login_two_factor_verify_refresh_and_logout() {
    let server = MockAuthHttp::start().await;
    let manager = manager(&server, 4096).await;
    let flow = credentials(&manager, "two-factor")
        .await
        .expect("first step");
    let AuthFlow::Challenge { flow_id, .. } = flow else {
        panic!("2FA challenge")
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
        .expect("2FA");
    let AuthFlow::Authenticated(session) = flow else {
        panic!("authenticated")
    };
    assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
    assert!(session.minecraft.access_token().is_none());
    let debug = format!("{session:?}");
    for secret in [
        "password-secret",
        "continuation-secret",
        "123456",
        "access-secret",
        "refresh-secret",
    ] {
        assert!(!debug.contains(secret));
    }
    manager
        .identity_for_launch(&session.account_id, &cancellation)
        .await
        .expect("verify");
    let refreshed = manager
        .refresh(&session.account_id, &cancellation)
        .await
        .expect("refresh");
    assert_eq!(refreshed.identity.username, "Player_1");
    manager
        .logout(&session.account_id, &cancellation)
        .await
        .expect("logout");
    assert!(manager.sessions().await.is_empty());
}

#[tokio::test]
async fn protocol_v1_maps_failures_and_enforces_response_limit() {
    let server = MockAuthHttp::start().await;
    let manager = manager(&server, 1024).await;
    assert!(matches!(
        credentials(&manager, "invalid").await,
        Err(Error::Auth(AuthError::InvalidCredentials { .. }))
    ));
    assert!(matches!(
        credentials(&manager, "rate-limited").await,
        Err(Error::Auth(AuthError::RateLimited {
            retry_after_seconds: Some(17),
            ..
        }))
    ));
    assert!(matches!(
        credentials(&manager, "server-error").await,
        Err(Error::Auth(AuthError::ProviderUnavailable { .. }))
    ));
    assert!(matches!(
        credentials(&manager, "typed-server-error").await,
        Err(Error::Auth(AuthError::ProviderUnavailable { .. }))
    ));
    assert!(matches!(
        credentials(&manager, "bad-json").await,
        Err(Error::Auth(AuthError::Protocol { .. }))
    ));
    assert!(matches!(
        credentials(&manager, "oversized").await,
        Err(Error::Auth(AuthError::Protocol { .. }))
    ));
    assert!(matches!(
        credentials(&manager, "timeout").await,
        Err(Error::Auth(AuthError::ProviderUnavailable { .. }))
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn protocol_request_is_cancelled_while_waiting_for_server() {
    let server = MockAuthHttp::start().await;
    let manager = manager(&server, 1024).await;
    let cancellation = CancellationToken::default();
    let AuthFlow::Challenge { flow_id, .. } = manager
        .begin("network", AuthRequest::default(), &cancellation)
        .await
        .expect("begin")
    else {
        panic!("credentials challenge")
    };
    let cancellation_request = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation_request.cancel();
    });
    let started = std::time::Instant::now();
    let result = manager
        .continue_flow(
            &flow_id,
            AuthResponse::Credentials {
                username: "timeout".into(),
                password: Some(SecretString::new("password-secret")),
            },
            &cancellation,
        )
        .await;
    assert!(matches!(
        result,
        Err(Error::Auth(AuthError::Cancelled { .. }))
    ));
    assert!(started.elapsed() < Duration::from_millis(750));
}
