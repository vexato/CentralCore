//! Opt-in end-to-end checks against team-controlled authentication services.
//!
//! These tests are intentionally ignored: they require disposable credentials
//! supplied through environment variables and must never run in CI by default.

use std::sync::Arc;

use centralcore::{
    auth::{
        AuthChallenge, AuthManager, AuthRequest, AuthResponse, AzuriomAuthProvider,
        InMemoryCredentialStore, MicrosoftAuthConfig, MicrosoftAuthProvider, MinecraftIdentity,
        SecretString,
    },
    download::CancellationToken,
    events::EventBus,
};
use url::Url;

fn manager() -> (AuthManager, tempfile::TempDir, CancellationToken) {
    let dir = tempfile::tempdir().expect("temporary auth data directory");
    let auth = AuthManager::new(
        dir.path(),
        Arc::new(InMemoryCredentialStore::default()),
        EventBus::new(32),
    );
    (auth, dir, CancellationToken::default())
}

#[tokio::test]
#[ignore = "requires a team-owned Microsoft account and Azure public client"]
async fn microsoft_real_account_produces_official_identity() {
    let client_id = std::env::var("CENTRALCORE_MS_CLIENT_ID").expect("client id env");
    let redirect =
        Url::parse(&std::env::var("CENTRALCORE_MS_REDIRECT_URL").expect("redirect URL env"))
            .expect("valid redirect URL");
    let callback = Url::parse(
        &std::env::var("CENTRALCORE_MS_CALLBACK_URL").expect("completed callback URL env"),
    )
    .expect("valid callback URL");
    let provider = MicrosoftAuthProvider::new(
        "microsoft-e2e",
        MicrosoftAuthConfig {
            client_id,
            redirect_url: redirect,
            tenant: std::env::var("CENTRALCORE_MS_TENANT").unwrap_or_else(|_| "consumers".into()),
        },
    )
    .expect("provider");
    let (auth, _dir, cancellation) = manager();
    auth.register(Arc::new(provider)).await.expect("register");
    let flow = auth
        .begin("microsoft-e2e", AuthRequest::default(), &cancellation)
        .await
        .expect("begin");
    assert!(matches!(
        flow,
        centralcore::auth::AuthFlow::Challenge {
            challenge: AuthChallenge::Browser { .. },
            ..
        }
    ));
    let flow_id = match flow {
        centralcore::auth::AuthFlow::Challenge { flow_id, .. } => flow_id,
        _ => unreachable!(),
    };
    let result = auth
        .continue_flow(
            &flow_id,
            AuthResponse::BrowserCallback {
                callback_url: callback,
            },
            &cancellation,
        )
        .await
        .expect("OAuth/Xbox/XSTS/Minecraft flow");
    let centralcore::auth::AuthFlow::Authenticated(session) = result else {
        panic!("expected session")
    };
    assert!(matches!(session.minecraft, MinecraftIdentity::Official(_)));
}

#[tokio::test]
#[ignore = "requires a team-controlled Azuriom instance and disposable account"]
async fn azuriom_real_account_produces_offline_identity() {
    let base = Url::parse(&std::env::var("CENTRALCORE_AZURIOM_URL").expect("Azuriom URL env"))
        .expect("valid Azuriom URL");
    let provider = AzuriomAuthProvider::new("azuriom-e2e", base).expect("provider");
    let username = std::env::var("CENTRALCORE_AZURIOM_USERNAME").expect("username env");
    let password =
        SecretString::new(std::env::var("CENTRALCORE_AZURIOM_PASSWORD").expect("password env"));
    let (auth, _dir, cancellation) = manager();
    auth.register(Arc::new(provider)).await.expect("register");
    let flow = auth
        .begin("azuriom-e2e", AuthRequest::default(), &cancellation)
        .await
        .expect("begin");
    let (flow_id, challenge) = match flow {
        centralcore::auth::AuthFlow::Challenge {
            flow_id, challenge, ..
        } => (flow_id, challenge),
        _ => panic!("expected credentials challenge"),
    };
    assert!(matches!(challenge, AuthChallenge::Credentials { .. }));
    let flow = auth
        .continue_flow(
            &flow_id,
            AuthResponse::Credentials {
                username,
                password: Some(password),
            },
            &cancellation,
        )
        .await
        .expect("Azuriom login");
    let flow = match flow {
        centralcore::auth::AuthFlow::Authenticated(_) => flow,
        centralcore::auth::AuthFlow::Challenge {
            flow_id,
            challenge: AuthChallenge::TwoFactorCode { .. },
            ..
        } => {
            let code = SecretString::new(
                std::env::var("CENTRALCORE_AZURIOM_2FA_CODE").expect("2FA code env"),
            );
            auth.continue_flow(
                &flow_id,
                AuthResponse::TwoFactorCode { code },
                &cancellation,
            )
            .await
            .expect("Azuriom 2FA")
        }
        _ => panic!("expected authenticated session or 2FA challenge"),
    };
    let session = match flow {
        centralcore::auth::AuthFlow::Authenticated(session) => session,
        _ => panic!("expected session after 2FA"),
    };
    assert!(matches!(session.minecraft, MinecraftIdentity::Offline(_)));
    let account = session.account_id.clone();
    let identity = auth
        .identity_for_launch(&account, &cancellation)
        .await
        .expect("Azuriom verify");
    assert!(matches!(identity, MinecraftIdentity::Offline(_)));
    auth.logout(&account, &cancellation).await.expect("logout");
}
