# Phase 6 validation report

This report records the implementation boundary and the reproducible evidence
for the extensible authentication architecture.

## Architecture and API

1. `AuthProvider` is an object-safe async, compile-time extension trait.
2. `AuthFlow` and `AuthChallenge` model credentials, browser, device-code and
   2FA interactions without UI or stdin access in Core.
3. `AuthSession` contains provider identity/session state, expiry and normalized
   launch identity.
4. `AuthIdentity` is separate from `MinecraftIdentity` (`Official`/`Offline`).
5. `CredentialStore` owns all token persistence; in-memory and OS-vault
   implementations are provided.
6. `AuthManager` provides registry, flow, session, refresh and logout APIs.
7. Capabilities are advertised; launch code never downcasts providers.
8. Offline, Microsoft, Azuriom, HTTP and custom Rust providers are available.

## Providers and trust

9. Microsoft uses public-client Authorization Code + PKCE and the OAuth → Xbox
   → XSTS → Minecraft Services chain.
10. Refresh repeats the token chain and is attempted before launch.
11. Azuriom uses the Rust AzAuth client, including a typed 2FA challenge.
12. Azuriom and HTTP providers always produce `MinecraftIdentity::Offline`.
13. HTTP implements CentralCorp Auth Protocol v1 (`login`, `session`, `refresh`,
    `logout`) with typed failures.
14. A custom provider example registers without modifying CentralCore.
15. CLI commands cover providers, login, status/accounts, refresh, logout and
    trusted provider add/remove/show.
16. LaunchPlan receives only normalized `MinecraftIdentity`.
17. Instance manifests contain an allow-list of already trusted provider IDs;
    they cannot define credential-bearing URLs.
18. Generic auth events and structured errors contain no secrets.

## Security and tests

19. Secret values are redacted from `Debug`, errors, events, tracing, CLI JSON
    and launch-plan diagnostics; secret allocations are zeroized on drop.
20. HTTP auth defaults to HTTPS, rejects URL credentials/query/fragment,
    disables redirects, bounds responses, applies timeouts and supports cancel.
21. Mock provider tests cover success, credentials, browser, device code, 2FA,
    expiry, refresh, failure and logout.
22. Local HTTP and Azuriom mocks cover success, typed failures, 429/500,
    malformed/oversized responses, timeout and cancellation.
23. Microsoft protocol tests mock OAuth, Xbox, XSTS, ownership, profile and
    refresh; no real account is used in CI.

## Reproducible validation

At the time of this report:

- `cargo fmt --all -- --check`: passed;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed;
- `cargo test --workspace`: 94 active tests passed, 5 intentionally ignored;
- `cargo doc --workspace --no-deps`: passed with no warnings;
- Fabric and Forge Phase 5 verification remained green.

The ignored tests in `tests/auth_external_e2e.rs` are the real Microsoft and
Azuriom checks. They require team-controlled services and disposable
credentials supplied only through environment variables; their commands are
documented in [e2e.md](e2e.md). Device Code is part of the generic contract and
mock provider; Microsoft currently exposes browser PKCE only. Remote Microsoft
revocation and a native loopback listener remain Phase 7 candidates.
