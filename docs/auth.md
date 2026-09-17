# Authentication architecture

CentralCore authentication is headless and provider-neutral. A frontend drives
the state machine exposed by `core.auth()`; providers never read stdin, open a
browser, or create a window.

```text
CLI / Tauri / Rust host
          |
      AuthManager ---- trusted local registry
          |
      AuthProvider
          |
       AuthFlow ---- AuthChallenge / AuthResponse
          |
      AuthSession
       /       \
AuthIdentity  MinecraftIdentity
                    |
                LaunchPlan
```

## Flow contract

`AuthManager::begin(provider_id, request, cancellation)` returns either an
`AuthFlow::Challenge` or `AuthFlow::Authenticated`. A challenge has an opaque
flow ID and one structured action:

- `Credentials`: labels and whether a password is required;
- `Browser`: authorization URL and expected callback URL;
- `DeviceCode`: verification URL, redacted user code, expiry and poll interval;
- `TwoFactorCode`: an optional display message.

The application renders that action and calls `continue_flow` with the matching
`AuthResponse`. Provider-owned continuation state remains inside AuthManager
and is wrapped as a secret. Device polling is initiated by the application, so
it can honor the interval, cancellation and expiration without a hidden task.

## Session and identity model

`AuthSession` contains a stable local account ID, provider ID, `AuthIdentity`,
provider session state, expiry/refresh information, and one
`MinecraftIdentity`. `ProviderSession` access/refresh/device values are not
Minecraft credentials.

`AuthIdentity` describes the account asserted by the provider: provider user
ID, username and explicitly non-secret metadata. `MinecraftIdentity` is a
separate enum:

- `Official`: Minecraft username, UUID, Minecraft Services access token,
  optional XUID and expiration;
- `Offline`: username and a stable UUID, with no official token.

Launch code consumes only `MinecraftIdentity`; it contains no Microsoft,
Azuriom or HTTP branch. Before account launch, `identity_for_launch` refreshes
an expired refreshable session and asks the provider to verify it.

## Manager API

`providers`, `register`, `begin`, `continue_flow`, `cancel_flow`, `sessions`, `session`,
`refresh`, `identity_for_launch`, and `logout` form the runtime API. The
configuration helpers `add_configured`, `configured`, `configured_provider`
and `remove_configured` manage the versioned local trust registry.

Provider behavior is discovered through `AuthCapabilities`, never through a
downcast or a concrete-provider comparison. See [provider details](auth/providers.md)
and the [custom provider tutorial](auth/custom-provider.md).

## Errors and cancellation

Callers match `AuthError` categories rather than parsing messages:
`InvalidCredentials`, `TwoFactorRequired`, `Cancelled`, `Expired`,
`ProviderUnavailable`, `RateLimited`, `AccountRestricted`,
`NoMinecraftOwnership`, `InvalidMinecraftProfile`, `CredentialStore` and
`Protocol`. Network requests have finite timeouts, honor 429 retry metadata,
and observe `CancellationToken::cancelled()` while sending and reading.

## Real E2E qualification

The repository contains deterministic mock E2E tests. Real provider tests are
manual by design: they require team-controlled accounts and must be run with
interactive input. The procedure is documented in [auth/e2e.md](auth/e2e.md);
the implementation and gate inventory is summarized in the [Phase 6 report](auth/phase6-report.md).

## Persistence

Non-secret account metadata is stored in `<data>/auth/accounts.json`. Provider
access/refresh/device secrets and official Minecraft access tokens are stored
through `CredentialStore`; they never enter an instance manifest or
`instance.json`. `SystemCredentialStore` uses the operating-system vault via
the `keyring` backend (Credential Manager, Keychain, or Secret Service).
`InMemoryCredentialStore` is available for tests and ephemeral hosts and can
be injected with `CentralCore::builder().credential_store(...)`.

Native vault APIs do not expose one portable enumeration operation.
`SystemCredentialStore` therefore maintains a versioned non-secret key index
inside the vault so `list` survives restarts. Concurrent processes merge their
observed index on updates; AuthManager still avoids enumeration and deletes its
fixed per-account key set explicitly. `InMemoryCredentialStore::list` is
complete and deterministic.
