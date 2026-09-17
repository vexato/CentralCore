# Authentication providers

## IDs and capabilities

Provider IDs are portable local identifiers. Built-in Offline is registered as
`offline`; configured providers use the locally chosen ID (for example
`microsoft`, `my-azuriom`, or `my-network`). A remote instance may reference
these IDs but cannot create them.

Every provider advertises capability flags for interaction, credentials, 2FA,
browser, device code, refresh, verification, logout and official Minecraft
sessions. Frontends use those flags and the actual challenges; they do not
inspect the Rust concrete type.

## Official implementations

- `OfflineAuthProvider` returns a stable Java-compatible offline UUID derived
  from `OfflinePlayer:<username>` and never invents an access token.
- `MicrosoftAuthProvider` uses public-client Authorization Code + PKCE and is
  the only supplied network provider that produces an official identity.
- `AzuriomAuthProvider` implements AzAuth directly and produces an offline
  Minecraft identity.
- `HttpAuthProvider` implements CentralCorp Auth Protocol v1 and produces an
  offline Minecraft identity.
- Any Rust application can register its own compile-time `AuthProvider`.

`MockAuthProvider` is public test support. Its scenarios cover immediate
success, credentials, 2FA, browser, device code, refresh after expiration,
failure and logout without network access.

## Trusted local registry

Configurable provider endpoints live in `<data>/auth/providers.json`:

```json
{
  "format_version": 1,
  "providers": {
    "my-azuriom": {
      "type": "azuriom",
      "base_url": "https://example.com/"
    }
  }
}
```

This file contains public configuration only. Microsoft client secrets and
user tokens are not valid fields. Adding HTTP or Azuriom configuration is an
explicit local trust decision because credentials will be sent to that origin.

An instance policy such as `providers: ["microsoft", "my-azuriom"]` is only an
allow-list reference. It cannot carry a URL, provision a provider, or redirect
credentials. This is the boundary that prevents a compromised static manifest
from silently selecting an attacker endpoint.

