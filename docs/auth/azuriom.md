# Azuriom authentication

`AzuriomAuthProvider` is a direct Rust client for AzAuth under `/api/auth/`.
It supports `authenticate`, `verify`, and `logout` without the JavaScript
library.

Login starts with a credentials challenge. If AzAuth requests two-factor
authentication, the provider returns `AuthChallenge::TwoFactorCode`; the
frontend collects the code without echo and calls `continue_flow`. The provider
never reads stdin or displays UI.

The Azuriom access token remains in `ProviderSession` and the credential vault.
It is not an official Minecraft access token. Azuriom accounts therefore
produce `MinecraftIdentity::Offline`, using the validated AzAuth name and
`game_id` UUID. Restored sessions are checked with `verify`; invalid or expired
tokens require reauthentication.

HTTPS is mandatory except for an explicitly trusted loopback development
configuration. Requests use bounded responses, no redirects and finite
timeouts. Invalid credentials, 2FA, disabled/banned accounts, rate limiting,
server failures and malformed responses map to typed Core errors.

Configure explicitly:

```text
ccorp auth provider add azuriom my-azuriom https://example.com/
ccorp auth login my-azuriom
```

