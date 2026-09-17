# CentralCorp Auth Protocol v1

`HttpAuthProvider` supports a small versioned JSON protocol. It is not a JSON
mapping engine and never executes server-provided script. Given a trusted base
URL ending in `/auth/v1/`, it sends POST requests to `login`, `session`,
`refresh`, and `logout`.

## Requests

Credentials login body:

```json
{"protocol_version":1,"username":"alex@example.com","password":"..."}
```

2FA continuation body:

```json
{"protocol_version":1,"continuation_token":"...","code":"..."}
```

Session, refresh and logout use:

```json
{"protocol_version":1,"token":"..."}
```

All secrets are body fields. They must never appear in a URL, query string,
fragment, log, event or error context.

## Responses

Successful login/session/refresh response:

```json
{
  "status":"success",
  "account":{"id":"42","username":"Alex","uuid":"uuid-or-null","metadata":{}},
  "session":{"access_token":"...","refresh_token":"...","expires_at":1893456000}
}
```

2FA response:

```json
{"status":"challenge","challenge":"two_factor","continuation_token":"...","message":"Code required"}
```

Typed error response:

```json
{"status":"error","code":"invalid_credentials","retry_after_seconds":null}
```

Defined v1 codes include `invalid_credentials`, `expired`, `account_banned`,
`account_disabled`, `rate_limited`, and `server_error`. Unknown values become a
sanitized protocol error; clients do not make decisions from message text.
Logout succeeds with `{"status":"success"}`.

## Identity and transport security

Protocol v1 always produces `MinecraftIdentity::Offline`, using the validated
username and optional UUID. A custom server cannot claim a Microsoft or
official Minecraft session through this protocol.

HTTPS is required by default. Base URLs with userinfo, query strings or
fragments are rejected; redirects are disabled, preventing HTTPS downgrade.
The default timeout is 15 seconds and response limit is 1 MiB (hard policy
maximum 4 MiB). HTTP is available only for an explicitly trusted loopback
development server. HTTP 429 maps to `RateLimited` and honors `Retry-After`
metadata; incorrect passwords are never retried automatically.

Configuration is a local trust action:

```text
ccorp auth provider add http my-network https://login.example/auth/v1/
```

Remote instance manifests may reference `my-network`, but cannot define that
URL or create the provider.

