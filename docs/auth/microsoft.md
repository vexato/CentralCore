# Microsoft authentication

`MicrosoftAuthProvider` is a public desktop-client implementation. Its
configuration contains `client_id`, a loopback `redirect_url`, and tenant
(normally `consumers`). There is deliberately no `client_secret`: a secret
embedded in a desktop launcher binary would not be confidential.

## Browser flow

The provider uses Authorization Code with PKCE S256. Each flow generates a
cryptographically random verifier and state value, places only the challenge
in the authorization URL, and validates both callback origin/path and state
before exchanging the code. The redirect URL must be loopback; the Core only
returns `AuthChallenge::Browser` and does not open a browser or listen on a
network interface. The host application owns browser launch and callback
capture. The current CLI prints the URL and accepts the complete callback URL.

After OAuth, the provider performs:

```text
Microsoft OAuth token
  -> Xbox user token
  -> XSTS authorization
  -> Minecraft login_with_xbox
  -> Minecraft entitlements
  -> Minecraft profile
  -> MinecraftIdentity::Official
```

Missing ownership/profile and Xbox/XSTS restrictions become structured
`AuthError` categories. An OAuth token alone is never presented to Minecraft.

## Refresh and persistence

The Microsoft refresh token is stored only by `CredentialStore`. Refresh first
obtains a new Microsoft OAuth token, then repeats Xbox, XSTS and Minecraft
Services exchange to obtain a current Minecraft access token and profile.
`AuthManager::identity_for_launch` does this automatically for expired,
refreshable accounts.

The implementation does not currently expose Microsoft Device Code or remote
revocation. Device Code is represented by the generic Core state machine and
can be implemented by another provider/host, but Microsoft login supplied in
this phase is PKCE browser flow. Logout removes the local session and all
vault entries.

CI tests use local mocked OAuth/Xbox/XSTS/Minecraft endpoints and no real
account. A real E2E requires a team-owned Azure public-client registration and
Minecraft-owning test account; tokens must never be committed as fixtures.

