# Manual authentication E2E

These checks use credentials owned by the team. Do not put passwords, OAuth
codes or tokens in the repository, command history, fixtures or bug reports.
Use a disposable data directory and delete it after the run.

## Microsoft

Register a public desktop client with the exact loopback redirect configured in
the local registry. No client secret is used.

```text
ccorp auth provider add microsoft microsoft <PUBLIC_CLIENT_ID> --redirect-url http://127.0.0.1:38475/callback
ccorp auth login microsoft
ccorp auth accounts
ccorp instance launch vanilla-test --account <ACCOUNT_ID>
```

Confirm that the account username and UUID are the Minecraft profile values and
that the launch arguments use `userType=msa` and the official session token.
Expire or wait for the token, then repeat launch and confirm refresh occurs
without another login. Test an account without Minecraft ownership and verify
that `no_minecraft_ownership` is returned.

The same check is available as an explicitly opt-in integration test. Export
`CENTRALCORE_MS_CLIENT_ID`, `CENTRALCORE_MS_REDIRECT_URL`,
`CENTRALCORE_MS_CALLBACK_URL` (the callback captured after browser login) and,
optionally, `CENTRALCORE_MS_TENANT`, then run:

```text
cargo test -p centralcore --test auth_external_e2e microsoft_real_account -- --ignored --nocapture
```

The current CLI prints the browser URL and accepts the complete callback URL;
the Core remains headless. A Tauri/desktop host can present the same Browser
challenge using its own browser/callback adapter.

## Azuriom

Use an instance controlled by the team and an account with a known `game_id`:

```text
ccorp auth provider add azuriom test https://azuriom.example/
ccorp auth login test
ccorp auth status
ccorp instance launch vanilla-test --account <ACCOUNT_ID>
ccorp auth logout <ACCOUNT_ID>
```

Exercise invalid credentials, 2FA (if enabled), verify after token expiry,
banned/disabled account, 429 and server failure. Confirm the launch identity is
`offline`, uses the validated Azuriom username/UUID, and never uses the
Azuriom access token as a Minecraft official token.

An opt-in integration check uses `CENTRALCORE_AZURIOM_URL`,
`CENTRALCORE_AZURIOM_USERNAME` and `CENTRALCORE_AZURIOM_PASSWORD`. If 2FA is
enabled, also provide `CENTRALCORE_AZURIOM_2FA_CODE`:

```text
cargo test -p centralcore --test auth_external_e2e azuriom_real_account -- --ignored --nocapture
```

## HTTP protocol and custom Rust provider

The local mock E2E test is:

```text
cargo test -p centralcore --test auth_http
```

The compile-time extension E2E prepares a LaunchPlan from a custom provider
session. With an installed instance available:

```text
CENTRALCORE_DATA_DIR=<data> CENTRALCORE_DEMO_INSTANCE=<instance-id> cargo run --example custom-auth-provider
```

The command registers the external provider, authenticates, verifies the
session, builds a plan through `MinecraftManager`, and logs out.
