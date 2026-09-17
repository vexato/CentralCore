# Integrating a UI

A UI is a thin adapter over one long-lived `CentralCore` value. Build it with a
platform application-data directory, subscribe to `events()` before starting
work, and move domain operations into async commands. Do not mirror Minecraft,
provider, Java, cache or signature logic in the frontend.

Recommended flow:

1. build `CentralCore` and retain it in application state;
2. forward `subscribe_envelopes()` values to IPC, handling broadcast lag;
3. list configured auth providers and accounts, run `begin`/`continue_flow`,
   and render typed challenges without logging responses;
4. list local and provider instances, plus component status/selections;
5. sync a provider only after an explicit trust decision is already stored;
6. build and display install/update/repair plans, create one cancellation token
   per user operation, then pass the original plan to its executor;
7. obtain `MinecraftIdentity`, build `LaunchPlan`, launch or launch detached;
8. use `processes()` for status/stop and stream process events for logs;
9. show Java/download/update progress from structured events, not parsed text.

`CoreEvent` variants are grouped conceptually as progress, state changes and
diagnostics. Event envelopes are format-versioned; IDs order one process only,
and timestamps are diagnostic rather than security clocks. Treat unknown event
variants as ignorable additions. Never serialize auth challenge responses,
access tokens or private signing keys into frontend logs.

Cancellation is cooperative. Dropping `CentralCore` does not kill Minecraft.
There is no hidden background worker requiring an async `Drop`; operation tasks
must be awaited or cancelled by the host. Persisted transactions and process
identity are reconciled during the next `build()`.
