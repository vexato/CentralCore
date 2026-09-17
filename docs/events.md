# Events

Phase 8 adds `UpdatePlanCreated`, `InstanceUpdateStarted`,
`InstanceUpdateProgress`, `InstanceUpdateCompleted`, and
`InstanceUpdateFailed`. Component changes emit `ComponentSelectionChanged`
and `ComponentEnabled` or `ComponentDisabled`. These generic events carry IDs,
revisions, counters, and bytes, never credentials or response bodies.

`EventBus` uses a Tokio broadcast channel and carries `CoreEvent` values. Each
subscriber has an independent receiver. Producers never wait for a frontend;
a slow receiver may observe Tokio's lag notification and then resume with the
newest available events.

Events contain progress, identifiers, paths, and sanitized errors. Credentials
and tokens are not valid event fields. A UI adapter may serialize events to
JSON and rename them for its frontend without changing CentralCore.

Vanilla installation emits manifest, library, asset and native phase events as
well as aggregate `InstallProgress`. Process events expose start, PID,
redacted stdout/stderr lines, and final exit code. The download layer throttles
byte progress events to avoid producing one event per network chunk.

Verification and repair add start/progress/completion events plus the complete
serializable `VerificationReport`. Cache verification and startup recovery
have their own lifecycle events. Process recovery distinguishes recovered,
lost, stopping, stopped, and identity-mismatch states without introducing any
CLI-specific payload.

Provider operations emit add/remove and sync lifecycle events, bounded
instance progress, cache-hit/not-modified notifications, definition updates
and update-available signals. URLs in events are sanitized and never include
userinfo or query strings. Provider events describe core state only and are
not terminal-formatting instructions.

Phase 9 adds `ManifestVerificationStarted`, `ManifestVerified`,
`ManifestVerificationFailed`, `SigningKeyTrusted`, `SigningKeyRemoved`,
`SigningKeyRotated`, and `ProviderRollbackRejected`. These expose provider IDs,
public-key fingerprints, revisions, and stable error categories only. Private
keys and signing-tool secrets can never appear in Core events.

Loader resolution emits `LoaderResolutionStarted` and
`LoaderResolutionCompleted`, including the exact loader/Minecraft coordinate
and plan operation counts. Forge processor execution emits generic
`LoaderProcessorStarted`/`LoaderProcessorCompleted` events. Event consumers do
not need loader-specific variants and no processor command line is exposed.

Authentication emits only generic lifecycle events:

- `AuthFlowStarted`, `AuthChallengeRequired`, `AuthFlowCompleted`,
  `AuthFlowFailed`;
- `AuthSessionCreated`, `AuthSessionRefreshed`, `AuthSessionExpired`,
  `AuthSessionRemoved`.

Payloads contain provider/account/flow identifiers, a challenge kind or a
stable error kind. They never contain a challenge response, URL query, opaque
flow state, password, code or token. There are no Microsoft- or
Azuriom-specific event variants.

Java lifecycle events are likewise provider-neutral: resolution, detection,
selection, download progress, installation and verification expose runtime
metadata only (`JavaResolutionStarted`, `JavaRuntimeDetected`,
`JavaRuntimeSelected`, `JavaRuntimeDownloadStarted`,
`JavaRuntimeDownloadProgress`, `JavaRuntimeDownloaded`,
`JavaRuntimeInstallStarted`, `JavaRuntimeInstalled`,
`JavaRuntimeVerificationStarted` and `JavaRuntimeVerificationCompleted`).
## Stable event envelope

`EventBus::subscribe_envelopes()` returns `EventEnvelope` format version 1 with
a process-local monotonic `EventId`, Unix-millisecond diagnostic timestamp and
the structured `CoreEvent`. This is the recommended boundary for Tauri/IPC and
structured logs. `subscribe()` remains the lightweight raw-event API.

Events fall into three practical groups: progress events report bounded work;
state-change events report committed lifecycle changes; diagnostic events
explain a rejected or recovered operation. Delivery is best-effort broadcast:
a slow receiver can observe `Lagged` and resume, so events are not a database or
transaction log.

`CoreEvent` is `#[non_exhaustive]`. Minor releases may add variants and fields
only through versioned DTO evolution; consumers must ignore unknown variants at
an IPC boundary. Existing variant meaning is not repurposed in 1.x. Envelopes
contain no credentials, authorization headers, private keys or challenge
responses.
