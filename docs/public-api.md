# Public API audit for 1.0

The audit inspected every `pub`, `pub mod` and `pub use` in `centralcore` before
the 1.0 stabilization edits.

## KEEP

- `CentralCore`, `CentralCoreBuilder` and the domain accessors `instances`,
  `providers`, `auth`, `java`, `loaders`, `minecraft`, `downloads`, `cache`,
  `processes`, `events` and `trust`;
- validated domain identifiers `InstanceId`, `ProviderId`,
  `ProviderInstanceId`, `ComponentId` and `KeyId`;
- extension contracts `AuthProvider`, `InstanceProvider`, `Loader`,
  `JavaDistributionProvider` and `CredentialStore`;
- public plan/report types required for inspect, dry-run, display and execute;
- structured domain errors, `CoreEvent`, trust/signature wrappers, cancellation
  token and redacting secret wrappers.

The remaining string identities (`account_id`, `runtime_id`) cross third-party
provider or persisted-format boundaries and are deliberately not converted to
newtypes in 1.0. Doing so without a shared validation invariant would add
wrapping without preventing mistakes.

## CHANGE BEFORE 1.0

- plan storage became private with read-only accessors; only CentralCore can
  construct executable plans;
- provider snapshot internals became private with semantic accessors;
- remote provider registration requires an explicit trust policy, while the
  CLI defaults new remote registrations to `Required`;
- `EventEnvelope` adds version, ordering and time metadata without replacing
  the compatible raw event subscription;
- process-stop failures carry their OS reason and wait for termination;
- component cycles have a structured error and iterative resolver.

## MAKE PRIVATE

- inter-process `LockManager`, lock guards and lock errors;
- HTTP conditional-fetch/cache DTOs;
- loader executor entry points and provider desired-file helpers;
- direct event emission and internal service constructors;
- raw provider JSON DTOs and stored snapshot fields.

## REMOVE

- redundant `AuthService` and `VerifiedProviderSnapshot` aliases;
- public `offline_uuid` helper;
- public construction fields for `InstallPlan`, `RepairPlan` and `UpdatePlan`.

These are intentional pre-1.0 breaking changes. The CLI and signing tool build
using only the resulting public API.

## Errors, events and concurrency

`centralcore::Error` is non-exhaustive and delegates to structured auth,
download, loader, Minecraft, provider, repair, recovery, process, cache and
trust errors. `thiserror` sources are retained; callers should match variants,
not display strings. Terminal wording remains a CLI concern.

`CoreEvent` and the important evolving error enums are non-exhaustive. Events
are serializable and secret-free. `CentralCore` and its cloneable managers are
`Send + Sync`; plans are immutable after creation. Two facade values can use
different data directories, and operating-system file locks coordinate two
values sharing one directory.

CentralCore owns no runtime thread requiring shutdown. Cancellation is scoped
to operations. Dropping the facade does not terminate Minecraft and does not
perform async I/O; interrupted transactions and detached process identities are
reconciled on the next build.
