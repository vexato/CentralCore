# CentralCore architecture

```text
                         CentralCore

 Instance -----------------------------------+
                                             |
 Provider ---> verified desired state        |
                                             v
                    Install / Repair / Update / Launch

 Auth ------> MinecraftIdentity
 Loader ----> LoaderPlan
 Java ------> JavaRuntime
 Trust -----> Verified ProviderSnapshot

 Cache / Downloads / Events / Locks / Processes
```

Install creates initial desired state, Repair restores current desired state,
Update changes desired state, and Launch consumes installed state. Provider
sync only publishes an available snapshot. `UpdatePlan` reuses DownloadManager,
CacheManager, Managed File Index, instance locks, journals, verification, and
recovery; it contains no Fabric- or Forge-specific update branch.

## Goals and boundaries

CentralCore is the product-facing engine. It owns launcher domain logic and
exposes it through a stable Rust API. Frontends translate user intent into API
calls and translate typed core events into their own presentation format.
CentralPanel and other backends are replaceable providers; they are not part
of the engine's domain model.

The core never invokes a shell, emits UI-specific events, stores global mutable
state, or assumes that Java exists on `PATH`. Commands are constructed with
`tokio::process::Command` and separate arguments.

```text
CLI / Tauri UI / Rust application
                |
         CentralCore facade
                |
  +-------------------------------------------------------------------+
  | instances | providers | auth | minecraft | loaders | downloads | cache |
  +-------------------------------------------------------------------+
                |
     provider and loader contracts
                |
  static JSON / CentralPanel / application adapters
```

## Public facade

`CentralCore` is built with `CentralCore::builder()`. Building validates the
configuration, creates the data layout, and wires services to one `EventBus`.
Callers access focused service handles (`instances()`, `providers()`, `java()`,
`minecraft()`, `loaders()`, `downloads()`, `auth()`, `processes()`, and `events()`) instead
of a single manager with unrelated responsibilities. Handles are cheaply
cloneable and do not rely on globals.

The facade deliberately re-exports only stable domain types. Persisted DTOs
and filesystem helpers remain module-private so the on-disk format can evolve
without exposing implementation details.

## Configuration and storage

`CoreConfig` has a `format_version`. Version 1 stores the data directory and
download/Java policies. Unknown versions fail explicitly instead of being
silently interpreted. Future migrations belong in the `config` module.

Each local instance is stored below `<data>/instances/<validated-id>`:

```text
instance-id/
  .minecraft/
  mods/
  config/
  logs/
  instance.json
```

Creation writes into a sibling staging directory and renames it into place.
Metadata updates use a temporary file followed by a rename. Instance IDs are
restricted to portable ASCII characters and are never accepted as arbitrary
paths. Reads and deletes reject symbolic-link instance directories.

## Module responsibilities

- `instance`: domain model, ID validation, and isolated local persistence.
- `events`: serializable event payloads and a Tokio broadcast bus. Slow
  subscribers cannot block engine work.
- `config`: versioned local configuration and policy validation.
- `download`: validated streaming downloads, bounded concurrency, retries,
  resumable temporary files, atomic commits, integrity checks, and
  cancellation primitives.
- `java`: normalized requirements, bounded system discovery, deterministic
  selection, trusted distribution providers and transactional managed runtimes.
- `auth`: a provider registry, UI-neutral flow/challenge state machine,
  credential-vault boundary, session lifecycle and normalized Minecraft
  identities. See [authentication architecture](auth.md).
- `providers`: registry, versioned snapshots, the backend-neutral contract,
  and local/HTTPS static JSON. Provider-specific routes and wire formats stay
  inside implementations.
- `loaders`: typed coordinates, registry, Fabric/Forge resolvers, the generic
  `LoaderPlan`, and its trusted processor executor. Vanilla remains the base
  Minecraft pipeline rather than a synthetic mod-loader implementation.
- `files`: portable relative-path and file-manifest domain types.
- `platform`: normalized operating-system and architecture detection.
- `minecraft`: Minecraft manifest and launch logic, implemented in Phase 2.
- `process`: concurrent process actors, output capture, persisted PID identity,
  stop requests, and exit status.
- `cache`: versioned managed-file metadata, bounded verification, usage
  reports, and reference-safe pruning.
- `lock`: per-resource operating-system file locks shared by instance, cache,
  download, and process operations.
- `mods`: required, optional, and disabled mod-selection model.

The boundaries are invariants, not naming conventions: providers do not
download; loaders do not launch; launch planning does not install Java; auth
does not depend on a loader; static-provider parsing does not contain
Fabric/Forge branches; and a UI does not implement Minecraft domain logic.

## Error model

Public async operations return `centralcore::Result<T>`. `Error` distinguishes
configuration, validation, I/O, serialization, provider, authentication,
loader, and unsupported-format failures while preserving useful sources. A
caller can match error categories without parsing strings.

## Extensibility contracts

`InstanceProvider`, `AuthProvider`, and `Loader` are async, object-safe traits.

Java resolution follows the same boundary: `JavaManager` consumes a normalized
`JavaRequirement`, selects a validated `JavaRuntime`, and delegates distribution
metadata to the object-safe `JavaDistributionProvider`. Minecraft and loaders
never know which distribution supplied the runtime.
They accept core-owned request/context types and return core-owned models.
This prevents the rest of the engine from learning about CentralPanel routes,
OAuth wire formats, or loader-specific installer details. Implementations can
be injected by applications and tested with in-memory mocks.

## Security invariants

- Any backend-supplied relative path passes `SafeRelativePath` validation.
- Absolute paths, parent components, prefixes, empty paths, NUL bytes, and
  platform separators in individual components are rejected.
- Instance directories that are symbolic links are rejected before reads or
  deletion.
- Download requests require HTTP(S), bounded policy values, and syntactically
  valid checksums.
- Tokens use a redacting wrapper and never enter event payloads or tracing
  fields.
- Archive extraction validates every entry independently and rejects
  symlinks, zip-slip paths, and configured size limits.
- Launch arguments are passed as an argument vector, never concatenated into a
  shell command. Backend JVM arguments will pass an allow/deny policy before
  execution.

## Delivery phases

1. Foundation: the API, storage, contracts, events, CLI, and tests described
   above.
2. Vanilla engine (implemented): official manifests, libraries/assets/natives,
   Java version selection, argument rules, and process launch.
3. Reliability (implemented): incremental repair, cache lifecycle/eviction,
   interrupted staging recovery, richer diagnostics, and hardened
   cross-process control.
4. Providers (implemented): static local/remote JSON, atomic snapshots,
   conditional HTTP caching, provider-managed files, and offline catalog use.
5. Loaders (implemented): Fabric Meta and modern Forge install profiles use
   the same versioned `LoaderPlan`, managed index, repair and launch overlay.
6. Authentication (implemented): generic challenge flows, local trust
   registry, Offline/Microsoft/Azuriom/HTTP providers, secure credential
   storage, account-aware launch and compile-time Rust extension contract.
7. Managed Java (implemented): normalized Minecraft/loader requirements,
   bounded system discovery, trusted distribution providers, content-addressed
   archives, transactional shared runtimes and automatic launch resolution.
8. Components and update plans (implemented): required/optional dependency
   graphs, provider desired-state diffs and offline transactional updates.
9. Provider trust (implemented): Ed25519 signed roots, child hashes, local
   trust decisions, rotation/revocation, verified snapshots and anti-rollback.
10. Library stabilization (implemented): reduced public surface, non-forgeable
    plans, versioned event envelopes, release metadata, examples and multi-OS CI.

Each phase must keep `cargo fmt`, `cargo clippy`, and the offline test suite
green before the next phase starts.

## Vanilla pipelines

```text
Instance
   -> Version resolver
   -> InstallPlan
   -> DownloadManager
   -> Assets / libraries / natives
   -> Java resolver
   -> LaunchPlan
   -> ProcessManager
```

Metadata resolution and execution are separate. `InstallPlan` is inspectable
before bulk downloads; `LaunchPlan` is inspectable before Java is spawned and
stores arguments separately rather than as a shell string.

## Managed Java pipeline

```text
Minecraft metadata + LoaderPlan -> JavaRequirement -> JavaManager
    -> explicit / managed / system selection
    -> ManagedJavaProvider -> trusted JavaDistributionProvider
    -> DownloadManager + SHA-256 cache -> secure staging -> JavaRuntime
    -> LaunchPlan
```

Minecraft, Fabric, Forge and `LaunchPlan` do not contain Adoptium-specific
logic. Remote instance manifests cannot register a Java source, choose a local
executable or inject an archive URL.

## Reliability pipeline

```text
managed-file index + filesystem
             -> VerificationReport
             -> RepairPlan
             -> verified incremental writes / native staging
             -> full verification
             -> Installed
```

`InstallPlan`, `RepairPlan`, and `LaunchPlan` remain distinct. Cache references
are reconstructed from versioned per-instance indexes rather than maintained
as fragile counters. Instance mutations and individual cache objects have
separate cross-process lock keys, allowing unrelated instances and downloads
to progress concurrently.

## Static-provider pipeline

```text
provider index + individual manifests
              -> parse / validate / normalize / resolve
              -> transactional ProviderSnapshot
              -> provider declaration + Vanilla InstallPlan
              -> SHA-256 content cache + managed-file index
              -> existing VerificationReport / RepairPlan / LaunchPlan
```

Provider declarations never write instances directly. `ProviderManager`
materializes an isolated local `Instance`, invokes the existing Vanilla
installer, commits verified provider files, then extends the same managed-file
index. `RepairPlan` uses a generic verified-copy primitive to restore an
instance file from its content-addressed cache object.

## Loader pipeline

```text
exact LoaderConfig -> LoaderRegistry -> FabricLoader / ForgeLoader
                   -> versioned LoaderPlan
                   -> InstallPlan + generic executor
                   -> managed-file index
                   -> verify / incremental repair
                   -> LaunchPlan overlay
```

The Minecraft pipelines never switch on Fabric or Forge. Ecosystem metadata,
Maven conventions, Forge token expansion and install-profile interpretation
remain inside their loader modules. Generic code only downloads typed objects,
extracts explicitly named trusted archive members, runs ordered Java
`ProcessorPlan` operations, validates declared outputs and composes the launch
overlay. This same contract can host a future Quilt or NeoForge resolver.

## Authentication pipeline

```text
trusted provider registry -> AuthProvider -> AuthFlow/AuthChallenge
                                         -> AuthSession
                                         -> MinecraftIdentity
                                         -> LaunchPlan
```

The launch and Minecraft modules receive only `MinecraftIdentity`; neither
contains provider-specific conditions. Provider endpoints are local trusted
configuration. Static/remote manifests may only refer to registered IDs and
cannot create credential-bearing network destinations. CentralPanel is not a
dependency of this pipeline.
