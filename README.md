# CentralCore

CentralCore is a reusable, UI-independent Minecraft launcher engine written in
Rust. It owns the difficult parts of a launcher—Minecraft metadata, Vanilla,
Fabric and Forge, Java runtimes, authenticated identities, signed providers,
cache integrity, install/update/repair plans, transactions, process lifecycle,
and structured events—without requiring CentralCorp Launcher or CentralPanel.

Use it for desktop launchers, server tools, automation, or a custom Rust
application. The workspace also contains `centralcorp-cli`, a normal public-API
consumer, and `centralcorp-sign`, an offline Ed25519 publisher tool.

## Install

CentralCore is available on [crates.io](https://crates.io/crates/centralcore)
as version 1.0.0:

```toml
[dependencies]
centralcore = "1.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Linux builds use the system Secret Service through D-Bus. On Debian/Ubuntu,
install the native build prerequisites with
`sudo apt-get install libdbus-1-dev pkg-config`.

## Quickstart

```rust,no_run
use centralcore::{CentralCore, InstanceSpec};

#[tokio::main]
async fn main() -> centralcore::Result<()> {
    let core = CentralCore::builder()
        .data_dir("./centralcore-data")
        .build()
        .await?;

    let instance = core.instances()
        .create(InstanceSpec::vanilla("survival", "Survival", "1.21.1")?)
        .await?;
    let cancellation = core.downloads().cancellation_token();
    let plan = core.minecraft()
        .resolve_install_plan(&instance, &cancellation)
        .await?;

    println!("{} files are required", plan.downloads().len());
    Ok(())
}
```

Plans are created by CentralCore, are inspectable for dry-run UI, and are then
consumed by the matching executor. This preserves staleness and transaction
checks.

## Providers and trust

Local static providers can remain explicitly unsigned. New remote providers
must choose a signature policy explicitly; production consumers should use
`SignaturePolicy::Required` and a locally trusted `KeyId`.

```rust,no_run
use centralcore::{
    providers::{ProviderId, ProviderSource},
    trust::{KeyId, SignaturePolicy},
    CentralCore,
};

# async fn add(core: &CentralCore) -> centralcore::Result<()> {
let id = ProviderId::new("demo")?;
let key_id = KeyId::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;
core.providers().add_with_trust(
    id.clone(),
    ProviderSource::parse("https://cdn.example.invalid/provider.json")?,
    SignaturePolicy::Required,
    Some(key_id),
).await?;
let report = core.providers().sync(&id).await?;
assert!(report.signature_verified);
# Ok(())
# }
```

The key must already exist in `core.trust()`. A provider cannot make its own key
trusted. See [the signature model](docs/security/signatures.md).

## Authentication extension

Implement `auth::AuthProvider`, then register an `Arc<dyn AuthProvider>` with
`core.auth().register(...)`. CentralCore handles sessions, credential-store
integration, refresh/verification and launch identities; provider secrets use
redacted types. See [`custom_auth_provider.rs`](crates/centralcore/examples/custom_auth_provider.rs)
and [the auth guide](docs/auth.md).

## Events

Subscribe before starting work. `subscribe_envelopes()` adds a process-local
monotonic ID, timestamp and format version suitable for IPC and logs.

```rust,no_run
# async fn listen(core: &centralcore::CentralCore) {
let mut events = core.events().subscribe_envelopes();
while let Ok(envelope) = events.recv().await {
    println!("{}: {:?}", envelope.id(), envelope.event());
}
# }
```

## Examples and guides

The packaged examples cover basic setup, Vanilla planning, static providers,
custom authentication, events, updates, trust, and a complete third-party
consumer flow:

```text
cargo run -p centralcore --example basic
cargo run -p centralcore --example launcher -- ./provider.json
cargo check -p centralcore --examples
```

Start with [architecture](docs/architecture.md), [UI integration](docs/integrating-a-ui.md),
[providers](docs/providers.md), [authentication](docs/auth.md),
[managed Java](docs/java.md), and [security review](docs/security/review-1.0.md).

## Platform and stability policy

Windows, Linux and macOS are CI targets. The MSRV is Rust 1.88. CentralCore
follows SemVer after 1.0; see [versioning](docs/versioning.md). The default build
is intentionally the supported full engine—there is no unstable feature matrix
in 1.0.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for quality gates. Report security issues
according to [SECURITY.md](SECURITY.md); do not disclose an unpatched critical
issue in a public ticket.

CentralCore is licensed under the [MIT License](LICENSE).
