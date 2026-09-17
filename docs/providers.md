# Providers

Sync and update are separate trust boundaries: sync atomically refreshes a
validated snapshot and never changes installed files. Manifest v1 now accepts
backward-compatible `components`; their URLs, hashes, sizes, paths, HTTPS/SSRF
rules, and limits are identical to ordinary provider files. A later revision
cannot overwrite local component choices.

`InstanceProvider` remains CentralCore's backend-neutral catalog contract. It
returns core-owned summaries, instance specifications, and file manifests;
provider implementations own their transport and wire-format conversion.

`ProviderManager` adds the persistent registry used by applications and the
CLI. A registration records an ID and a `ProviderSource` (`Local` or `Remote`)
without implying that the source is reachable. `sync` creates a fully
validated `ProviderSnapshot`; listing and launching use the last committed
snapshot and therefore do not contact the provider.

Logical instance identity is the structured pair `ProviderInstanceId {
provider_id, instance_id }`. Its CLI spelling is `provider:instance`. A short
instance ID is accepted only when it does not name a local instance and occurs
in exactly one configured provider.

Static providers implement the same `InstanceProvider` trait used by mock and
future custom adapters. CentralPanel support must remain an implementation of
this boundary: no Laravel, Azuriom, authentication route, or CentralPanel URL
belongs elsewhere in the engine.

Removing a provider only removes its registration. Materialized instances are
retained and reported as `provider_removed`; no installation or user file is
deleted.

An instance definition may select Vanilla, Fabric, or Forge. Fabric and Forge
require an exact loader version. The provider only returns `LoaderConfig`; the
same registry and `LoaderPlan` pipeline used by local instances performs all
resolution, installation and repair.

```rust,no_run
use centralcore::{providers::{ProviderId, ProviderSource}, CentralCore};

# async fn example() -> centralcore::Result<()> {
let core = CentralCore::builder().data_dir("./data").build().await?;
let id = ProviderId::new("example")?;
core.providers()
    .add(id.clone(), ProviderSource::parse("./provider.json")?)
    .await?;
core.providers().sync(&id).await?;
let entries = core.providers().instances(Some(&id)).await?;
assert!(!entries.is_empty());
# Ok(())
# }
```
