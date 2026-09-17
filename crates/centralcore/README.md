# centralcore

`centralcore` is a UI-independent, asynchronous Minecraft launcher library.
It provides Vanilla, Fabric and Forge planning; instance lifecycle operations;
authentication extension points; managed Java; signed static providers; cache,
repair and update workflows; process management; and structured events.

```rust,no_run
use centralcore::{CentralCore, InstanceSpec};

#[tokio::main]
async fn main() -> centralcore::Result<()> {
    let core = CentralCore::builder()
        .data_dir("./centralcore-data")
        .build()
        .await?;
    let instance = core.instances()
        .create(InstanceSpec::vanilla("demo", "Demo", "1.21.1")?)
        .await?;
    println!("{}", instance.id());
    Ok(())
}
```

The crate has no dependency on Tauri, Svelte, CentralPanel, or the official
CentralCorp CLI. See the repository README and `docs/` for the complete guides,
security model, public examples, and versioning policy.

Licensed under MIT.
