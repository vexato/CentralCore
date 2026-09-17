# Instance updates

`UpdatePlan` moves a provider-backed instance from one desired revision to another. Planning is read-only; applying the plan is a separate call.

```rust
let plan = core.providers().plan_update(&instance_id).await?;
let report = core.providers().apply_update(plan, &cancellation, false).await?;
```

The comparison uses the installed Managed File Index and the latest synchronized provider definition. Files with the same path, SHA-256, and size are kept. Added and changed files pass through `DownloadManager` and `CacheManager`; only managed paths from the old definition can be removed. Unindexed saves, screenshots, resource packs, shader packs, logs, `options.txt`, and other user content are never update-removal candidates.

When Minecraft or loader configuration changes, planning also resolves the normal
InstallPlan and exposes missing base artifact count/size. `--offline` uses only
cached Minecraft/loader metadata and fails clearly when it is unavailable.

## Transactions and recovery

An update holds the existing instance inter-process lock and refuses to run while Minecraft is active. Changed files are downloaded into the content-addressed cache, verified, copied to transaction staging, and only then moved into the instance. Replaced and removed managed files first move into a transaction backup. The Managed File Index, component selections, and installed revision commit only after full verification.

On startup, abandoned update staging is restored to the prior consistent state before verification. CentralCore promises recovery, not an unconditional filesystem-wide rollback. A Minecraft/loader version change reuses the normal install pipeline; a repair may be required if a process is forcibly killed during loader-specific processing.

## CLI

```bash
ccorp instance update demo:survival --dry-run
ccorp instance update demo:survival
ccorp instance update demo:survival --offline
```

`provider sync` only replaces the available snapshot. It never changes installed files. Offline update succeeds only when every required changed object is locally recoverable.

## Plan roles

- `InstallPlan`: creates the first desired state.
- `RepairPlan`: restores the currently installed desired state.
- `UpdatePlan`: moves between desired states.
- `LaunchPlan`: launches installed state and never downloads updates.
