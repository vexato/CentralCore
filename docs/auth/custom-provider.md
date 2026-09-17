# Create a custom AuthProvider

Rust providers are linked at compile time. CentralCore deliberately does not
load `.dll`, `.so`, or `.dylib` authentication plugins: Rust has no stable ABI,
and loading arbitrary native code would expand the crash and security surface.

The complete runnable implementation is
[`examples/custom-auth-provider.rs`](../../examples/custom-auth-provider.rs).
Its essential registration sequence is:

```rust,ignore
use std::sync::Arc;
use centralcore::{CentralCore, Result};

# struct MyProvider;
# // Implement AuthProvider as shown in examples/custom-auth-provider.rs.

# async fn register(core: &CentralCore) -> Result<()> {
core.auth().register(Arc::new(MyProvider)).await?;
# Ok(()) }
```

The documentation outline uses placeholders; no shipped implementation does.
For a real provider:

1. declare accurate capabilities;
2. return UI-neutral challenges and retain continuation data in secret state;
3. build `AuthSession` with provider and Minecraft credentials separated;
4. produce `Official` only after validating an actual Minecraft Services
   session, otherwise produce `Offline`;
5. check the cancellation token and impose timeouts on network operations;
6. put persistent secrets through `CredentialStore`, never arbitrary files;
7. register the provider; AuthManager persistence, lifecycle events, refresh
   before launch and LaunchPlan normalization do the rest.

Run the no-network example with `cargo run --example custom-auth-provider`.
To prove the normalized session reaches a real `LaunchPlan`, point it at an
already installed instance:

```text
CENTRALCORE_DATA_DIR=<data> CENTRALCORE_DEMO_INSTANCE=<instance-id> cargo run --example custom-auth-provider
```
