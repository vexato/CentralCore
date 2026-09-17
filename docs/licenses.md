# License audit

CentralCore itself is MIT licensed. The audit below covers the direct
dependencies declared by the `centralcore` crate at the 1.0 stabilization
point; exact resolved versions remain recorded in `Cargo.lock`.

| Dependency | Purpose | Declared license family |
|---|---|---|
| async-trait | object-safe async extension contracts | MIT OR Apache-2.0 |
| base64 | portable signatures and protocol values | MIT OR Apache-2.0 |
| ed25519-dalek | standard Ed25519 verification | BSD-3-Clause |
| flate2, tar, zip | bounded runtime/native archive handling | MIT OR Apache-2.0 / MIT |
| fs2 | portable inter-process file locking | MIT OR Apache-2.0 |
| futures-util | bounded concurrent operations | MIT OR Apache-2.0 |
| getrandom | OAuth/PKCE randomness from the OS | MIT OR Apache-2.0 |
| keyring | native credential-store adapters | MIT OR Apache-2.0 |
| md5, sha1, sha2 | upstream compatibility hashes and SHA-256 integrity | MIT OR Apache-2.0 |
| quick-xml | Maven metadata parsing | MIT |
| regex | Java version parsing | MIT OR Apache-2.0 |
| reqwest | HTTP transport with rustls | MIT OR Apache-2.0 |
| serde, serde_json, serde_jcs | DTOs, persisted JSON and RFC 8785 canonicalization | MIT OR Apache-2.0 |
| sysinfo | portable process inspection and PID identity | MIT |
| thiserror | structured error sources | MIT OR Apache-2.0 |
| tokio | asynchronous runtime and process/filesystem I/O | MIT |
| tracing | structured diagnostics | MIT |
| url | validated URL domain type | MIT OR Apache-2.0 |
| zeroize | secret-memory cleanup | MIT OR Apache-2.0 |

These permissive licenses are compatible with MIT distribution. This document
is not a substitute for the license texts shipped by dependencies. Release
automation must re-run the audit when `Cargo.lock` changes, inspect transitive
licenses, and stop on an unknown, copyleft, or unlicensed package pending human
review. No dependency was reimplemented merely to reduce the package count.

The Phase 10 `cargo metadata --locked` audit covered target-specific packages
for all platforms and found no missing license. The only expression mentioning
a copyleft option was `r-efi` (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`), which
offers explicit permissive alternatives. This is a compatibility inventory,
not legal advice; release owners remain responsible for notices and review.
