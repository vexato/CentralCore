# Contributing

Install Rust 1.82 or newer and clone the repository. Before submitting a
change, run `scripts/quality.ps1` on Windows or `scripts/quality.sh` on Unix.

Architecture rules:

- providers describe desired state and never perform downloads themselves;
- loaders resolve/install loader state and never launch Minecraft;
- a `LaunchPlan` never downloads Java;
- auth is independent from loaders and provider-content trust;
- `StaticProvider` knows only the generic loader model, not Fabric/Forge code;
- UI adapters contain presentation and IPC, not Minecraft business logic;
- filesystem, network and process operations use shared policy boundaries;
- no `unsafe`, secret logging, unbounded archive extraction or shell-built
  launch commands.

Public API changes need rationale, rustdoc, a consumer example/test, and a
SemVer assessment. Security-sensitive changes require negative tests and an
update to the security review. Keep errors structured with their source and
events serializable and secret-free. Do not add production `unwrap`, `expect`,
`panic!`, `todo!` or `unimplemented!` on external input paths.

Real Microsoft/Azuriom/Minecraft-network E2E tests use explicitly configured CI
secrets and run nightly/manually, not on every pull request. Never commit those
secrets, generated private signing keys, game downloads, caches or `target/`.
