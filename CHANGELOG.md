# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and
Semantic Versioning.

## [1.0.0] - Unreleased

### Added

- Stable `CentralCore` facade and domain managers for instances, providers,
  authentication, Java, downloads, cache, trust, events, Minecraft and process
  lifecycle.
- Vanilla, Fabric and modern Forge planning and execution.
- Signed Ed25519 static providers, local trust store, key transition/revocation,
  anti-rollback state, verified snapshots and offline reuse.
- Inspectable, core-created install, update, repair and launch plans.
- Versioned event envelopes for IPC adapters.
- `ccorp-sign prepare` publisher workflow for hashing child manifests and
  signing a publishable provider tree.

### Changed

- Remote provider registration now requires an explicit signature policy.
- Plan fields and provider snapshot storage are encapsulated behind read-only
  accessors so consumers cannot bypass staleness or verification invariants.
- Component dependency resolution is iterative and rejects cycles explicitly.
- Detached process stop waits for confirmed termination and includes actionable
  operating-system failure context.

### Security

- No private signing key is accepted by the runtime library.
- Secret-bearing authentication values redact `Debug` and are absent from
  events and tracing fields.
- Path, symlink, archive, SSRF, signature, rollback and PID-identity boundaries
  are reviewed in `docs/security/review-1.0.md`.

### Known limitations

- Forge support targets modern install profiles; historical formats vary.
- Process stop owns only the verified main Java process, not an arbitrary
  descendant tree.
- Private signing-key encryption and HSM integration are delegated to the
  operator's secret store.
