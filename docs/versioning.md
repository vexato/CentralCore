# Versioning and MSRV

CentralCore follows Semantic Versioning from 1.0.0:

- patch releases contain compatible correctness and security fixes;
- minor releases may add backward-compatible types, methods, enum variants and
  serialized event variants;
- a major release is required for an intentional breaking public API change.

Public enums that are intended to grow are `#[non_exhaustive]`; consumers must
include a fallback match arm. Persisted formats and network protocols have
their own explicit version fields and are not inferred from the crate version.

The minimum supported Rust version (MSRV) is 1.88. This is the lowest version
compatible with the locked 1.0 dependency graph (notably the current URL/IDNA
Unicode data stack), and the project tests it in CI. An MSRV increase may occur
in a minor release when a maintained dependency or an important correctness
improvement requires it; it must be called out in the changelog.

The 1.0 crate intentionally exposes one supported full-engine configuration.
Authentication, managed Java, signatures, Fabric and Forge are not fragmented
into a large Cargo feature matrix yet. This avoids API states that have not
received the same integration and security testing. Feature partitioning can
be proposed later with explicit compile-matrix coverage.
