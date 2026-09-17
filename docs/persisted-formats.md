# Persisted formats and migration policy

CentralCore persists configuration, instance specifications, managed-file
indexes, provider registry/snapshots and HTTP cache documents, transactions,
component selections, managed Java runtime manifests, authentication metadata,
process identities, trust keys and anti-rollback state.

Each owned JSON format has a `format_version` (or a protocol-specific version
such as `signature_version`). Readers accept the current version and documented
legacy forms only. A newer unknown version returns `Error::UnsupportedFormat`
or the corresponding structured domain error; it is never silently rewritten.
Truncated or invalid JSON preserves its `serde_json::Error` source. Atomic
temporary-file/rename writes and transaction journals limit partial commits.

Migrations must be explicit, tested from a fixture of every supported old
version, idempotent, and leave a recoverable previous file until commit. The
crate version is not used as a persisted schema version. Credential secrets
live in the platform vault; JSON auth metadata contains references and
non-secret session fields only.
