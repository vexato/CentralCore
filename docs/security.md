# Security

## Updates and optional components

Update removal candidates come exclusively from the previous Managed File
Index; a provider revision cannot request deletion of arbitrary user files.
Every new or replacement file is staged, size/hash verified, and committed
under the instance lock. Component files have exactly the same path traversal,
symlink, HTTPS, SSRF, response-size, and SHA-256 requirements as required files.
Provider sync does not mutate installed files or local component selections.

CentralCore treats provider responses, archives, manifests, and launch options
as untrusted data. Current foundation invariants include strict portable
relative paths, bounded instance IDs, URL scheme/host policy, download size
limits, validated hashes, redacted secret debug output, and symlink rejection
for instance roots.

The Vanilla phase must preserve these invariants while adding archive-entry
validation, per-entry and aggregate decompression limits, SHA-1/SHA-256
verification before atomic moves, and symlink checks on destination parents.
Process launch uses argument arrays directly and never delegates command
construction to a shell. Known authentication values are removed from process
logs and from `LaunchPlan` debug output.

Phase 3 adds per-resource OS locks and versioned managed-file indexes. Repair
only mutates paths explicitly present in those indexes; user saves, options,
screenshots, packs, and other `.minecraft` content are outside its ownership.
Cache pruning reconstructs references from instance indexes and skips locked
objects. Persisted processes require PID, start time, executable, and working
directory agreement before any stop attempt.

Static provider v1 requires SHA-256 and exact size for every distributed file.
Remote JSON is strictly bounded before parsing. Remote sources require HTTPS
by default; URL credentials and HTTPS-to-HTTP redirect downgrades are rejected.
Provider retrieval checks literal and resolved loopback, link-local and private
addresses unless a development/private-network policy is explicitly enabled.
Local references retain a trusted root and every accessed component is checked
for symlinks, preventing `..` and link-based escape.

Providers cannot supply executable paths, shell fragments, arbitrary JVM/game
arguments or Java agents. Provider file destinations pass `SafeRelativePath`,
are rooted below `.minecraft`, and conflict with another managed owner rather
than using silent last-writer-wins behavior.

Fabric and Forge metadata is accepted only by built-in loader implementations
and converted to typed `LoaderPlan` operations. Static providers can select an
exact loader coordinate but cannot inject processors. Forge processors are
Java processes started directly with separate arguments; no shell is involved.
Their installer, processor jars and classpath entries are integrity-checked
cache objects, archive extraction names are fixed by the loader resolver, and
declared outputs are verified before the finalized plan is committed. A
generated output lacking an upstream digest receives a local SHA-256 snapshot
for subsequent verify and repair.

Authentication secrets use `SecretString`, whose `Debug` output is always
redacted and whose allocation is zeroized on drop. Passwords, 2FA codes,
provider tokens, Microsoft/Xbox/XSTS tokens and Minecraft tokens are excluded
from events, CLI JSON, tracing, errors and `LaunchPlan` debug output. Protocol
error codes are sanitized and are intentionally omitted from `AuthError`
`Debug`/`Display`, preventing a malicious server from reflecting a secret.

`CredentialStore` is the only persistence boundary for tokens. The default
`SystemCredentialStore` uses Windows Credential Manager, macOS Keychain or
Linux Secret Service through the native keyring backend; account JSON contains
only non-secret identity and expiry metadata. Tests use
`InMemoryCredentialStore`. Refresh tokens never enter `instance.json`.

Managed Java archives are treated as untrusted downloads: trusted distribution
metadata and SHA-256 verification are required before secure extraction. The
staging directory uses existing traversal and symlink protections, and only an
executable that successfully reports its version may be committed.

HTTP authentication is HTTPS-only by default, rejects URL credentials, query
strings and fragments, disables redirects, bounds response size, and uses a
finite timeout. Explicit plaintext support is restricted to trusted loopback
development configuration. Credentials are body-only and request/response
bodies are never logged.

The versioned auth provider registry is local trust state. An instance manifest
can allow registered provider IDs, but cannot define or redirect an endpoint.
Consequently, a compromised static provider cannot cause a password, token or
2FA code to be sent to an unapproved origin.
