# CentralCore 1.0 security review

| Threat | Mitigation | Remaining limitation |
|---|---|---|
| Path traversal / symlink replacement | validated relative paths, canonical containment, real-file/directory checks, transactional destinations | a fully compromised user account can alter its own files |
| Hostile ZIP/TAR | entry-by-entry path/type and expanded-size limits; links rejected | archive parser dependencies remain in the trusted computing base |
| Command injection | executable plus separate argument vector; no shell for Minecraft/Forge processors | a trusted manifest may still request expensive valid processing |
| Auth secret disclosure | redacting secret types, platform credential vault, secret-free events and tracing tests | host applications can explicitly call `expose_secret()` |
| HTTP SSRF / redirects | scheme, credentials, redirect and private-address policy at shared boundaries | DNS rebinding cannot be eliminated without a pinned transport design |
| CDN/manifest tampering | Ed25519 signed root, child SHA-256 references, file SHA-256 verification | compromise of the official private key remains authoritative until revocation |
| Signed rollback | durable highest verified provider/instance revision | an administrator can use the explicit local rollback override |
| Credential storage failure | structured errors; secrets do not fall back to plaintext files | security inherits the configured OS vault |
| Process kill / PID reuse | PID + start time + executable + working-directory identity before stop | only the main Java process is owned; a malicious same-user OS is out of scope |
| Corrupt metadata | version checks, bounded reads, parse errors and previous/snapshot recovery | some corruption requires administrator cleanup or restore |

No `unsafe` code is permitted in CentralCore. The review found no mutable
global singleton and no production panic reachable from untrusted input;
remaining `expect` calls are tests or static compile-time-owned URL invariants.
The runtime never accepts a provider private key, and provider trust is separate
from authentication endpoint trust and managed-Java distribution integrity.

Out of scope: a compromised CentralCore binary, compromised user machine,
malicious administrator holding an approved signing key, or secrecy after a
host application deliberately extracts a credential.
