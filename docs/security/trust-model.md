# Provider trust model

## Root of trust

A remote provider cannot make its own key trusted. Trust is established only by
an explicit local operation through the CentralCore `TrustStore` API or
`ccorp trust add`. Provider registrations bind a provider ID and source to a
signature policy and, for signed providers, an expected key ID.

A key ID is the lowercase fingerprint:

```text
sha256:<64 hexadecimal characters>
```

It is SHA-256 over the exact 32-byte Ed25519 public key. Labels are local hints;
the fingerprint is the stable identity.

The trust store persists public keys and verified key transitions below the
CentralCore data directory. It never stores or accepts a private key. Removing
or revoking a key prevents future synchronization but does not delete installed
instances or the last valid snapshot.

## Policies

- `required`: the detached signature must be present, valid, and made by the
  configured key or an explicitly authorized successor.
- `optional`: an absent signature is reported as unsigned; if one is present it
  must be valid and trusted.
- `disabled`: signature retrieval and verification are disabled. This is the
  explicit compatibility mode for legacy providers.

Local providers may use any policy. Existing API registrations default to
`optional` for compatibility. Applications should make `required` the default
for new production HTTP(S) providers. Neither `optional` nor `disabled` means
that unsigned content is cryptographically trusted.

## Snapshot boundary

Network or filesystem bytes are untrusted until their detached signature (when
applicable), schema, child hashes, URL policy, and revision monotonicity have all
been checked. Only then is a verified snapshot constructed and atomically made
active. Install and update planning consume that snapshot, never a raw network
manifest.

Signature metadata records the algorithm, key ID, signature, canonical content
hash, verification time, and root revision. Cached document/signature material
allows an already verified snapshot to remain usable offline. HTTP 304 reuses
the corresponding verified bytes and status; it is not treated as new content.

If any verification step fails, synchronization fails before the active
snapshot or anti-rollback counters are replaced. The old snapshot and installed
instance stay usable.

## Anti-rollback

CentralCore separately persists the highest verified provider revision and the
highest verified revision of each instance manifest. A signed revision lower
than either high-water mark is rejected even if its signature is valid and the
current snapshot file has been removed or damaged. An equal revision with
different authenticated content is also rejected.

Rollback override is an explicit local administrative API/CLI option. It
permits a deliberate sync but does not silently erase the recorded high-water
mark; later normal syncs remain protected.

## Threat model

The model protects against:

- a compromised CDN or static host changing an index or manifest;
- a man-in-the-middle supplying modified provider metadata;
- a fake provider signed by an unknown or wrong key;
- replay of an older correctly signed provider or instance revision;
- a file server returning bytes different from the authenticated SHA-256.

It does not automatically protect against:

- compromise or malicious use of the official private signing key;
- compromise of the user's machine, trust store, or CentralCore data directory;
- a compromised CentralCore binary or cryptographic dependency;
- an administrator who intentionally trusts a malicious key or disables policy;
- availability attacks, deletion, or a server refusing to return new content;
- AuthProvider credentials/endpoints or managed Java distribution, which have
  separate trust models.

