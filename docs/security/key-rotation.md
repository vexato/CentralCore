# Provider signing-key rotation

Rotation is an explicit, one-hop authorization from a currently trusted key to
a new Ed25519 public key. It is not a PKI or certificate hierarchy.

The version-1 transition document contains:

```json
{
  "transition_version": 1,
  "provider_id": "demo",
  "from_key_id": "sha256:...",
  "to_key": {
    "algorithm": "ed25519",
    "public_key": "base64...",
    "label": "2027 signing key"
  },
  "valid_from_revision": 13,
  "signature": "base64..."
}
```

The old key signs the RFC 8785 canonical form of all fields except `signature`,
prefixed by `centralcore-key-transition-v1\0`. CentralCore checks that the old
key is locally trusted, the provider identity matches, the new key ID is derived
from its bytes, and the transition signature is valid. Applying the transition
stores the new public key and the scoped `old -> new` authorization.

A provider bound to the old key may then accept indexes signed by the new key
only at or above `valid_from_revision`. Unrelated keys and transitions for a
different provider remain invalid. Rotation emits a public-fingerprint event;
no private material is involved.

Revocation is local. Removing/revoking a key blocks future syncs using it.
Existing installed instances and the last accepted snapshot are retained. In a
private-key compromise, an administrator must distribute a locally trusted
replacement or a transition signed before revoking the old key; this small
model cannot distinguish a legitimate old-key signature from one produced by
an attacker holding the same private key.
