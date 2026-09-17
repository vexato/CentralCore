# Provider signatures

CentralCore uses Ed25519 provider signatures. Ed25519 is a standard, modern
signature scheme with small public keys and signatures, deterministic signing,
and mature Rust implementations. CentralCore uses `ed25519-dalek`; it does not
implement a signature primitive or random-number generator.

Signatures authenticate provider metadata. SHA-256 remains responsible for
checking downloaded file contents:

- an Ed25519 signature answers "was this metadata published by an approved
  key and left unchanged?";
- a SHA-256 file digest answers "are these the bytes named by the authenticated
  metadata?".

## Detached format

An index named `provider.json` has a sibling named `provider.json.sig`:

```json
{
  "signature_version": 1,
  "algorithm": "ed25519",
  "key_id": "sha256:...",
  "signature": "base64..."
}
```

The signature is made over this byte sequence:

```text
centralcore-provider-signature-v1\0 || RFC8785(provider.json)
```

The domain separator prevents a signature created for another protocol from
being interpreted as a CentralCore provider signature. Base64 uses the standard
alphabet with padding. Unknown versions and algorithms are rejected.

`provider.json` stays ordinary, readable JSON. Before signing or verification,
it is parsed and serialized using JSON Canonicalization Scheme (RFC 8785/JCS).
Whitespace, newline style, indentation, and object-member order therefore do
not affect the signature. Array order and values remain significant. Duplicate
JSON object names are not valid provider input.

## Signed root and child manifests

The signed provider index is the root of the content tree. A signed index must
contain:

- a monotonically increasing, non-zero provider `revision`;
- every instance manifest path;
- the SHA-256 digest of every instance manifest.

Instance manifests are authenticated by those signed digests. Their component
declarations, file URLs, sizes, and file SHA-256 digests consequently inherit
the root signature. Individual mods do not need signatures: their bytes are
still checked against the SHA-256 digest in the authenticated manifest.

This intentionally avoids a Merkle tree and one signature per child. It gives
static/CDN hosting two root files plus the existing instance files. A modified
URL invalidates the child digest; modified downloaded file bytes fail their
existing SHA-256 check.

Legacy unsigned indexes may omit the root revision and child digests only when
their local registration policy explicitly permits unsigned content. A present
signature is always validated; malformed or invalid signatures are never
downgraded to unsigned content.

## Signing keys

The signing utility writes a versioned JSON private-key file containing the
base64-encoded 32-byte Ed25519 seed and a portable JSON public-key file. The
format is intentionally small and documented by `ccorp-sign keygen`; it is not
an invented encrypted keystore. Private-key files are created as new files with
restrictive permissions where the platform supports that operation. They must
be handled as CI secrets, excluded from source control, and never published.
CentralCore runtime APIs accept public keys only.

Private-key encryption is deliberately not invented by this project. The first
format version is unencrypted; deployments needing encryption should keep the
file inside their CI/OS secret store and materialize it only for the signing
step.

The signing utility is non-interactive and suitable for CI:

```text
ccorp-sign keygen \
  --private-key signing.private.json \
  --public-key signing.public.json \
  --label production

ccorp-sign sign provider.json --private-key signing.private.json
ccorp-sign verify provider.json --public-key signing.public.json
```

For the safer publisher workflow, let the tool calculate child digests and
produce an isolated artifact tree:

```text
ccorp-sign prepare provider.json \
  --private-key signing.private.json \
  --output-dir publish
```

`prepare` validates that every manifest is a real file contained below the
provider root, copies it while preserving the relative path, calculates its
raw-byte SHA-256, updates the output index and writes `provider.json.sig`. The
source tree is not modified. `sign` remains available for exporters that
already calculate child hashes. Neither command uploads a key or artifact.

In CI, materialize the private-key file from the CI secret store into a
permission-restricted temporary file, run `prepare`, publish only the output
directory, then delete the workspace according to the runner's secret policy.
The private JSON must never be echoed, cached as an artifact or committed.

For rotation:

```text
ccorp-sign transition \
  --provider demo \
  --old-private-key signing.private.json \
  --new-public-key next.public.json \
  --valid-from-revision 13 \
  --output demo-key-transition.json

ccorp trust rotate demo-key-transition.json
```
