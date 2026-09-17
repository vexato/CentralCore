# Static provider

`StaticProvider` consumes a version-1 provider index and one version-1 manifest
per instance. Both a local file tree and a remote HTTP(S) tree are supported.
Remote references are resolved with `Url::join`; local references are resolved
relative to the containing document and cannot escape the provider root.

```text
provider.json
provider.json.sig  # when signatures are enabled
instances/
  survival.json
files/
  config/centralcorp-test.json
```

```text
ccorp provider add demo examples/static-provider/provider.json
ccorp provider sync demo
ccorp provider list
ccorp provider show demo
ccorp instance list
ccorp instance install demo:survival
ccorp instance verify demo:survival
ccorp instance launch demo:survival --offline Steve
```

For a signed provider, trust is always established locally and the provider is
bound to that fingerprint:

```text
ccorp trust add centralcorp-signing-key.public.json
ccorp provider add demo https://cdn.example/provider.json \
  --signature-policy required --key sha256:<fingerprint>
ccorp provider sync demo
```

`--trust-key <file>` combines the first two local trust steps. It does not read
or accept private keys. See [provider signatures](security/signatures.md), the
[trust model](security/trust-model.md), and [key rotation](security/key-rotation.md).

`provider add` never requires network access. `provider sync` performs
fetch/read, bounded parsing, normalization and complete validation before it
replaces the active snapshot. One invalid instance rejects the whole sync. A
previous valid snapshot remains active on JSON, HTTP, validation or write
failure.

Remote documents retain URL, ETag, Last-Modified, retrieval time and content
SHA-256 metadata. Conditional requests use `If-None-Match` and
`If-Modified-Since`; an index-level 304 reuses the complete snapshot. These
HTTP validators optimize retrieval only and never replace installed-file hash
verification. A 304 reuses the cached verified signature state, but a locally
revoked key still blocks the sync.

By default remote sources require HTTPS and public network destinations.
Development HTTP/private endpoints require explicit `download` and
`providers.allow_private_networks` configuration. URL userinfo, unsupported
schemes, query/fragment components, HTTPS-to-HTTP redirects, loopback,
link-local and private targets are rejected by the applicable policy.

The ready-to-run example is in `examples/static-provider`. It contains no
redistributed Minecraft artifact; CentralCore resolves Vanilla files from the
official metadata pipeline.

To publish a loader instance, replace the loader declaration with an exact
coordinate such as `{"type":"fabric","version":"0.19.5"}` or
`{"type":"forge","version":"47.4.23"}`. StaticProvider does not parse
ecosystem metadata and cannot declare processors or arguments; it passes the
coordinate to the generic loader registry.

Once the shared cache contains every required object, installation can be
forced offline with `ccorp instance install demo:survival --offline`. The same
snapshot and content-addressed objects support offline listing, verification
and repair.

## Manual validation (2026-09-11)

The bundled local provider installed Minecraft 1.20.4 with 3,854 Mojang files
and one provider file. Full verification reported 3,879 valid files. After the
provider config was deliberately corrupted, verification reported exactly one
corruption; dry-run proposed zero downloads and one cache copy, and offline
repair returned the instance to 3,879 valid files. A second provider instance
then installed fully offline with zero downloaded bytes.

The repaired instance launched with Eclipse Adoptium Java 17 and the offline
profile `CentralCorpTest`. Its detached log confirmed LWJGL 3.3.2, OpenAL and
texture-atlas initialization before the development environment closed the
window normally.
