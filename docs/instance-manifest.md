# CentralCorp Instance Manifest v1

Format v1 remains current and backward compatible. Phase 8 adds an optional
`components` array; older manifests without it retain their previous behavior.
Top-level `files` remain required. Optional content uses a component so it has
a stable identity and separate local selection state. See `docs/components.md`.

The public schemas are `docs/schema/provider-v1.schema.json` and
`docs/schema/instance-v1.schema.json`. Runtime validation is authoritative and
adds checks JSON Schema cannot express safely: portable IDs and paths,
duplicate detection, URL/source resolution, network policy, file limits and
cross-origin managed-path conflicts.

An index identifies a provider and references individual manifests:

```json
{
  "format_version": 1,
  "provider": { "id": "example-network", "name": "Example Network" },
  "instances": [
    { "id": "survival", "manifest": "instances/survival.json" }
  ]
}
```

An instance manifest declares desired engine state, not local installation
state:

```json
{
  "format_version": 1,
  "id": "survival",
  "name": "Survival",
  "revision": 1,
  "minecraft": {
    "version": "1.20.4",
    "loader": { "type": "vanilla" }
  },
  "java": {
    "memory": { "minimum_mb": 1024, "recommended_mb": 2048 }
  },
  "server": { "address": "play.example.com", "port": 25565 },
  "authentication": {
    "required": true,
    "providers": ["microsoft", "my-azuriom"]
  },
  "files": [
    {
      "id": "server-config",
      "path": "config/server.json",
      "url": "../files/server.json",
      "size": 128,
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Every provider file is mandatory in v1 and requires exact size plus SHA-256.
Duplicate destinations are rejected. File paths are rooted below the
instance's `.minecraft` directory. Optional declarations are reserved by the
schema but rejected until the selection model is implemented.

Loader declarations are a discriminated union. Vanilla omits `version`; Fabric
and Forge require an exact version:

```json
{ "type": "fabric", "version": "0.19.5" }
```

```json
{ "type": "forge", "version": "47.4.23" }
```

`latest`, missing versions on mod loaders, and versions on Vanilla are rejected.
StaticProvider only selects the loader coordinate: it cannot provide processors
or executable arguments. `LoaderRegistry` resolves the same declaration used by
locally created instances, so the provider contains no Fabric/Forge-specific
installation logic.

Only structured Java memory recommendations and server coordinates are
accepted. The format intentionally has no arbitrary JVM arguments, game
arguments, executable paths, Java agents or shell commands. Manifest signing is
reserved for a future version and no custom cryptography is implied by v1.

`authentication.required` selects required versus optional authentication;
`providers` is an allow-list of local provider IDs. The policy is independent
of Vanilla/Fabric/Forge. It does not create providers and contains no endpoint,
credential or provider configuration. A listed ID must already be registered
or explicitly trusted in the local auth registry. An empty list is valid only
when authentication is optional.
