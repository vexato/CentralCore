# Provider components

A component is a stable provider-defined group of one or more managed files. It can represent a mod, configuration, resource pack, or another bundle. CentralCore does not assume one component equals one JAR.

```json
{
  "id": "sodium",
  "name": "Sodium",
  "required": false,
  "default_enabled": false,
  "requires": [],
  "conflicts": [],
  "files": [{
    "id": "sodium-jar",
    "path": "mods/sodium.jar",
    "url": "../files/sodium.jar",
    "size": 123,
    "sha256": "..."
  }]
}
```

IDs use lowercase ASCII letters, digits, `.`, `_`, and `-`, start with a letter or digit, and are at most 64 bytes. Paths must be unique across top-level files and every component, preventing contradictory ownership.

Required components are always active. Optional components use `default_enabled` only when first discovered. Explicit local choices live in versioned `runtime/components.json`, separate from the provider snapshot; later defaults cannot overwrite them. Preferences for removed components are retained as harmless historical metadata.

Simple transitive `requires` and effective conflict checks are supported. Dependencies are enabled in the resolved set. Disabling a component still required by an enabled component is rejected. This is intentionally not a general package solver.

```bash
ccorp instance component list demo:survival
ccorp instance component enable demo:survival sodium
ccorp instance component enable demo:survival sodium --offline
ccorp instance component disable demo:survival sodium
```

Enable/disable applies the same `UpdatePlan` used for revisions. Disabling removes only files whose index origin identifies that component. Cache objects may remain for later offline enable. Verify and repair use the active index, so an absent disabled component is healthy and is never silently reinstalled.

