# Loader architecture

CentralCore models every mod loader as a producer of a versioned, serializable
`LoaderPlan`. The Minecraft install, verify, repair, cache, and launch pipelines
never branch on Fabric or Forge. They only compose and execute the operations in
that plan.

```text
LoaderConfig
    |
    v
LoaderRegistry -> Loader::resolve()
    |
    v
LoaderPlan
    |-- downloads and classpath entries
    |-- launch overlay (main class, JVM/game arguments, Java requirement)
    |-- trusted archive entries
    |-- ordered ProcessorPlan operations
    `-- generated outputs
             |
             v
InstallPlan -> Managed File Index -> Verify / Repair -> LaunchPlan
```

## Plan contract

A loader plan has an exact `LoaderIdentity` (`kind`, Minecraft version, loader
version), cache-relative downloads, classpath additions, an optional main-class
override, structured JVM/game arguments, an optional minimum Java major version,
trusted archive-entry extractions, and ordered processor plans. A processor plan
contains only a Java artifact, a classpath, separated arguments, and declared
outputs. There is no shell command string.

Paths in plans are `SafeRelativePath` values rooted below the shared Minecraft
cache. A loader implementation resolves ecosystem-specific placeholders before
returning its plan. Consequently the executor does not understand Forge data
tokens or Fabric metadata.

Processor operations are accepted only from loader implementations registered by
the application. Static providers can select an exact loader version but cannot
declare processors, arbitrary JVM arguments, or generated files.

## Fabric

`FabricLoader` consumes the official Fabric Meta v2 API. A compatible entry
supplies the exact loader and intermediary coordinates, checksummed common/client
libraries, client main class, and minimum Java version. Fabric API is deliberately
not installed because it is a separate mod.

## Forge

`ForgeLoader` resolves an exact Maven version, validates the official installer,
parses `install_profile.json` and `version.json`, and converts the client-side
profile to the generic plan. Modern Forge (`spec: 1`, Minecraft 1.13+) is the
initial supported family. Installer data entries are extracted by exact name,
then processors are executed in declared order with an argument vector.

Processor outputs are validated after each invocation. Outputs without an
upstream digest receive a locally computed SHA-256 digest before the installed
plan and managed index are committed. Repair can therefore rerun only the
processor chain needed by a damaged generated artifact.

Pre-1.13 Forge uses materially different installation formats and is rejected
with a structured compatibility error. The registry and plan format do not
prevent adding a separate historical Forge resolver later.

## Persistence and offline behavior

The committed plan is stored below the instance runtime directory. Launch and
repair consume that snapshot and never contact loader metadata services. Exact
loader artifacts are shared through the existing cache and managed-file index.
An offline install succeeds when the cached plan and every required object are
present and valid.

