# Vanilla installation

Provider-backed first installation resolves required components and optional
defaults before materializing files. It does not install all optional content
and remove disabled content afterward. Existing local choices are honored on
subsequent installations.

Installation follows this pipeline:

```text
catalog -> version metadata -> asset index -> InstallPlan
        -> client/libraries/assets/native archives/logging
        -> verified cache -> native staging -> final commit
```

For a modded instance, the Vanilla resolver additionally asks `LoaderRegistry`
for a versioned `LoaderPlan`. Its downloads are merged into `InstallPlan` and
use the same bounded `DownloadManager` and shared cache. After Vanilla native
commit, the generic loader executor performs exact archive extractions and
ordered Java processors, validates their outputs, persists the finalized plan,
and records every loader-owned or generated file in the managed index.

Fabric plans only add libraries and a launch overlay. Modern Forge plans can
also contain installer archive entries and processors. Neither path introduces
a loader-specific branch in installation.

The shared cache is below `<data>/minecraft` and prevents identical libraries
and assets from being downloaded for every instance. Downloads are streamed,
bounded by configured concurrency, retried, resumed through `.part` files, and
validated by expected size and SHA-1 when Mojang provides them.

An instance moves through `NotInstalled`, `Installing`, `Recoverable`,
`Installed`, or `Broken`. `Installed` is written only after every planned file
validates, natives have been extracted through a transaction-specific staging
directory, and the managed-file index has committed. A cancellation token
stops new batches and active streams without deleting valid cache entries.

Install writes a versioned transaction journal for `created`, `downloading`,
`validating`, `committing`, and terminal state transitions. Restart recovery
never assumes an old `Installing` state is broken: it checks the instance lock
and managed index, then promotes it or marks it recoverable.

Manual workflow:

```text
ccorp minecraft versions
ccorp instance create vanilla-test --minecraft 1.20.4 --name "Vanilla Test"
ccorp instance install vanilla-test
ccorp instance status vanilla-test
```

Loader instances require exact, reproducible versions:

```text
ccorp instance create fabric-test --minecraft 1.20.4 --loader fabric --loader-version 0.19.5
ccorp instance create forge-test --minecraft 1.20.1 --loader forge --loader-version 47.4.23
```
