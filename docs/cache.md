# Cache management and locking

Component files use the same SHA-256 content-addressed provider cache as
required files. Disabling removes materialized files, not cache objects. Cache
pruning computes liveness from current Managed File Index documents and never
treats installed runtime/instance storage as artifact cache.

Java archive artifacts may be content-addressed in the shared cache, while an
installed runtime remains a separate managed object. Cache pruning retains
references from installed runtime manifests and never removes a runtime merely
because no instance currently has it open.

`CacheManager` owns the versioned metadata for `<data>/minecraft`. Its index is
reconstructible from installed instance managed-file indexes; it is an
optimization and not a fragile reference counter.

Cache status groups bytes into versions, libraries, assets, metadata,
temporary files, and other managed objects. Verification reports missing,
corrupted, orphaned-index, and abandoned temporary entries. Pruning first
targets abandoned temporary files, then indexed objects that are not
referenced by any instance. Dry-run is the default inspection mechanism.

CentralCore uses OS file locks stored below `<data>/locks`. Cache locks are
derived from the SHA-256 of the validated relative resource path, so unrelated
downloads continue concurrently. Instance mutation locks are derived from the
validated instance ID. Lock files are harmless persistent coordination names;
the OS releases their locks automatically when a process exits.

Every cache write remains:

```text
resource lock -> resume/write .part -> hash/size validation -> atomic rename
```

No final object is exposed before validation.

Fabric libraries, Forge installer/profile data, processor jars and generated
outputs use the same versioned cache index and per-resource locks. Loader-owned
entries retain `ManagedFileOrigin::Loader`, while the exact loader identity and
processor graph live in the committed instance `LoaderPlan`. This lets verify
and repair reconstruct a corrupt loader artifact without a loader-specific
cache implementation.

Provider payloads extend this cache without changing Mojang's layout. Their
path is content-addressed as
`provider/objects/sha256/<prefix>/<sha256>`, so identical bytes from different
providers share one validated object. Each installed provider file has a
managed-index link to that object. Offline repair uses this reconstructible
link and the existing `RepairPlan` verified-copy operation; cache corruption
still requires the original local source or permitted network access.

The real Minecraft 1.20.4 cache contained 3,856 indexed objects and 710.55 MiB
of data. Full verification reported zero missing, corrupted, or unexpected
objects. Two simultaneous instance installs then reused the same 3,854-file
plan with zero downloaded bytes; both instance reports and the cache report
remained healthy.
