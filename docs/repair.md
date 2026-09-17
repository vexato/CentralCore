# Verification and repair design

Repair restores the desired state already recorded in the Managed File Index;
it does not adopt a newer provider revision. Update changes desired state first.
Disabled components are absent from the index, so verify does not report them
missing and repair never silently reinstalls them.

Phase 3 extends the existing Vanilla `InstallPlan`; it does not introduce a
second installer. A successful install writes a versioned managed-file index
containing every cache object and extracted native owned by CentralCore. User
data below `.minecraft` is deliberately absent from that index.

```text
managed-file index + current filesystem
                 -> VerificationReport
                 -> RepairPlan
                 -> incremental executor
                 -> full final verification
```

`RepairPlan` contains the observed checks, only the downloads that are missing
or invalid, native archives that must be re-extracted, and safe managed
removals. Constructing a plan does not alter files. Dry-run stops after plan
construction. Repair replaces invalid cache objects through the same verified
temporary-file and atomic-rename path as installation.

Fast verification accepts an unchanged size and modification timestamp that
were recorded immediately after a cryptographic verification. Any metadata
change falls back to the expected hash. Full verification always hashes every
managed file. Missing and corrupted files are reported separately.

CentralCore never treats saves, screenshots, options, server lists, resource
packs, shader packs, logs, or unknown `.minecraft` content as managed files.
Repair and prune therefore cannot remove them.

## Real validation (2026-09-11)

Minecraft 1.20.4 was installed in an isolated data directory and all 3,877
managed instance files verified. The cached Gson 2.10.1 library was then
replaced with a 34-byte corruption. Verification reported exactly one
corrupted file; dry-run proposed one 276.73 KiB download and made no change.
Repair downloaded that library only, reused 3,876 files, and the final full
verification was healthy. Minecraft subsequently initialized LWJGL, OpenAL,
resources, and texture atlases.
