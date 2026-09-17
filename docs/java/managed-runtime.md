# Managed Java runtime

Managed installation follows one transaction:

```text
trusted distribution metadata
  -> DownloadManager (bounded, retrying, cancellable)
  -> SHA-256 verification
  -> secure staging extraction
  -> java -version and architecture validation
  -> atomic runtime commit
```

Runtime directories are shared by instances. A runtime manifest records the
provider, vendor, full version, major, OS, architecture, archive digest and
installation time. The archive may be retained in the artifact cache, but an
installed runtime is a separate live object and is never removed by ordinary
cache pruning.

Managed installation is enabled by the default `JavaPolicy`. Set
`auto_install_java = false` to retain managed selection but prevent downloads,
or `managed = false` together with `auto_install_java = false` to use only
system/explicit Java. Install locks are per runtime identity so concurrent
launchers have one writer.

The built-in provider is Eclipse Temurin through the official Adoptium API v3.
CentralCore requests a JRE HotSpot image and accepts the OS/architecture pairs
that Adoptium returns for Windows, Linux and macOS. Adoptium supplies the
archive SHA-256 and size; CentralCore does not redistribute archives in Git.
Temurin binaries are distributed under GPLv2 with the Classpath Exception.

Archives live in `cache/java/objects/sha256`; installed runtimes live in
`runtimes/java/<major>/<runtime-id>`. A validated distribution sidecar lets a
cached archive be installed without a metadata request. Interrupted
`.install-*` directories are removed at startup. Repair is a full
transactional reinstall, not a file-by-file patch.

ZIP and tar.gz extraction rejects absolute/traversal paths, links, excessive
entry counts and decompression limits. On Unix only the owner execute bits
needed by `bin/java` are restored. macOS `Contents/Home/bin/java` layouts are
found by the same bounded runtime search.

Production E2E coverage currently confirms Windows x86_64. Linux x86_64,
macOS x86_64 and macOS arm64 are implemented through the same Adoptium
contract and covered by platform/archive unit tests, but still require a
release-machine launch smoke test. Windows/Linux arm64 are normalized and can
be resolved when the provider publishes a matching image; they are not yet
claimed as release-tested targets.

Mojang runtime metadata was considered as a second source, but Phase 7 ships
only the production Adoptium implementation. A future Mojang source must
implement the same `JavaDistributionProvider`; it must not introduce a second
manager or bypass CentralCore's cache, integrity and extraction pipeline.
