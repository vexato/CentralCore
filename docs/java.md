# Java runtime management

CentralCore resolves Java independently from Minecraft and loaders. Minecraft
metadata and a loader plan contribute a minimum `JavaRequirement`; `JavaManager`
then selects a validated `JavaRuntime` for the host architecture.

The public model is:

- `JavaRequirement`: required major version and normalized `Architecture`;
- `JavaRuntime`: executable, detected full version, major, architecture,
  optional vendor and `JavaRuntimeSource`;
- `JavaDistributionProvider`: trusted, compile-time extension point for runtime
  metadata and archives.

System discovery remains bounded to `JAVA_HOME`, PATH and conventional vendor
roots (`Program Files`, `/usr/lib/jvm`, and macOS JavaVirtualMachines). At most
64 direct children of each known root are considered; no disk-wide scan is
performed. Every candidate is
executed with `java -XshowSettings:properties -version`; version, architecture
and vendor are read from the process output. A directory containing a binary
is not accepted on its own. Managed runtimes are stored below the shared CentralCore data
directory, separately from instances, and are selected by requirement rather
than a mutable global Java setting.

The deterministic default order is explicit instance runtime, explicitly
selected managed runtime, compatible managed runtime, compatible system
runtime, then automatic managed installation. `prefer_system_java` reverses
the middle two choices. `auto_install_java = false` guarantees that resolution
never downloads Java.

The CLI exposes `java detect`, `list`, `available --major`, `install`,
`verify`, `repair`, `remove`, and `select`. `instance show` reports the merged
requirement and the currently selectable installed runtime.

See [managed-runtime.md](java/managed-runtime.md) for installation semantics
and [custom-provider.md](java/custom-provider.md) for the extension contract.
