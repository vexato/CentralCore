# Vanilla launch

`MinecraftManager::build_launch_plan` verifies installation state, loads the
cached version metadata, resolves rules and classpath, selects the exact Mojang
Java major when available, and expands JVM/game placeholders. `LaunchPlan`
keeps executable, JVM arguments, main class, game arguments, and working
directory separate. Its debug/printable form redacts access tokens.

For an account launch, the CLI resolves `account -> AuthSession -> refresh if
expired -> verify -> MinecraftIdentity` before asking Minecraft to build the
plan. `LaunchPlan` sees only `MinecraftIdentity::Official` or `Offline`; it has
no Microsoft, Azuriom, HTTP or provider-ID branch.

When an installed loader plan exists, launch composes its generic overlay:
classpath additions, JVM/game arguments, loader version ID, main-class override
and minimum Java requirement. Launch does not fetch Fabric or Forge metadata;
the committed plan is sufficient for warm-cache and offline operation.

`ProcessManager` launches through `tokio::process::Command`, captures both
streams asynchronously, tracks multiple instance IDs, exposes PID/kill/wait,
and persists enough process identity to avoid blindly killing a reused PID.
Detached launch redirects output to instance log files so closing the CLI does
not close Minecraft's stdout/stderr pipes.

```text
ccorp instance launch vanilla-test --offline CentralCorpTest
ccorp instance launch vanilla-test --account microsoft-account-id
ccorp instance launch vanilla-test --offline CentralCorpTest --detach
ccorp instance status vanilla-test
ccorp instance stop vanilla-test
```

## Manual validation (2026-09-11)

Minecraft 1.20.4 was installed from Mojang on Windows and launched with Eclipse
Adoptium Java 17. The real client initialized LWJGL 3.3.2, OpenAL, resource
packs, texture atlases, and then exited normally with code 0. Authlib logged an
expected HTTP 401 while fetching online profile properties for the deliberately
offline session; this did not prevent the client from starting.

The development UI environment automatically closed the Minecraft window
shortly after initialization. Consequently the manual `stop` command observed
an already-stopped instance; kill/wait behavior is additionally covered by a
long-running child-process test.

## Loader validation (2026-09-13)

Fabric Loader 0.19.5 on Minecraft 1.20.4 reached Fabric's Knot client, Mixin,
LWJGL and resource initialization. Forge 47.4.23 on Minecraft 1.20.1 reached
ModLauncher 10.0.9, FML discovery, loaded the Forge universal module and the
SRG client under Eclipse Adoptium Java 17. These were real detached client
launches from the dedicated `.phase5-e2e` data directory.

## Managed Java validation (2026-09-16)

Phase 7 repeated Vanilla 1.20.4, Fabric 1.20.4 and Forge 1.20.1 launches with
the executable recorded below `runtimes/java/17/adoptium-*`. Forge reached its
client initialization after aligning `${version_name}` with the actual cached
base-client JAR name, preventing duplicate raw/transformed Minecraft modules.
