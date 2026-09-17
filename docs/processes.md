# Process persistence and recovery

Each launched process is identified by PID, executable path, working
directory, and OS process start time. A new CentralCore invocation checks all
available attributes before reporting an instance as running or sending a
stop request. A PID match alone is never sufficient.

Normal launch retains asynchronous stdout/stderr readers and waits through a
`RunningInstance`. Detached launch redirects output to instance log files,
persists identity, and lets the CLI exit while Minecraft remains alive.
Subsequent `status` and `stop` commands use the persisted identity. Stale or
mismatched records are removed and produce structured process recovery events.

The Windows stabilization test validates a detached subprocess through two
independent `ProcessManager` values: launch returns a PID, the second manager
recovers its identity, stop terminates that exact process, and final status is
not running. This deterministic test covers the failure mechanism without
claiming a graphical Minecraft E2E run.
## Stop semantics

CentralCore owns the verified main Java process. Before stopping a detached
process it matches PID, process start time, canonical executable and working
directory to reject PID reuse. It then requests forced termination and waits up
to five seconds for the identity to disappear. State is removed only after that
confirmation.

On Unix the portable forced signal supplied by `sysinfo` is used. On Windows,
`taskkill.exe /F` is attempted first; environments where `taskkill` incorrectly
returns access denied use the system Windows PowerShell `Stop-Process` API as a
fallback. The command contains only the already validated numeric PID and runs
without a visible window. Failures preserve both OS diagnostics in the
structured `StopFailed` error.

There is no cross-platform graceful Minecraft shutdown protocol for an already
detached process. Version 1.0 therefore defines `stop` as forced termination of
the main process. It does not pass `/T` or kill descendants by name: doing so
could terminate unrelated reused processes. Process-tree ownership may be
added later only with an equally strong per-process identity model.
