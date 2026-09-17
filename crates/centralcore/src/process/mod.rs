//! Asynchronous multi-instance Minecraft process lifecycle management.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    sync::{broadcast, mpsc, watch, RwLock},
    time::{sleep, Duration, Instant},
};

use crate::{
    events::{CoreEvent, EventBus, ProcessStream},
    instance::InstanceId,
    lock::LockManager,
    minecraft::{LaunchPlan, MinecraftError},
    Error, Result,
};

/// Completed process status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub code: Option<i32>,
    pub success: bool,
}

/// Handle returned after a process has been detached from the current runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedInstance {
    pub instance_id: InstanceId,
    pub pid: u32,
}

/// Result of scanning persisted process identities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecoveryReport {
    pub recovered: u64,
    pub lost: u64,
    pub identity_mismatches: u64,
}

/// Structured persisted-process failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProcessRecoveryError {
    #[error(
        "persisted PID {pid} no longer matches the Minecraft process identity for `{instance_id}`"
    )]
    IdentityMismatch { instance_id: String, pid: u32 },
    #[error("persisted process state for `{instance_id}` is invalid: {reason}")]
    InvalidState { instance_id: String, reason: String },
    #[error("operating system refused to stop PID {pid} for instance `{instance_id}`: {reason}")]
    StopFailed {
        instance_id: String,
        pid: u32,
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct ProcessEntry {
    pid: u32,
    executable: PathBuf,
    kill: mpsc::Sender<ProcessCommand>,
    exit: watch::Receiver<Option<ProcessExit>>,
    stdout: broadcast::Sender<String>,
    stderr: broadcast::Sender<String>,
}

#[derive(Debug)]
enum ProcessCommand {
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedProcess {
    pid: u32,
    executable: PathBuf,
    working_directory: PathBuf,
    #[serde(default)]
    start_time: Option<u64>,
}

/// Registry capable of tracking several Minecraft processes concurrently.
#[derive(Debug, Clone)]
pub struct ProcessManager {
    entries: Arc<RwLock<HashMap<InstanceId, ProcessEntry>>>,
    state_root: PathBuf,
    events: EventBus,
    locks: LockManager,
}

impl ProcessManager {
    pub(crate) fn new(state_root: PathBuf, events: EventBus) -> Self {
        let lock_root = state_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("locks");
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            state_root,
            events,
            locks: LockManager::new(lock_root),
        }
    }

    /// Launches one plan without invoking a shell.
    pub async fn launch(
        &self,
        instance_id: &InstanceId,
        plan: &LaunchPlan,
    ) -> Result<RunningInstance> {
        let _process_lock = self
            .locks
            .try_acquire_exclusive(format!("process:{instance_id}"))
            .await?;
        if self.is_running(instance_id).await? {
            return Err(MinecraftError::AlreadyRunning(instance_id.to_string()).into());
        }
        let mut command = plan.command();
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        let mut child = command
            .spawn()
            .map_err(|error| MinecraftError::Launch(error.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| Error::Process("spawned process did not expose a PID".into()))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (kill_tx, mut kill_rx) = mpsc::channel(2);
        let (exit_tx, exit_rx) = watch::channel(None);
        let (stdout_tx, _) = broadcast::channel(1024);
        let (stderr_tx, _) = broadcast::channel(1024);
        let entry = ProcessEntry {
            pid,
            executable: tokio::fs::canonicalize(plan.executable()).await?,
            kill: kill_tx,
            exit: exit_rx.clone(),
            stdout: stdout_tx.clone(),
            stderr: stderr_tx.clone(),
        };
        if let Err(error) = self.persist(instance_id, pid, plan).await {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(error);
        }
        self.entries
            .write()
            .await
            .insert(instance_id.clone(), entry.clone());

        self.events.emit(CoreEvent::MinecraftStarted {
            instance_id: instance_id.to_string(),
            pid,
        });
        if let Some(stdout) = stdout {
            tokio::spawn(read_stream(
                stdout,
                instance_id.to_string(),
                ProcessStream::Stdout,
                self.events.clone(),
                plan.sensitive_values().to_vec(),
                stdout_tx,
            ));
        }
        if let Some(stderr) = stderr {
            tokio::spawn(read_stream(
                stderr,
                instance_id.to_string(),
                ProcessStream::Stderr,
                self.events.clone(),
                plan.sensitive_values().to_vec(),
                stderr_tx,
            ));
        }

        let events = self.events.clone();
        let state_path = self.state_path(instance_id);
        let id = instance_id.to_string();
        tokio::spawn(async move {
            let status = tokio::select! {
                status = child.wait() => status,
                command = kill_rx.recv() => {
                    if matches!(command, Some(ProcessCommand::Kill)) {
                        let _ = child.start_kill();
                    }
                    child.wait().await
                }
            };
            let exit = match status {
                Ok(status) => ProcessExit {
                    code: status.code(),
                    success: status.success(),
                },
                Err(_) => ProcessExit {
                    code: None,
                    success: false,
                },
            };
            let _ = exit_tx.send(Some(exit));
            let _ = tokio::fs::remove_file(state_path).await;
            events.emit(CoreEvent::MinecraftStopped {
                instance_id: id.clone(),
                exit_code: exit.code,
            });
            events.emit(CoreEvent::ProcessStopped {
                instance_id: id,
                pid,
            });
        });

        Ok(RunningInstance {
            instance_id: instance_id.clone(),
            entry,
            events: self.events.clone(),
        })
    }

    /// Launches Minecraft with file-backed logs and leaves it running when the
    /// current Tokio runtime or CLI process exits.
    pub async fn launch_detached(
        &self,
        instance_id: &InstanceId,
        plan: &LaunchPlan,
    ) -> Result<DetachedInstance> {
        let _process_lock = self
            .locks
            .try_acquire_exclusive(format!("process:{instance_id}"))
            .await?;
        if self.is_running(instance_id).await? {
            return Err(MinecraftError::AlreadyRunning(instance_id.to_string()).into());
        }
        let instance_root = plan.working_directory().parent().ok_or_else(|| {
            Error::Process("launch working directory has no instance root".into())
        })?;
        let logs = instance_root.join("logs");
        tokio::fs::create_dir_all(&logs).await?;
        let stdout = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs.join("minecraft-stdout.log"))
            .await?
            .into_std()
            .await;
        let stderr = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs.join("minecraft-stderr.log"))
            .await?
            .into_std()
            .await;
        let mut command = plan.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(false);
        let child = command
            .spawn()
            .map_err(|error| MinecraftError::Launch(error.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| Error::Process("spawned process did not expose a PID".into()))?;
        self.persist(instance_id, pid, plan).await?;
        self.events.emit(CoreEvent::MinecraftStarted {
            instance_id: instance_id.to_string(),
            pid,
        });
        drop(child);
        Ok(DetachedInstance {
            instance_id: instance_id.clone(),
            pid,
        })
    }

    /// Reconciles every persisted process record with the operating system.
    pub async fn recover(&self) -> Result<ProcessRecoveryReport> {
        tokio::fs::create_dir_all(&self.state_root).await?;
        let mut reader = tokio::fs::read_dir(&self.state_root).await?;
        let mut report = ProcessRecoveryReport::default();
        while let Some(entry) = reader.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            let Ok(id) = InstanceId::new(stem) else {
                continue;
            };
            let Some(process) = self.read_persisted(&id).await? else {
                continue;
            };
            match probe_process(&process).await? {
                ProcessProbe::Alive => {
                    report.recovered += 1;
                    self.events.emit(CoreEvent::ProcessRecovered {
                        instance_id: id.to_string(),
                        pid: process.pid,
                    });
                }
                ProcessProbe::Gone => {
                    report.lost += 1;
                    tokio::fs::remove_file(path).await?;
                    self.events.emit(CoreEvent::ProcessLost {
                        instance_id: id.to_string(),
                        pid: process.pid,
                    });
                }
                ProcessProbe::IdentityMismatch => {
                    report.identity_mismatches += 1;
                    tokio::fs::remove_file(path).await?;
                    self.events.emit(CoreEvent::ProcessIdentityMismatch {
                        instance_id: id.to_string(),
                        pid: process.pid,
                    });
                }
            }
        }
        Ok(report)
    }

    /// Returns whether an in-memory or safely identified persisted process is alive.
    pub async fn is_running(&self, instance_id: &InstanceId) -> Result<bool> {
        if let Some(entry) = self.entries.read().await.get(instance_id) {
            return Ok(entry.exit.borrow().is_none());
        }
        let Some(process) = self.read_persisted(instance_id).await? else {
            return Ok(false);
        };
        match probe_process(&process).await? {
            ProcessProbe::Alive => {
                self.events.emit(CoreEvent::ProcessRecovered {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                });
                Ok(true)
            }
            ProcessProbe::Gone => {
                let _ = tokio::fs::remove_file(self.state_path(instance_id)).await;
                self.events.emit(CoreEvent::ProcessLost {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                });
                Ok(false)
            }
            ProcessProbe::IdentityMismatch => {
                let _ = tokio::fs::remove_file(self.state_path(instance_id)).await;
                self.events.emit(CoreEvent::ProcessIdentityMismatch {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                });
                Ok(false)
            }
        }
    }

    /// Reports whether an active tracked process uses the given executable.
    pub async fn is_executable_running(&self, executable: impl AsRef<Path>) -> Result<bool> {
        let executable = tokio::fs::canonicalize(executable).await?;
        if self.entries.read().await.values().any(|entry| {
            entry.exit.borrow().is_none()
                && path_matches(Some(entry.executable.as_path()), &executable)
        }) {
            return Ok(true);
        }
        if !tokio::fs::try_exists(&self.state_root).await? {
            return Ok(false);
        }
        let mut reader = tokio::fs::read_dir(&self.state_root).await?;
        while let Some(entry) = reader.next_entry().await? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(entry.path()).await else {
                continue;
            };
            let Ok(process) = serde_json::from_slice::<PersistedProcess>(&bytes) else {
                continue;
            };
            if path_matches(Some(process.executable.as_path()), &executable)
                && matches!(probe_process(&process).await?, ProcessProbe::Alive)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Stops a tracked process, including one launched by another CLI process.
    pub async fn kill(&self, instance_id: &InstanceId) -> Result<bool> {
        let _process_lock = self
            .locks
            .acquire_exclusive(format!("process:{instance_id}"))
            .await?;
        if let Some(entry) = self.entries.read().await.get(instance_id).cloned() {
            self.events.emit(CoreEvent::ProcessStopping {
                instance_id: instance_id.to_string(),
                pid: entry.pid,
            });
            entry
                .kill
                .send(ProcessCommand::Kill)
                .await
                .map_err(|_| Error::Process("process monitor is no longer available".into()))?;
            return Ok(true);
        }
        let Some(process) = self.read_persisted(instance_id).await? else {
            return Ok(false);
        };
        match probe_process(&process).await? {
            ProcessProbe::Alive => {}
            ProcessProbe::Gone => {
                let _ = tokio::fs::remove_file(self.state_path(instance_id)).await;
                self.events.emit(CoreEvent::ProcessLost {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                });
                return Ok(false);
            }
            ProcessProbe::IdentityMismatch => {
                let _ = tokio::fs::remove_file(self.state_path(instance_id)).await;
                self.events.emit(CoreEvent::ProcessIdentityMismatch {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                });
                return Err(ProcessRecoveryError::IdentityMismatch {
                    instance_id: instance_id.to_string(),
                    pid: process.pid,
                }
                .into());
            }
        }
        self.events.emit(CoreEvent::ProcessStopping {
            instance_id: instance_id.to_string(),
            pid: process.pid,
        });
        let pid = process.pid;
        if let Err(reason) = stop_persisted(&process).await? {
            return Err(ProcessRecoveryError::StopFailed {
                instance_id: instance_id.to_string(),
                pid,
                reason,
            }
            .into());
        }
        let _ = tokio::fs::remove_file(self.state_path(instance_id)).await;
        self.events.emit(CoreEvent::ProcessStopped {
            instance_id: instance_id.to_string(),
            pid,
        });
        Ok(true)
    }

    async fn persist(&self, id: &InstanceId, pid: u32, plan: &LaunchPlan) -> Result<()> {
        tokio::fs::create_dir_all(&self.state_root).await?;
        let root_metadata = tokio::fs::symlink_metadata(&self.state_root).await?;
        if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
            return Err(Error::UnsafeFilesystemEntry {
                path: self.state_root.clone(),
                reason: "process state root must be a real directory",
            });
        }
        let state = PersistedProcess {
            pid,
            executable: tokio::fs::canonicalize(plan.executable()).await?,
            working_directory: tokio::fs::canonicalize(plan.working_directory()).await?,
            start_time: process_start_time(pid).await?,
        };
        let destination = self.state_path(id);
        let temporary = self
            .state_root
            .join(format!("{}.{}.tmp", id.as_str(), std::process::id()));
        tokio::fs::write(&temporary, serde_json::to_vec_pretty(&state)?).await?;
        if tokio::fs::try_exists(&destination).await? {
            let metadata = tokio::fs::symlink_metadata(&destination).await?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::UnsafeFilesystemEntry {
                    path: destination,
                    reason: "process state must be a real file",
                });
            }
            tokio::fs::remove_file(&destination).await?;
        }
        tokio::fs::rename(temporary, destination).await?;
        Ok(())
    }

    async fn read_persisted(&self, id: &InstanceId) -> Result<Option<PersistedProcess>> {
        let path = self.state_path(id);
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn state_path(&self, id: &InstanceId) -> PathBuf {
        self.state_root.join(format!("{}.json", id.as_str()))
    }
}

/// Handle for one live or recently-exited Minecraft process.
#[derive(Debug, Clone)]
pub struct RunningInstance {
    instance_id: InstanceId,
    entry: ProcessEntry,
    events: EventBus,
}

impl RunningInstance {
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.entry.pid
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.entry.exit.borrow().is_none()
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.entry.exit.borrow().as_ref().and_then(|exit| exit.code)
    }

    /// Subscribes to redacted stdout lines for this process.
    #[must_use]
    pub fn stdout(&self) -> broadcast::Receiver<String> {
        self.entry.stdout.subscribe()
    }

    /// Subscribes to redacted stderr lines for this process.
    #[must_use]
    pub fn stderr(&self) -> broadcast::Receiver<String> {
        self.entry.stderr.subscribe()
    }

    pub async fn kill(&self) -> Result<()> {
        self.entry
            .kill
            .send(ProcessCommand::Kill)
            .await
            .map_err(|_| Error::Process("process monitor is no longer available".into()))
    }

    pub async fn wait(&self) -> Result<ProcessExit> {
        let mut receiver = self.entry.exit.clone();
        loop {
            if let Some(exit) = *receiver.borrow() {
                return Ok(exit);
            }
            receiver.changed().await.map_err(|_| {
                Error::Process("process monitor closed without an exit status".into())
            })?;
        }
    }

    #[must_use]
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<CoreEvent> {
        self.events.subscribe()
    }
}

async fn read_stream<R: AsyncRead + Unpin>(
    stream: R,
    instance_id: String,
    kind: ProcessStream,
    events: EventBus,
    secrets: Vec<String>,
    output: broadcast::Sender<String>,
) {
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = redact(&line, &secrets);
        let _ = output.send(line.clone());
        events.emit(CoreEvent::MinecraftLog {
            instance_id: instance_id.clone(),
            stream: kind,
            line: line.clone(),
        });
        events.emit(match kind {
            ProcessStream::Stdout => CoreEvent::MinecraftStdout {
                instance_id: instance_id.clone(),
                line,
            },
            ProcessStream::Stderr => CoreEvent::MinecraftStderr {
                instance_id: instance_id.clone(),
                line,
            },
        });
    }
}

fn redact(line: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(line.to_owned(), |line, secret| {
            line.replace(secret, "[REDACTED]")
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessProbe {
    Alive,
    Gone,
    IdentityMismatch,
}

async fn probe_process(expected: &PersistedProcess) -> Result<ProcessProbe> {
    let pid_value = expected.pid;
    let executable = expected.executable.clone();
    let working_directory = expected.working_directory.clone();
    let start_time = expected.start_time;
    tokio::task::spawn_blocking(move || {
        let mut system = System::new();
        let pid = Pid::from_u32(pid_value);
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        let Some(process) = system.process(pid) else {
            return ProcessProbe::Gone;
        };
        let expected = PersistedProcess {
            pid: pid_value,
            executable,
            working_directory,
            start_time,
        };
        if persisted_identity_matches(process, &expected) {
            ProcessProbe::Alive
        } else {
            ProcessProbe::IdentityMismatch
        }
    })
    .await
    .map_err(|error| Error::Process(error.to_string()))
}

async fn stop_persisted(expected: &PersistedProcess) -> Result<std::result::Result<(), String>> {
    let expected_for_check = expected.clone();
    let identity_still_matches = tokio::task::spawn_blocking(move || {
        let mut system = System::new();
        let pid = Pid::from_u32(expected_for_check.pid);
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        let Some(process) = system.process(pid) else {
            return false;
        };
        persisted_identity_matches(process, &expected_for_check)
    })
    .await
    .map_err(|error| Error::Process(error.to_string()))?;
    if !identity_still_matches {
        return Ok(Err(
            "the persisted process identity changed before termination".into(),
        ));
    }

    let request = request_forced_stop(expected.pid).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match probe_process(expected).await? {
            ProcessProbe::Gone | ProcessProbe::IdentityMismatch => return Ok(Ok(())),
            ProcessProbe::Alive if Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            ProcessProbe::Alive => {
                let reason = request
                    .err()
                    .unwrap_or_else(|| "the process remained alive after the stop timeout".into());
                return Ok(Err(reason));
            }
        }
    }
}

#[cfg(windows)]
async fn request_forced_stop(pid: u32) -> std::result::Result<(), String> {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let taskkill = tokio::process::Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .await
        .map_err(|error| format!("could not execute taskkill.exe: {error}"))?;
    if taskkill.status.success() {
        return Ok(());
    }

    // Some Windows environments deny `taskkill.exe` while still allowing the
    // owning user to terminate the process through the native process API.
    // Windows PowerShell's Stop-Process provides that safe, system-supplied
    // fallback without weakening the persisted PID identity checks above.
    let powershell = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| {
            root.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .unwrap_or_else(|| PathBuf::from("powershell.exe"));
    let script = format!("Stop-Process -Id {pid} -Force -ErrorAction Stop");
    let fallback = tokio::process::Command::new(powershell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .await;
    if fallback
        .as_ref()
        .is_ok_and(|output| output.status.success())
    {
        return Ok(());
    }

    let taskkill_reason = command_failure("taskkill.exe", &taskkill);
    let fallback_reason = match fallback {
        Ok(output) => command_failure("Stop-Process", &output),
        Err(error) => format!("could not execute Windows PowerShell: {error}"),
    };
    Err(format!(
        "{taskkill_reason}; fallback failed: {fallback_reason}"
    ))
}

#[cfg(windows)]
fn command_failure(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    if detail.is_empty() {
        format!("{command} exited with status {}", output.status)
    } else {
        format!("{command} exited with status {}: {detail}", output.status)
    }
}

#[cfg(not(windows))]
async fn request_forced_stop(pid_value: u32) -> std::result::Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut system = System::new();
        let pid = Pid::from_u32(pid_value);
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        let Some(process) = system.process(pid) else {
            return Ok(());
        };
        if process.kill() {
            Ok(())
        } else {
            Err("the operating system rejected the forced termination request".into())
        }
    })
    .await
    .map_err(|error| error.to_string())?
}

fn path_matches(actual: Option<&Path>, expected: &Path) -> bool {
    actual.is_some_and(|actual| path_key(actual) == path_key(expected))
}

fn persisted_identity_matches(process: &sysinfo::Process, expected: &PersistedProcess) -> bool {
    path_matches(process.exe(), &expected.executable)
        && expected
            .start_time
            .is_none_or(|start_time| process.start_time() == start_time)
        && process
            .cwd()
            .is_none_or(|cwd| path_matches(Some(cwd), &expected.working_directory))
}

async fn process_start_time(pid: u32) -> Result<Option<u64>> {
    tokio::task::spawn_blocking(move || {
        let mut system = System::new();
        let pid = Pid::from_u32(pid);
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        system.process(pid).map(sysinfo::Process::start_time)
    })
    .await
    .map_err(|error| Error::Process(error.to_string()))
}

fn path_key(path: &Path) -> String {
    let value = path.to_string_lossy();
    let value = value
        .strip_prefix(r"\\?\UNC\")
        .map(|path| format!(r"\\{path}"))
        .or_else(|| value.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or_else(|| value.into_owned());
    if cfg!(windows) {
        value.to_lowercase()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, time::Duration};

    use super::*;

    #[test]
    fn redacts_every_known_secret() {
        assert_eq!(
            redact("token=secret", &["secret".into()]),
            "token=[REDACTED]"
        );
    }

    #[test]
    fn normalizes_windows_verbatim_paths_for_identity_checks() {
        assert_eq!(
            path_key(Path::new(r"\\?\C:\Games\Minecraft")),
            path_key(Path::new(r"C:\Games\Minecraft"))
        );
    }

    #[tokio::test]
    async fn launches_tracks_and_kills_without_blocking_tokio() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let manager = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        let plan = LaunchPlan::from_parts_for_test(
            std::env::current_exe().expect("test executable"),
            vec![OsString::from("--exact"), OsString::from("--ignored")],
            "process::tests::long_running_child".into(),
            vec![OsString::from("--nocapture")],
            temporary.path().to_path_buf(),
        );
        let id = InstanceId::new("process-test").expect("id");
        let running = manager.launch(&id, &plan).await.expect("launch");
        assert!(running.is_running());
        assert!(manager.is_running(&id).await.expect("status"));
        let external = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        assert!(external.is_running(&id).await.expect("external status"));
        assert_eq!(external.recover().await.expect("recovery").recovered, 1);
        running.kill().await.expect("kill");
        let exit = tokio::time::timeout(Duration::from_secs(5), running.wait())
            .await
            .expect("wait timeout")
            .expect("wait");
        assert!(!exit.success);
    }

    #[tokio::test]
    async fn detached_process_is_visible_to_a_new_manager() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let manager = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        let plan = LaunchPlan::from_parts_for_test(
            std::env::current_exe().expect("test executable"),
            vec![OsString::from("--exact"), OsString::from("--ignored")],
            "process::tests::short_lived_child".into(),
            vec![OsString::from("--nocapture")],
            temporary.path().join(".minecraft"),
        );
        tokio::fs::create_dir_all(plan.working_directory())
            .await
            .expect("working directory");
        let id = InstanceId::new("detached-test").expect("id");
        let detached = manager
            .launch_detached(&id, &plan)
            .await
            .expect("detached launch");
        assert!(detached.pid > 0);
        let external = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        assert!(external.is_running(&id).await.expect("running"));
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(!external.is_running(&id).await.expect("stopped"));
    }

    #[tokio::test]
    async fn detached_process_can_be_stopped_by_a_new_manager() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let manager = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        let plan = LaunchPlan::from_parts_for_test(
            std::env::current_exe().expect("test executable"),
            vec![OsString::from("--exact"), OsString::from("--ignored")],
            "process::tests::long_running_child".into(),
            vec![OsString::from("--nocapture")],
            temporary.path().join(".minecraft"),
        );
        tokio::fs::create_dir_all(plan.working_directory())
            .await
            .expect("working directory");
        let id = InstanceId::new("detached-stop-test").expect("id");
        let detached = manager
            .launch_detached(&id, &plan)
            .await
            .expect("detached launch");
        assert!(detached.pid > 0);

        let external = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        assert!(external.is_running(&id).await.expect("running"));
        assert!(external.kill(&id).await.expect("external stop"));
        assert!(!external.is_running(&id).await.expect("stopped"));
    }

    #[tokio::test]
    async fn identity_mismatch_is_never_reported_as_running() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let manager = ProcessManager::new(temporary.path().join("processes"), EventBus::new(32));
        tokio::fs::create_dir_all(&manager.state_root)
            .await
            .expect("state root");
        let id = InstanceId::new("mismatch").expect("id");
        let state = PersistedProcess {
            pid: std::process::id(),
            executable: PathBuf::from("definitely-not-this-process.exe"),
            working_directory: temporary.path().to_path_buf(),
            start_time: None,
        };
        tokio::fs::write(
            manager.state_path(&id),
            serde_json::to_vec(&state).expect("state"),
        )
        .await
        .expect("write state");
        assert!(!manager.is_running(&id).await.expect("status"));
        assert!(!manager.state_path(&id).exists());
    }

    #[test]
    #[ignore = "helper process spawned by launches_tracks_and_kills_without_blocking_tokio"]
    fn long_running_child() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "helper process spawned by detached_process_is_visible_to_a_new_manager"]
    fn short_lived_child() {
        std::thread::sleep(Duration::from_millis(500));
    }
}
