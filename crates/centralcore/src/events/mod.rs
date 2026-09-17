//! Typed, UI-agnostic events emitted by CentralCore.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::{
    auth::AuthChallengeKind, cache::VerificationReport, minecraft::InstallProgress,
    providers::UpdatePhase,
};

/// A structured event emitted by a core service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CoreEvent {
    AuthFlowStarted {
        provider_id: String,
    },
    AuthChallengeRequired {
        provider_id: String,
        flow_id: String,
        challenge: AuthChallengeKind,
    },
    AuthFlowCompleted {
        provider_id: String,
        account_id: String,
    },
    AuthFlowFailed {
        provider_id: String,
        error_kind: String,
    },
    AuthSessionCreated {
        provider_id: String,
        account_id: String,
    },
    AuthSessionRefreshed {
        provider_id: String,
        account_id: String,
    },
    AuthSessionExpired {
        provider_id: String,
        account_id: String,
    },
    AuthSessionRemoved {
        provider_id: String,
        account_id: String,
    },
    InstanceCreated {
        instance_id: String,
    },
    InstanceDeleted {
        instance_id: String,
    },
    InstanceInstalling {
        instance_id: String,
    },
    InstanceInstalled {
        instance_id: String,
    },
    InstanceRepairStarted {
        instance_id: String,
    },
    InstanceRepairCompleted {
        instance_id: String,
    },
    InstanceRepairFailed {
        instance_id: String,
        message: String,
    },
    InstanceVerificationStarted {
        instance_id: String,
        full: bool,
    },
    InstanceVerificationProgress {
        instance_id: String,
        checked_files: u64,
        total_files: u64,
    },
    InstanceVerificationCompleted {
        instance_id: String,
        report: VerificationReport,
    },
    RepairPlanCreated {
        instance_id: String,
        downloads: u64,
        extractions: u64,
    },
    InstanceRepairProgress {
        instance_id: String,
        completed_files: u64,
        total_files: u64,
    },
    FileDownloadStarted {
        download_id: String,
        path: String,
        expected_bytes: Option<u64>,
    },
    FileDownloadProgress {
        download_id: String,
        downloaded_bytes: u64,
        expected_bytes: Option<u64>,
        bytes_per_second: u64,
        completed_files: u64,
        total_files: u64,
    },
    FileDownloadCompleted {
        download_id: String,
        path: String,
    },
    FileDownloadFailed {
        download_id: String,
        message: String,
    },
    JavaDetectionStarted,
    JavaRuntimeDetected {
        executable: String,
        major_version: u16,
        source: String,
    },
    JavaResolutionStarted {
        required_major: u16,
        architecture: String,
    },
    JavaRuntimeSelected {
        executable: String,
        major_version: u16,
        source: String,
    },
    JavaRuntimeDownloadStarted {
        provider: String,
        major_version: u16,
    },
    JavaRuntimeDownloadProgress {
        provider: String,
        downloaded_bytes: u64,
        expected_bytes: Option<u64>,
        bytes_per_second: u64,
    },
    JavaRuntimeDownloaded {
        provider: String,
        major_version: u16,
    },
    JavaRuntimeInstallStarted {
        provider: String,
        major_version: u16,
    },
    JavaRuntimeInstalled {
        provider: String,
        major_version: u16,
    },
    JavaRuntimeVerificationStarted {
        executable: String,
    },
    JavaRuntimeVerificationCompleted {
        executable: String,
        major_version: u16,
    },
    LoaderResolutionStarted {
        loader: String,
        minecraft_version: String,
        loader_version: Option<String>,
    },
    LoaderResolutionCompleted {
        loader: String,
        minecraft_version: String,
        loader_version: String,
        downloads: u64,
        processors: u64,
    },
    LoaderProcessorStarted {
        instance_id: String,
        processor_id: String,
    },
    LoaderProcessorCompleted {
        instance_id: String,
        processor_id: String,
    },
    MinecraftInstallStarted {
        instance_id: String,
        version_id: String,
    },
    VersionManifestDownloadStarted,
    LibraryDownloadStarted {
        instance_id: String,
        path: String,
    },
    AssetDownloadStarted {
        instance_id: String,
        path: String,
    },
    NativeExtractionStarted {
        instance_id: String,
        archives: u64,
    },
    MinecraftInstallProgress {
        instance_id: String,
        progress: InstallProgress,
    },
    MinecraftInstallCompleted {
        instance_id: String,
        version_id: String,
    },
    MinecraftInstallFailed {
        instance_id: String,
        message: String,
    },
    MinecraftStarting {
        instance_id: String,
    },
    MinecraftStarted {
        instance_id: String,
        pid: u32,
    },
    MinecraftLog {
        instance_id: String,
        stream: ProcessStream,
        line: String,
    },
    MinecraftStdout {
        instance_id: String,
        line: String,
    },
    MinecraftStderr {
        instance_id: String,
        line: String,
    },
    MinecraftStopped {
        instance_id: String,
        exit_code: Option<i32>,
    },
    CacheVerificationStarted {
        full: bool,
    },
    CacheVerificationCompleted {
        valid: u64,
        missing: u64,
        corrupted: u64,
    },
    RecoveryStarted,
    RecoveryCompleted {
        recovered_instances: u64,
        recoverable_instances: u64,
    },
    ProcessRecovered {
        instance_id: String,
        pid: u32,
    },
    ProcessLost {
        instance_id: String,
        pid: u32,
    },
    ProcessStopping {
        instance_id: String,
        pid: u32,
    },
    ProcessStopped {
        instance_id: String,
        pid: u32,
    },
    ProcessIdentityMismatch {
        instance_id: String,
        pid: u32,
    },
    ProviderAdded {
        provider_id: String,
    },
    ProviderRemoved {
        provider_id: String,
    },
    ProviderSyncStarted {
        provider_id: String,
    },
    ProviderSyncProgress {
        provider_id: String,
        completed_instances: u64,
        total_instances: u64,
    },
    ProviderSyncCompleted {
        provider_id: String,
        instances: u64,
    },
    ProviderSyncFailed {
        provider_id: String,
        message: String,
    },
    ProviderCacheHit {
        provider_id: String,
        url: String,
    },
    ProviderNotModified {
        provider_id: String,
    },
    ManifestVerificationStarted {
        provider_id: String,
    },
    ManifestVerified {
        provider_id: String,
        key_id: String,
        revision: u64,
    },
    ManifestVerificationFailed {
        provider_id: String,
        error_kind: String,
    },
    SigningKeyTrusted {
        key_id: String,
    },
    SigningKeyRemoved {
        key_id: String,
    },
    SigningKeyRotated {
        provider_id: String,
        old_key_id: String,
        new_key_id: String,
    },
    ProviderRollbackRejected {
        provider_id: String,
        received_revision: u64,
        highest_revision: u64,
    },
    InstanceDefinitionUpdated {
        provider_id: String,
        instance_id: String,
        revision: u64,
    },
    InstanceUpdateAvailable {
        provider_id: String,
        instance_id: String,
        installed_revision: u64,
        available_revision: u64,
    },
    InstanceUpdateCheckStarted {
        provider_id: String,
        instance_id: String,
    },
    UpdatePlanCreated {
        instance_id: String,
        from_revision: u64,
        to_revision: u64,
        downloads: u64,
        replacements: u64,
        removals: u64,
    },
    InstanceUpdateStarted {
        instance_id: String,
        from_revision: u64,
        to_revision: u64,
    },
    InstanceUpdateProgress {
        instance_id: String,
        phase: UpdatePhase,
        completed_files: u64,
        total_files: u64,
        completed_bytes: u64,
        total_bytes: u64,
    },
    InstanceUpdateCompleted {
        instance_id: String,
        from_revision: u64,
        to_revision: u64,
    },
    InstanceUpdateFailed {
        instance_id: String,
        message: String,
    },
    ComponentEnabled {
        instance_id: String,
        component_id: String,
    },
    ComponentDisabled {
        instance_id: String,
        component_id: String,
    },
    ComponentSelectionChanged {
        instance_id: String,
        component_id: String,
        enabled: bool,
    },
}

/// Identifies the process stream used by a log event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStream {
    Stdout,
    Stderr,
}

/// Monotonic identifier assigned by one [`EventBus`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(u64);

impl EventId {
    /// Returns the process-local monotonic value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Versioned metadata attached to events for logs, IPC, and UI adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    format_version: u32,
    id: EventId,
    timestamp_unix_millis: u64,
    event: CoreEvent,
}

impl EventEnvelope {
    /// Current serialized envelope format.
    pub const FORMAT_VERSION: u32 = 1;

    /// Envelope format version.
    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Process-local event sequence identifier.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Best-effort wall-clock timestamp in Unix milliseconds.
    #[must_use]
    pub const fn timestamp_unix_millis(&self) -> u64 {
        self.timestamp_unix_millis
    }

    /// Structured CentralCore event payload.
    #[must_use]
    pub const fn event(&self) -> &CoreEvent {
        &self.event
    }

    /// Consumes the envelope and returns its payload.
    #[must_use]
    pub fn into_event(self) -> CoreEvent {
        self.event
    }
}

/// Multi-subscriber event transport used by the core.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<CoreEvent>>,
    envelope_sender: Arc<broadcast::Sender<EventEnvelope>>,
    next_id: Arc<AtomicU64>,
}

impl EventBus {
    /// Creates a bus retaining up to `capacity` events per subscriber.
    ///
    /// A lagging subscriber receives Tokio's `Lagged` error and can continue
    /// with newer events; it never blocks the producer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        let (envelope_sender, _) = broadcast::channel(capacity.max(1));
        Self {
            sender: Arc::new(sender),
            envelope_sender: Arc::new(envelope_sender),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Returns a new independent event receiver.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<CoreEvent> {
        self.sender.subscribe()
    }

    /// Subscribes to versioned events carrying ordering and timestamp metadata.
    ///
    /// IDs are monotonic only within this bus/process and may contain gaps when
    /// a receiver lags. The timestamp is diagnostic and must not be used as a
    /// security or transaction ordering authority.
    #[must_use]
    pub fn subscribe_envelopes(&self) -> broadcast::Receiver<EventEnvelope> {
        self.envelope_sender.subscribe()
    }

    /// Publishes an event. Having no active subscriber is not an error.
    pub(crate) fn emit(&self, event: CoreEvent) {
        let envelope = EventEnvelope {
            format_version: EventEnvelope::FORMAT_VERSION,
            id: EventId(self.next_id.fetch_add(1, Ordering::Relaxed)),
            timestamp_unix_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            event: event.clone(),
        };
        let _ = self.sender.send(event);
        let _ = self.envelope_sender.send(envelope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_events_have_stable_secret_free_json() {
        let event = CoreEvent::InstanceUpdateProgress {
            instance_id: "demo_survival".into(),
            phase: UpdatePhase::Downloading,
            completed_files: 2,
            total_files: 4,
            completed_bytes: 128,
            total_bytes: 256,
        };
        let json = serde_json::to_value(event).expect("event JSON");
        assert_eq!(json["type"], "instance_update_progress");
        assert_eq!(json["phase"], "downloading");
        let text = json.to_string();
        for forbidden in ["password", "access_token", "refresh_token", "body"] {
            assert!(!text.contains(forbidden));
        }
    }
}
