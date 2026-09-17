//! Java runtime policy and local discovery.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    download::{CancellationToken, DownloadManager},
    events::{CoreEvent, EventBus},
    lock::LockManager,
    platform::{Architecture, OperatingSystem, Platform},
    Error, Result,
};

mod adoptium;
mod managed;
mod system;

pub use adoptium::AdoptiumJavaProvider;
pub use managed::{
    ManagedJavaProvider, ManagedJavaRuntime, RuntimeManifest, RUNTIME_MANIFEST_FORMAT_VERSION,
};
pub use system::SystemJavaProvider;

/// Minimum Java capability required by Minecraft and its loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaRequirement {
    pub major_version: u16,
    pub architecture: Architecture,
}

impl JavaRequirement {
    #[must_use]
    pub const fn new(major_version: u16, architecture: Architecture) -> Self {
        Self {
            major_version,
            architecture,
        }
    }

    #[must_use]
    pub const fn current(major_version: u16) -> Self {
        Self::new(major_version, Platform::current().architecture)
    }

    /// Combines Minecraft's minimum with an optional loader minimum.
    #[must_use]
    pub const fn with_loader_minimum(self, loader_major: Option<u16>) -> Self {
        let major_version = match loader_major {
            Some(loader) if loader > self.major_version => loader,
            _ => self.major_version,
        };
        Self {
            major_version,
            architecture: self.architecture,
        }
    }
}

/// Origin of a runtime selected for a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaRuntimeSource {
    System,
    Managed,
}

/// Supported distribution archive containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaArchiveKind {
    Zip,
    TarGz,
}

/// A validated Java executable ready to be passed to a LaunchPlan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaRuntime {
    pub executable: PathBuf,
    pub major_version: u16,
    pub full_version: String,
    pub architecture: Architecture,
    pub vendor: Option<String>,
    pub source: JavaRuntimeSource,
}

impl From<&JavaInstallation> for JavaRuntime {
    fn from(installation: &JavaInstallation) -> Self {
        Self {
            executable: installation.executable.clone(),
            major_version: installation.version.major,
            full_version: installation.version.raw.clone(),
            architecture: installation.architecture,
            vendor: installation.vendor.clone(),
            source: match installation.source {
                JavaSource::Managed => JavaRuntimeSource::Managed,
                JavaSource::JavaHome
                | JavaSource::Path
                | JavaSource::KnownLocation
                | JavaSource::Explicit => JavaRuntimeSource::System,
            },
        }
    }
}

/// A distribution archive selected by a trusted Java distribution provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaDistribution {
    pub provider: String,
    pub vendor: String,
    pub version: String,
    pub major_version: u16,
    pub operating_system: OperatingSystem,
    pub architecture: Architecture,
    pub archive_url: url::Url,
    pub archive_sha256: String,
    pub archive_size: Option<u64>,
    pub archive_kind: JavaArchiveKind,
}

/// Query passed to a replaceable Java distribution service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaDistributionRequest {
    pub requirement: JavaRequirement,
    pub operating_system: OperatingSystem,
}

/// Stable extension contract for trusted Java distribution metadata services.
#[async_trait]
pub trait JavaDistributionProvider: Send + Sync {
    fn id(&self) -> &str;

    async fn resolve(
        &self,
        request: JavaDistributionRequest,
        cancellation: &CancellationToken,
    ) -> Result<JavaDistribution>;
}

/// CentralCore Java selection policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaPolicy {
    #[serde(default = "default_true")]
    pub managed: bool,
    pub preferred_major: Option<u16>,
    #[serde(default = "default_true")]
    pub auto_install_java: bool,
    #[serde(default = "default_true")]
    pub prefer_managed_java: bool,
    #[serde(default)]
    pub prefer_system_java: bool,
    #[serde(default)]
    pub selected_runtime: Option<String>,
}

/// Java settings owned by one instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaInstanceConfig {
    pub executable: Option<PathBuf>,
    pub minimum_memory_mib: u32,
    pub maximum_memory_mib: u32,
}

impl Default for JavaInstanceConfig {
    fn default() -> Self {
        Self {
            executable: None,
            minimum_memory_mib: 512,
            maximum_memory_mib: 2048,
        }
    }
}

impl Default for JavaPolicy {
    fn default() -> Self {
        Self {
            managed: true,
            preferred_major: None,
            auto_install_java: true,
            prefer_managed_java: true,
            prefer_system_java: false,
            selected_runtime: None,
        }
    }
}

impl JavaPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.prefer_managed_java && self.prefer_system_java {
            return Err(Error::InvalidConfig(
                "prefer_managed_java and prefer_system_java cannot both be true".into(),
            ));
        }
        if self.auto_install_java && !self.managed {
            return Err(Error::InvalidConfig(
                "auto_install_java requires managed Java to be enabled".into(),
            ));
        }
        if let Some(runtime) = &self.selected_runtime {
            if runtime.is_empty()
                || runtime.len() > 160
                || !runtime
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(Error::InvalidConfig(
                    "selected Java runtime id is invalid".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Origin of a discovered runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaSource {
    JavaHome,
    Path,
    KnownLocation,
    Managed,
    Explicit,
}

/// Parsed Java release information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaVersion {
    pub raw: String,
    pub major: u16,
}

impl JavaVersion {
    /// Parses standard `java -version` output from OpenJDK and legacy Java 8.
    pub fn parse(output: &str) -> Result<Self> {
        let version = output
            .lines()
            .find_map(|line| {
                let start = line.find('"')? + 1;
                let end = line[start..].find('"')? + start;
                Some(&line[start..end])
            })
            .ok_or_else(|| Error::Java("could not find a quoted Java version".into()))?;

        let first = version.split('.').next().unwrap_or_default();
        let major_text = if first == "1" {
            version.split('.').nth(1).unwrap_or_default()
        } else {
            first
        };
        let major = major_text
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .unwrap_or_default()
            .parse::<u16>()
            .map_err(|_| Error::Java(format!("invalid Java version `{version}`")))?;
        if major == 0 {
            return Err(Error::Java("Java major version cannot be zero".into()));
        }
        Ok(Self {
            raw: version.to_owned(),
            major,
        })
    }
}

/// A usable Java executable and its detected version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaInstallation {
    pub executable: PathBuf,
    pub version: JavaVersion,
    pub architecture: Architecture,
    pub vendor: Option<String>,
    pub source: JavaSource,
}

/// Java discovery service.
#[derive(Debug, Clone)]
pub struct JavaManager {
    policy: JavaPolicy,
    events: EventBus,
    system: SystemJavaProvider,
    managed: ManagedJavaProvider,
}

impl JavaManager {
    pub(crate) fn new(
        policy: JavaPolicy,
        runtime_root: PathBuf,
        cache_root: PathBuf,
        downloads: DownloadManager,
        locks: LockManager,
        events: EventBus,
    ) -> Self {
        let system = SystemJavaProvider::new(events.clone());
        let managed = ManagedJavaProvider::new(
            runtime_root,
            cache_root,
            downloads.clone(),
            locks,
            events.clone(),
            Arc::new(AdoptiumJavaProvider::new(downloads)),
        );
        Self {
            policy,
            events,
            system,
            managed,
        }
    }

    #[must_use]
    pub fn policy(&self) -> &JavaPolicy {
        &self.policy
    }

    #[must_use]
    pub fn managed(&self) -> &ManagedJavaProvider {
        &self.managed
    }

    #[must_use]
    pub fn system(&self) -> &SystemJavaProvider {
        &self.system
    }

    pub async fn register_distribution_provider(
        &self,
        provider: Arc<dyn JavaDistributionProvider>,
    ) -> Result<()> {
        self.managed.register(provider).await
    }

    /// Resolves one validated runtime using the deterministic local policy.
    pub async fn resolve_runtime(
        &self,
        explicit: Option<&Path>,
        requirement: JavaRequirement,
        cancellation: &CancellationToken,
    ) -> Result<JavaRuntime> {
        self.emit_resolution_started(requirement);
        let (local, found_system) = self
            .resolve_installed_runtime_with_diagnostics(explicit, requirement)
            .await?;
        if let Some(runtime) = local {
            self.emit_runtime_selected(&runtime);
            return Ok(runtime);
        }

        if self.policy.managed && self.policy.auto_install_java {
            let runtime = self
                .managed
                .install(requirement, cancellation)
                .await?
                .runtime;
            self.emit_runtime_selected(&runtime);
            return Ok(runtime);
        }

        let detail = if found_system.is_empty() {
            "no Java runtime was found".to_owned()
        } else {
            format!(
                "found incompatible Java versions: {}",
                found_system.join(", ")
            )
        };
        Err(Error::Java(format!(
            "Java {} is required but no compatible runtime is installed or available in the local cache ({detail})",
            requirement.major_version
        )))
    }

    /// Resolves only an already-installed runtime and never accesses the network.
    pub async fn resolve_installed_runtime(
        &self,
        explicit: Option<&Path>,
        requirement: JavaRequirement,
    ) -> Result<Option<JavaRuntime>> {
        self.resolve_installed_runtime_with_diagnostics(explicit, requirement)
            .await
            .map(|(runtime, _)| runtime)
    }

    async fn resolve_installed_runtime_with_diagnostics(
        &self,
        explicit: Option<&Path>,
        requirement: JavaRequirement,
    ) -> Result<(Option<JavaRuntime>, Vec<String>)> {
        if let Some(executable) = explicit {
            let installation = self
                .system
                .inspect(executable, JavaSource::Explicit)
                .await?;
            if installation.version.major < requirement.major_version
                || installation.architecture != requirement.architecture
            {
                return Err(Error::Java(format!(
                    "Java {} is required, but explicit runtime `{}` is Java {} for {:?}",
                    requirement.major_version,
                    executable.display(),
                    installation.version.major,
                    installation.architecture
                )));
            }
            let runtime = JavaRuntime::from(&installation);
            return Ok((Some(runtime), Vec::new()));
        }

        if let Some(selected) = &self.policy.selected_runtime {
            let managed = self.managed.verify(selected).await?;
            if runtime_compatible(&managed.runtime, requirement) {
                return Ok((Some(managed.runtime), Vec::new()));
            }
            return Err(Error::Java(format!(
                "selected managed runtime `{selected}` is incompatible with Java {}",
                requirement.major_version
            )));
        }

        let managed_first = self.policy.managed
            && self.policy.prefer_managed_java
            && !self.policy.prefer_system_java;
        if managed_first {
            if let Some(runtime) = self.select_managed(requirement).await? {
                return Ok((Some(runtime), Vec::new()));
            }
        }

        let system = self.system.detect().await?;
        if let Some(runtime) = self.select_runtime(&system, requirement) {
            return Ok((Some(runtime), Vec::new()));
        }

        if !managed_first && self.policy.managed {
            if let Some(runtime) = self.select_managed(requirement).await? {
                return Ok((Some(runtime), Vec::new()));
            }
        }
        let found = system
            .iter()
            .map(|runtime| runtime.version.major.to_string())
            .collect::<Vec<_>>();
        Ok((None, found))
    }

    async fn select_managed(&self, requirement: JavaRequirement) -> Result<Option<JavaRuntime>> {
        Ok(self
            .managed
            .list()
            .await?
            .into_iter()
            .map(|managed| managed.runtime)
            .filter(|runtime| runtime_compatible(runtime, requirement))
            .min_by_key(|runtime| runtime.major_version))
    }

    pub(crate) fn emit_resolution_started(&self, requirement: JavaRequirement) {
        self.events.emit(CoreEvent::JavaResolutionStarted {
            required_major: requirement.major_version,
            architecture: format!("{:?}", requirement.architecture),
        });
    }

    pub(crate) fn emit_runtime_selected(&self, runtime: &JavaRuntime) {
        self.events.emit(CoreEvent::JavaRuntimeSelected {
            executable: runtime.executable.display().to_string(),
            major_version: runtime.major_version,
            source: format!("{:?}", runtime.source),
        });
    }

    /// Inspects one explicit executable without invoking a shell.
    pub async fn detect_java_version(&self, executable: impl AsRef<Path>) -> Result<JavaVersion> {
        self.system
            .inspect(executable, JavaSource::Explicit)
            .await
            .map(|runtime| runtime.version)
    }

    /// Detects candidates from `JAVA_HOME` and every directory on `PATH`.
    /// Missing or invalid candidates are skipped.
    pub async fn detect_installed_java(&self) -> Result<Vec<JavaInstallation>> {
        self.system.detect().await
    }

    /// Chooses the lowest runtime satisfying `required_major`, preferring the
    /// configured major when it is compatible.
    #[must_use]
    pub fn select_best_java<'a>(
        &self,
        installations: &'a [JavaInstallation],
        required_major: u16,
    ) -> Option<&'a JavaInstallation> {
        if let Some(preferred) = self.policy.preferred_major {
            if preferred >= required_major {
                if let Some(found) = installations.iter().find(|installation| {
                    installation.version.major == preferred
                        && installation.architecture == Platform::current().architecture
                }) {
                    return Some(found);
                }
            }
        }
        installations
            .iter()
            .filter(|installation| {
                installation.version.major >= required_major
                    && installation.architecture == Platform::current().architecture
            })
            .min_by_key(|installation| installation.version.major)
    }

    /// Selects and normalizes a system runtime for a structured requirement.
    #[must_use]
    pub fn select_runtime(
        &self,
        installations: &[JavaInstallation],
        requirement: JavaRequirement,
    ) -> Option<JavaRuntime> {
        self.select_best_java(installations, requirement.major_version)
            .filter(|installation| installation.architecture == requirement.architecture)
            .map(JavaRuntime::from)
    }

    /// Validates one executable against a required major version.
    pub async fn validate_java(
        &self,
        executable: impl AsRef<Path>,
        required_major: u16,
    ) -> Result<JavaVersion> {
        let version = self.detect_java_version(executable).await?;
        if version.major < required_major {
            return Err(Error::Java(format!(
                "Java {required_major} or newer is required, found {}",
                version.major
            )));
        }
        Ok(version)
    }
}

fn java_candidates() -> Vec<(PathBuf, JavaSource)> {
    let executable = if cfg!(windows) { "java.exe" } else { "java" };
    let mut candidates = Vec::new();
    if let Some(java_home) = std::env::var_os("JAVA_HOME") {
        candidates.push((
            PathBuf::from(java_home).join("bin").join(executable),
            JavaSource::JavaHome,
        ));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path)
                .map(|directory| (directory.join(OsString::from(executable)), JavaSource::Path)),
        );
    }
    candidates.extend(known_java_candidates(executable));
    candidates
}

fn known_java_candidates(executable: &str) -> Vec<(PathBuf, JavaSource)> {
    let mut candidates = Vec::new();
    if cfg!(windows) {
        for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(root) = std::env::var_os(variable) {
                for vendor in ["Eclipse Adoptium", "Java", "Microsoft"] {
                    append_runtime_children(
                        &mut candidates,
                        &PathBuf::from(&root).join(vendor),
                        Path::new("bin").join(executable),
                    );
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        append_runtime_children(
            &mut candidates,
            Path::new("/Library/Java/JavaVirtualMachines"),
            Path::new("Contents/Home/bin").join(executable),
        );
        if let Some(user_profile) = std::env::var_os("HOME") {
            append_runtime_children(
                &mut candidates,
                &PathBuf::from(user_profile).join("Library/Java/JavaVirtualMachines"),
                Path::new("Contents/Home/bin").join(executable),
            );
        }
    } else if cfg!(target_os = "linux") {
        candidates.extend([
            (PathBuf::from("/usr/bin/java"), JavaSource::KnownLocation),
            (
                PathBuf::from("/usr/local/bin/java"),
                JavaSource::KnownLocation,
            ),
        ]);
        append_runtime_children(
            &mut candidates,
            Path::new("/usr/lib/jvm"),
            Path::new("bin").join(executable),
        );
    }
    candidates
}

fn append_runtime_children(
    candidates: &mut Vec<(PathBuf, JavaSource)>,
    root: &Path,
    executable: PathBuf,
) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut paths = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path().join(&executable))
        .collect::<Vec<_>>();
    paths.sort();
    candidates.extend(
        paths
            .into_iter()
            .take(64)
            .map(|path| (path, JavaSource::KnownLocation)),
    );
}

const fn default_true() -> bool {
    true
}

fn runtime_compatible(runtime: &JavaRuntime, requirement: JavaRequirement) -> bool {
    runtime.major_version >= requirement.major_version
        && runtime.architecture == requirement.architecture
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> JavaManager {
        let root = std::env::temp_dir().join("centralcore-java-unit-tests");
        let events = EventBus::new(8);
        let downloads =
            DownloadManager::new(Default::default(), events.clone()).expect("downloads");
        let locks = LockManager::new(root.join("locks"));
        JavaManager::new(
            JavaPolicy::default(),
            root.join("runtimes"),
            root.join("cache"),
            downloads,
            locks,
            events,
        )
    }

    #[test]
    fn parses_modern_and_legacy_versions() {
        for (fixture, expected) in [
            (r#"java version "1.8.0_401" Oracle Corporation"#, 8),
            (r#"openjdk version "17.0.12" Eclipse Adoptium"#, 17),
            (r#"openjdk version "21.0.4" Microsoft"#, 21),
            (r#"openjdk version "21.0.4" Amazon Corretto"#, 21),
            (r#"openjdk version "22-ea" OpenJDK"#, 22),
        ] {
            assert_eq!(
                JavaVersion::parse(fixture).expect("fixture").major,
                expected
            );
        }
    }

    #[test]
    fn requirement_and_runtime_are_normalized_and_serializable() {
        let requirement = JavaRequirement::current(21);
        assert_eq!(requirement.major_version, 21);
        assert_eq!(requirement.architecture, Platform::current().architecture);
        let runtime = JavaRuntime {
            executable: PathBuf::from("runtime/bin/java"),
            major_version: 21,
            full_version: "21.0.4".into(),
            architecture: requirement.architecture,
            vendor: Some("Test JDK".into()),
            source: JavaRuntimeSource::Managed,
        };
        let encoded = serde_json::to_string(&runtime).expect("runtime JSON");
        let decoded: JavaRuntime = serde_json::from_str(&encoded).expect("runtime JSON");
        assert_eq!(decoded, runtime);
    }

    #[test]
    fn loader_requirement_is_merged_without_provider_specific_logic() {
        let requirement = JavaRequirement::new(17, Architecture::X86_64);
        assert_eq!(requirement.with_loader_minimum(Some(21)).major_version, 21);
        assert_eq!(requirement.with_loader_minimum(Some(8)).major_version, 17);
        assert_eq!(requirement.with_loader_minimum(None).major_version, 17);
    }

    #[test]
    fn selects_smallest_compatible_runtime() {
        let manager = test_manager();
        let installations = [17, 21, 22].map(|major| JavaInstallation {
            executable: PathBuf::from(format!("java-{major}")),
            version: JavaVersion {
                raw: major.to_string(),
                major,
            },
            architecture: Platform::current().architecture,
            vendor: None,
            source: JavaSource::Explicit,
        });
        assert_eq!(
            manager
                .select_best_java(&installations, 21)
                .map(|java| java.version.major),
            Some(21)
        );
    }

    #[test]
    fn structured_selection_rejects_wrong_architecture() {
        let manager = test_manager();
        let wrong = if Platform::current().architecture == Architecture::X86_64 {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        };
        let installation = JavaInstallation {
            executable: PathBuf::from("java"),
            version: JavaVersion {
                raw: "21.0.4".into(),
                major: 21,
            },
            architecture: wrong,
            vendor: None,
            source: JavaSource::Path,
        };
        assert!(manager
            .select_runtime(&[installation], JavaRequirement::current(21))
            .is_none());
    }

    #[test]
    fn policy_rejects_conflicting_or_unsafe_preferences() {
        let conflicting = JavaPolicy {
            prefer_managed_java: true,
            prefer_system_java: true,
            ..JavaPolicy::default()
        };
        assert!(conflicting.validate().is_err());
        let disabled = JavaPolicy {
            managed: false,
            auto_install_java: true,
            prefer_managed_java: false,
            ..JavaPolicy::default()
        };
        assert!(disabled.validate().is_err());
        let invalid_id = JavaPolicy {
            selected_runtime: Some("../../java".into()),
            ..JavaPolicy::default()
        };
        assert!(invalid_id.validate().is_err());
    }

    #[test]
    fn legacy_java_policy_enables_safe_managed_defaults() {
        let policy: JavaPolicy = serde_json::from_str(r#"{"managed":true,"preferred_major":null}"#)
            .expect("legacy policy");
        assert!(policy.auto_install_java);
        assert!(policy.prefer_managed_java);
        assert!(!policy.prefer_system_java);
        assert!(policy.selected_runtime.is_none());
    }
}
