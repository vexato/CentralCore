//! Bounded discovery and validation of system Java runtimes.

use std::{collections::HashSet, path::Path};

use tokio::process::Command;

use super::{java_candidates, Architecture, JavaInstallation, JavaSource, JavaVersion};
use crate::{
    events::{CoreEvent, EventBus},
    Error, Result,
};

#[derive(Debug, Clone)]
pub struct SystemJavaProvider {
    events: EventBus,
}

impl SystemJavaProvider {
    pub(super) fn new(events: EventBus) -> Self {
        Self { events }
    }

    /// Executes the candidate and derives version, vendor and architecture.
    pub async fn inspect(
        &self,
        executable: impl AsRef<Path>,
        source: JavaSource,
    ) -> Result<JavaInstallation> {
        let executable = executable.as_ref();
        let output = Command::new(executable)
            .args(["-XshowSettings:properties", "-version"])
            .output()
            .await?;
        if !output.status.success() {
            return Err(Error::Java(format!(
                "`{}` exited unsuccessfully while reporting its properties",
                executable.display()
            )));
        }
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let version = JavaVersion::parse(&combined)?;
        let architecture = property(&combined, "os.arch")
            .and_then(parse_architecture)
            .ok_or_else(|| Error::Java("Java did not report a supported architecture".into()))?;
        let vendor = property(&combined, "java.vendor").map(str::to_owned);
        Ok(JavaInstallation {
            executable: executable.to_path_buf(),
            version,
            architecture,
            vendor,
            source,
        })
    }

    /// Searches only bounded, conventional candidates (`JAVA_HOME` and PATH).
    pub async fn detect(&self) -> Result<Vec<JavaInstallation>> {
        self.events.emit(CoreEvent::JavaDetectionStarted);
        let mut installations = Vec::new();
        let mut seen = HashSet::new();
        for (candidate, source) in java_candidates() {
            let canonical = match tokio::fs::canonicalize(&candidate).await {
                Ok(path) => path,
                Err(_) => continue,
            };
            if !seen.insert(canonical.clone()) {
                continue;
            }
            match self.inspect(&canonical, source).await {
                Ok(runtime) => {
                    self.events.emit(CoreEvent::JavaRuntimeDetected {
                        executable: canonical.display().to_string(),
                        major_version: runtime.version.major,
                        source: "system".into(),
                    });
                    installations.push(runtime);
                }
                Err(error) => tracing::debug!(
                    path = %candidate.display(),
                    %error,
                    "ignored invalid Java candidate"
                ),
            }
        }
        Ok(installations)
    }
}

fn property<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        (key.trim() == name)
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn parse_architecture(value: &str) -> Option<Architecture> {
    match value.to_ascii_lowercase().as_str() {
        "x86" | "i386" | "i486" | "i586" | "i686" | "x32" => Some(Architecture::X86),
        "x86_64" | "amd64" | "x64" => Some(Architecture::X86_64),
        "aarch64" | "arm64" => Some(Architecture::Aarch64),
        "arm" | "arm32" => Some(Architecture::Arm),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vendor_architecture_aliases() {
        let output = "    java.vendor = Eclipse Adoptium\n    os.arch = amd64\n";
        assert_eq!(property(output, "java.vendor"), Some("Eclipse Adoptium"));
        assert_eq!(
            property(output, "os.arch").and_then(parse_architecture),
            Some(Architecture::X86_64)
        );
        assert_eq!(parse_architecture("arm64"), Some(Architecture::Aarch64));
    }
}
