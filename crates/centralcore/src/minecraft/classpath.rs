//! Platform-aware, testable Minecraft classpath construction.

use std::{ffi::OsString, path::PathBuf};

use crate::platform::OperatingSystem;

/// Ordered classpath entries resolved for one launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classpath {
    entries: Vec<PathBuf>,
}

impl Classpath {
    #[must_use]
    pub fn new(entries: Vec<PathBuf>) -> Self {
        Self { entries }
    }

    #[must_use]
    pub fn entries(&self) -> &[PathBuf] {
        &self.entries
    }

    /// Renders with the target OS separator, independent of the test host.
    #[must_use]
    pub fn render_for(&self, os: OperatingSystem) -> OsString {
        let separator = if os == OperatingSystem::Windows {
            ";"
        } else {
            ":"
        };
        let mut rendered = OsString::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if index > 0 {
                rendered.push(separator);
            }
            rendered.push(entry.as_os_str());
        }
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_windows_and_unix_separators() {
        let classpath = Classpath::new(vec![
            PathBuf::from("first.jar"),
            PathBuf::from("second.jar"),
        ]);
        assert_eq!(
            classpath.render_for(OperatingSystem::Windows),
            "first.jar;second.jar"
        );
        assert_eq!(
            classpath.render_for(OperatingSystem::Linux),
            "first.jar:second.jar"
        );
    }
}
