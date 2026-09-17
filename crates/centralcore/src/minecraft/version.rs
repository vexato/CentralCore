//! Java requirements derived from version metadata.

use super::VersionMetadata;

#[must_use]
pub(crate) fn required_java_major(metadata: &VersionMetadata) -> u16 {
    metadata
        .java_version
        .as_ref()
        .map(|requirement| requirement.major_version)
        .unwrap_or_else(|| legacy_java_requirement(&metadata.id))
}

fn legacy_java_requirement(version: &str) -> u16 {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|value| value.parse::<u16>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u16>().ok());
    let patch = parts
        .next()
        .and_then(|value| value.split('-').next())
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_default();
    match (major, minor, patch) {
        (Some(1), Some(minor), _) if minor >= 21 => 21,
        (Some(1), Some(20), patch) if patch >= 5 => 21,
        (Some(1), Some(minor), _) if minor >= 18 => 17,
        (Some(1), Some(17), _) => 16,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_legacy_versions_to_java_generations() {
        assert_eq!(legacy_java_requirement("1.12.2"), 8);
        assert_eq!(legacy_java_requirement("1.17.1"), 16);
        assert_eq!(legacy_java_requirement("1.18.2"), 17);
        assert_eq!(legacy_java_requirement("1.20.1"), 17);
        assert_eq!(legacy_java_requirement("1.20.6"), 21);
    }
}
