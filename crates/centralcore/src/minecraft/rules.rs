//! Centralized evaluation of Mojang rules.

use std::collections::BTreeMap;

use regex::Regex;

use crate::platform::{Architecture, OperatingSystem, Platform};

use super::{Rule, RuleAction};

/// Host and launcher features used when evaluating Mojang rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleContext {
    pub platform: Platform,
    pub os_version: String,
    pub features: BTreeMap<String, bool>,
}

impl RuleContext {
    #[must_use]
    pub fn current(features: BTreeMap<String, bool>) -> Self {
        Self {
            platform: Platform::current(),
            os_version: sysinfo::System::os_version().unwrap_or_default(),
            features,
        }
    }

    #[must_use]
    pub fn allows(&self, rules: &[Rule]) -> bool {
        if rules.is_empty() {
            return true;
        }
        let mut allowed = false;
        for rule in rules {
            if self.matches(rule) {
                allowed = rule.action == RuleAction::Allow;
            }
        }
        allowed
    }

    fn matches(&self, rule: &Rule) -> bool {
        if let Some(os) = &rule.os {
            if os
                .name
                .as_deref()
                .is_some_and(|name| name != os_name(self.platform.os))
            {
                return false;
            }
            if os
                .arch
                .as_deref()
                .is_some_and(|arch| !arch_matches(arch, self.platform.architecture))
            {
                return false;
            }
            if let Some(pattern) = &os.version {
                let Ok(regex) = Regex::new(pattern) else {
                    return false;
                };
                if !regex.is_match(&self.os_version) {
                    return false;
                }
            }
        }
        rule.features
            .iter()
            .all(|(name, expected)| self.features.get(name).copied().unwrap_or(false) == *expected)
    }
}

pub(crate) const fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Windows => "windows",
        OperatingSystem::Linux => "linux",
        OperatingSystem::MacOs => "osx",
        OperatingSystem::Other => "unknown",
    }
}

fn arch_matches(value: &str, architecture: Architecture) -> bool {
    match architecture {
        Architecture::X86 => matches!(value, "x86" | "i386" | "i686" | "32"),
        Architecture::X86_64 => matches!(value, "x86_64" | "amd64" | "64"),
        Architecture::Aarch64 => matches!(value, "aarch64" | "arm64"),
        Architecture::Arm => matches!(value, "arm" | "arm32"),
        Architecture::Other => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minecraft::manifest::RuleOs;

    #[test]
    fn evaluates_allow_disallow_and_features_in_order() {
        let context = RuleContext {
            platform: Platform {
                os: OperatingSystem::Linux,
                architecture: Architecture::X86_64,
            },
            os_version: "6.8".into(),
            features: BTreeMap::from([("is_demo_user".into(), true)]),
        };
        let rules = vec![
            Rule {
                action: RuleAction::Allow,
                os: Some(RuleOs {
                    name: Some("linux".into()),
                    arch: Some("x86_64".into()),
                    version: Some(r"^6\.".into()),
                }),
                features: BTreeMap::new(),
            },
            Rule {
                action: RuleAction::Disallow,
                os: None,
                features: BTreeMap::from([("is_demo_user".into(), false)]),
            },
        ];
        assert!(context.allows(&rules));
    }

    #[test]
    fn absent_feature_defaults_to_false() {
        let context = RuleContext {
            platform: Platform::current(),
            os_version: String::new(),
            features: BTreeMap::new(),
        };
        let rule = Rule {
            action: RuleAction::Allow,
            os: None,
            features: BTreeMap::from([("has_custom_resolution".into(), true)]),
        };
        assert!(!context.allows(&[rule]));
    }
}
