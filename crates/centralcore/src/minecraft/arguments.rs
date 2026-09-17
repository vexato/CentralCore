//! Rule-aware argument expansion without shell command construction.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Argument, RuleContext};

/// Resolution optionally requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

/// Mojang feature flags used by conditional arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FeatureSet {
    pub is_demo_user: bool,
    pub has_custom_resolution: bool,
    pub has_quick_plays_support: bool,
    pub is_quick_play_singleplayer: bool,
    pub is_quick_play_multiplayer: bool,
    pub is_quick_play_realms: bool,
}

impl FeatureSet {
    pub(crate) fn as_map(&self) -> BTreeMap<String, bool> {
        BTreeMap::from([
            ("is_demo_user".into(), self.is_demo_user),
            ("has_custom_resolution".into(), self.has_custom_resolution),
            (
                "has_quick_plays_support".into(),
                self.has_quick_plays_support,
            ),
            (
                "is_quick_play_singleplayer".into(),
                self.is_quick_play_singleplayer,
            ),
            (
                "is_quick_play_multiplayer".into(),
                self.is_quick_play_multiplayer,
            ),
            ("is_quick_play_realms".into(), self.is_quick_play_realms),
        ])
    }
}

/// Caller-controlled, non-provider launch options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchOptions {
    pub resolution: Option<Resolution>,
    pub features: FeatureSet,
    pub launcher_name: String,
    pub launcher_version: String,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            resolution: None,
            features: FeatureSet::default(),
            launcher_name: "CentralCore".into(),
            launcher_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

pub(crate) fn resolve_arguments(
    arguments: &[Argument],
    rules: &RuleContext,
    variables: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut result = Vec::new();
    for argument in arguments {
        match argument {
            Argument::Plain(value) => result.push(substitute(value, variables)),
            Argument::Conditional {
                rules: argument_rules,
                value,
            } if rules.allows(argument_rules) => {
                result.extend(
                    value
                        .values()
                        .into_iter()
                        .map(|value| substitute(value, variables)),
                );
            }
            Argument::Conditional { .. } => {}
        }
    }
    result
}

pub(crate) fn substitute(value: &str, variables: &BTreeMap<String, String>) -> String {
    let mut result = value.to_owned();
    for (name, replacement) in variables {
        result = result.replace(&format!("${{{name}}}"), replacement);
    }
    result
}

pub(crate) fn split_legacy_arguments(
    value: &str,
) -> std::result::Result<Vec<String>, &'static str> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
        } else if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                arguments.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("unterminated escape or quote in legacy arguments");
    }
    if !current.is_empty() {
        arguments.push(current);
    }
    Ok(arguments)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::minecraft::{ArgumentValue, Rule, RuleAction};

    use super::*;

    #[test]
    fn substitutes_variables_and_conditional_arguments() {
        let arguments = vec![
            Argument::Plain("--username".into()),
            Argument::Plain("${auth_player_name}".into()),
            Argument::Conditional {
                rules: vec![Rule {
                    action: RuleAction::Allow,
                    os: None,
                    features: BTreeMap::from([("is_demo_user".into(), true)]),
                }],
                value: ArgumentValue::One("--demo".into()),
            },
        ];
        let rules = RuleContext::current(BTreeMap::from([("is_demo_user".into(), true)]));
        let resolved = resolve_arguments(
            &arguments,
            &rules,
            &BTreeMap::from([("auth_player_name".into(), "Steve".into())]),
        );
        assert_eq!(resolved, ["--username", "Steve", "--demo"]);
    }

    #[test]
    fn splits_quoted_legacy_arguments() {
        assert_eq!(
            split_legacy_arguments(r#"--username "Central Corp" --demo"#).expect("split"),
            ["--username", "Central Corp", "--demo"]
        );
    }
}
