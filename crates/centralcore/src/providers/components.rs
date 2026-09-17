//! Provider component selection, persistence, and deterministic resolution.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{instance::Instance, Error, Result};

use super::{ComponentId, ComponentRequirement, ProviderComponent, ProviderError};

const COMPONENT_SELECTION_FORMAT_VERSION: u32 = 1;

/// Local user choices. This document is intentionally separate from provider snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentSelections {
    pub format_version: u32,
    pub components: BTreeMap<ComponentId, bool>,
}

impl Default for ComponentSelections {
    fn default() -> Self {
        Self {
            format_version: COMPONENT_SELECTION_FORMAT_VERSION,
            components: BTreeMap::new(),
        }
    }
}

/// Resolved status suitable for a CLI or UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub id: ComponentId,
    pub name: String,
    pub description: Option<String>,
    pub requirement: ComponentRequirement,
    pub selected: bool,
    pub enabled: bool,
    pub enabled_by: Vec<ComponentId>,
}

/// Deterministic component set after dependencies and conflicts are validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedComponentSet {
    enabled: BTreeSet<ComponentId>,
    statuses: Vec<ComponentStatus>,
}

impl ResolvedComponentSet {
    #[must_use]
    pub fn is_enabled(&self, id: &ComponentId) -> bool {
        self.enabled.contains(id)
    }

    #[must_use]
    pub fn statuses(&self) -> &[ComponentStatus] {
        &self.statuses
    }
}

/// Applies defaults only to components which have never had a local choice.
pub(crate) fn initialize_selections(
    components: &[ProviderComponent],
    selections: &mut ComponentSelections,
) {
    for component in components {
        if component.requirement == ComponentRequirement::Optional {
            selections
                .components
                .entry(component.id.clone())
                .or_insert(component.default_enabled);
        }
    }
}

/// Resolves required components, explicit choices, transitive dependencies, and conflicts.
pub fn resolve_components(
    components: &[ProviderComponent],
    selections: &ComponentSelections,
) -> Result<ResolvedComponentSet> {
    let by_id = components
        .iter()
        .map(|component| (component.id.clone(), component))
        .collect::<BTreeMap<_, _>>();
    validate_dependency_graph(&by_id)?;
    let mut enabled = components
        .iter()
        .filter(|component| {
            component.requirement == ComponentRequirement::Required
                || selections
                    .components
                    .get(&component.id)
                    .copied()
                    .unwrap_or(component.default_enabled)
        })
        .map(|component| component.id.clone())
        .collect::<BTreeSet<_>>();
    let mut enabled_by = BTreeMap::<ComponentId, BTreeSet<ComponentId>>::new();
    let mut pending = enabled.iter().cloned().collect::<VecDeque<_>>();
    while let Some(id) = pending.pop_front() {
        let component = by_id[&id];
        for dependency in &component.requires {
            enabled_by
                .entry(dependency.clone())
                .or_default()
                .insert(id.clone());
            if enabled.insert(dependency.clone()) {
                pending.push_back(dependency.clone());
            }
        }
    }
    for id in &enabled {
        let component = by_id[id];
        if let Some(conflict) = component
            .conflicts
            .iter()
            .find(|conflict| enabled.contains(*conflict))
        {
            return Err(ProviderError::ComponentConflict {
                left: id.to_string(),
                right: conflict.to_string(),
            }
            .into());
        }
    }
    let statuses = components
        .iter()
        .map(|component| ComponentStatus {
            id: component.id.clone(),
            name: component.name.clone(),
            description: component.description.clone(),
            requirement: component.requirement,
            selected: component.requirement == ComponentRequirement::Required
                || selections
                    .components
                    .get(&component.id)
                    .copied()
                    .unwrap_or(component.default_enabled),
            enabled: enabled.contains(&component.id),
            enabled_by: enabled_by
                .remove(&component.id)
                .unwrap_or_default()
                .into_iter()
                .collect(),
        })
        .collect();
    Ok(ResolvedComponentSet { enabled, statuses })
}

fn validate_dependency_graph(by_id: &BTreeMap<ComponentId, &ProviderComponent>) -> Result<()> {
    let mut dependency_count = BTreeMap::<ComponentId, usize>::new();
    let mut dependents = BTreeMap::<ComponentId, Vec<ComponentId>>::new();
    for (id, component) in by_id {
        dependency_count.insert(id.clone(), component.requires.len());
        for dependency in &component.requires {
            if !by_id.contains_key(dependency) {
                return Err(ProviderError::InvalidComponentReference {
                    component: id.to_string(),
                    referenced: dependency.to_string(),
                }
                .into());
            }
            dependents
                .entry(dependency.clone())
                .or_default()
                .push(id.clone());
        }
    }
    let mut ready = dependency_count
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect::<VecDeque<_>>();
    let mut resolved = 0_usize;
    while let Some(id) = ready.pop_front() {
        resolved += 1;
        for dependent in dependents.get(&id).into_iter().flatten() {
            let count = dependency_count.get_mut(dependent).ok_or_else(|| {
                ProviderError::InvalidComponentReference {
                    component: dependent.to_string(),
                    referenced: id.to_string(),
                }
            })?;
            *count -= 1;
            if *count == 0 {
                ready.push_back(dependent.clone());
            }
        }
    }
    if resolved != by_id.len() {
        return Err(ProviderError::ComponentDependencyCycle {
            components: dependency_count
                .into_iter()
                .filter(|(_, count)| *count > 0)
                .map(|(id, _)| id.to_string())
                .collect(),
        }
        .into());
    }
    Ok(())
}

pub(crate) async fn load_selections(instance: &Instance) -> Result<ComponentSelections> {
    let path = instance.path().join("runtime").join("components.json");
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let document: ComponentSelections = serde_json::from_slice(&bytes)?;
            if document.format_version != COMPONENT_SELECTION_FORMAT_VERSION {
                return Err(Error::UnsupportedFormat {
                    kind: "component selections",
                    version: document.format_version,
                });
            }
            Ok(document)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(ComponentSelections::default())
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn write_selections(
    instance: &Instance,
    selections: &ComponentSelections,
) -> Result<()> {
    let runtime = instance.path().join("runtime");
    tokio::fs::create_dir_all(&runtime).await?;
    let destination = runtime.join("components.json");
    let temporary = runtime.join("components.json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(selections)?).await?;
    if tokio::fs::try_exists(&destination).await? {
        tokio::fs::remove_file(&destination).await?;
    }
    tokio::fs::rename(temporary, destination).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{ProviderFile, ProviderResource};
    use crate::{files::SafeRelativePath, providers::ComponentRequirement};
    use url::Url;

    fn component(
        id: &str,
        required: bool,
        default_enabled: bool,
        requires: &[&str],
        conflicts: &[&str],
    ) -> ProviderComponent {
        ProviderComponent {
            id: ComponentId::new(id).expect("id"),
            name: id.to_owned(),
            description: None,
            requirement: if required {
                ComponentRequirement::Required
            } else {
                ComponentRequirement::Optional
            },
            default_enabled,
            requires: requires
                .iter()
                .map(|id| ComponentId::new(*id).expect("dependency"))
                .collect(),
            conflicts: conflicts
                .iter()
                .map(|id| ComponentId::new(*id).expect("conflict"))
                .collect(),
            files: vec![ProviderFile {
                id: id.to_owned(),
                path: SafeRelativePath::new(format!("mods/{id}.jar")).expect("path"),
                source: ProviderResource::Remote(
                    Url::parse("https://example.invalid/file").expect("url"),
                ),
                size: 1,
                sha256: crate::files::FileHash::new(
                    crate::files::HashAlgorithm::Sha256,
                    "00".repeat(32),
                )
                .expect("hash"),
                required,
            }],
        }
    }

    #[test]
    fn defaults_apply_only_when_selection_is_absent() {
        let components = vec![component("sodium", false, true, &[], &[])];
        let mut selections = ComponentSelections::default();
        initialize_selections(&components, &mut selections);
        assert_eq!(selections.components.get(&components[0].id), Some(&true));
        selections
            .components
            .insert(components[0].id.clone(), false);
        initialize_selections(&components, &mut selections);
        assert_eq!(selections.components.get(&components[0].id), Some(&false));
    }

    #[test]
    fn dependency_is_enabled_transitively() {
        let components = vec![
            component("sodium", false, false, &[], &[]),
            component("iris", false, true, &["sodium"], &[]),
        ];
        let resolved =
            resolve_components(&components, &ComponentSelections::default()).expect("resolution");
        assert!(resolved.is_enabled(&ComponentId::new("sodium").expect("id")));
        assert!(resolved.is_enabled(&ComponentId::new("iris").expect("id")));
    }

    #[test]
    fn enabled_conflict_is_rejected() {
        let components = vec![
            component("alpha", false, true, &[], &["beta"]),
            component("beta", false, true, &[], &[]),
        ];
        assert!(resolve_components(&components, &ComponentSelections::default()).is_err());
    }

    #[test]
    fn dependency_cycle_is_a_structured_error() {
        let components = vec![
            component("alpha", false, true, &["beta"], &[]),
            component("beta", false, false, &["alpha"], &[]),
        ];
        let error = resolve_components(&components, &ComponentSelections::default())
            .expect_err("cycle must fail");
        assert!(matches!(
            error,
            Error::StaticProvider(ProviderError::ComponentDependencyCycle { .. })
        ));
    }

    #[test]
    fn ten_thousand_component_chain_resolves_without_recursion() {
        let components = (0..10_000)
            .map(|index| {
                let id = format!("component-{index}");
                let dependency = (index > 0).then(|| {
                    ComponentId::new(format!("component-{}", index - 1)).expect("dependency")
                });
                ProviderComponent {
                    id: ComponentId::new(id.clone()).expect("id"),
                    name: id,
                    description: None,
                    requirement: ComponentRequirement::Optional,
                    default_enabled: index == 9_999,
                    requires: dependency.into_iter().collect(),
                    conflicts: Vec::new(),
                    files: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        let resolved = resolve_components(&components, &ComponentSelections::default())
            .expect("large graph must resolve");
        assert_eq!(resolved.enabled.len(), 10_000);
    }
}
