//! Testable Vanilla launch-plan construction.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
};

use tokio::process::Command;

use crate::{
    auth::MinecraftIdentity,
    download::CancellationToken,
    instance::Instance,
    java::{JavaManager, JavaRequirement, JavaRuntime},
    loaders::LoaderPlan,
    platform::Platform,
    Result,
};

use super::{
    arguments::{resolve_arguments, split_legacy_arguments, substitute},
    libraries::{cache_path, resolve_libraries},
    version::required_java_major,
    Classpath, LaunchOptions, MinecraftError, RuleContext, VersionMetadata,
};

/// Fully resolved command definition. It contains no shell command string.
#[derive(Clone)]
pub struct LaunchPlan {
    executable: PathBuf,
    java_runtime: JavaRuntime,
    jvm_args: Vec<OsString>,
    main_class: String,
    game_args: Vec<OsString>,
    working_directory: PathBuf,
    sensitive_values: Vec<String>,
}

impl fmt::Debug for LaunchPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchPlan")
            .field("command", &self.redacted_command())
            .field("working_directory", &self.working_directory)
            .finish()
    }
}

impl LaunchPlan {
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        executable: PathBuf,
        jvm_args: Vec<OsString>,
        main_class: String,
        game_args: Vec<OsString>,
        working_directory: PathBuf,
    ) -> Self {
        Self {
            executable: executable.clone(),
            java_runtime: JavaRuntime {
                executable: executable.clone(),
                major_version: 0,
                full_version: "test".into(),
                architecture: Platform::current().architecture,
                vendor: None,
                source: crate::java::JavaRuntimeSource::System,
            },
            jvm_args,
            main_class,
            game_args,
            working_directory,
            sensitive_values: Vec::new(),
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn java_runtime(&self) -> &JavaRuntime {
        &self.java_runtime
    }

    #[must_use]
    pub fn jvm_args(&self) -> &[OsString] {
        &self.jvm_args
    }

    #[must_use]
    pub fn main_class(&self) -> &str {
        &self.main_class
    }

    #[must_use]
    pub fn game_args(&self) -> &[OsString] {
        &self.game_args
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Returns a printable command with known credential values removed.
    #[must_use]
    pub fn redacted_command(&self) -> Vec<String> {
        std::iter::once(self.executable.display().to_string())
            .chain(self.jvm_args.iter().map(os_to_string))
            .chain(std::iter::once(self.main_class.clone()))
            .chain(self.game_args.iter().map(os_to_string))
            .map(|argument| redact(&argument, &self.sensitive_values))
            .collect()
    }

    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(&self.jvm_args)
            .arg(&self.main_class)
            .args(&self.game_args)
            .current_dir(&self.working_directory);
        command
    }

    pub(crate) fn sensitive_values(&self) -> &[String] {
        &self.sensitive_values
    }
}

pub(crate) async fn build_launch_plan(
    instance: &Instance,
    metadata: &VersionMetadata,
    loader: Option<&LoaderPlan>,
    cache_root: &Path,
    java_manager: &JavaManager,
    context: LaunchContext<'_>,
) -> Result<LaunchPlan> {
    let LaunchContext {
        identity,
        options,
        cancellation,
    } = context;
    if metadata.main_class.is_empty() || metadata.main_class.chars().any(char::is_control) {
        return Err(MinecraftError::LaunchPlan("invalid main class".into()).into());
    }
    let requirement = JavaRequirement::current(required_java_major(metadata))
        .with_loader_minimum(loader.and_then(|plan| plan.minimum_java_major));
    let java_runtime = java_manager
        .resolve_runtime(
            instance.spec().java().executable.as_deref(),
            requirement,
            cancellation,
        )
        .await?;
    let cache_root = normalize_path(tokio::fs::canonicalize(cache_root).await?);
    let instance_root = normalize_path(tokio::fs::canonicalize(instance.path()).await?);
    let mut feature_map = options.features.as_map();
    if options.resolution.is_some() {
        feature_map.insert("has_custom_resolution".into(), true);
    }
    let rules = RuleContext::current(feature_map);
    let libraries = resolve_libraries(&metadata.libraries, &rules)?;
    let mut classpath_entries = libraries
        .iter()
        .filter_map(|library| library.artifact.as_ref())
        .map(|artifact| cache_path(&cache_root, artifact))
        .collect::<Vec<_>>();
    if let Some(loader) = loader {
        classpath_entries.extend(
            loader
                .classpath_additions
                .iter()
                .map(|path| path.join_under(&cache_root)),
        );
    }
    let client = cache_root
        .join("versions")
        .join(&metadata.id)
        .join(format!("{}.jar", metadata.id));
    classpath_entries.push(client);
    let classpath = Classpath::new(classpath_entries);
    let platform = Platform::current();
    let natives = instance_root.join("runtime").join("natives");
    let assets = cache_root.join("assets");
    let virtual_assets = assets.join("virtual").join(&metadata.asset_index.id);
    let game_assets = if tokio::fs::try_exists(&virtual_assets).await? {
        virtual_assets
    } else {
        assets.clone()
    };
    let libraries_root = cache_root.join("libraries");
    let game_directory = instance_root.join(".minecraft");
    let access_token = identity
        .access_token()
        .map(|token| token.expose_secret().to_owned())
        .unwrap_or_else(|| "0".into());
    let sensitive_values = identity
        .access_token()
        .map(|token| vec![token.expose_secret().to_owned()])
        .unwrap_or_default();
    let classpath_value = path_value(classpath.render_for(platform.os).as_os_str())?;
    let mut variables = BTreeMap::from([
        ("natives_directory".into(), path_value(natives.as_os_str())?),
        ("launcher_name".into(), options.launcher_name.clone()),
        ("launcher_version".into(), options.launcher_version.clone()),
        ("classpath".into(), classpath_value),
        (
            "library_directory".into(),
            path_value(libraries_root.as_os_str())?,
        ),
        (
            "classpath_separator".into(),
            if cfg!(windows) {
                ";".into()
            } else {
                ":".into()
            },
        ),
        ("auth_player_name".into(), identity.username().to_owned()),
        // This value must match the cached client JAR filename. Forge uses it
        // in its ignore list to avoid loading both the base and transformed
        // Minecraft modules.
        ("version_name".into(), metadata.id.clone()),
        (
            "game_directory".into(),
            path_value(game_directory.as_os_str())?,
        ),
        ("assets_root".into(), path_value(assets.as_os_str())?),
        ("game_assets".into(), path_value(game_assets.as_os_str())?),
        ("assets_index_name".into(), metadata.asset_index.id.clone()),
        ("auth_uuid".into(), identity.uuid().to_owned()),
        ("auth_access_token".into(), access_token.clone()),
        ("auth_session".into(), access_token.clone()),
        ("clientid".into(), String::new()),
        (
            "auth_xuid".into(),
            identity.xuid().unwrap_or_default().to_owned(),
        ),
        ("user_type".into(), identity.user_type().into()),
        ("version_type".into(), metadata.kind.as_str().to_owned()),
        ("user_properties".into(), "{}".into()),
        ("profile_properties".into(), "{}".into()),
    ]);
    if let Some(resolution) = options.resolution {
        variables.insert("resolution_width".into(), resolution.width.to_string());
        variables.insert("resolution_height".into(), resolution.height.to_string());
    }

    let mut jvm_args = vec![
        format!("-Xms{}M", instance.spec().java().minimum_memory_mib),
        format!("-Xmx{}M", instance.spec().java().maximum_memory_mib),
    ];
    if let Some(arguments) = &metadata.arguments {
        jvm_args.extend(resolve_arguments(&arguments.jvm, &rules, &variables));
    } else {
        jvm_args.extend([
            format!("-Djava.library.path={}", variables["natives_directory"]),
            "-cp".into(),
            variables["classpath"].clone(),
        ]);
    }
    if let Some(loader) = loader {
        jvm_args.extend(resolve_arguments(&loader.jvm_arguments, &rules, &variables));
    }
    if let Some(logging) = metadata
        .logging
        .as_ref()
        .and_then(|logging| logging.client.as_ref())
    {
        let path = cache_root.join("log_configs").join(&logging.file.id);
        let argument = logging
            .argument
            .replace("${path}", &path_value(path.as_os_str())?);
        jvm_args.push(argument);
    }

    let mut game_args = if let Some(arguments) = &metadata.arguments {
        resolve_arguments(&arguments.game, &rules, &variables)
    } else if let Some(arguments) = &metadata.minecraft_arguments {
        split_legacy_arguments(arguments)
            .map_err(|error| MinecraftError::LaunchPlan(error.into()))?
            .into_iter()
            .map(|argument| substitute(&argument, &variables))
            .collect()
    } else {
        return Err(MinecraftError::LaunchPlan(
            "version contains neither modern nor legacy game arguments".into(),
        )
        .into());
    };
    if let Some(server) = instance.spec().server() {
        game_args.extend([
            "--server".into(),
            server.host.clone(),
            "--port".into(),
            server.port.to_string(),
        ]);
    }
    if let Some(loader) = loader {
        game_args.extend(resolve_arguments(
            &loader.game_arguments,
            &rules,
            &variables,
        ));
    }
    tokio::fs::create_dir_all(&game_directory).await?;
    Ok(LaunchPlan {
        executable: java_runtime.executable.clone(),
        java_runtime,
        jvm_args: jvm_args.into_iter().map(OsString::from).collect(),
        main_class: loader
            .and_then(|plan| plan.main_class.clone())
            .unwrap_or_else(|| metadata.main_class.clone()),
        game_args: game_args.into_iter().map(OsString::from).collect(),
        working_directory: game_directory,
        sensitive_values,
    })
}

pub(crate) struct LaunchContext<'a> {
    pub identity: &'a MinecraftIdentity,
    pub options: &'a LaunchOptions,
    pub cancellation: &'a CancellationToken,
}

fn path_value(path: &OsStr) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        MinecraftError::LaunchPlan("a launch path is not valid Unicode".into()).into()
    })
}

fn normalize_path(path: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return path;
    }
    let value = path.to_string_lossy();
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{path}"))
    } else if let Some(path) = value.strip_prefix(r"\\?\") {
        PathBuf::from(path)
    } else {
        path
    }
}

fn os_to_string(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn redact(value: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(value.to_owned(), |value, secret| {
            value.replace(secret, "[REDACTED]")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_plan_never_prints_token() {
        let plan = LaunchPlan {
            executable: PathBuf::from("java"),
            java_runtime: JavaRuntime {
                executable: PathBuf::from("java"),
                major_version: 21,
                full_version: "21.0.0".into(),
                architecture: Platform::current().architecture,
                vendor: None,
                source: crate::java::JavaRuntimeSource::System,
            },
            jvm_args: vec![OsString::from("-cp"), OsString::from("libs")],
            main_class: "Main".into(),
            game_args: vec![OsString::from("secret-token")],
            working_directory: PathBuf::from("game"),
            sensitive_values: vec!["secret-token".into()],
        };
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("secret-token"));
        assert_eq!(plan.command().as_std().get_program(), "java");
    }
}
