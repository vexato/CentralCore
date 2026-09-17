use std::{error::Error as StdError, future::Future, io, path::PathBuf};

use centralcore::{
    auth::{
        AuthChallenge, AuthFlow, AuthProviderConfig, AuthRequest, AuthResponse, AuthSession,
        MinecraftIdentity, SecretString,
    },
    config_path,
    errors::AuthError,
    loaders::{LoaderConfig, LoaderKind},
    minecraft::{InstallPhase, LaunchOptions, RepairOptions, VerifyOptions},
    providers::{ComponentId, ProviderId, ProviderSource},
    trust::{KeyId, KeyTransition, PublicKeyFile, SignaturePolicy},
    CachePolicy, CentralCore, CoreConfig, CoreEvent, InstanceSpec,
};
use clap::{Parser, Subcommand};
use serde_json::json;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "ccorp",
    version,
    about = "CLI for the CentralCore Minecraft engine"
)]
struct Cli {
    /// Emit machine-readable JSON or JSON Lines for progress.
    #[arg(long, global = true)]
    json: bool,

    /// CentralCore data directory.
    #[arg(long, global = true, default_value = ".centralcore")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect Java runtimes available on this machine.
    Java {
        #[command(subcommand)]
        command: JavaCommand,
    },
    /// Query official Minecraft metadata.
    Minecraft {
        #[command(subcommand)]
        command: MinecraftCommand,
    },
    /// Query supported mod-loader versions.
    Loader {
        #[command(subcommand)]
        command: LoaderCommand,
    },
    /// Manage isolated local instances.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    /// Inspect and maintain the shared Minecraft cache.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Configure and synchronize static instance providers.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Manage locally trusted provider-signing public keys.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Authenticate accounts and manage trusted auth providers.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// List registered providers and their capabilities.
    Providers,
    /// Run a provider's generic interactive challenge flow.
    Login { provider: String },
    /// Show account/session status without secrets.
    Status,
    /// List known accounts without secrets.
    Accounts,
    /// Refresh one account.
    Refresh { account: String },
    /// Log out and remove one account.
    Logout { account: String },
    /// Manage locally trusted configurable providers.
    Provider {
        #[command(subcommand)]
        command: AuthProviderCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuthProviderCommand {
    /// Trust and register an Azuriom or CentralCorp HTTP endpoint.
    Add {
        #[arg(value_parser = ["azuriom", "http", "microsoft"])]
        kind: String,
        id: String,
        /// Base URL for azuriom/http, public client ID for microsoft.
        value: String,
        /// Registered loopback callback required for microsoft.
        #[arg(long)]
        redirect_url: Option<String>,
        /// Explicit development-only opt-in for an HTTP loopback endpoint.
        #[arg(long)]
        allow_insecure_loopback: bool,
    },
    Remove {
        id: String,
    },
    Show {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum JavaCommand {
    /// Detect Java from JAVA_HOME and PATH.
    Detect,
    /// List installed managed runtimes.
    List,
    /// Query approved distribution providers for one Java major.
    Available {
        #[arg(long)]
        major: u16,
    },
    /// Download and transactionally install one managed runtime.
    Install { major: u16 },
    /// Verify one or every managed runtime.
    Verify { runtime: Option<String> },
    /// Reinstall a damaged runtime from the verified archive cache.
    Repair { runtime: String },
    /// Remove one managed runtime.
    Remove { runtime: String },
    /// Persist an explicit managed-runtime preference.
    Select { runtime: String },
}

#[derive(Debug, Subcommand)]
enum MinecraftCommand {
    /// List versions from Mojang's official manifest.
    Versions {
        /// Maximum number of newest versions to display.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum LoaderCommand {
    /// List exact loader versions compatible with a Minecraft version.
    Versions {
        #[arg(value_parser = ["fabric", "forge"])]
        loader: String,
        #[arg(long)]
        minecraft: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum InstanceCommand {
    /// List local instances.
    List,
    /// Create an isolated Vanilla, Fabric, or Forge instance.
    Create {
        id: String,
        /// Minecraft version. Preferred Phase 2 syntax.
        #[arg(long)]
        minecraft: Option<String>,
        /// Human-readable instance name; defaults to the identifier.
        #[arg(long)]
        name: Option<String>,
        /// Phase 1 positional name, retained for compatibility.
        legacy_name: Option<String>,
        /// Phase 1 positional Minecraft version, retained for compatibility.
        legacy_minecraft_version: Option<String>,
        /// Loader family. Omit for Vanilla.
        #[arg(long, value_parser = ["fabric", "forge"])]
        loader: Option<String>,
        /// Exact loader version; required with --loader.
        #[arg(long, requires = "loader")]
        loader_version: Option<String>,
    },
    /// Show one local instance.
    Show { id: String },
    /// Download and validate a complete Vanilla installation.
    Install {
        id: String,
        /// Require all Minecraft and provider artifacts to already exist in local caches.
        #[arg(long)]
        offline: bool,
    },
    /// Launch Vanilla and wait for it to exit.
    Launch {
        id: String,
        /// Offline player name used by the generic authentication contract.
        #[arg(long, conflicts_with = "account")]
        offline: Option<String>,
        /// Persisted account ID returned by `ccorp auth accounts`.
        #[arg(long, conflicts_with = "offline")]
        account: Option<String>,
        /// Leave Minecraft running after this CLI process exits.
        #[arg(long)]
        detach: bool,
    },
    /// Verify every managed file without modifying it.
    Verify {
        id: String,
        /// Always recompute cryptographic hashes.
        #[arg(long)]
        full: bool,
        /// Explicitly document that no network may be used.
        #[arg(long)]
        offline: bool,
    },
    /// Incrementally restore missing or corrupted managed files.
    Repair {
        id: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        full: bool,
        #[arg(long)]
        offline: bool,
    },
    /// Update a provider-backed instance to the latest synchronized revision.
    Update {
        id: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        offline: bool,
    },
    /// Inspect or change provider components.
    Component {
        #[command(subcommand)]
        command: ComponentCommand,
    },
    /// Show installation/process state.
    Status { id: String },
    /// Stop a running instance.
    Stop { id: String },
    /// Delete one local instance and all files below it.
    Delete { id: String },
}

#[derive(Debug, Subcommand)]
enum ComponentCommand {
    /// List required/optional components and effective state.
    List { instance: String },
    /// Enable one optional component and install its managed files.
    Enable {
        instance: String,
        component: String,
        #[arg(long)]
        offline: bool,
    },
    /// Disable one optional component and remove only its managed files.
    Disable { instance: String, component: String },
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Display cache disk usage by category.
    Status,
    /// Verify indexed cache objects.
    Verify {
        #[arg(long)]
        full: bool,
    },
    /// Remove only unreferenced or temporary cache files.
    Prune {
        #[arg(long)]
        dry_run: bool,
        /// Optional maximum cache size such as 5GB, 750MB, or bytes.
        #[arg(long, value_parser = parse_byte_size)]
        max_size: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    /// Register a local JSON file or remote HTTP(S) index.
    Add {
        id: String,
        source: String,
        /// Signature enforcement for this provider.
        #[arg(long, value_parser = ["required", "optional", "disabled"])]
        signature_policy: Option<String>,
        /// Expected fingerprint of a key already present in the trust store.
        #[arg(long, conflicts_with = "trust_key")]
        key: Option<String>,
        /// Explicitly trust this public-key file and bind the provider to it.
        #[arg(long, conflicts_with = "key")]
        trust_key: Option<PathBuf>,
    },
    /// List configured providers without contacting them.
    List,
    /// Show a provider registration and its last valid snapshot.
    Show { id: String },
    /// Atomically refresh a provider snapshot.
    Sync {
        id: String,
        /// Explicitly activate an older signed revision without lowering the high-water mark.
        #[arg(long)]
        allow_rollback: bool,
    },
    /// Remove only the provider registration; installed instances are retained.
    Remove { id: String },
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// List trusted and locally revoked public keys.
    List,
    /// Show one key by stable SHA-256 fingerprint.
    Show { key_id: String },
    /// Add an explicit public-key file; never reads private keys.
    Add { public_key_file: PathBuf },
    /// Locally revoke a key without deleting installed instances.
    Remove { key_id: String },
    /// Verify and apply an old-key-signed transition declaration.
    Rotate { transition_file: PathBuf },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;

    let cli = Cli::parse();
    let core = CentralCore::builder()
        .data_dir(&cli.data_dir)
        .build()
        .await?;

    match cli.command {
        Command::Java { command } => {
            run_java_command(&core, command, &cli.data_dir, cli.json).await?
        }
        Command::Minecraft {
            command: MinecraftCommand::Versions { limit },
        } => print_versions(&core, cli.json, limit).await?,
        Command::Loader {
            command:
                LoaderCommand::Versions {
                    loader,
                    minecraft,
                    limit,
                },
        } => print_loader_versions(&core, cli.json, &loader, &minecraft, limit).await?,
        Command::Instance {
            command: InstanceCommand::List,
        } => list_instances(&core, cli.json).await?,
        Command::Instance {
            command:
                InstanceCommand::Create {
                    id,
                    minecraft,
                    name,
                    legacy_name,
                    legacy_minecraft_version,
                    loader,
                    loader_version,
                },
        } => {
            let version = minecraft.or(legacy_minecraft_version).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provide --minecraft <version> (or the legacy positional version)",
                )
            })?;
            let name = name.or(legacy_name).unwrap_or_else(|| id.clone());
            let mut spec = InstanceSpec::vanilla(id, name, version)?;
            match (loader, loader_version) {
                (Some(loader), Some(version)) => {
                    spec = spec.with_loader(LoaderConfig::new(loader.parse()?, version)?)?;
                }
                (Some(_), None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--loader requires --loader-version <exact-version>",
                    )
                    .into());
                }
                (None, Some(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--loader-version requires --loader",
                    )
                    .into());
                }
                (None, None) => {}
            }
            let instance = core.instances().create(spec).await?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "id": instance.id(),
                        "name": instance.name(),
                        "path": instance.path(),
                    }))?
                );
            } else {
                println!(
                    "Created instance `{}` at {}.",
                    instance.id(),
                    instance.path().display()
                );
            }
        }
        Command::Instance {
            command: InstanceCommand::Show { id },
        } => {
            let instance = core.providers().resolve_local_instance(&id).await?;
            let requirement = core.minecraft().java_requirement(&instance).await.ok();
            let selected = if let Some(requirement) = requirement {
                core.java()
                    .resolve_installed_runtime(
                        instance.spec().java().executable.as_deref(),
                        requirement,
                    )
                    .await?
            } else {
                None
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "instance": instance.spec(),
                        "required_java": requirement,
                        "selected_java": selected,
                    }))?
                );
            } else {
                println!("{} ({})", instance.name(), instance.id());
                println!("Minecraft: {}", instance.spec().minecraft().version());
                println!("Directory: {}", instance.path().display());
                if let Some(requirement) = requirement {
                    println!("Required Java: {}", requirement.major_version);
                    if let Some(runtime) = selected {
                        println!(
                            "Selected Java: {:?} Java {} ({})",
                            runtime.source,
                            runtime.full_version,
                            runtime.executable.display()
                        );
                    } else {
                        println!("Selected Java: none installed");
                    }
                }
            }
        }
        Command::Instance {
            command: InstanceCommand::Install { id, offline },
        } => install_instance(&core, &id, offline, cli.json).await?,
        Command::Instance {
            command:
                InstanceCommand::Launch {
                    id,
                    offline,
                    account,
                    detach,
                },
        } => {
            launch_instance(
                &core,
                &id,
                offline.as_deref(),
                account.as_deref(),
                detach,
                cli.json,
            )
            .await?
        }
        Command::Instance {
            command: InstanceCommand::Verify { id, full, offline },
        } => verify_instance(&core, &id, full, offline, cli.json).await?,
        Command::Instance {
            command:
                InstanceCommand::Repair {
                    id,
                    dry_run,
                    full,
                    offline,
                },
        } => repair_instance(&core, &id, dry_run, full, offline, cli.json).await?,
        Command::Instance {
            command:
                InstanceCommand::Update {
                    id,
                    dry_run,
                    offline,
                },
        } => update_instance(&core, &id, dry_run, offline, cli.json).await?,
        Command::Instance {
            command: InstanceCommand::Component { command },
        } => component_command(&core, command, cli.json).await?,
        Command::Instance {
            command: InstanceCommand::Status { id },
        } => {
            if let Some(key) = core.providers().resolve_provider_reference(&id).await? {
                let entry = core
                    .providers()
                    .instances(Some(&key.provider_id))
                    .await?
                    .into_iter()
                    .find(|entry| entry.id == key)
                    .ok_or_else(|| io::Error::other("provider instance disappeared"))?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                } else {
                    println!(
                        "{}: {:?} (available revision {})",
                        id, entry.state, entry.revision
                    );
                }
                return Ok(());
            }
            let instance = core.providers().resolve_local_instance(&id).await?;
            let local_id = instance.id().clone();
            let status = core.minecraft().status(&local_id).await?;
            if cli.json {
                println!(
                    "{}",
                    json!({ "id": id, "local_instance_id": local_id, "status": status })
                );
            } else {
                println!("{}: {:?}", id, status);
            }
        }
        Command::Instance {
            command: InstanceCommand::Stop { id },
        } => {
            let instance = core.providers().resolve_local_instance(&id).await?;
            let local_id = instance.id().clone();
            let stopped = core.minecraft().stop(&local_id).await?;
            if cli.json {
                println!(
                    "{}",
                    json!({ "id": id, "local_instance_id": local_id, "stop_requested": stopped })
                );
            } else if stopped {
                println!("Stop requested for `{id}`.");
            } else {
                println!("Instance `{id}` is not running.");
            }
        }
        Command::Instance {
            command: InstanceCommand::Delete { id },
        } => {
            let instance = core.providers().resolve_local_instance(&id).await?;
            core.instances().delete(instance.id().to_string()).await?;
            if cli.json {
                println!("{}", json!({ "deleted": id }));
            } else {
                println!("Deleted instance `{id}`.");
            }
        }
        Command::Cache {
            command: CacheCommand::Status,
        } => cache_status(&core, cli.json).await?,
        Command::Cache {
            command: CacheCommand::Verify { full },
        } => cache_verify(&core, full, cli.json).await?,
        Command::Cache {
            command: CacheCommand::Prune { dry_run, max_size },
        } => cache_prune(&core, dry_run, max_size, cli.json).await?,
        Command::Provider { command } => provider_command(&core, command, cli.json).await?,
        Command::Trust { command } => trust_command(&core, command, cli.json).await?,
        Command::Auth { command } => auth_command(&core, command, cli.json).await?,
    }
    Ok(())
}

async fn auth_command(
    core: &CentralCore,
    command: AuthCommand,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    match command {
        AuthCommand::Providers => {
            let providers = core.auth().providers().await;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&providers)?);
            } else {
                for provider in providers {
                    println!("{}\t{:?}", provider.id, provider.capabilities);
                }
            }
        }
        AuthCommand::Login { provider } => {
            run_auth_flow(core, &provider, json_output).await?;
        }
        AuthCommand::Status | AuthCommand::Accounts => {
            let sessions = core.auth().sessions().await;
            let accounts = sessions
                .iter()
                .map(auth_session_summary)
                .collect::<Vec<_>>();
            if json_output {
                println!("{}", serde_json::to_string_pretty(&accounts)?);
            } else if accounts.is_empty() {
                println!("No authenticated accounts.");
            } else {
                for account in accounts {
                    println!(
                        "{}\t{}\t{}\t{}",
                        account["account_id"].as_str().unwrap_or_default(),
                        account["provider_id"].as_str().unwrap_or_default(),
                        account["username"].as_str().unwrap_or_default(),
                        account["minecraft_identity"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        AuthCommand::Refresh { account } => {
            let cancellation = core.downloads().cancellation_token();
            let provider_id = core.auth().session(&account).await?.provider_id;
            let session = await_auth_operation(
                &provider_id,
                &cancellation,
                core.auth().refresh(&account, &cancellation),
            )
            .await?;
            if json_output {
                println!(
                    "{}",
                    json!({"account_id":session.account_id,"provider_id":session.provider_id,"refreshed":true})
                );
            } else {
                println!("Refreshed account `{}`.", session.account_id);
            }
        }
        AuthCommand::Logout { account } => {
            let cancellation = core.downloads().cancellation_token();
            let provider_id = core.auth().session(&account).await?.provider_id;
            await_auth_operation(
                &provider_id,
                &cancellation,
                core.auth().logout(&account, &cancellation),
            )
            .await?;
            if json_output {
                println!("{}", json!({"account_id":account,"removed":true}));
            } else {
                println!("Logged out account `{account}`.");
            }
        }
        AuthCommand::Provider { command } => match command {
            AuthProviderCommand::Add {
                kind,
                id,
                value,
                redirect_url,
                allow_insecure_loopback,
            } => {
                let config = match kind.as_str() {
                    "azuriom" => AuthProviderConfig::Azuriom {
                        base_url: url::Url::parse(&value)?,
                        allow_insecure_loopback,
                    },
                    "http" => AuthProviderConfig::Http {
                        base_url: url::Url::parse(&value)?,
                        allow_insecure_loopback,
                    },
                    "microsoft" => AuthProviderConfig::Microsoft {
                        client_id: value,
                        redirect_url: url::Url::parse(redirect_url.as_deref().ok_or_else(
                            || {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "microsoft requires --redirect-url <loopback-url>",
                                )
                            },
                        )?)?,
                        tenant: "consumers".into(),
                    },
                    _ => unreachable!("clap validates auth provider kinds"),
                };
                core.auth().add_configured(id.clone(), config).await?;
                if json_output {
                    println!("{}", json!({"provider_id":id,"trusted":true}));
                } else {
                    println!(
                        "Trusted authentication provider `{id}`. Credentials may be sent to its configured endpoint."
                    );
                }
            }
            AuthProviderCommand::Remove { id } => {
                core.auth().remove_configured(&id).await?;
                if json_output {
                    println!("{}", json!({"provider_id":id,"removed":true}));
                } else {
                    println!("Removed trusted authentication provider `{id}`.");
                }
            }
            AuthProviderCommand::Show { id } => {
                let provider = core.auth().configured_provider(&id).await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&provider)?);
                } else {
                    println!("{}: {:?}", provider.id, provider.config);
                }
            }
        },
    }
    Ok(())
}

fn auth_session_summary(session: &AuthSession) -> serde_json::Value {
    json!({
        "account_id": session.account_id,
        "provider_id": session.provider_id,
        "provider_user_id": session.identity.provider_user_id,
        "username": session.identity.username,
        "expires_at": session.expires_at,
        "refreshable": session.refreshable,
        "minecraft_identity": match session.minecraft {
            MinecraftIdentity::Official(_) => "official",
            MinecraftIdentity::Offline(_) => "offline",
            _ => "unknown",
        }
    })
}

async fn run_auth_flow(
    core: &CentralCore,
    provider: &str,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let cancellation = core.downloads().cancellation_token();
    let mut flow = await_auth_operation(
        provider,
        &cancellation,
        core.auth()
            .begin(provider, AuthRequest::default(), &cancellation),
    )
    .await?;
    loop {
        flow = match flow {
            AuthFlow::Authenticated(session) => {
                if json_output {
                    println!(
                        "{}",
                        json!({
                            "authenticated":true,
                            "account_id":session.account_id,
                            "provider_id":session.provider_id,
                            "username":session.identity.username
                        })
                    );
                } else {
                    println!(
                        "Authenticated {} as `{}` (account `{}`).",
                        session.provider_id, session.identity.username, session.account_id
                    );
                }
                return Ok(());
            }
            AuthFlow::Challenge {
                flow_id, challenge, ..
            } => {
                let response = match challenge {
                    AuthChallenge::Credentials {
                        username_label,
                        password_label,
                        password_required,
                    } => {
                        let username = prompt_line(&format!("{username_label}: "))?;
                        let password = if password_required {
                            Some(SecretString::new(rpassword::prompt_password(format!(
                                "{password_label}: "
                            ))?))
                        } else {
                            None
                        };
                        AuthResponse::Credentials { username, password }
                    }
                    AuthChallenge::TwoFactorCode { message } => {
                        if let Some(message) = message {
                            eprintln!("{message}");
                        }
                        AuthResponse::TwoFactorCode {
                            code: SecretString::new(rpassword::prompt_password("Code: ")?),
                        }
                    }
                    AuthChallenge::Browser {
                        authorization_url,
                        callback_url,
                    } => {
                        eprintln!("Open:\n{authorization_url}");
                        eprintln!(
                            "After authentication, paste the complete callback URL ({callback_url})."
                        );
                        AuthResponse::BrowserCallback {
                            callback_url: url::Url::parse(&prompt_line("Callback URL: ")?)?,
                        }
                    }
                    AuthChallenge::DeviceCode {
                        verification_uri,
                        user_code,
                        expires_at,
                        poll_interval_seconds,
                    } => {
                        eprintln!(
                            "Open:\n{verification_uri}\n\nEnter code:\n{}\n\nWaiting for authentication...",
                            user_code.expose_secret()
                        );
                        if unix_now() >= expires_at {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "device code expired",
                            )
                            .into());
                        }
                        let sleep = tokio::time::sleep(std::time::Duration::from_secs(
                            poll_interval_seconds.max(1),
                        ));
                        tokio::pin!(sleep);
                        tokio::select! {
                            () = &mut sleep => {}
                            interrupt = tokio::signal::ctrl_c() => {
                                interrupt?;
                                cancellation.cancel();
                                core.auth().cancel_flow(&flow_id).await?;
                                return Err(AuthError::Cancelled {
                                    provider: provider.to_owned(),
                                }
                                .into());
                            }
                        }
                        AuthResponse::PollDeviceCode
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "unsupported authentication challenge",
                        )
                        .into())
                    }
                };
                await_auth_operation(
                    provider,
                    &cancellation,
                    core.auth().continue_flow(&flow_id, response, &cancellation),
                )
                .await?
            }
            _ => return Err(io::Error::other("unsupported authentication flow state").into()),
        };
    }
}

async fn await_auth_operation<T, F>(
    provider: &str,
    cancellation: &centralcore::download::CancellationToken,
    operation: F,
) -> Result<T, Box<dyn StdError + Send + Sync>>
where
    F: Future<Output = centralcore::Result<T>>,
{
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => Ok(result?),
        interrupt = tokio::signal::ctrl_c() => {
            interrupt?;
            cancellation.cancel();
            Err(AuthError::Cancelled {
                provider: provider.to_owned(),
            }
            .into())
        }
    }
}

fn prompt_line(prompt: &str) -> io::Result<String> {
    use std::io::Write as _;
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

async fn print_java(
    core: &CentralCore,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let installations = core.java().detect_installed_java().await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&installations)?);
    } else if installations.is_empty() {
        println!("No Java runtime detected.");
    } else {
        for java in installations {
            println!(
                "Java {} ({}) - {}",
                java.version.major,
                java.version.raw,
                java.executable.display()
            );
        }
    }
    Ok(())
}

async fn run_java_command(
    core: &CentralCore,
    command: JavaCommand,
    data_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    match command {
        JavaCommand::Detect => print_java(core, json_output).await?,
        JavaCommand::List => {
            let runtimes = core.java().managed().list().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&runtimes)?);
            } else if runtimes.is_empty() {
                println!("No managed Java runtime installed.");
            } else {
                for runtime in runtimes {
                    println!(
                        "{}: Java {} {} ({:?}) - {}",
                        runtime.id,
                        runtime.runtime.major_version,
                        runtime.runtime.full_version,
                        runtime.runtime.architecture,
                        runtime.runtime.executable.display()
                    );
                }
            }
        }
        JavaCommand::Available { major } => {
            let cancellation = core.downloads().cancellation_token();
            let available = core.java().managed().available(
                centralcore::java::JavaRequirement::current(major),
                &cancellation,
            );
            tokio::pin!(available);
            let distributions = tokio::select! {
                result = &mut available => result?,
                interrupt = tokio::signal::ctrl_c() => {
                    interrupt?;
                    cancellation.cancel();
                    let _ = available.await;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Java metadata lookup cancelled safely").into());
                }
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&distributions)?);
            } else {
                for distribution in distributions {
                    println!(
                        "{}: {} Java {} {} ({:?}/{:?})",
                        distribution.provider,
                        distribution.vendor,
                        distribution.major_version,
                        distribution.version,
                        distribution.operating_system,
                        distribution.architecture
                    );
                }
            }
        }
        JavaCommand::Install { major } => {
            let cancellation = core.downloads().cancellation_token();
            let install = core.java().managed().install(
                centralcore::java::JavaRequirement::current(major),
                &cancellation,
            );
            tokio::pin!(install);
            let runtime = tokio::select! {
                result = &mut install => result?,
                interrupt = tokio::signal::ctrl_c() => {
                    interrupt?;
                    cancellation.cancel();
                    let _ = install.await;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Java installation cancelled safely").into());
                }
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&runtime)?);
            } else {
                println!(
                    "Installed managed runtime `{}` at {}.",
                    runtime.id,
                    runtime.directory.display()
                );
            }
        }
        JavaCommand::Verify { runtime } => {
            let verified = if let Some(runtime) = runtime {
                vec![core.java().managed().verify(&runtime).await?]
            } else {
                core.java().managed().list().await?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&verified)?);
            } else {
                for runtime in verified {
                    println!("{}: valid", runtime.id);
                }
            }
        }
        JavaCommand::Repair { runtime } => {
            let cancellation = core.downloads().cancellation_token();
            let repair = core.java().managed().repair(&runtime, &cancellation);
            tokio::pin!(repair);
            let repaired = tokio::select! {
                result = &mut repair => result?,
                interrupt = tokio::signal::ctrl_c() => {
                    interrupt?;
                    cancellation.cancel();
                    let _ = repair.await;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Java repair cancelled safely").into());
                }
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&repaired)?);
            } else {
                println!("Repaired managed runtime `{}`.", repaired.id);
            }
        }
        JavaCommand::Remove { runtime } => {
            core.remove_java_runtime(&runtime).await?;
            let path = config_path(data_dir);
            let mut config = CoreConfig::load(&path).await?;
            if config.java.selected_runtime.as_deref() == Some(runtime.as_str()) {
                config.java.selected_runtime = None;
                config.save(&path).await?;
            }
            if json_output {
                println!("{}", json!({"removed":runtime}));
            } else {
                println!("Removed managed runtime `{runtime}`.");
            }
        }
        JavaCommand::Select { runtime } => {
            core.java().managed().verify(&runtime).await?;
            let path = config_path(data_dir);
            let mut config = CoreConfig::load(&path).await?;
            config.java.managed = true;
            config.java.prefer_managed_java = true;
            config.java.prefer_system_java = false;
            config.java.selected_runtime = Some(runtime.clone());
            config.save(path).await?;
            if json_output {
                println!("{}", json!({"selected":runtime}));
            } else {
                println!("Selected managed runtime `{runtime}`.");
            }
        }
    }
    Ok(())
}

async fn print_versions(
    core: &CentralCore,
    json_output: bool,
    limit: usize,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let manifest = core.minecraft().versions().await?;
    let versions = manifest
        .versions
        .into_iter()
        .take(limit)
        .collect::<Vec<_>>();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&versions)?);
    } else {
        for version in versions {
            println!("{}\t{}", version.id, version.kind.as_str());
        }
    }
    Ok(())
}

async fn print_loader_versions(
    core: &CentralCore,
    json_output: bool,
    loader: &str,
    minecraft: &str,
    limit: usize,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let kind: LoaderKind = loader.parse()?;
    let cancellation = core.downloads().cancellation_token();
    let versions = core
        .loaders()
        .versions(kind, minecraft, &cancellation)
        .await?
        .into_iter()
        .take(limit)
        .collect::<Vec<_>>();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&versions)?);
    } else {
        for version in versions {
            println!(
                "{}\t{}",
                version.version,
                if version.stable { "stable" } else { "unstable" }
            );
        }
    }
    Ok(())
}

async fn list_instances(
    core: &CentralCore,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let instances = core.instances().list().await?;
    let provider_instances = core.providers().instances(None).await?;
    let materialized = provider_instances
        .iter()
        .filter_map(|entry| entry.local_instance_id.clone())
        .collect::<std::collections::HashSet<_>>();
    if json_output {
        let mut values: Vec<_> = provider_instances
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.id,
                    "name": entry.name,
                    "minecraft_version": entry.minecraft_version,
                    "provider": entry.id.provider_id,
                    "revision": entry.revision,
                    "local_instance_id": entry.local_instance_id,
                    "state": entry.state,
                })
            })
            .collect();
        values.extend(
            instances
                .iter()
                .filter(|instance| !materialized.contains(instance.id()))
                .map(|instance| {
                    json!({
                        "id": instance.id(),
                        "name": instance.name(),
                        "minecraft_version": instance.spec().minecraft().version(),
                        "provider": "local",
                        "path": instance.path(),
                    })
                }),
        );
        println!("{}", serde_json::to_string_pretty(&values)?);
    } else if instances.is_empty() && provider_instances.is_empty() {
        println!("No local instances.");
    } else {
        for entry in provider_instances {
            println!(
                "{}\t{}\tMinecraft {}\t{:?}",
                entry.id, entry.name, entry.minecraft_version, entry.state
            );
        }
        for instance in instances
            .into_iter()
            .filter(|instance| !materialized.contains(instance.id()))
        {
            println!(
                "{}\t{}\tMinecraft {}\tLocal",
                instance.id(),
                instance.name(),
                instance.spec().minecraft().version()
            );
        }
    }
    Ok(())
}

async fn install_instance(
    core: &CentralCore,
    id: &str,
    offline: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let provider_key = core.providers().resolve_provider_reference(id).await?;
    let instance = match &provider_key {
        Some(key) => core.providers().materialize(key).await?,
        None => core.instances().get(id.to_owned()).await?,
    };
    let cancellation = core.downloads().cancellation_token();
    let mut receiver = core.events().subscribe();
    let observed_id = instance.id().to_string();
    let output = tokio::spawn(async move {
        while let Ok(event) = receiver.recv().await {
            if let CoreEvent::MinecraftInstallProgress {
                instance_id,
                progress,
            } = event
            {
                if instance_id != observed_id {
                    continue;
                }
                if json_output {
                    println!(
                        "{}",
                        json!({ "event": "install_progress", "instance_id": instance_id, "progress": progress })
                    );
                } else {
                    let phase = match progress.phase {
                        InstallPhase::Metadata => "metadata",
                        InstallPhase::Client => "client",
                        InstallPhase::Libraries => "libraries",
                        InstallPhase::Assets => "assets",
                        InstallPhase::Natives => "natives",
                        InstallPhase::Logging => "logging",
                        InstallPhase::Loader => "loader",
                        InstallPhase::Finalizing => "finalizing",
                    };
                    println!(
                        "[{phase}] {}/{} files, {} bytes",
                        progress.completed_files, progress.total_files, progress.downloaded_bytes
                    );
                }
            }
        }
    });
    let (plan, provider_files) = if let Some(key) = provider_key {
        let installation = async {
            if offline {
                core.providers().install_offline(&key, &cancellation).await
            } else {
                core.providers().install(&key, &cancellation).await
            }
        };
        tokio::pin!(installation);
        let outcome = tokio::select! {
            result = &mut installation => result?,
            interrupt = tokio::signal::ctrl_c() => {
                interrupt?;
                eprintln!("Cancelling installation...");
                cancellation.cancel();
                let result = installation.await;
                eprintln!("Installation cancelled safely.");
                result?
            }
        };
        (outcome.minecraft, outcome.provider_files)
    } else {
        let installation = async {
            if offline {
                core.minecraft()
                    .install_cached(&instance, &cancellation)
                    .await
            } else {
                core.minecraft().install(&instance, &cancellation).await
            }
        };
        tokio::pin!(installation);
        let plan = tokio::select! {
            result = &mut installation => result?,
            interrupt = tokio::signal::ctrl_c() => {
                interrupt?;
                eprintln!("Cancelling installation...");
                cancellation.cancel();
                let result = installation.await;
                eprintln!("Installation cancelled safely.");
                result?
            }
        };
        (plan, 0)
    };
    output.abort();
    if json_output {
        println!(
            "{}",
            json!({ "event": "install_completed", "instance_id": id, "local_instance_id": instance.id(), "version": plan.version().id, "provider_files":provider_files })
        );
    } else {
        println!(
            "Installed Minecraft {} for `{}` ({} Minecraft files, {} provider files).",
            plan.version().id,
            id,
            plan.downloads().len(),
            provider_files
        );
    }
    Ok(())
}

async fn launch_instance(
    core: &CentralCore,
    id: &str,
    offline: Option<&str>,
    account: Option<&str>,
    detach: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let instance = core.providers().resolve_local_instance(id).await?;
    let cancellation = core.downloads().cancellation_token();
    let (provider_id, identity) = if let Some(account) = account {
        let session = core.auth().session(account).await?;
        let provider_id = session.provider_id.clone();
        let identity = await_auth_operation(
            &provider_id,
            &cancellation,
            core.auth().identity_for_launch(account, &cancellation),
        )
        .await?;
        (provider_id, identity)
    } else {
        let username = offline.unwrap_or("Player");
        let flow = core
            .auth()
            .begin(
                "offline",
                AuthRequest {
                    account_hint: Some(username.to_owned()),
                    ..AuthRequest::default()
                },
                &cancellation,
            )
            .await?;
        let AuthFlow::Authenticated(session) = flow else {
            return Err(
                io::Error::other("offline authentication unexpectedly required input").into(),
            );
        };
        (session.provider_id, session.minecraft)
    };
    if !instance.spec().authentication().allows(&provider_id) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("authentication provider `{provider_id}` is not allowed by this instance"),
        )
        .into());
    }
    let launch_options = LaunchOptions::default();
    if detach {
        let launch = core.minecraft().launch_detached_with_cancellation(
            &instance,
            &identity,
            &launch_options,
            &cancellation,
        );
        tokio::pin!(launch);
        let running = tokio::select! {
            result = &mut launch => result?,
            interrupt = tokio::signal::ctrl_c() => {
                interrupt?;
                cancellation.cancel();
                let result = launch.await;
                match result {
                    Ok(running) => running,
                    Err(_) => return Err(io::Error::new(io::ErrorKind::Interrupted, "launch cancelled safely").into()),
                }
            }
        };
        if json_output {
            println!(
                "{}",
                json!({"event":"started", "pid":running.pid, "detached":true})
            );
        } else {
            println!("Minecraft started with PID {} (detached).", running.pid);
        }
        return Ok(());
    }
    let mut receiver = core.events().subscribe();
    let observed_id = instance.id().to_string();
    let logs = tokio::spawn(async move {
        while let Ok(event) = receiver.recv().await {
            match event {
                CoreEvent::MinecraftStdout { instance_id, line } if instance_id == observed_id => {
                    if json_output {
                        println!("{}", json!({"stream":"stdout", "line":line}));
                    } else {
                        println!("{line}");
                    }
                }
                CoreEvent::MinecraftStderr { instance_id, line } if instance_id == observed_id => {
                    if json_output {
                        println!("{}", json!({"stream":"stderr", "line":line}));
                    } else {
                        eprintln!("{line}");
                    }
                }
                _ => {}
            }
        }
    });
    let launch = core.minecraft().launch_with_cancellation(
        &instance,
        &identity,
        &launch_options,
        &cancellation,
    );
    tokio::pin!(launch);
    let running = tokio::select! {
        result = &mut launch => result?,
        interrupt = tokio::signal::ctrl_c() => {
            interrupt?;
            cancellation.cancel();
            let result = launch.await;
            match result {
                Ok(running) => running,
                Err(_) => {
                    logs.abort();
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "launch cancelled safely").into());
                }
            }
        }
    };
    if json_output {
        println!("{}", json!({"event":"started", "pid":running.pid()}));
    } else {
        println!("Minecraft started with PID {}.", running.pid());
    }
    let exit = running.wait().await?;
    logs.abort();
    if json_output {
        println!("{}", json!({"event":"stopped", "exit":exit}));
    } else {
        println!("Minecraft stopped with exit code {:?}.", exit.code);
    }
    if !exit.success {
        return Err(
            io::Error::other(format!("Minecraft exited unsuccessfully ({:?})", exit.code)).into(),
        );
    }
    Ok(())
}

async fn verify_instance(
    core: &CentralCore,
    id: &str,
    full: bool,
    offline: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let instance = core.providers().resolve_local_instance(id).await?;
    let report = core
        .minecraft()
        .verify(&instance, VerifyOptions { full })
        .await?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "operation":"instance_verify",
                "offline":offline,
                "report":report
            }))?
        );
    } else {
        println!("Verification for `{}`:", instance.id());
        println!("  valid:      {}", report.valid);
        println!("  missing:    {}", report.missing);
        println!("  corrupted:  {}", report.corrupted);
        println!("  unexpected: {}", report.unexpected);
        println!(
            "Instance is {}.",
            if report.is_healthy() {
                "healthy"
            } else {
                "damaged"
            }
        );
    }
    if report.is_healthy() {
        Ok(())
    } else {
        Err(io::Error::other("instance verification failed").into())
    }
}

async fn repair_instance(
    core: &CentralCore,
    id: &str,
    dry_run: bool,
    full: bool,
    offline: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let instance = core.providers().resolve_local_instance(id).await?;
    let options = RepairOptions {
        full_verification: full,
        offline,
    };
    if dry_run {
        let plan = core
            .minecraft()
            .resolve_repair_plan(&instance, options)
            .await?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "operation":"repair_plan",
                    "instance_id":plan.instance_id(),
                    "downloads":plan.downloads().iter().map(|item| json!({
                        "path":item.request.destination,
                        "previous_state":item.previous_state,
                        "kind":item.kind,
                        "bytes":item.request.expected_size
                    })).collect::<Vec<_>>(),
                    "copies":plan.copies().iter().map(|item| json!({
                        "source":item.source,
                        "destination":item.destination,
                        "previous_state":item.previous_state,
                        "kind":item.kind,
                        "bytes":item.expected_size
                    })).collect::<Vec<_>>(),
                    "extractions":plan.extractions(),
                    "removals":plan.removals(),
                    "total_download_bytes":plan.total_download_bytes(),
                    "dry_run":true
                }))?
            );
        } else {
            println!("Repair plan for `{}`", instance.id());
            println!("  downloads:   {}", plan.downloads().len());
            println!("  copies:      {}", plan.copies().len());
            println!("  extractions: {}", plan.extractions().len());
            println!("  removals:    {}", plan.removals().len());
            println!(
                "  download:    {}",
                format_bytes(plan.total_download_bytes().unwrap_or_default())
            );
            for download in plan.downloads() {
                println!(
                    "  {:?}: {}",
                    download.previous_state, download.request.destination
                );
            }
            println!("No changes applied.");
        }
        return Ok(());
    }

    let cancellation = core.downloads().cancellation_token();
    let repair = core.minecraft().repair(&instance, options, &cancellation);
    tokio::pin!(repair);
    let outcome = tokio::select! {
        result = &mut repair => result?,
        interrupt = tokio::signal::ctrl_c() => {
            interrupt?;
            eprintln!("Cancelling repair...");
            cancellation.cancel();
            let result = repair.await;
            eprintln!("Repair cancelled safely.");
            result?
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "operation":"instance_repair",
                "instance_id":instance.id(),
                "verification":outcome.verification,
                "metrics":outcome.metrics
            }))?
        );
    } else {
        println!("Verification successful. Instance repaired.");
        println!(
            "{} files downloaded ({}), {} files reused.",
            outcome.metrics.files_downloaded,
            format_bytes(outcome.metrics.bytes_downloaded),
            outcome.metrics.files_reused
        );
    }
    Ok(())
}

async fn cache_status(
    core: &CentralCore,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let status = core.cache().status().await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("CentralCore cache");
        println!("  Versions:  {}", format_bytes(status.versions.bytes));
        println!("  Libraries: {}", format_bytes(status.libraries.bytes));
        println!("  Assets:    {}", format_bytes(status.assets.bytes));
        println!("  Metadata:  {}", format_bytes(status.metadata.bytes));
        println!("  Temporary: {}", format_bytes(status.temporary.bytes));
        println!("  Other:     {}", format_bytes(status.other.bytes));
        println!("  Total:     {}", format_bytes(status.total_bytes));
    }
    Ok(())
}

async fn update_instance(
    core: &CentralCore,
    id: &str,
    dry_run: bool,
    offline: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let key = core
        .providers()
        .resolve_provider_reference(id)
        .await?
        .ok_or_else(|| io::Error::other("updates require a provider-backed instance"))?;
    let plan = if offline {
        core.providers().plan_update_offline(&key).await?
    } else {
        core.providers().plan_update(&key).await?
    };
    if dry_run {
        if json_output {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            println!("Update plan");
            println!("Instance: {}", plan.instance());
            println!(
                "Revision: {} -> {}",
                plan.from_revision(),
                plan.to_revision()
            );
            println!("Keep:       {} files", plan.kept_files().len());
            println!("Download:   {} files", plan.downloads().len());
            println!("Replace:    {} files", plan.replacements().len());
            println!("Remove:     {} files", plan.removals().len());
            println!("Optional:   {} changes", plan.optional_changes().len());
            if plan.base_game_changed() {
                println!("Base game:  changed ({} artifacts)", plan.base_downloads());
            }
            println!("Download size: {}", format_bytes(plan.download_size()));
            println!("No changes applied.");
        }
        return Ok(());
    }
    let cancellation = core.downloads().cancellation_token();
    let update = core.providers().apply_update(plan, &cancellation, offline);
    tokio::pin!(update);
    let report = tokio::select! {
        result = &mut update => result?,
        interrupt = tokio::signal::ctrl_c() => {
            interrupt?;
            cancellation.cancel();
            update.await?
        }
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Updated `{}` from revision {} to {}.",
            id, report.from_revision, report.to_revision
        );
        println!(
            "Kept {}, downloaded {}, replaced {}, removed {} files ({} transferred).",
            report.files_kept,
            report.files_downloaded,
            report.files_replaced,
            report.files_removed,
            format_bytes(report.bytes_downloaded)
        );
    }
    Ok(())
}

async fn component_command(
    core: &CentralCore,
    command: ComponentCommand,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    match command {
        ComponentCommand::List { instance } => {
            let key = core
                .providers()
                .resolve_provider_reference(&instance)
                .await?
                .ok_or_else(|| io::Error::other("components require a provider-backed instance"))?;
            let components = core.providers().components(&key).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&components)?);
            } else if components.is_empty() {
                println!("No components declared.");
            } else {
                for component in components {
                    println!(
                        "{}\t{}\t{:?}",
                        component.name,
                        if component.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        component.requirement
                    );
                }
            }
        }
        ComponentCommand::Enable {
            instance,
            component,
            offline,
        } => {
            change_component(core, &instance, &component, true, offline, json_output).await?;
        }
        ComponentCommand::Disable {
            instance,
            component,
        } => {
            change_component(core, &instance, &component, false, true, json_output).await?;
        }
    }
    Ok(())
}

async fn change_component(
    core: &CentralCore,
    instance: &str,
    component: &str,
    enabled: bool,
    offline: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let key = core
        .providers()
        .resolve_provider_reference(instance)
        .await?
        .ok_or_else(|| io::Error::other("components require a provider-backed instance"))?;
    let component = ComponentId::new(component)?;
    let cancellation = core.downloads().cancellation_token();
    let report = core
        .providers()
        .set_component_enabled(&key, &component, enabled, &cancellation, offline)
        .await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Component `{}` {} for `{}`.",
            component,
            if enabled { "enabled" } else { "disabled" },
            instance
        );
    }
    Ok(())
}

async fn cache_verify(
    core: &CentralCore,
    full: bool,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let report = core.cache().verify(full).await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Cache verification:");
        println!("  valid: {}", report.valid);
        println!("  missing: {}", report.missing);
        println!("  corrupted: {}", report.corrupted);
        println!("  unexpected: {}", report.unexpected);
    }
    if report.is_healthy() {
        Ok(())
    } else {
        Err(io::Error::other("cache verification failed").into())
    }
}

async fn cache_prune(
    core: &CentralCore,
    dry_run: bool,
    max_size: Option<u64>,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let report = core
        .cache()
        .prune(
            &CachePolicy {
                max_size,
                max_age: None,
            },
            dry_run,
        )
        .await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if dry_run {
        println!("Cache prune dry-run:");
        println!("  candidates: {}", report.candidates.len());
        println!(
            "  reclaimable: {}",
            format_bytes(report.candidates.iter().map(|item| item.bytes).sum())
        );
        println!("No changes applied.");
    } else {
        println!(
            "Removed {} files ({}); {} locked files skipped.",
            report.removed_files,
            format_bytes(report.removed_bytes),
            report.skipped_locked
        );
    }
    Ok(())
}

async fn provider_command(
    core: &CentralCore,
    command: ProviderCommand,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    match command {
        ProviderCommand::Add {
            id,
            source,
            signature_policy,
            key,
            trust_key,
        } => {
            let source = ProviderSource::parse(source)?;
            let signature_policy = match signature_policy.as_deref() {
                Some("required") => SignaturePolicy::Required,
                Some("optional") => SignaturePolicy::Optional,
                Some("disabled") => SignaturePolicy::Disabled,
                None if matches!(source, ProviderSource::Remote(_)) => SignaturePolicy::Required,
                None => SignaturePolicy::Optional,
                Some(_) => unreachable!("clap validates signature policy"),
            };
            let trusted_key_id = if let Some(path) = trust_key {
                let file: PublicKeyFile = serde_json::from_slice(&tokio::fs::read(path).await?)?;
                Some(core.trust().add_key_file(file).await?.id)
            } else {
                key.map(KeyId::parse).transpose()?
            };
            let registration = core
                .providers()
                .add_with_trust(
                    ProviderId::new(id)?,
                    source,
                    signature_policy,
                    trusted_key_id,
                )
                .await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&registration)?);
            } else {
                println!("Added provider `{}`.", registration.id);
            }
        }
        ProviderCommand::List => {
            let registrations = core.providers().list().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&registrations)?);
            } else if registrations.is_empty() {
                println!("No configured providers.");
            } else {
                for registration in registrations {
                    let snapshot = core.providers().snapshot(&registration.id).await.ok();
                    let status = snapshot
                        .as_ref()
                        .map(|snapshot| format!("{:?}", snapshot.verification().signature_status))
                        .unwrap_or_else(|| "Not synced".into());
                    println!(
                        "{}\t{}\t{}",
                        registration.id,
                        match &registration.source {
                            ProviderSource::Local(path) => path.display().to_string(),
                            ProviderSource::Remote(url) => url.to_string(),
                        },
                        status
                    );
                }
            }
        }
        ProviderCommand::Show { id } => {
            let id = ProviderId::new(id)?;
            let registration = core.providers().get(&id).await?;
            let snapshot = core.providers().snapshot(&id).await.ok();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "registration":registration,
                        "snapshot":snapshot
                    }))?
                );
            } else {
                println!("Provider `{}`", registration.id);
                println!("Source: {:?}", registration.source);
                println!("Signature policy: {:?}", registration.signature_policy);
                if let Some(key_id) = &registration.trusted_key_id {
                    println!("Expected key: {key_id}");
                }
                if let Some(snapshot) = snapshot {
                    println!("Name: {}", snapshot.provider().name);
                    println!("Instances: {}", snapshot.instances().len());
                    println!("Last sync: {}", snapshot.synced_unix_seconds());
                    println!("Signature: {:?}", snapshot.verification().signature_status);
                    if let Some(key_id) = &snapshot.verification().key_id {
                        println!("Signing key: {key_id}");
                    }
                    if let Some(revision) = snapshot.revision() {
                        println!("Revision: {revision}");
                    }
                } else {
                    println!("No valid snapshot. Run `ccorp provider sync {id}`.");
                }
            }
        }
        ProviderCommand::Sync { id, allow_rollback } => {
            let report = core
                .providers()
                .sync_with_options(
                    &ProviderId::new(id)?,
                    centralcore::providers::ProviderSyncOptions { allow_rollback },
                )
                .await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if report.not_modified {
                println!(
                    "Provider `{}` is unchanged ({} instances).",
                    report.provider_id, report.instances
                );
            } else {
                println!(
                    "Synchronized provider `{}`: {} valid instances.",
                    report.provider_id, report.instances
                );
            }
            if !json_output {
                println!("Signature: {:?}", report.signature_status);
                if let Some(key_id) = &report.key_id {
                    println!("Key:       {key_id}");
                }
                if let Some(revision) = report.revision {
                    println!("Revision:  {revision}");
                }
            }
        }
        ProviderCommand::Remove { id } => {
            let id = ProviderId::new(id)?;
            core.providers().remove(&id).await?;
            if json_output {
                println!("{}", json!({"removed":id}));
            } else {
                println!("Removed provider `{id}`; installed instances were retained.");
            }
        }
    }
    Ok(())
}

async fn trust_command(
    core: &CentralCore,
    command: TrustCommand,
    json_output: bool,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    match command {
        TrustCommand::List => {
            let keys = core.trust().list().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&keys)?);
            } else if keys.is_empty() {
                println!("No provider-signing keys are trusted.");
            } else {
                for key in keys {
                    println!(
                        "{}\t{}\t{}",
                        key.id,
                        if key.revoked { "revoked" } else { "trusted" },
                        key.label.as_deref().unwrap_or("")
                    );
                }
            }
        }
        TrustCommand::Show { key_id } => {
            let key = core.trust().show(&KeyId::parse(key_id)?).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                println!("Key:       {}", key.id);
                println!("Algorithm: {}", key.algorithm);
                println!(
                    "Status:    {}",
                    if key.revoked { "revoked" } else { "trusted" }
                );
                if let Some(label) = key.label {
                    println!("Label:     {label}");
                }
                println!("Public:    {}", key.public_key.to_base64());
            }
        }
        TrustCommand::Add { public_key_file } => {
            let file: PublicKeyFile =
                serde_json::from_slice(&tokio::fs::read(public_key_file).await?)?;
            let key = core.trust().add_key_file(file).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                println!("Trusted provider-signing key {}.", key.id);
            }
        }
        TrustCommand::Remove { key_id } => {
            let key = core.trust().remove(&KeyId::parse(key_id)?).await?;
            if json_output {
                println!("{}", json!({ "key_id": key.id, "revoked": true }));
            } else {
                println!("Revoked provider-signing key {}.", key.id);
            }
        }
        TrustCommand::Rotate { transition_file } => {
            let transition: KeyTransition =
                serde_json::from_slice(&tokio::fs::read(transition_file).await?)?;
            let key = core.trust().apply_transition(transition).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                println!("Trusted rotated provider-signing key {}.", key.id);
            }
        }
    }
    Ok(())
}

fn parse_byte_size(value: &str) -> Result<u64, String> {
    let normalized = value.trim().to_ascii_uppercase();
    let (number, multiplier) = [
        ("GIB", 1024_u64.pow(3)),
        ("GB", 1_000_u64.pow(3)),
        ("MIB", 1024_u64.pow(2)),
        ("MB", 1_000_u64.pow(2)),
        ("KIB", 1024_u64),
        ("KB", 1_000_u64),
        ("B", 1_u64),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        normalized
            .strip_suffix(suffix)
            .map(|number| (number.trim(), multiplier))
    })
    .unwrap_or((normalized.as_str(), 1));
    number
        .parse::<u64>()
        .map_err(|_| format!("invalid byte size `{value}`"))?
        .checked_mul(multiplier)
        .ok_or_else(|| format!("byte size `{value}` is too large"))
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
        ("B", 1),
    ];
    let (unit, size) = UNITS
        .into_iter()
        .find(|(_, size)| bytes >= *size)
        .unwrap_or(("B", 1));
    if size == 1 {
        format!("{bytes} B")
    } else {
        format!("{:.2} {unit}", bytes as f64 / size as f64)
    }
}

#[cfg(test)]
mod auth_output_tests {
    use super::*;
    use centralcore::auth::{AuthIdentity, OfflineMinecraftIdentity, ProviderSession};
    use std::collections::BTreeMap;

    #[test]
    fn account_json_contains_no_session_secret() {
        let session = AuthSession {
            account_id: "test-account".into(),
            provider_id: "test".into(),
            identity: AuthIdentity {
                provider_user_id: "42".into(),
                username: "Player_1".into(),
                metadata: BTreeMap::new(),
            },
            provider_session: ProviderSession {
                access_token: Some(SecretString::new("provider-access-secret")),
                refresh_token: Some(SecretString::new("provider-refresh-secret")),
                device_secret: Some(SecretString::new("device-secret")),
                metadata: BTreeMap::new(),
            },
            expires_at: Some(42),
            refreshable: true,
            minecraft: MinecraftIdentity::Offline(
                OfflineMinecraftIdentity::new("Player_1").expect("offline identity"),
            ),
        };
        let rendered = auth_session_summary(&session).to_string();
        for secret in [
            "provider-access-secret",
            "provider-refresh-secret",
            "device-secret",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
}
