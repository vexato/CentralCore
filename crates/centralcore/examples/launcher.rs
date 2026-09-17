use centralcore::{
    auth::{AuthFlow, AuthRequest},
    minecraft::LaunchOptions,
    providers::{ProviderId, ProviderSource},
    CentralCore, Error, Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    let provider_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./provider.json".into());
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let mut events = core.events().subscribe_envelopes();
    let event_task = tokio::spawn(async move {
        while let Ok(envelope) = events.recv().await {
            println!("{}: {:?}", envelope.id(), envelope.event());
        }
    });

    let provider_id = ProviderId::new("demo")?;
    core.providers()
        .add(provider_id.clone(), ProviderSource::parse(provider_path)?)
        .await?;
    core.providers().sync(&provider_id).await?;
    let entry = core
        .providers()
        .instances(Some(&provider_id))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| Error::NotFound {
            kind: "provider instance",
            id: provider_id.to_string(),
        })?;

    let cancellation = core.downloads().cancellation_token();
    let installed = core.providers().install(&entry.id, &cancellation).await?;
    let update = core.providers().plan_update(&entry.id).await?;
    println!(
        "update {} -> {} ({} changed files)",
        update.from_revision(),
        update.to_revision(),
        update.downloads().len() + update.replacements().len()
    );

    let flow = core
        .auth()
        .begin(
            "offline",
            AuthRequest {
                account_hint: Some("Developer".into()),
                ..AuthRequest::default()
            },
            &cancellation,
        )
        .await?;
    let AuthFlow::Authenticated(session) = flow else {
        return Err(Error::Authentication {
            provider: "offline".into(),
            message: "unexpected interactive challenge".into(),
        });
    };
    let identity = core
        .auth()
        .identity_for_launch(&session.account_id, &cancellation)
        .await?;
    let launch = core
        .minecraft()
        .build_launch_plan(&installed.instance, &identity, &LaunchOptions::default())
        .await?;
    println!("launch: {:?}", launch.redacted_command());

    if std::env::var_os("CENTRALCORE_RUN").is_some() {
        let running = core
            .minecraft()
            .launch(&installed.instance, &identity, &LaunchOptions::default())
            .await?;
        println!("Minecraft PID: {}", running.pid());
    }
    event_task.abort();
    Ok(())
}
