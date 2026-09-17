use centralcore::{providers::ProviderInstanceId, CentralCore, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let instance: ProviderInstanceId = "demo:survival".parse()?;
    let plan = core.providers().plan_update(&instance).await?;
    println!(
        "revision {} -> {}, {} downloads",
        plan.from_revision(),
        plan.to_revision(),
        plan.downloads().len()
    );
    let cancellation = core.downloads().cancellation_token();
    core.providers()
        .apply_update(plan, &cancellation, false)
        .await?;
    Ok(())
}
