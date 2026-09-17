use centralcore::{
    providers::{ProviderId, ProviderSource},
    CentralCore, Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let id = ProviderId::new("demo")?;
    core.providers()
        .add(id.clone(), ProviderSource::parse("./provider.json")?)
        .await?;
    let report = core.providers().sync(&id).await?;
    println!("synchronized {} instances", report.instances);
    Ok(())
}
