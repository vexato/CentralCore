use centralcore::{CentralCore, InstanceSpec, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let instance = core
        .instances()
        .create(InstanceSpec::vanilla("vanilla", "Vanilla", "1.21.1")?)
        .await?;
    let cancellation = core.downloads().cancellation_token();
    let plan = core
        .minecraft()
        .resolve_install_plan(&instance, &cancellation)
        .await?;
    println!(
        "{} downloads, {:?} known bytes",
        plan.downloads().len(),
        plan.total_bytes()
    );
    // A host may inspect the immutable plan before calling `minecraft().install(...)`.
    Ok(())
}
