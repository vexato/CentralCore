use centralcore::{CentralCore, InstanceSpec, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder()
        .data_dir("./centralcore-data")
        .build()
        .await?;
    let instance = core
        .instances()
        .create(InstanceSpec::vanilla("example", "Example", "1.21.1")?)
        .await?;
    println!("{}: {}", instance.id(), instance.path().display());
    Ok(())
}
