use centralcore::{trust::PublicKeyFile, CentralCore, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let bytes = tokio::fs::read("./publisher.public.json").await?;
    let key: PublicKeyFile = serde_json::from_slice(&bytes)?;
    let trusted = core.trust().add_key_file(key).await?;
    println!("trusted publisher key {}", trusted.id);
    Ok(())
}
