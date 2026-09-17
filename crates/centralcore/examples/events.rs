use centralcore::{CentralCore, InstanceSpec, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder().data_dir("./data").build().await?;
    let mut events = core.events().subscribe_envelopes();
    let listener = tokio::spawn(async move {
        while let Ok(envelope) = events.recv().await {
            println!("event {}: {:?}", envelope.id(), envelope.event());
        }
    });
    core.instances()
        .create(InstanceSpec::vanilla("events", "Events", "1.21.1")?)
        .await?;
    listener.abort();
    Ok(())
}
