use async_trait::async_trait;
use centralcore::{
    files::FileManifest,
    providers::{InstanceProvider, RemoteInstance, RemoteInstanceSummary},
    CentralCore, CoreEvent, InstanceId, InstanceSpec, Result,
};

struct MockProvider {
    instance: InstanceSpec,
}

#[async_trait]
impl InstanceProvider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    async fn list_instances(&self) -> Result<Vec<RemoteInstanceSummary>> {
        Ok(vec![RemoteInstanceSummary {
            id: self.instance.id().clone(),
            name: self.instance.name().to_owned(),
            description: Some("fixture".into()),
        }])
    }

    async fn get_instance(&self, id: &InstanceId) -> Result<RemoteInstance> {
        assert_eq!(id, self.instance.id());
        Ok(RemoteInstance {
            spec: self.instance.clone(),
            description: Some("fixture".into()),
        })
    }

    async fn get_manifest(&self, _id: &InstanceId) -> Result<FileManifest> {
        Ok(FileManifest {
            format_version: FileManifest::FORMAT_VERSION,
            files: Vec::new(),
        })
    }
}

#[tokio::test]
async fn core_emits_serializable_instance_events() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let core = CentralCore::builder()
        .data_dir(temporary.path())
        .build()
        .await
        .expect("core");
    let mut receiver = core.events().subscribe();

    core.instances()
        .create(InstanceSpec::vanilla("event-test", "Event Test", "1.21.1").expect("spec"))
        .await
        .expect("create");

    let event = receiver.recv().await.expect("event");
    assert_eq!(
        event,
        CoreEvent::InstanceCreated {
            instance_id: "event-test".into()
        }
    );
    assert!(serde_json::to_string(&event)
        .expect("serialize event")
        .contains("instance_created"));
}

#[tokio::test]
async fn provider_contract_works_with_an_in_memory_mock() {
    let provider: Box<dyn InstanceProvider> = Box::new(MockProvider {
        instance: InstanceSpec::vanilla("remote", "Remote", "1.20.6").expect("spec"),
    });

    let listed = provider.list_instances().await.expect("list");
    let remote = provider.get_instance(&listed[0].id).await.expect("get");
    let manifest = provider
        .get_manifest(remote.spec.id())
        .await
        .expect("manifest");

    assert_eq!(provider.id(), "mock");
    assert_eq!(remote.spec.name(), "Remote");
    manifest.validate().expect("valid manifest");
}
