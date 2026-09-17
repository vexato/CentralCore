use std::sync::Arc;

use async_trait::async_trait;
use centralcore::{
    download::CancellationToken,
    java::{
        JavaArchiveKind, JavaDistribution, JavaDistributionProvider, JavaDistributionRequest,
        JavaRequirement,
    },
    platform::OperatingSystem,
    CentralCore, Error, Result,
};
use url::Url;

struct CompanyMirror;

#[async_trait]
impl JavaDistributionProvider for CompanyMirror {
    fn id(&self) -> &str {
        "company-mirror"
    }

    async fn resolve(
        &self,
        request: JavaDistributionRequest,
        cancellation: &CancellationToken,
    ) -> Result<JavaDistribution> {
        if cancellation.is_cancelled() {
            return Err(centralcore::download::DownloadError::Cancelled.into());
        }
        let (platform, archive_kind, extension) = match request.operating_system {
            OperatingSystem::Windows => ("windows", JavaArchiveKind::Zip, "zip"),
            OperatingSystem::Linux => ("linux", JavaArchiveKind::TarGz, "tar.gz"),
            OperatingSystem::MacOs => ("macos", JavaArchiveKind::TarGz, "tar.gz"),
            _ => return Err(Error::Java("unsupported mirror platform".into())),
        };
        let version = format!("{}.0.0-company", request.requirement.major_version);
        Ok(JavaDistribution {
            provider: self.id().into(),
            vendor: "Example Company".into(),
            version: version.clone(),
            major_version: request.requirement.major_version,
            operating_system: request.operating_system,
            architecture: request.requirement.architecture,
            archive_url: Url::parse(&format!(
                "https://java.example.invalid/{platform}/{version}/runtime.{extension}"
            ))
            .map_err(|error| Error::Java(error.to_string()))?,
            archive_sha256: "00".repeat(32),
            archive_size: None,
            archive_kind,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let core = CentralCore::builder()
        .data_dir(".custom-java-provider-demo")
        .build()
        .await?;
    core.java()
        .register_distribution_provider(Arc::new(CompanyMirror))
        .await?;

    let providers = core.java().managed().provider_ids().await;
    assert!(providers
        .iter()
        .any(|provider| provider == "company-mirror"));
    let _request = JavaRequirement::current(21);
    println!("Registered Java providers: {}", providers.join(", "));
    Ok(())
}
