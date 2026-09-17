//! Eclipse Temurin metadata provider backed by the Adoptium API v3.

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use super::{
    Architecture, JavaArchiveKind, JavaDistribution, JavaDistributionProvider,
    JavaDistributionRequest, OperatingSystem,
};
use crate::{
    download::{CancellationToken, DownloadManager},
    Error, Result,
};

const METADATA_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AdoptiumJavaProvider {
    downloads: DownloadManager,
    api_base: Url,
}

impl AdoptiumJavaProvider {
    pub(crate) fn new(downloads: DownloadManager) -> Self {
        Self {
            downloads,
            api_base: Url::parse("https://api.adoptium.net/v3/").expect("static Adoptium URL"),
        }
    }

    #[cfg(test)]
    fn with_base(downloads: DownloadManager, api_base: Url) -> Self {
        Self {
            downloads,
            api_base,
        }
    }

    fn metadata_url(&self, request: JavaDistributionRequest) -> Result<Url> {
        let os = adoptium_os(request.operating_system)?;
        let architecture = adoptium_arch(request.requirement.architecture)?;
        let mut url = self
            .api_base
            .join(&format!(
                "assets/latest/{}/hotspot",
                request.requirement.major_version
            ))
            .map_err(|_| Error::Java("invalid Adoptium metadata endpoint".into()))?;
        url.query_pairs_mut()
            .append_pair("architecture", architecture)
            .append_pair("image_type", "jre")
            .append_pair("os", os)
            .append_pair("vendor", "eclipse");
        Ok(url)
    }
}

#[async_trait]
impl JavaDistributionProvider for AdoptiumJavaProvider {
    fn id(&self) -> &str {
        "adoptium"
    }

    async fn resolve(
        &self,
        request: JavaDistributionRequest,
        cancellation: &CancellationToken,
    ) -> Result<JavaDistribution> {
        let url = self.metadata_url(request)?;
        let assets: Vec<AdoptiumAsset> = self
            .downloads
            .fetch_json(&url, None, None, METADATA_LIMIT, cancellation)
            .await?;
        let asset = assets.into_iter().next().ok_or_else(|| {
            Error::Java(format!(
                "Adoptium has no Java {} runtime for this platform",
                request.requirement.major_version
            ))
        })?;
        let version = asset
            .version
            .and_then(|version| version.semver)
            .unwrap_or(asset.release_name);
        let archive_kind = match request.operating_system {
            OperatingSystem::Windows => JavaArchiveKind::Zip,
            OperatingSystem::Linux | OperatingSystem::MacOs => JavaArchiveKind::TarGz,
            _ => return Err(Error::Java("unsupported operating system".into())),
        };
        Ok(JavaDistribution {
            provider: self.id().into(),
            vendor: "Eclipse Adoptium".into(),
            version,
            major_version: request.requirement.major_version,
            operating_system: request.operating_system,
            architecture: request.requirement.architecture,
            archive_url: asset.binary.package.link,
            archive_sha256: asset.binary.package.checksum,
            archive_size: Some(asset.binary.package.size),
            archive_kind,
        })
    }
}

fn adoptium_os(os: OperatingSystem) -> Result<&'static str> {
    match os {
        OperatingSystem::Windows => Ok("windows"),
        OperatingSystem::Linux => Ok("linux"),
        OperatingSystem::MacOs => Ok("mac"),
        _ => Err(Error::Java("unsupported operating system".into())),
    }
}

fn adoptium_arch(architecture: Architecture) -> Result<&'static str> {
    match architecture {
        Architecture::X86 => Ok("x86"),
        Architecture::X86_64 => Ok("x64"),
        Architecture::Aarch64 => Ok("aarch64"),
        Architecture::Arm => Ok("arm"),
        _ => Err(Error::Java("unsupported CPU architecture".into())),
    }
}

#[derive(Deserialize)]
struct AdoptiumAsset {
    binary: AdoptiumBinary,
    release_name: String,
    version: Option<AdoptiumVersion>,
}

#[derive(Deserialize)]
struct AdoptiumBinary {
    package: AdoptiumPackage,
}

#[derive(Deserialize)]
struct AdoptiumPackage {
    checksum: String,
    link: Url,
    size: u64,
}

#[derive(Deserialize)]
struct AdoptiumVersion {
    semver: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        download::DownloadConfig, events::EventBus, java::JavaRequirement, platform::Platform,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn maps_normalized_platform_values() {
        assert_eq!(adoptium_os(OperatingSystem::MacOs).expect("mac"), "mac");
        assert_eq!(adoptium_arch(Architecture::X86_64).expect("x64"), "x64");
        assert_eq!(
            adoptium_arch(Architecture::Aarch64).expect("arm64"),
            "aarch64"
        );
    }

    #[tokio::test]
    async fn resolves_official_metadata_into_a_verified_distribution() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let count = socket.read(&mut request).await.expect("request");
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.contains("/v3/assets/latest/21/hotspot?"));
            assert!(request.contains("image_type=jre"));
            let body = format!(
                r#"[{{"binary":{{"package":{{"checksum":"{}","link":"https://example.test/runtime.zip","size":42}}}},"release_name":"jdk-21.0.4+7","version":{{"semver":"21.0.4+7"}}}}]"#,
                "ab".repeat(32)
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("response");
        });
        let downloads = DownloadManager::new(
            DownloadConfig {
                allow_insecure_http: true,
                retries: 0,
                ..DownloadConfig::default()
            },
            EventBus::new(8),
        )
        .expect("downloads");
        let provider = AdoptiumJavaProvider::with_base(
            downloads,
            Url::parse(&format!("http://{address}/v3/")).expect("base"),
        );
        let distribution = provider
            .resolve(
                JavaDistributionRequest {
                    requirement: JavaRequirement::current(21),
                    operating_system: Platform::current().os,
                },
                &CancellationToken::default(),
            )
            .await
            .expect("distribution");
        server.await.expect("server");
        assert_eq!(distribution.provider, "adoptium");
        assert_eq!(distribution.major_version, 21);
        assert_eq!(distribution.archive_size, Some(42));
        assert_eq!(distribution.archive_sha256, "ab".repeat(32));
    }
}
