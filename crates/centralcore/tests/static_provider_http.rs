use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use centralcore::{
    providers::{ProviderId, ProviderSource},
    trust::SignaturePolicy,
    CentralCore, CoreConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use url::Url;

struct MockProviderHttp {
    base: Url,
    fail_index: Arc<AtomicBool>,
    index_requests: Arc<AtomicUsize>,
    instance_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl MockProviderHttp {
    async fn start(oversized: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let fail_index = Arc::new(AtomicBool::new(false));
        let index_requests = Arc::new(AtomicUsize::new(0));
        let instance_requests = Arc::new(AtomicUsize::new(0));
        let task_fail = fail_index.clone();
        let task_index = index_requests.clone();
        let task_instance = instance_requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let fail = task_fail.clone();
                let index_count = task_index.clone();
                let instance_count = task_instance.clone();
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8192];
                    let Ok(read) = socket.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let has_index_etag = request
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case("if-none-match: \"index-v1\""));
                    let (status, headers, body) = match path {
                        "/provider.json" if fail.load(Ordering::SeqCst) => {
                            index_count.fetch_add(1, Ordering::SeqCst);
                            ("500 Internal Server Error", "", "failure".to_owned())
                        }
                        "/provider.json" if has_index_etag => {
                            index_count.fetch_add(1, Ordering::SeqCst);
                            ("304 Not Modified", "ETag: \"index-v1\"\r\n", String::new())
                        }
                        "/provider.json" => {
                            index_count.fetch_add(1, Ordering::SeqCst);
                            let body = if oversized {
                                "x".repeat(512)
                            } else {
                                serde_json::json!({
                                    "format_version":1,
                                    "provider":{"id":"http-fixture","name":"HTTP Fixture"},
                                    "instances":[{"id":"survival","manifest":"instances/survival.json"}]
                                })
                                .to_string()
                            };
                            ("200 OK", "ETag: \"index-v1\"\r\n", body)
                        }
                        "/instances/survival.json" => {
                            instance_count.fetch_add(1, Ordering::SeqCst);
                            (
                                "200 OK",
                                "ETag: \"instance-v1\"\r\nLast-Modified: Thu, 10 Sep 2026 12:00:00 GMT\r\n",
                                serde_json::json!({
                                    "format_version":1,
                                    "id":"survival",
                                    "name":"Survival",
                                    "revision":1,
                                    "minecraft":{"version":"1.20.4","loader":{"type":"vanilla"}},
                                    "files":[]
                                })
                                .to_string(),
                            )
                        }
                        _ => ("404 Not Found", "", "missing".to_owned()),
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            base: Url::parse(&format!("http://{address}/")).expect("base URL"),
            fail_index,
            index_requests,
            instance_requests,
            task,
        }
    }
}

impl Drop for MockProviderHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn test_core(data: &std::path::Path, max_index_size: u64) -> CentralCore {
    let mut config = CoreConfig::new(data);
    config.download.allow_insecure_http = true;
    config.download.allowed_hosts = vec!["127.0.0.1".into()];
    config.download.retries = 0;
    config.providers.allow_private_networks = true;
    config.providers.max_index_size = max_index_size;
    CentralCore::builder()
        .config(config)
        .build()
        .await
        .expect("core")
}

#[tokio::test]
async fn remote_sync_uses_etag_and_keeps_last_snapshot_after_failure() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let server = MockProviderHttp::start(false).await;
    let core = test_core(temporary.path(), 4096).await;
    let id = ProviderId::new("http-demo").expect("id");
    core.providers()
        .add_with_trust(
            id.clone(),
            ProviderSource::Remote(server.base.join("provider.json").expect("URL")),
            SignaturePolicy::Optional,
            None,
        )
        .await
        .expect("add");

    let first = core.providers().sync(&id).await.expect("first sync");
    assert!(!first.not_modified);
    let second = core.providers().sync(&id).await.expect("conditional sync");
    assert!(second.not_modified);
    assert_eq!(server.index_requests.load(Ordering::SeqCst), 2);
    assert_eq!(server.instance_requests.load(Ordering::SeqCst), 1);

    server.fail_index.store(true, Ordering::SeqCst);
    assert!(core.providers().sync(&id).await.is_err());
    let retained = core.providers().snapshot(&id).await.expect("snapshot");
    assert_eq!(retained.instances().len(), 1);
    assert_eq!(
        retained
            .instances()
            .values()
            .next()
            .expect("instance")
            .revision,
        1
    );
}

#[tokio::test]
async fn remote_provider_index_is_strictly_bounded() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let server = MockProviderHttp::start(true).await;
    let core = test_core(temporary.path(), 128).await;
    let id = ProviderId::new("oversized").expect("id");
    core.providers()
        .add_with_trust(
            id.clone(),
            ProviderSource::Remote(server.base.join("provider.json").expect("URL")),
            SignaturePolicy::Disabled,
            None,
        )
        .await
        .expect("add");
    assert!(core.providers().sync(&id).await.is_err());
    assert!(core.providers().snapshot(&id).await.is_err());
}
