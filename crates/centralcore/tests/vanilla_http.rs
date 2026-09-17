use std::{
    collections::{HashMap, VecDeque},
    io::{Cursor, Write},
    sync::Arc,
    time::Duration,
};

use centralcore::{
    config::CoreConfig,
    download::{DownloadError, DownloadRequest},
    files::{FileHash, HashAlgorithm, SafeRelativePath},
    instance::InstanceStatus,
    minecraft::{RepairOptions, VerifyOptions},
    CentralCore, InstanceSpec,
};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use url::Url;

#[derive(Clone)]
struct Response {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
    declared_length: Option<usize>,
    truncate_at: Option<usize>,
    location: Option<String>,
    support_range: bool,
}

struct MockServer {
    base: Url,
    routes: Arc<Mutex<HashMap<String, VecDeque<Response>>>>,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl MockServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let routes = Arc::new(Mutex::new(HashMap::<String, VecDeque<Response>>::new()));
        let hits = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let route_state = routes.clone();
        let hit_state = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let routes = route_state.clone();
                let hits = hit_state.clone();
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8192];
                    let read = match socket.read(&mut request).await {
                        Ok(read) => read,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&request[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    *hits.lock().await.entry(path.clone()).or_default() += 1;
                    let response = {
                        let mut routes = routes.lock().await;
                        routes.get_mut(&path).and_then(|responses| {
                            if responses.len() > 1 {
                                responses.pop_front()
                            } else {
                                responses.front().cloned()
                            }
                        })
                    }
                    .unwrap_or(Response {
                        status: 404,
                        body: Vec::new(),
                        delay: Duration::ZERO,
                        declared_length: None,
                        truncate_at: None,
                        location: None,
                        support_range: false,
                    });
                    tokio::time::sleep(response.delay).await;
                    let requested_range = request.lines().find_map(|line| {
                        line.strip_prefix("Range: bytes=")
                            .or_else(|| line.strip_prefix("range: bytes="))
                            .and_then(|value| value.strip_suffix('-'))
                            .and_then(|value| value.parse::<usize>().ok())
                    });
                    let range_start = requested_range.filter(|_| response.support_range);
                    let status = if range_start.is_some() {
                        206
                    } else {
                        response.status
                    };
                    let body = range_start
                        .and_then(|start| response.body.get(start..))
                        .unwrap_or(&response.body);
                    let reason = if matches!(status, 200 | 206) {
                        "OK"
                    } else {
                        "ERROR"
                    };
                    let mut headers = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.declared_length.unwrap_or(body.len())
                    );
                    if let Some(start) = range_start {
                        headers.push_str(&format!(
                            "Content-Range: bytes {start}-{}/{}\r\n",
                            response.body.len().saturating_sub(1),
                            response.body.len()
                        ));
                    }
                    if let Some(location) = &response.location {
                        headers.push_str(&format!("Location: {location}\r\n"));
                    }
                    headers.push_str("\r\n");
                    let _ = socket.write_all(headers.as_bytes()).await;
                    let written = response.truncate_at.unwrap_or(body.len()).min(body.len());
                    let _ = socket.write_all(&body[..written]).await;
                });
            }
        });
        Self {
            base: Url::parse(&format!("http://{address}/")).expect("base URL"),
            routes,
            hits,
        }
    }

    async fn route(&self, path: &str, responses: Vec<Response>) {
        self.routes
            .lock()
            .await
            .insert(path.to_owned(), responses.into());
    }

    fn url(&self, path: &str) -> Url {
        self.base
            .join(path.trim_start_matches('/'))
            .expect("route URL")
    }

    async fn hits(&self, path: &str) -> usize {
        self.hits.lock().await.get(path).copied().unwrap_or(0)
    }
}

fn ok(body: impl Into<Vec<u8>>) -> Response {
    Response {
        status: 200,
        body: body.into(),
        delay: Duration::ZERO,
        declared_length: None,
        truncate_at: None,
        location: None,
        support_range: false,
    }
}

fn sha1(bytes: &[u8]) -> String {
    format!("{:x}", Sha1::digest(bytes))
}

fn native_archive() -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    writer
        .start_file(
            "centralcore-test.dll",
            zip::write::SimpleFileOptions::default(),
        )
        .expect("native entry");
    writer.write_all(b"native").expect("native bytes");
    writer.finish().expect("finish ZIP").into_inner()
}

async fn test_core(server: &MockServer, root: &std::path::Path) -> CentralCore {
    let mut config = CoreConfig::new(root);
    config.download.allow_insecure_http = true;
    config.download.retries = 1;
    config.download.timeout_seconds = 1;
    config.download.allowed_hosts = vec!["127.0.0.1".into()];
    config.minecraft.version_manifest_url = server.url("manifest.json");
    config.minecraft.asset_base_url = server.url("assets/");
    CentralCore::builder()
        .config(config)
        .build()
        .await
        .expect("core")
}

#[tokio::test]
async fn installs_client_libraries_assets_and_natives_from_mock_http() {
    let server = MockServer::start().await;
    let client = b"client".to_vec();
    let library = b"library".to_vec();
    let native = native_archive();
    let asset = b"asset".to_vec();
    let asset_hash = sha1(&asset);
    let asset_index = serde_json::to_vec(&serde_json::json!({
        "objects": {
            "minecraft/test.txt": {"hash": asset_hash, "size": asset.len()}
        }
    }))
    .expect("asset index");
    let version = serde_json::to_vec(&serde_json::json!({
        "id":"test-vanilla",
        "type":"release",
        "mainClass":"net.minecraft.client.main.Main",
        "assets":"test-assets",
        "assetIndex": {
            "id":"test-assets", "sha1":sha1(&asset_index), "size":asset_index.len(),
            "url":server.url("asset-index.json")
        },
        "downloads": {
            "client": {"sha1":sha1(&client), "size":client.len(), "url":server.url("client.jar")}
        },
        "libraries": [
            {"name":"org.example:regular:1.0", "downloads":{"artifact":{
                "path":"org/example/regular/1.0/regular-1.0.jar", "sha1":sha1(&library),
                "size":library.len(), "url":server.url("library.jar")
            }}},
            {"name":"org.example:native:1.0:natives-test", "downloads":{"artifact":{
                "path":"org/example/native/1.0/native-1.0-natives-test.jar", "sha1":sha1(&native),
                "size":native.len(), "url":server.url("native.jar")
            }}}
        ],
        "arguments":{"jvm":["-cp","${classpath}"],"game":["--username","${auth_player_name}"]},
        "javaVersion":{"majorVersion":21}
    }))
    .expect("version");
    let manifest = serde_json::to_vec(&serde_json::json!({
        "latest":{"release":"test-vanilla","snapshot":"test-vanilla"},
        "versions":[{
            "id":"test-vanilla", "type":"release", "url":server.url("version.json"),
            "time":"now", "releaseTime":"now", "sha1":sha1(&version)
        }]
    }))
    .expect("manifest");
    server.route("/manifest.json", vec![ok(manifest)]).await;
    server.route("/version.json", vec![ok(version)]).await;
    server
        .route("/asset-index.json", vec![ok(asset_index)])
        .await;
    server.route("/client.jar", vec![ok(client)]).await;
    server.route("/library.jar", vec![ok(library)]).await;
    server.route("/native.jar", vec![ok(native)]).await;
    server
        .route(
            &format!("/assets/{}/{}", &asset_hash[..2], asset_hash),
            vec![ok(asset)],
        )
        .await;

    let temporary = tempfile::tempdir().expect("tempdir");
    let core = test_core(&server, temporary.path()).await;
    let instance = core
        .instances()
        .create(InstanceSpec::vanilla("mock", "Mock", "test-vanilla").expect("spec"))
        .await
        .expect("instance");
    let plan = core
        .minecraft()
        .install(&instance, &core.downloads().cancellation_token())
        .await
        .expect("install");

    assert_eq!(plan.version().id, "test-vanilla");
    assert_eq!(
        core.minecraft()
            .status(instance.id())
            .await
            .expect("status"),
        InstanceStatus::Installed
    );
    assert!(temporary
        .path()
        .join("minecraft/versions/test-vanilla/test-vanilla.jar")
        .is_file());
    assert!(temporary
        .path()
        .join("minecraft/libraries/org/example/regular/1.0/regular-1.0.jar")
        .is_file());
    assert!(instance
        .path()
        .join("runtime/natives/centralcore-test.dll")
        .is_file());

    let healthy = core
        .minecraft()
        .verify(&instance, VerifyOptions { full: true })
        .await
        .expect("initial verification");
    assert!(healthy.is_healthy());

    let cases = [
        (
            temporary
                .path()
                .join("minecraft/versions/test-vanilla/test-vanilla.jar"),
            "/client.jar".to_owned(),
        ),
        (
            temporary
                .path()
                .join("minecraft/libraries/org/example/regular/1.0/regular-1.0.jar"),
            "/library.jar".to_owned(),
        ),
        (
            temporary.path().join(format!(
                "minecraft/assets/objects/{}/{}",
                &asset_hash[..2],
                asset_hash
            )),
            format!("/assets/{}/{}", &asset_hash[..2], asset_hash),
        ),
    ];
    for (path, route) in cases {
        let hits_before = server.hits(&route).await;
        tokio::fs::write(&path, b"corrupted")
            .await
            .expect("corrupt managed file");
        let damaged = core
            .minecraft()
            .verify(&instance, VerifyOptions { full: true })
            .await
            .expect("damaged verification");
        assert_eq!(damaged.corrupted, 1);
        let repair = core
            .minecraft()
            .repair(
                &instance,
                RepairOptions::default(),
                &core.downloads().cancellation_token(),
            )
            .await
            .expect("incremental repair");
        assert_eq!(repair.metrics.files_downloaded, 1);
        assert_eq!(server.hits(&route).await, hits_before + 1);
        assert!(repair.verification.is_healthy());
    }

    let native_path = instance.path().join("runtime/natives/centralcore-test.dll");
    tokio::fs::remove_file(&native_path)
        .await
        .expect("remove native");
    let native_plan = core
        .minecraft()
        .resolve_repair_plan(&instance, RepairOptions::default())
        .await
        .expect("native repair plan");
    assert_eq!(native_plan.downloads().len(), 0);
    assert_eq!(native_plan.extractions().len(), 1);
    let native_repair = core
        .minecraft()
        .repair(
            &instance,
            RepairOptions {
                offline: true,
                ..RepairOptions::default()
            },
            &core.downloads().cancellation_token(),
        )
        .await
        .expect("offline native repair");
    assert!(native_repair.verification.is_healthy());
    assert!(native_path.is_file());
}

#[tokio::test]
async fn download_manager_retries_status_and_rejects_integrity_failures_and_timeouts() {
    let server = MockServer::start().await;
    server
        .route(
            "/retry.bin",
            vec![
                Response {
                    status: 500,
                    body: Vec::new(),
                    delay: Duration::ZERO,
                    declared_length: None,
                    truncate_at: None,
                    location: None,
                    support_range: false,
                },
                ok(b"eventual".to_vec()),
            ],
        )
        .await;
    server.route("/bad.bin", vec![ok(b"wrong".to_vec())]).await;
    server
        .route(
            "/rate.bin",
            vec![
                Response {
                    status: 429,
                    body: Vec::new(),
                    delay: Duration::ZERO,
                    declared_length: None,
                    truncate_at: None,
                    location: None,
                    support_range: false,
                },
                ok(b"rate-ok".to_vec()),
            ],
        )
        .await;
    server
        .route(
            "/redirect.bin",
            vec![Response {
                status: 302,
                body: Vec::new(),
                delay: Duration::ZERO,
                declared_length: None,
                truncate_at: None,
                location: Some(server.url("redirect-target.bin").to_string()),
                support_range: false,
            }],
        )
        .await;
    server
        .route("/redirect-target.bin", vec![ok(b"redirected".to_vec())])
        .await;
    server
        .route(
            "/truncated.bin",
            vec![Response {
                status: 200,
                body: b"0123456789".to_vec(),
                delay: Duration::ZERO,
                declared_length: Some(10),
                truncate_at: Some(5),
                location: None,
                support_range: false,
            }],
        )
        .await;
    server
        .route(
            "/resume.bin",
            vec![Response {
                status: 200,
                body: b"resumable".to_vec(),
                delay: Duration::ZERO,
                declared_length: None,
                truncate_at: None,
                location: None,
                support_range: true,
            }],
        )
        .await;
    server
        .route(
            "/slow.bin",
            vec![Response {
                status: 200,
                body: b"slow".to_vec(),
                delay: Duration::from_millis(1_200),
                declared_length: None,
                truncate_at: None,
                location: None,
                support_range: false,
            }],
        )
        .await;
    let temporary = tempfile::tempdir().expect("tempdir");
    let core = test_core(&server, temporary.path()).await;
    let token = core.downloads().cancellation_token();
    let retry = DownloadRequest {
        id: "retry".into(),
        source: server.url("retry.bin"),
        destination: SafeRelativePath::new("retry.bin").expect("path"),
        expected_size: Some(8),
        expected_hash: None,
    };
    core.downloads()
        .download(temporary.path(), &retry, &token)
        .await
        .expect("retried download");
    assert_eq!(server.hits("/retry.bin").await, 2);

    let rate = DownloadRequest {
        id: "rate".into(),
        source: server.url("rate.bin"),
        destination: SafeRelativePath::new("rate.bin").expect("path"),
        expected_size: Some(7),
        expected_hash: None,
    };
    core.downloads()
        .download(temporary.path(), &rate, &token)
        .await
        .expect("429 retry");
    assert_eq!(server.hits("/rate.bin").await, 2);

    let redirect = DownloadRequest {
        id: "redirect".into(),
        source: server.url("redirect.bin"),
        destination: SafeRelativePath::new("redirect.bin").expect("path"),
        expected_size: Some(10),
        expected_hash: None,
    };
    core.downloads()
        .download(temporary.path(), &redirect, &token)
        .await
        .expect("redirect");

    let resume = DownloadRequest {
        id: "resume".into(),
        source: server.url("resume.bin"),
        destination: SafeRelativePath::new("resume.bin").expect("path"),
        expected_size: Some(9),
        expected_hash: Some(
            FileHash::new(HashAlgorithm::Sha1, sha1(b"resumable")).expect("resume hash"),
        ),
    };
    tokio::fs::write(temporary.path().join("resume.bin.part"), b"resu")
        .await
        .expect("partial");
    core.downloads()
        .download(temporary.path(), &resume, &token)
        .await
        .expect("resume");
    assert_eq!(
        tokio::fs::read(temporary.path().join("resume.bin"))
            .await
            .expect("resumed file"),
        b"resumable"
    );

    let truncated = DownloadRequest {
        id: "truncated".into(),
        source: server.url("truncated.bin"),
        destination: SafeRelativePath::new("truncated.bin").expect("path"),
        expected_size: Some(10),
        expected_hash: None,
    };
    assert!(core
        .downloads()
        .download(temporary.path(), &truncated, &token)
        .await
        .is_err());

    let bad = DownloadRequest {
        id: "bad".into(),
        source: server.url("bad.bin"),
        destination: SafeRelativePath::new("bad.bin").expect("path"),
        expected_size: Some(5),
        expected_hash: Some(FileHash::new(HashAlgorithm::Sha1, "a".repeat(40)).expect("hash")),
    };
    assert!(matches!(
        core.downloads()
            .download(temporary.path(), &bad, &token)
            .await,
        Err(centralcore::Error::Download(
            DownloadError::ChecksumMismatch { .. }
        ))
    ));

    let slow = core
        .downloads()
        .fetch_bytes(&server.url("slow.bin"), None, None, 32, &token)
        .await;
    assert!(slow.is_err());
}

#[tokio::test]
async fn concurrent_downloads_share_one_atomic_cache_writer() {
    let server = MockServer::start().await;
    let bytes = b"shared-cache-object".to_vec();
    server
        .route(
            "/shared.bin",
            vec![Response {
                status: 200,
                body: bytes.clone(),
                delay: Duration::from_millis(100),
                declared_length: None,
                truncate_at: None,
                location: None,
                support_range: false,
            }],
        )
        .await;
    let temporary = tempfile::tempdir().expect("tempdir");
    let core = test_core(&server, temporary.path()).await;
    let request = DownloadRequest {
        id: "shared".into(),
        source: server.url("shared.bin"),
        destination: SafeRelativePath::new("assets/shared.bin").expect("path"),
        expected_size: Some(bytes.len() as u64),
        expected_hash: Some(
            FileHash::new(HashAlgorithm::Sha1, sha1(&bytes)).expect("expected hash"),
        ),
    };
    let left_token = core.downloads().cancellation_token();
    let right_token = core.downloads().cancellation_token();
    let cache = core.minecraft().cache_root();
    let (left, right) = tokio::join!(
        core.downloads().download(cache, &request, &left_token),
        core.downloads().download(cache, &request, &right_token),
    );
    let left = left.expect("left download");
    let right = right.expect("right download");
    assert_ne!(left.reused, right.reused);
    assert_eq!(server.hits("/shared.bin").await, 1);
    assert_eq!(
        tokio::fs::read(request.destination.join_under(cache))
            .await
            .expect("cached object"),
        bytes
    );
}

#[tokio::test]
async fn cancelled_install_is_recoverable_and_never_installed() {
    let server = MockServer::start().await;
    let temporary = tempfile::tempdir().expect("tempdir");
    let core = test_core(&server, temporary.path()).await;
    let instance = core
        .instances()
        .create(InstanceSpec::vanilla("cancelled", "Cancelled", "test").expect("spec"))
        .await
        .expect("instance");
    let cancellation = core.downloads().cancellation_token();
    cancellation.cancel();
    assert!(core
        .minecraft()
        .install(&instance, &cancellation)
        .await
        .is_err());
    assert_eq!(
        core.instances().status("cancelled").await.expect("status"),
        InstanceStatus::Recoverable
    );
    drop(core);
    let restarted = test_core(&server, temporary.path()).await;
    assert_eq!(
        restarted
            .instances()
            .status("cancelled")
            .await
            .expect("restarted status"),
        InstanceStatus::Recoverable
    );
}
