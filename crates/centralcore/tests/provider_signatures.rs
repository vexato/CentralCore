use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use centralcore::{
    providers::{InstanceProvider, ProviderId, ProviderSource},
    trust::{
        provider_signing_payload, transition_signing_payload, KeyTransition, KeyTransitionPayload,
        PublicKey, PublicKeyFile, SignatureEnvelope, SignaturePolicy, SignatureStatus, TrustError,
        KEY_TRANSITION_VERSION,
    },
    CentralCore, Error,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest as _, Sha256};

async fn write_revision(root: &Path, provider_revision: u64, instance_revision: u64) {
    let instances = root.join("instances");
    tokio::fs::create_dir_all(&instances)
        .await
        .expect("instances");
    let manifest = serde_json::to_vec_pretty(&json!({
        "format_version": 1,
        "id": "survival",
        "name": "Survival",
        "description": null,
        "revision": instance_revision,
        "minecraft": { "version": "1.20.1", "loader": { "type": "vanilla" } },
        "files": []
    }))
    .expect("manifest JSON");
    tokio::fs::write(instances.join("survival.json"), &manifest)
        .await
        .expect("manifest");
    let manifest_hash = format!("{:x}", Sha256::digest(&manifest));
    let provider = serde_json::to_vec_pretty(&json!({
        "format_version": 1,
        "revision": provider_revision,
        "provider": { "id": "demo", "name": "Demo", "description": null },
        "instances": [{
            "id": "survival",
            "manifest": "instances/survival.json",
            "sha256": manifest_hash
        }]
    }))
    .expect("provider JSON");
    tokio::fs::write(root.join("provider.json"), provider)
        .await
        .expect("provider");
}

async fn sign_provider(root: &Path, signing: &SigningKey) {
    let path = root.join("provider.json");
    let document = tokio::fs::read(&path).await.expect("provider bytes");
    let public = PublicKey::from_bytes(signing.verifying_key().to_bytes());
    let signature = signing.sign(&provider_signing_payload(&document).expect("payload"));
    let envelope = SignatureEnvelope::ed25519(public.key_id(), signature.to_bytes());
    tokio::fs::write(
        root.join("provider.json.sig"),
        serde_json::to_vec_pretty(&envelope).expect("envelope"),
    )
    .await
    .expect("signature");
}

async fn configured_core(
    data: &Path,
    provider_root: &Path,
    signing: &SigningKey,
) -> (CentralCore, ProviderId) {
    let core = CentralCore::builder()
        .data_dir(data)
        .build()
        .await
        .expect("core");
    let public = PublicKey::from_bytes(signing.verifying_key().to_bytes());
    let trusted = core
        .trust()
        .add_key(public, Some("test key".into()))
        .await
        .expect("trust key");
    let id = ProviderId::new("demo").expect("provider ID");
    core.providers()
        .add_with_trust(
            id.clone(),
            ProviderSource::Local(provider_root.join("provider.json")),
            SignaturePolicy::Required,
            Some(trusted.id),
        )
        .await
        .expect("provider registration");
    (core, id)
}

#[tokio::test]
async fn signed_provider_sync_accepts_valid_root_and_child_hashes() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    write_revision(&provider, 1, 1).await;
    let signing = SigningKey::generate(&mut OsRng);
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;

    let report = core.providers().sync(&id).await.expect("signed sync");
    assert_eq!(report.signature_status, SignatureStatus::Verified);
    assert_eq!(report.revision, Some(1));
    assert_eq!(
        report.key_id,
        Some(PublicKey::from_bytes(signing.verifying_key().to_bytes()).key_id())
    );
    let snapshot = core.providers().snapshot(&id).await.expect("snapshot");
    assert_eq!(snapshot.revision(), Some(1));
    assert_eq!(
        snapshot.verification().signature_status,
        SignatureStatus::Verified
    );
}

#[tokio::test]
async fn invalid_signature_never_replaces_last_valid_snapshot() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 1");

    write_revision(&provider, 2, 2).await;
    sign_provider(&provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 2");

    write_revision(&provider, 3, 3).await;
    sign_provider(&provider, &signing).await;
    let path = provider.join("provider.json");
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.expect("provider bytes"))
            .expect("provider JSON");
    tampered["provider"]["name"] = json!("Tampered after signing");
    tokio::fs::write(
        &path,
        serde_json::to_vec_pretty(&tampered).expect("tampered JSON"),
    )
    .await
    .expect("tampered provider");
    let error = core
        .providers()
        .sync(&id)
        .await
        .expect_err("invalid signature");
    assert!(matches!(error, Error::Trust(TrustError::SignatureInvalid)));
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("old snapshot")
            .revision(),
        Some(2)
    );
}

#[tokio::test]
async fn signed_revision_replay_is_rejected_and_highest_snapshot_remains_active() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 1");
    write_revision(&provider, 2, 2).await;
    sign_provider(&provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 2");

    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let error = core.providers().sync(&id).await.expect_err("rollback");
    assert!(matches!(
        error,
        Error::Trust(TrustError::ManifestRollbackDetected {
            received: 1,
            highest: 2,
            ..
        })
    ));
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("snapshot")
            .revision(),
        Some(2)
    );
}

#[tokio::test]
async fn authorized_rotation_is_accepted_but_unrelated_key_is_rejected() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let key_a = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &key_a).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &key_a).await;
    core.providers().sync(&id).await.expect("key A");

    let key_b = SigningKey::generate(&mut OsRng);
    let payload = KeyTransitionPayload {
        transition_version: KEY_TRANSITION_VERSION,
        provider_id: "demo".into(),
        from_key_id: PublicKey::from_bytes(key_a.verifying_key().to_bytes()).key_id(),
        to_key: PublicKeyFile::new(
            PublicKey::from_bytes(key_b.verifying_key().to_bytes()),
            Some("B".into()),
        ),
        valid_from_revision: 2,
    };
    let signature = key_a.sign(&transition_signing_payload(&payload).expect("transition payload"));
    core.trust()
        .apply_transition(KeyTransition {
            payload,
            signature: BASE64.encode(signature.to_bytes()),
        })
        .await
        .expect("rotation");
    write_revision(&provider, 2, 2).await;
    sign_provider(&provider, &key_b).await;
    core.providers().sync(&id).await.expect("key B");

    let key_c = SigningKey::generate(&mut OsRng);
    core.trust()
        .add_key(
            PublicKey::from_bytes(key_c.verifying_key().to_bytes()),
            None,
        )
        .await
        .expect("trust unrelated C");
    write_revision(&provider, 3, 3).await;
    sign_provider(&provider, &key_c).await;
    let error = core
        .providers()
        .sync(&id)
        .await
        .expect_err("unauthorized C");
    assert!(matches!(
        error,
        Error::Trust(TrustError::SigningKeyMismatch { .. })
    ));
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("snapshot")
            .revision(),
        Some(2)
    );
}

#[tokio::test]
async fn required_policy_rejects_a_missing_signature() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    let error = core
        .providers()
        .sync(&id)
        .await
        .expect_err("missing signature");
    assert!(matches!(error, Error::Trust(TrustError::SignatureMissing)));
}

#[tokio::test]
async fn authenticated_child_tampering_preserves_the_previous_snapshot() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 1");

    write_revision(&provider, 2, 2).await;
    sign_provider(&provider, &signing).await;
    tokio::fs::write(
        provider.join("instances/survival.json"),
        br#"{"truncated":true}"#,
    )
    .await
    .expect("tampered child");
    let error = core
        .providers()
        .sync(&id)
        .await
        .expect_err("child mismatch");
    assert!(matches!(error, Error::Trust(TrustError::SignatureInvalid)));
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("snapshot")
            .revision(),
        Some(1)
    );
}

#[tokio::test]
async fn revoked_key_blocks_new_sync_without_destroying_cached_snapshot() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    core.providers().sync(&id).await.expect("revision 1");
    let key_id = PublicKey::from_bytes(signing.verifying_key().to_bytes()).key_id();
    core.trust().remove(&key_id).await.expect("revoke");
    let error = core.providers().sync(&id).await.expect_err("revoked key");
    assert!(matches!(
        error,
        Error::Trust(TrustError::UntrustedSigningKey(_))
    ));
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("cached snapshot")
            .revision(),
        Some(1)
    );
}

#[tokio::test]
async fn verified_snapshot_catalog_remains_available_offline() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    let signing = SigningKey::generate(&mut OsRng);
    write_revision(&provider, 1, 1).await;
    sign_provider(&provider, &signing).await;
    let (core, id) = configured_core(&temporary.path().join("data"), &provider, &signing).await;
    core.providers().sync(&id).await.expect("signed sync");
    tokio::fs::remove_dir_all(&provider)
        .await
        .expect("simulate provider outage");

    let static_provider = core
        .providers()
        .static_provider(&id)
        .await
        .expect("cached provider");
    assert_eq!(
        static_provider
            .list_instances()
            .await
            .expect("offline list")
            .len(),
        1
    );
    assert_eq!(
        core.providers()
            .snapshot(&id)
            .await
            .expect("offline snapshot")
            .verification()
            .signature_status,
        SignatureStatus::Verified
    );
}

#[tokio::test]
async fn explicit_legacy_policy_reports_unsigned_instead_of_trusted() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let provider = temporary.path().join("provider");
    write_revision(&provider, 1, 1).await;
    let core = CentralCore::builder()
        .data_dir(temporary.path().join("data"))
        .build()
        .await
        .expect("core");
    let id = ProviderId::new("demo").expect("ID");
    core.providers()
        .add_with_trust(
            id.clone(),
            ProviderSource::Local(provider.join("provider.json")),
            SignaturePolicy::Optional,
            None,
        )
        .await
        .expect("legacy registration");
    let report = core.providers().sync(&id).await.expect("legacy sync");
    assert_eq!(report.signature_status, SignatureStatus::Unsigned);
    assert!(report.key_id.is_none());
}
