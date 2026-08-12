use age::secrecy::SecretString;
use cargo_ai_core::{
    ConnectionDefinition, MemoryRecord, Sensitivity, Vault,
    transfer::{decrypt_pack, encrypt_pack},
};
use chrono::Utc;
use std::{collections::BTreeMap, fs, path::Path};
use uuid::Uuid;

fn directory_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in fs::read_dir(path).expect("read disposable vault directory") {
        let entry = entry.expect("read disposable vault entry");
        if entry.file_type().expect("read entry type").is_file() {
            bytes.extend(fs::read(entry.path()).expect("read disposable vault file"));
        }
    }
    bytes
}

#[test]
fn encrypted_pack_restores_profile_and_portable_content_on_a_clean_device() {
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("vault.sqlite3");
    let source = Vault::open_with_key(&source_path, [0x11; 32]).unwrap();
    let profile = source.create_profile("Clean Device Ada").unwrap();
    let connection = ConnectionDefinition {
        id: Uuid::new_v4(),
        name: "portable-research".into(),
        transport: "streamable_http".into(),
        command: None,
        args: vec![],
        url: Some("https://portable.example.test/mcp".into()),
        environment_keys: vec!["PORTABLE_REAUTH_REQUIRED".into()],
        metadata: BTreeMap::from([("source".into(), "clean-device-test".into())]),
    };
    source.upsert_connection(&connection).unwrap();
    let memories = vec![
        MemoryRecord {
            id: Uuid::new_v4(),
            title: "Working style".into(),
            body: "Prefer precise clean-device recovery evidence".into(),
            sensitivity: Sensitivity::Private,
            allowed_hosts: vec!["Codex".into(), "Claude Code".into()],
            created_at: Utc::now(),
        },
        MemoryRecord {
            id: Uuid::new_v4(),
            title: "Sensitive boundary".into(),
            body: "Never copy credentials into portable configuration".into(),
            sensitivity: Sensitivity::Sensitive,
            allowed_hosts: vec![],
            created_at: Utc::now(),
        },
    ];
    for memory in &memories {
        source.add_memory(memory).unwrap();
    }

    let pack = source.export_safe().unwrap();
    let passphrase = "clean-device-passphrase-marker-2026";
    let encrypted = encrypt_pack(&pack, SecretString::from(passphrase)).unwrap();
    drop(source);

    for plaintext in [
        profile.display_name.as_str(),
        memories[0].body.as_str(),
        memories[1].body.as_str(),
        "portable.example.test",
        passphrase,
    ] {
        assert!(!String::from_utf8_lossy(&encrypted).contains(plaintext));
    }

    let target_dir = tempfile::tempdir().unwrap();
    let target_path = target_dir.path().join("vault.sqlite3");
    let target_key = [0x22; 32];
    let target = Vault::open_with_key(&target_path, target_key).unwrap();
    assert!(target.profile().unwrap().is_none());
    let decrypted = decrypt_pack(&encrypted, SecretString::from(passphrase)).unwrap();
    let first = target.import_pack(&decrypted).unwrap();
    assert_eq!(first.connections_added, 1);
    assert_eq!(first.memory_added, 2);
    assert_eq!(target.profile().unwrap(), Some(profile.clone()));
    assert_eq!(target.connections().unwrap(), vec![connection.clone()]);
    assert_eq!(target.memory().unwrap(), memories);
    assert!(target.deployments().unwrap().is_empty());
    assert!(target.provider_grants().unwrap().is_empty());
    drop(target);

    let reopened = Vault::open_with_key(&target_path, target_key).unwrap();
    assert_eq!(reopened.profile().unwrap(), Some(profile));
    assert_eq!(reopened.connections().unwrap(), vec![connection]);
    assert_eq!(reopened.memory().unwrap(), memories);
    assert!(reopened.verify_receipt_chain().unwrap());
    let second = reopened.import_pack(&decrypted).unwrap();
    assert_eq!(second.connections_skipped, 1);
    assert_eq!(second.memory_skipped, 2);
    drop(reopened);

    let persisted = directory_bytes(target_dir.path());
    for plaintext in [
        "Clean Device Ada",
        "Prefer precise clean-device recovery evidence",
        "Never copy credentials into portable configuration",
        "portable.example.test",
        passphrase,
    ] {
        assert!(!String::from_utf8_lossy(&persisted).contains(plaintext));
    }

    let rejected_dir = tempfile::tempdir().unwrap();
    let rejected =
        Vault::open_with_key(rejected_dir.path().join("vault.sqlite3"), [0x33; 32]).unwrap();
    assert!(
        decrypt_pack(
            &encrypted,
            SecretString::from("wrong-clean-device-passphrase")
        )
        .is_err()
    );
    assert!(rejected.profile().unwrap().is_none());
    assert!(rejected.connections().unwrap().is_empty());
    assert!(rejected.memory().unwrap().is_empty());
}
