use crate::{
    AuditReceipt, ConnectionDefinition, LocalProfile, ManagedDeployment, MemoryRecord,
    PackImportResult, PortablePack,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use chrono::Utc;
use directories::ProjectDirs;
#[cfg(test)]
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "ai.cargo.desktop";
const ENVELOPE_VERSION: u8 = 1;

pub struct Vault {
    path: PathBuf,
    db: Connection,
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("ai", "Cargo", "Cargo")
            .context("cannot resolve application data directory")?;
        Ok(dirs.data_local_dir().join("vault.sqlite3"))
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let key = Self::load_or_create_key(&path)?;
        Self::open_with_key(path, key)
    }

    pub fn open_with_key(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() && fs::symlink_metadata(&path)?.file_type().is_symlink() {
            bail!("refusing a symlinked vault database");
        }
        if let Some(parent) = path.parent() {
            let existed = parent.exists();
            fs::create_dir_all(parent)?;
            if !existed {
                set_private_directory(parent)?;
            }
        }
        let db = Connection::open(&path)?;
        set_private_file(&path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        let vault = Self {
            path,
            db,
            key: Zeroizing::new(key),
        };
        vault.migrate()?;
        vault.encrypt_legacy_rows()?;
        vault.harden_database_files()?;
        Ok(vault)
    }

    fn keyring_label(path: &Path) -> String {
        format!(
            "vault-{:x}",
            Sha256::digest(path.to_string_lossy().as_bytes())
        )
    }

    fn load_or_create_key(path: &Path) -> Result<[u8; 32]> {
        let label = Self::keyring_label(path);
        let entry = keyring::Entry::new(KEYRING_SERVICE, &label)?;
        match entry.get_password() {
            Ok(encoded) => {
                let decoded = STANDARD_NO_PAD
                    .decode(encoded)
                    .context("invalid keychain vault key")?;
                decoded
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid keychain vault key length"))
            }
            Err(keyring::Error::NoEntry) => {
                if path.exists() && fs::symlink_metadata(path)?.len() > 0 {
                    bail!(
                        "the vault database exists but its OS keychain key is missing; refusing to replace the key"
                    );
                }
                let key: [u8; 32] = rand::random();
                entry.set_password(&STANDARD_NO_PAD.encode(key))?;
                Ok(key)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn harden_database_files(&self) -> Result<()> {
        set_private_file(&self.path)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", self.path.display()));
            if sidecar.exists() {
                set_private_file(&sidecar)?;
            }
        }
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        self.db.execute_batch(
            r#"
          CREATE TABLE IF NOT EXISTS profile (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS memory (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS deployments (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        "#,
        )?;
        Ok(())
    }

    fn encrypt_legacy_rows(&self) -> Result<()> {
        for table in [
            "profile",
            "connections",
            "memory",
            "receipts",
            "deployments",
        ] {
            let query = format!("SELECT id, document FROM {table} WHERE typeof(document)='text'");
            let mut statement = self.db.prepare(&query)?;
            let rows: Vec<(String, String)> = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);
            for (id, plain) in rows {
                let encrypted = self.seal(table, &id, plain.as_bytes())?;
                self.db.execute(
                    &format!("UPDATE {table} SET document=?1 WHERE id=?2"),
                    params![encrypted, id],
                )?;
            }
        }
        Ok(())
    }

    fn seal(&self, table: &str, id: &str, plain: &[u8]) -> Result<Vec<u8>> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).expect("fixed key length");
        let nonce_bytes: [u8; 24] = rand::random();
        let aad = format!("cargo:{table}:{id}:v{ENVELOPE_VERSION}");
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plain,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("vault encryption failed"))?;
        let mut envelope = Vec::with_capacity(1 + 24 + encrypted.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&encrypted);
        Ok(envelope)
    }

    fn open_document(&self, table: &str, id: &str, envelope: &[u8]) -> Result<Vec<u8>> {
        if envelope.len() < 42 || envelope[0] != ENVELOPE_VERSION {
            bail!("unsupported or corrupt vault record");
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).expect("fixed key length");
        let aad = format!("cargo:{table}:{id}:v{ENVELOPE_VERSION}");
        cipher
            .decrypt(
                XNonce::from_slice(&envelope[1..25]),
                Payload {
                    msg: &envelope[25..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("vault authentication failed"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn create_profile(&self, display_name: &str) -> Result<LocalProfile> {
        if display_name.trim().is_empty() {
            bail!("display name cannot be empty");
        }
        if self.profile()?.is_some() {
            bail!("a local profile already exists");
        }
        let profile = LocalProfile {
            id: Uuid::new_v4(),
            display_name: display_name.trim().into(),
            created_at: Utc::now(),
        };
        self.put("profile", profile.id, &profile)?;
        self.receipt(
            "profile.created",
            &profile.id.to_string(),
            "success",
            &profile.display_name,
        )?;
        Ok(profile)
    }

    pub fn profile(&self) -> Result<Option<LocalProfile>> {
        self.one("profile")
    }

    pub fn upsert_connection(&self, item: &ConnectionDefinition) -> Result<()> {
        self.put("connections", item.id, item)?;
        self.receipt(
            "connection.saved",
            &item.id.to_string(),
            "success",
            &item.name,
        )?;
        Ok(())
    }

    pub fn merge_imported_connection(&self, item: &ConnectionDefinition) -> Result<bool> {
        let source_path = item.metadata.get("source_path");
        if let Some(existing) = self.connections()?.into_iter().find(|candidate| {
            candidate.name == item.name && candidate.metadata.get("source_path") == source_path
        }) {
            let mut updated = item.clone();
            updated.id = existing.id;
            self.upsert_connection(&updated)?;
            Ok(false)
        } else {
            self.upsert_connection(item)?;
            Ok(true)
        }
    }

    pub fn add_memory(&self, item: &MemoryRecord) -> Result<()> {
        self.put("memory", item.id, item)?;
        self.receipt("memory.saved", &item.id.to_string(), "success", &item.title)?;
        Ok(())
    }

    fn put<T: serde::Serialize>(&self, table: &str, id: Uuid, item: &T) -> Result<()> {
        let id = id.to_string();
        let encrypted = self.seal(table, &id, &serde_json::to_vec(item)?)?;
        self.db.execute(&format!("INSERT INTO {table}(id,document) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET document=excluded.document"), params![id, encrypted])?;
        Ok(())
    }

    fn one<T: serde::de::DeserializeOwned>(&self, table: &str) -> Result<Option<T>> {
        let query = format!("SELECT id, document FROM {table} LIMIT 1");
        let raw: Option<(String, Vec<u8>)> = self
            .db
            .query_row(&query, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        raw.map(|(id, value)| {
            Ok(serde_json::from_slice(
                &self.open_document(table, &id, &value)?,
            )?)
        })
        .transpose()
    }

    pub fn connections(&self) -> Result<Vec<ConnectionDefinition>> {
        self.all("connections", false)
    }
    pub fn connection(&self, id: Uuid) -> Result<Option<ConnectionDefinition>> {
        self.by_id("connections", id)
    }
    pub fn memory(&self) -> Result<Vec<MemoryRecord>> {
        self.all("memory", false)
    }
    pub fn receipts(&self) -> Result<Vec<AuditReceipt>> {
        self.all("receipts", true)
    }
    pub fn deployments(&self) -> Result<Vec<ManagedDeployment>> {
        self.all("deployments", true)
    }

    pub fn deployment(&self, id: Uuid) -> Result<Option<ManagedDeployment>> {
        self.by_id("deployments", id)
    }

    pub fn save_deployment(&self, deployment: &ManagedDeployment) -> Result<()> {
        self.put("deployments", deployment.id, deployment)?;
        self.receipt(
            "deployment.state",
            &deployment.id.to_string(),
            "success",
            &format!("{}:{:?}", deployment.host, deployment.state),
        )
    }

    fn by_id<T: serde::de::DeserializeOwned>(&self, table: &str, id: Uuid) -> Result<Option<T>> {
        let id = id.to_string();
        let query = format!("SELECT document FROM {table} WHERE id=?1");
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(&query, params![id], |row| row.get(0))
            .optional()?;
        raw.map(|value| {
            Ok(serde_json::from_slice(
                &self.open_document(table, &id, &value)?,
            )?)
        })
        .transpose()
    }

    fn all<T: serde::de::DeserializeOwned>(&self, table: &str, descending: bool) -> Result<Vec<T>> {
        let sql = format!(
            "SELECT id, document FROM {table} ORDER BY rowid {}",
            if descending { "DESC" } else { "ASC" }
        );
        let mut statement = self.db.prepare(&sql)?;
        let raw: Vec<(String, Vec<u8>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        raw.into_iter()
            .map(|(id, value)| {
                Ok(serde_json::from_slice(
                    &self.open_document(table, &id, &value)?,
                )?)
            })
            .collect()
    }

    pub fn export_safe(&self) -> Result<PortablePack> {
        let connection_ids = self
            .connections()?
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>();
        let memory_ids = self
            .memory()?
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>();
        self.export_selected(&connection_ids, &memory_ids)
    }

    pub fn export_selected(
        &self,
        connection_ids: &[Uuid],
        memory_ids: &[Uuid],
    ) -> Result<PortablePack> {
        let requested_connections: HashSet<_> = connection_ids.iter().copied().collect();
        let requested_memory: HashSet<_> = memory_ids.iter().copied().collect();
        if requested_connections.len() != connection_ids.len()
            || requested_memory.len() != memory_ids.len()
        {
            bail!("export selection contains duplicate record IDs");
        }
        let all_connections = self.connections()?;
        let all_memory = self.memory()?;
        let selected_connections = all_connections
            .iter()
            .filter(|item| requested_connections.contains(&item.id))
            .map(crate::adapters::sanitize_connection_definition)
            .collect::<Result<Vec<_>>>()?;
        let selected_memory = all_memory
            .into_iter()
            .filter(|item| requested_memory.contains(&item.id))
            .collect::<Vec<_>>();
        if selected_connections.len() != requested_connections.len()
            || selected_memory.len() != requested_memory.len()
        {
            bail!("export selection contains an unknown record ID");
        }
        Ok(PortablePack {
            format: "cargo-ai-pack".into(),
            version: 2,
            contains_secrets: false,
            exported_at: Utc::now(),
            profile: self.profile()?.context("create a profile first")?,
            connections: selected_connections,
            memory: selected_memory,
        })
    }

    pub fn import_pack(&self, pack: &PortablePack) -> Result<PackImportResult> {
        let pack = validate_portable_pack(pack)?;

        let transaction = self.db.unchecked_transaction()?;
        let result = (|| {
            if self.profile()?.is_none() {
                self.put("profile", pack.profile.id, &pack.profile)?;
            }
            let mut existing_connections = self.connections()?;
            let mut existing_memory = self.memory()?;
            let mut result = PackImportResult {
                connections_added: 0,
                connections_skipped: 0,
                memory_added: 0,
                memory_skipped: 0,
            };
            for connection in &pack.connections {
                let duplicate = existing_connections.iter().any(|existing| {
                    existing.id == connection.id
                        || (existing.name == connection.name
                            && existing.metadata.get("source") == connection.metadata.get("source"))
                });
                if duplicate {
                    result.connections_skipped += 1;
                } else {
                    self.put("connections", connection.id, connection)?;
                    existing_connections.push(connection.clone());
                    result.connections_added += 1;
                }
            }
            for memory in &pack.memory {
                let duplicate = existing_memory.iter().any(|existing| {
                    existing.id == memory.id
                        || (existing.title == memory.title && existing.body == memory.body)
                });
                if duplicate {
                    result.memory_skipped += 1;
                } else {
                    self.put("memory", memory.id, memory)?;
                    existing_memory.push(memory.clone());
                    result.memory_added += 1;
                }
            }
            self.receipt(
                "pack.imported",
                &pack.profile.id.to_string(),
                "success",
                &format!(
                    "connections:{};memory:{}",
                    result.connections_added, result.memory_added
                ),
            )?;
            Ok::<_, anyhow::Error>(result)
        })();
        match result {
            Ok(result) => {
                transaction.commit()?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn store_secret(&self, label: &str, secret: SecretString) -> Result<()> {
        keyring::Entry::new(KEYRING_SERVICE, label)?.set_password(secret.expose_secret())?;
        self.receipt("secret.stored", label, "success", "os-keychain-reference")?;
        Ok(())
    }

    pub fn delete_secret(&self, label: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, label)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e.into()),
        }
        self.receipt("secret.deleted", label, "success", "os-keychain-reference")?;
        Ok(())
    }

    fn receipt(&self, action: &str, target: &str, outcome: &str, evidence: &str) -> Result<()> {
        let previous_hash = self.receipts()?.first().map(|r| r.record_hash.clone());
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let evidence_sha256 = format!("{:x}", Sha256::digest(evidence.as_bytes()));
        let canonical = format!(
            "{id}|{action}|{target}|{outcome}|{evidence_sha256}|{}|{}",
            previous_hash.as_deref().unwrap_or(""),
            created_at.to_rfc3339()
        );
        let record_hash = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        let receipt = AuditReceipt {
            id,
            action: action.into(),
            target: target.into(),
            outcome: outcome.into(),
            evidence_sha256,
            previous_hash,
            record_hash,
            created_at,
        };
        self.put("receipts", receipt.id, &receipt)
    }

    pub fn verify_receipt_chain(&self) -> Result<bool> {
        let mut receipts = self.receipts()?;
        receipts.reverse();
        let mut previous: Option<String> = None;
        for receipt in receipts {
            if receipt.previous_hash != previous {
                return Ok(false);
            }
            let canonical = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                receipt.id,
                receipt.action,
                receipt.target,
                receipt.outcome,
                receipt.evidence_sha256,
                receipt.previous_hash.as_deref().unwrap_or(""),
                receipt.created_at.to_rfc3339()
            );
            if format!("{:x}", Sha256::digest(canonical.as_bytes())) != receipt.record_hash {
                return Ok(false);
            }
            previous = Some(receipt.record_hash);
        }
        Ok(true)
    }

    #[cfg(test)]
    fn raw_documents_contain(&self, needle: &str) -> Result<bool> {
        for table in [
            "profile",
            "connections",
            "memory",
            "receipts",
            "deployments",
        ] {
            let mut statement = self.db.prepare(&format!("SELECT document FROM {table}"))?;
            for value in statement.query_map([], |r| {
                r.get_ref(0).map(|v| match v {
                    ValueRef::Text(v) | ValueRef::Blob(v) => v.to_vec(),
                    _ => vec![],
                })
            })? {
                if String::from_utf8_lossy(&value?).contains(needle) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

pub fn validate_portable_pack(pack: &PortablePack) -> Result<PortablePack> {
    if pack.format != "cargo-ai-pack" || pack.version != 2 || pack.contains_secrets {
        bail!("unsupported portable pack format, version, or secret-content flag");
    }
    if pack.connections.len() > 2_000 || pack.memory.len() > 10_000 {
        bail!("portable pack exceeds record-count limits");
    }
    if pack.profile.display_name.trim().is_empty()
        || pack.profile.display_name.chars().count() > 200
    {
        bail!("portable pack contains an invalid profile");
    }
    let connections = pack
        .connections
        .iter()
        .map(crate::adapters::sanitize_connection_definition)
        .collect::<Result<Vec<_>>>()?;
    let mut connection_ids = HashSet::new();
    if connections
        .iter()
        .any(|item| !connection_ids.insert(item.id))
    {
        bail!("portable pack contains duplicate connection IDs");
    }
    let mut memory_ids = HashSet::new();
    for memory in &pack.memory {
        if !memory_ids.insert(memory.id) {
            bail!("portable pack contains duplicate memory IDs");
        }
        if memory.title.trim().is_empty()
            || memory.title.chars().count() > 200
            || memory.body.trim().is_empty()
            || memory.body.len() > 256 * 1024
            || memory.allowed_hosts.len() > 64
            || memory.allowed_hosts.iter().any(|host| host.len() > 200)
        {
            bail!("portable pack contains an invalid memory record");
        }
    }
    let mut validated = pack.clone();
    validated.profile.display_name = validated.profile.display_name.trim().into();
    validated.connections = connections;
    Ok(validated)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn profile_is_encrypted_and_receipts_verify() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(dir.path().join("vault.db"), [7; 32]).unwrap();
        let profile = vault.create_profile("Ada Lovelace").unwrap();
        assert_eq!(vault.profile().unwrap().unwrap(), profile);
        assert!(!vault.raw_documents_contain("Ada Lovelace").unwrap());
        assert!(vault.verify_receipt_chain().unwrap());
        assert_eq!(vault.export_safe().unwrap().format, "cargo-ai-pack");
    }
    #[test]
    fn wrong_key_cannot_open_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        {
            let vault = Vault::open_with_key(&path, [1; 32]).unwrap();
            vault.create_profile("Private").unwrap();
        }
        let wrong = Vault::open_with_key(&path, [2; 32]);
        assert!(wrong.is_err() || wrong.unwrap().profile().is_err());
    }

    #[test]
    fn pack_import_is_idempotent_and_keeps_local_profile() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Vault::open_with_key(source_dir.path().join("source.db"), [3; 32]).unwrap();
        source.create_profile("Source").unwrap();
        let memory = MemoryRecord {
            id: Uuid::new_v4(),
            title: "Working style".into(),
            body: "Prefer concise updates".into(),
            sensitivity: crate::Sensitivity::Private,
            allowed_hosts: vec!["Codex".into()],
            created_at: Utc::now(),
        };
        source.add_memory(&memory).unwrap();
        let pack = source.export_safe().unwrap();

        let target_dir = tempfile::tempdir().unwrap();
        let target = Vault::open_with_key(target_dir.path().join("target.db"), [4; 32]).unwrap();
        target.create_profile("Target").unwrap();
        let first = target.import_pack(&pack).unwrap();
        let second = target.import_pack(&pack).unwrap();
        assert_eq!(first.memory_added, 1);
        assert_eq!(second.memory_skipped, 1);
        assert_eq!(target.profile().unwrap().unwrap().display_name, "Target");
        assert_eq!(target.memory().unwrap(), vec![memory]);
    }

    #[test]
    fn portable_export_redacts_arguments_and_device_paths() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(dir.path().join("vault.db"), [8; 32]).unwrap();
        vault.create_profile("Exporter").unwrap();
        vault
            .upsert_connection(&ConnectionDefinition {
                id: Uuid::new_v4(),
                name: "private-docs".into(),
                transport: "stdio".into(),
                command: Some("docs-server".into()),
                args: vec!["--api-key".into(), "sk-do-not-export".into()],
                url: None,
                environment_keys: vec![],
                metadata: BTreeMap::from([
                    ("source".into(), "test".into()),
                    (
                        "source_path".into(),
                        "/Users/private/.cursor/mcp.json".into(),
                    ),
                ]),
            })
            .unwrap();
        let pack = vault.export_safe().unwrap();
        let serialized = serde_json::to_string(&pack).unwrap();
        assert!(!serialized.contains("sk-do-not-export"));
        assert!(!serialized.contains("/Users/private"));
        assert!(!pack.contains_secrets);
        assert_eq!(pack.connections[0].args[1], "<redacted>");
    }

    #[test]
    fn invalid_pack_is_rejected_before_any_record_is_written() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Vault::open_with_key(source_dir.path().join("source.db"), [9; 32]).unwrap();
        source.create_profile("Source").unwrap();
        let mut pack = source.export_safe().unwrap();
        pack.memory.push(MemoryRecord {
            id: Uuid::new_v4(),
            title: "Invalid".into(),
            body: "".into(),
            sensitivity: crate::Sensitivity::Private,
            allowed_hosts: vec![],
            created_at: Utc::now(),
        });

        let target_dir = tempfile::tempdir().unwrap();
        let target = Vault::open_with_key(target_dir.path().join("target.db"), [10; 32]).unwrap();
        assert!(target.import_pack(&pack).is_err());
        assert!(target.profile().unwrap().is_none());
        assert!(target.connections().unwrap().is_empty());
        assert!(target.memory().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn vault_database_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let _vault = Vault::open_with_key(&path, [11; 32]).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
