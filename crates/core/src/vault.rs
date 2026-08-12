use crate::{
    AuditReceipt, ConnectionDefinition, DeploymentState, ExecutionCredentialActivation,
    ExecutionCredentialActivationKind, ExecutionCredentialActivationState,
    ExecutionCredentialRequirement, ExecutionCredentialStatus, ExecutionCredentialWrite,
    ExecutionGrant, ExecutionGrantStatus, ExecutionGrantView, GrantActivationOperation,
    GrantActivationState, LocalProfile, ManagedDeployment, MemoryRecord, PackImportResult,
    PortablePack, ProviderGrant, RevocationOperation, RevocationVerification,
    TokenRevocationResult, execution::ExecutionGrantPreview,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use chrono::Utc;
use directories::ProjectDirs;
use fs2::FileExt;
#[cfg(test)]
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

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
        let path = normalize_vault_path(path.as_ref())?;
        let key = Self::load_or_create_key(&path)?;
        Self::open_with_key(path, key)
    }

    pub fn open_with_key(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let path = normalize_vault_path(path.as_ref())?;
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
        vault.reconcile_execution_credential_activations()?;
        vault.reconcile_grant_activations()?;
        vault.reconcile_pending_provider_authorizations()?;
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

    fn with_execution_credential_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let lock_path = self.path.with_file_name(format!(
            "{}.execution-credentials.lock",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .context("vault filename is not valid UTF-8")?
        ));
        let lock_file = open_private_lock_file(&lock_path)?;
        lock_file.lock_exclusive()?;
        validate_lock_file_identity(&lock_file, &lock_path)?;
        let result = operation();
        let identity = validate_lock_file_identity(&lock_file, &lock_path);
        let unlock = FileExt::unlock(&lock_file);
        match (result, identity, unlock) {
            (Ok(value), Ok(()), Ok(())) => Ok(value),
            (Err(error), _, _) => Err(error),
            (Ok(_), Err(error), _) => Err(error),
            (Ok(_), Ok(()), Err(error)) => Err(error.into()),
        }
    }

    fn migrate(&self) -> Result<()> {
        self.db.execute_batch(
            r#"
          CREATE TABLE IF NOT EXISTS profile (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS memory (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS deployments (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS execution_grants (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS execution_credential_activations (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS execution_grant_owners (
            owner_key TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL UNIQUE,
            connection_id TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS consumed_execution_previews (
            preview_id TEXT PRIMARY KEY
          );
          CREATE TABLE IF NOT EXISTS provider_grants (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS provider_lifecycle_owners (
            connection_id TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL UNIQUE
          );
          CREATE TABLE IF NOT EXISTS grant_activations (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY, document BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        "#,
        )?;
        // Backfill lifecycle ownership for existing encrypted grant records.
        // Conflicting legacy rows are surfaced instead of silently choosing an
        // owner, because that state requires explicit reconciliation.
        for grant in self.provider_grants()? {
            if !grant.status.is_terminal() {
                self.claim_provider_lifecycle(grant.connection_id, grant.id)?;
            }
        }
        Ok(())
    }

    fn encrypt_legacy_rows(&self) -> Result<()> {
        for table in [
            "profile",
            "connections",
            "memory",
            "receipts",
            "deployments",
            "execution_grants",
            "execution_credential_activations",
            "provider_grants",
            "grant_activations",
            "revocations",
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
        validate_display_name(display_name)?;
        if self.profile()?.is_some() {
            bail!("a local profile already exists");
        }
        let profile = LocalProfile {
            id: Uuid::new_v4(),
            display_name: display_name.trim().into(),
            created_at: Utc::now(),
        };
        let transaction = self.db.unchecked_transaction()?;
        self.put("profile", profile.id, &profile)?;
        self.receipt(
            "profile.created",
            &profile.id.to_string(),
            "success",
            &profile.display_name,
        )?;
        transaction.commit()?;
        Ok(profile)
    }

    pub fn rename_profile(&self, display_name: &str) -> Result<LocalProfile> {
        validate_display_name(display_name)?;
        let mut profile = self.profile()?.context("local profile was not found")?;
        profile.display_name = display_name.trim().into();
        let transaction = self.db.unchecked_transaction()?;
        self.put("profile", profile.id, &profile)?;
        self.receipt(
            "profile.renamed",
            &profile.id.to_string(),
            "success",
            &profile.display_name,
        )?;
        transaction.commit()?;
        Ok(profile)
    }

    pub fn profile(&self) -> Result<Option<LocalProfile>> {
        self.one("profile")
    }

    pub fn upsert_connection(&self, item: &ConnectionDefinition) -> Result<()> {
        let transaction = self.db.unchecked_transaction()?;
        self.put("connections", item.id, item)?;
        self.receipt(
            "connection.saved",
            &item.id.to_string(),
            "success",
            &item.name,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Creates a user-authored portable definition after applying the same
    /// sanitization boundary used for imported and exported definitions.
    pub fn create_connection(&self, item: &ConnectionDefinition) -> Result<ConnectionDefinition> {
        let item = crate::adapters::sanitize_manual_connection_definition(item)?;
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            if self
                .connections()?
                .iter()
                .any(|existing| existing.name == item.name)
            {
                bail!("a connection with this name already exists");
            }
            self.put("connections", item.id, &item)?;
            self.receipt(
                "connection.created",
                &item.id.to_string(),
                "success",
                &item.name,
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(item)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn merge_imported_connections(&self, items: &[ConnectionDefinition]) -> Result<usize> {
        let transaction = self.db.unchecked_transaction()?;
        let mut existing = self.connections()?;
        for item in items {
            let source_path = item.metadata.get("source_path");
            let mut saved = item.clone();
            if let Some(previous) = existing.iter().find(|candidate| {
                candidate.name == item.name && candidate.metadata.get("source_path") == source_path
            }) {
                saved.id = previous.id;
            } else {
                existing.push(saved.clone());
            }
            self.put("connections", saved.id, &saved)?;
            self.receipt(
                "connection.saved",
                &saved.id.to_string(),
                "success",
                &saved.name,
            )?;
        }
        transaction.commit()?;
        Ok(items.len())
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
        validate_memory(item)?;
        let transaction = self.db.unchecked_transaction()?;
        self.put("memory", item.id, item)?;
        self.receipt("memory.saved", &item.id.to_string(), "success", &item.title)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn update_memory(&self, item: &MemoryRecord) -> Result<()> {
        validate_memory(item)?;
        if self.memory_record(item.id)?.is_none() {
            bail!("memory record was not found");
        }
        let transaction = self.db.unchecked_transaction()?;
        self.put("memory", item.id, item)?;
        self.receipt(
            "memory.updated",
            &item.id.to_string(),
            "success",
            &item.title,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_memory(&self, id: Uuid) -> Result<()> {
        let memory = self
            .memory_record(id)?
            .context("memory record was not found")?;
        let transaction = self.db.unchecked_transaction()?;
        self.delete_row("memory", id)?;
        self.receipt("memory.deleted", &id.to_string(), "success", &memory.title)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_connection(&self, id: Uuid) -> Result<()> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let connection = self.connection(id)?.context("connection was not found")?;
            let is_managed = self.deployments()?.iter().any(|deployment| {
                deployment.connection_id == id && deployment.state != DeploymentState::HostRemoved
            });
            if is_managed {
                bail!(
                    "remove every active managed host deployment before deleting this connection"
                );
            }
            if self
                .provider_grants()?
                .iter()
                .any(|grant| grant.connection_id == id && !grant.status.is_terminal())
            {
                bail!(
                    "verify or explicitly resolve every provider grant before deleting this connection"
                );
            }
            if self
                .execution_grants()?
                .iter()
                .any(|grant| grant.connection_id == id && !grant.status.is_terminal())
            {
                bail!("cancel every pending local execution grant before deleting this connection");
            }
            self.delete_row("connections", id)?;
            self.receipt(
                "connection.deleted",
                &id.to_string(),
                "success",
                &connection.name,
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
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
    pub fn connection_count(&self) -> Result<usize> {
        self.count("connections")
    }
    pub fn connection(&self, id: Uuid) -> Result<Option<ConnectionDefinition>> {
        self.by_id("connections", id)
    }
    pub fn memory(&self) -> Result<Vec<MemoryRecord>> {
        self.all("memory", false)
    }
    pub fn memory_count(&self) -> Result<usize> {
        self.count("memory")
    }
    pub fn memory_record(&self, id: Uuid) -> Result<Option<MemoryRecord>> {
        self.by_id("memory", id)
    }
    pub fn receipts(&self) -> Result<Vec<AuditReceipt>> {
        self.all("receipts", true)
    }
    pub fn deployments(&self) -> Result<Vec<ManagedDeployment>> {
        self.all("deployments", true)
    }

    /// Creates an inert preview from the current encrypted definition. The
    /// returned object cannot be caller-constructed or used to activate code.
    pub fn prepare_execution_grant(
        &self,
        connection_id: Uuid,
        host: &str,
    ) -> Result<ExecutionGrantPreview> {
        let profile = self.profile()?.context("create a local profile first")?;
        let connection = self
            .connection(connection_id)?
            .context("connection was not found")?;
        crate::execution::prepare_execution_grant_preview(profile.id, &connection, host)
    }

    /// Atomically consumes one fresh backend preview and records an inert,
    /// immutable execution intent. This method cannot store credentials,
    /// install host configuration, spawn a process, or create an active grant.
    pub fn reserve_execution_grant(
        &self,
        preview: ExecutionGrantPreview,
    ) -> Result<ExecutionGrant> {
        if Utc::now() >= preview.expires_at() {
            bail!("execution preview expired; create a new preview");
        }
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Utc::now() >= preview.expires_at() {
                bail!("execution preview expired while waiting for the vault write lock");
            }
            let profile = self.profile()?.context("local profile was not found")?;
            if profile.id != preview.expected_profile_id() {
                bail!("the local profile changed after this execution preview");
            }
            let connection = self
                .connection(preview.connection_id())?
                .context("connection was not found")?;
            let current = crate::execution::prepare_execution_grant_preview(
                profile.id,
                &connection,
                preview.host(),
            )?;
            if current.source_fingerprint() != preview.source_fingerprint()
                || current.snapshot_sha256() != preview.snapshot_sha256()
            {
                bail!("the connection changed after this execution preview");
            }
            self.db.execute(
                "INSERT INTO consumed_execution_previews(preview_id) VALUES (?1)",
                params![preview.id().to_string()],
            )?;
            let id = Uuid::new_v4();
            let owner_key = crate::execution::owner_key(preview.connection_id(), preview.host());
            self.db.execute(
                "INSERT INTO execution_grant_owners(owner_key,grant_id,connection_id) VALUES (?1,?2,?3)",
                params![owner_key, id.to_string(), preview.connection_id().to_string()],
            )?;
            let grant = ExecutionGrant {
                id,
                connection_id: preview.connection_id(),
                host: preview.host().into(),
                source_fingerprint: preview.source_fingerprint().into(),
                snapshot: preview.snapshot().clone(),
                snapshot_sha256: preview.snapshot_sha256().into(),
                required_credentials: preview
                    .snapshot()
                    .credential_names
                    .iter()
                    .map(|name| ExecutionCredentialRequirement {
                        binding_id: Uuid::new_v4(),
                        name: name.clone(),
                        status: ExecutionCredentialStatus::Missing,
                        secret_ref: None,
                    })
                    .collect(),
                status: ExecutionGrantStatus::AwaitingCredentials,
                revision: 0,
                created_at: Utc::now(),
                cancelled_at: None,
            };
            crate::execution::validate_execution_grant(&grant)?;
            self.put("execution_grants", grant.id, &grant)?;
            self.receipt(
                "execution_grant.reserved",
                &grant.id.to_string(),
                "awaiting_credentials",
                &grant.snapshot_sha256,
            )?;
            Ok::<ExecutionGrant, anyhow::Error>(grant)
        })();
        match result {
            Ok(grant) => {
                self.db.execute_batch("COMMIT")?;
                Ok(grant)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub(crate) fn execution_grant(&self, id: Uuid) -> Result<Option<ExecutionGrant>> {
        let grant: Option<ExecutionGrant> = self.by_id("execution_grants", id)?;
        grant
            .map(|grant| self.validate_execution_grant_owner(grant))
            .transpose()
    }

    pub fn execution_grant_view(&self, id: Uuid) -> Result<Option<ExecutionGrantView>> {
        Ok(self
            .execution_grant(id)?
            .as_ref()
            .map(ExecutionGrantView::from))
    }

    pub fn execution_grant_views(&self) -> Result<Vec<ExecutionGrantView>> {
        Ok(self
            .execution_grants()?
            .iter()
            .map(ExecutionGrantView::from)
            .collect())
    }

    pub(crate) fn execution_grants(&self) -> Result<Vec<ExecutionGrant>> {
        self.validate_execution_owner_index()?;
        self.all::<ExecutionGrant>("execution_grants", true)?
            .into_iter()
            .map(|grant| self.validate_execution_grant_owner(grant))
            .collect()
    }

    fn execution_credential_activations(&self) -> Result<Vec<ExecutionCredentialActivation>> {
        self.all::<ExecutionCredentialActivation>("execution_credential_activations", true)?
            .into_iter()
            .map(|activation| {
                crate::execution::validate_credential_activation(&activation)?;
                Ok(activation)
            })
            .collect()
    }

    /// Journals and stores environment credentials without exposing them to a
    /// host configuration or creating executable authority. Values must come
    /// from a trusted native caller; they are never returned from this method.
    pub fn store_execution_credentials(
        &self,
        grant_id: Uuid,
        expected_revision: u64,
        values: Vec<(String, SecretString)>,
    ) -> Result<ExecutionGrantView> {
        let mut provided: std::collections::HashMap<String, SecretString> =
            std::collections::HashMap::new();
        for (name, value) in values {
            if provided.insert(name, value).is_some() {
                bail!("credential input contains a duplicate environment name");
            }
        }
        self.with_execution_credential_lock(|| {
            self.store_execution_credentials_locked(grant_id, expected_revision, provided)
        })
    }

    fn store_execution_credentials_locked(
        &self,
        grant_id: Uuid,
        expected_revision: u64,
        mut provided: std::collections::HashMap<String, SecretString>,
    ) -> Result<ExecutionGrantView> {
        let supplied_count = provided.len();
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let staged = (|| {
            let grant: ExecutionGrant = self
                .by_id("execution_grants", grant_id)?
                .context("execution grant was not found")?;
            let grant = self.validate_execution_grant_owner(grant)?;
            if grant.status != ExecutionGrantStatus::AwaitingCredentials
                || grant.revision != expected_revision
            {
                bail!("execution grant changed after credential review");
            }
            if self
                .execution_credential_activations()?
                .iter()
                .any(|activation| {
                    activation.grant_id == grant.id
                        && activation.state != ExecutionCredentialActivationState::Completed
                })
            {
                bail!("execution credential custody is already pending");
            }
            if supplied_count != grant.required_credentials.len()
                || grant
                    .required_credentials
                    .iter()
                    .any(|requirement| !provided.contains_key(&requirement.name))
            {
                bail!("credential values must exactly match the reviewed environment names");
            }
            let activation = ExecutionCredentialActivation {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                grant_revision: grant.revision,
                kind: ExecutionCredentialActivationKind::Write,
                credentials: grant
                    .required_credentials
                    .iter()
                    .map(|requirement| ExecutionCredentialWrite {
                        binding_id: requirement.binding_id,
                        name: requirement.name.clone(),
                        secret_ref: crate::execution::new_secret_reference(
                            grant.id,
                            requirement.binding_id,
                        ),
                    })
                    .collect(),
                state: ExecutionCredentialActivationState::Staged,
                created_at: Utc::now(),
                completed_at: None,
            };
            crate::execution::validate_credential_activation(&activation)?;
            self.put(
                "execution_credential_activations",
                activation.id,
                &activation,
            )?;
            self.receipt(
                "execution_credentials.write_started",
                &activation.id.to_string(),
                "staged",
                &format!(
                    "grant:{};revision:{};count:{}",
                    grant.id,
                    grant.revision,
                    activation.credentials.len()
                ),
            )?;
            Ok::<ExecutionCredentialActivation, anyhow::Error>(activation)
        })();
        let mut activation = match staged {
            Ok(activation) => {
                self.db.execute_batch("COMMIT")?;
                activation
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                return Err(error);
            }
        };

        // Hold the cross-process writer lock for the entire external
        // Keychain write and final encrypted grant transition. A second Cargo
        // process therefore cannot misclassify this live Staged operation as
        // abandoned crash residue.
        self.db.execute_batch("BEGIN IMMEDIATE")?;

        for credential in &activation.credentials {
            let value = provided
                .remove(&credential.name)
                .context("reviewed credential value was not supplied")?;
            if let Err(error) = self
                .put_secret_value(&credential.secret_ref, &value)
                .and_then(|()| self.verify_secret_value(&credential.secret_ref))
            {
                activation.state = ExecutionCredentialActivationState::CleanupPending;
                let _ = self.put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                );
                let cleanup = self.cleanup_execution_credential_activation_locked(&mut activation);
                let _ = self.db.execute_batch(if cleanup.is_ok() {
                    "COMMIT"
                } else {
                    "ROLLBACK"
                });
                return match cleanup {
                    Ok(()) => Err(error.context(
                        "execution credential storage failed; staged values were cleaned up",
                    )),
                    Err(cleanup_error) => Err(error.context(format!(
                        "execution credential storage failed and cleanup remains pending: {cleanup_error}"
                    ))),
                };
            }
        }

        activation.state = ExecutionCredentialActivationState::CredentialsWritten;
        let finalized = (|| {
            self.put(
                "execution_credential_activations",
                activation.id,
                &activation,
            )?;
            self.receipt(
                "execution_credentials.written",
                &activation.id.to_string(),
                "verified",
                &format!("count:{}", activation.credentials.len()),
            )?;
            self.finalize_execution_credential_activation_locked(&mut activation)
        })();
        match finalized {
            Ok(grant) => {
                self.db.execute_batch("COMMIT")?;
                Ok(ExecutionGrantView::from(&grant))
            }
            Err(error) => {
                activation.state = ExecutionCredentialActivationState::CleanupPending;
                let _ = self.put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                );
                let cleanup = self.cleanup_execution_credential_activation_locked(&mut activation);
                let _ = self.db.execute_batch(if cleanup.is_ok() {
                    "COMMIT"
                } else {
                    "ROLLBACK"
                });
                match cleanup {
                    Ok(()) => Err(error.context(
                        "credential activation could not finalize; staged values were reconciled",
                    )),
                    Err(cleanup_error) => Err(error.context(format!(
                        "credential activation could not finalize and reconciliation remains pending: {cleanup_error}"
                    ))),
                }
            }
        }
    }

    fn finalize_execution_credential_activation_locked(
        &self,
        activation: &mut ExecutionCredentialActivation,
    ) -> Result<ExecutionGrant> {
        crate::execution::validate_credential_activation(activation)?;
        if activation.kind != ExecutionCredentialActivationKind::Write
            || activation.state != ExecutionCredentialActivationState::CredentialsWritten
        {
            bail!("execution credential activation is not ready to finalize");
        }
        let grant: ExecutionGrant = self
            .by_id("execution_grants", activation.grant_id)?
            .context("execution grant was not found")?;
        let mut grant = self.validate_execution_grant_owner(grant)?;
        if grant.status != ExecutionGrantStatus::AwaitingCredentials
            || grant.revision != activation.grant_revision
            || grant.required_credentials.len() != activation.credentials.len()
        {
            bail!("execution grant changed during credential custody");
        }
        for write in &activation.credentials {
            self.verify_secret_value(&write.secret_ref)?;
            let requirement = grant
                .required_credentials
                .iter_mut()
                .find(|item| item.binding_id == write.binding_id && item.name == write.name)
                .context("credential activation no longer matches its reviewed binding")?;
            requirement.status = ExecutionCredentialStatus::Stored;
            requirement.secret_ref = Some(write.secret_ref.clone());
        }
        grant.status = ExecutionGrantStatus::CredentialsReady;
        grant.revision += 1;
        crate::execution::validate_execution_grant(&grant)?;
        activation.state = ExecutionCredentialActivationState::Completed;
        activation.completed_at = Some(Utc::now());
        crate::execution::validate_credential_activation(activation)?;
        self.put("execution_grants", grant.id, &grant)?;
        self.put(
            "execution_credential_activations",
            activation.id,
            activation,
        )?;
        self.receipt(
            "execution_credentials.ready",
            &grant.id.to_string(),
            "verified",
            &format!(
                "revision:{};count:{}",
                grant.revision,
                activation.credentials.len()
            ),
        )?;
        Ok(grant)
    }

    fn reconcile_execution_credential_activations(&self) -> Result<()> {
        self.with_execution_credential_lock(|| {
            self.reconcile_execution_credential_activations_locked()
        })
    }

    fn reconcile_execution_credential_activations_locked(&self) -> Result<()> {
        let activation_ids = self
            .execution_credential_activations()?
            .into_iter()
            .filter(|activation| activation.state != ExecutionCredentialActivationState::Completed)
            .map(|activation| activation.id)
            .collect::<Vec<_>>();
        for activation_id in activation_ids {
            self.db.execute_batch("BEGIN IMMEDIATE")?;
            let result = (|| {
                let mut activation: ExecutionCredentialActivation = self
                    .by_id("execution_credential_activations", activation_id)?
                    .context("execution credential activation was not found")?;
                crate::execution::validate_credential_activation(&activation)?;
                if activation.state == ExecutionCredentialActivationState::Completed {
                    return Ok::<(), anyhow::Error>(());
                }
                if activation.kind == ExecutionCredentialActivationKind::Write
                    && activation.state == ExecutionCredentialActivationState::CredentialsWritten
                    && activation
                        .credentials
                        .iter()
                        .all(|item| self.verify_secret_value(&item.secret_ref).is_ok())
                {
                    let _ =
                        self.finalize_execution_credential_activation_locked(&mut activation)?;
                    return Ok(());
                }
                activation.state = ExecutionCredentialActivationState::CleanupPending;
                self.put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                )?;
                self.cleanup_execution_credential_activation_locked(&mut activation)
            })();
            match result {
                Ok(()) => self.db.execute_batch("COMMIT")?,
                Err(error) => {
                    let _ = self.db.execute_batch("ROLLBACK");
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn cleanup_execution_credential_activation_locked(
        &self,
        activation: &mut ExecutionCredentialActivation,
    ) -> Result<()> {
        crate::execution::validate_credential_activation(activation)?;
        if activation.state != ExecutionCredentialActivationState::CleanupPending {
            bail!("execution credential activation is not ready for cleanup");
        }
        for credential in &activation.credentials {
            self.delete_secret_value(&credential.secret_ref)?;
            if self.secret_value_exists(&credential.secret_ref)? {
                bail!("execution credential remains present after Keychain deletion");
            }
        }
        if activation.kind == ExecutionCredentialActivationKind::Delete {
            let grant: ExecutionGrant = self
                .by_id("execution_grants", activation.grant_id)?
                .context("execution grant was not found")?;
            let mut grant = self.validate_execution_grant_owner(grant)?;
            if grant.status != ExecutionGrantStatus::CredentialsReady
                || grant.revision != activation.grant_revision
            {
                bail!("execution grant changed during credential deletion");
            }
            for write in &activation.credentials {
                let requirement = grant
                    .required_credentials
                    .iter_mut()
                    .find(|item| {
                        item.binding_id == write.binding_id
                            && item.name == write.name
                            && item.secret_ref.as_deref() == Some(write.secret_ref.as_str())
                    })
                    .context("credential deletion no longer matches its binding")?;
                requirement.status = ExecutionCredentialStatus::Missing;
                requirement.secret_ref = None;
            }
            grant.status = ExecutionGrantStatus::AwaitingCredentials;
            grant.revision += 1;
            crate::execution::validate_execution_grant(&grant)?;
            self.put("execution_grants", grant.id, &grant)?;
        }
        activation.state = ExecutionCredentialActivationState::Completed;
        activation.completed_at = Some(Utc::now());
        crate::execution::validate_credential_activation(activation)?;
        self.put(
            "execution_credential_activations",
            activation.id,
            activation,
        )?;
        self.receipt(
            "execution_credentials.cleaned",
            &activation.id.to_string(),
            "verified",
            "credential-references-deleted",
        )?;
        Ok(())
    }

    /// Deletes every locally stored environment credential and returns the
    /// immutable grant to an inert missing-credentials state.
    pub fn forget_execution_credentials(
        &self,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<ExecutionGrantView> {
        self.with_execution_credential_lock(|| {
            self.forget_execution_credentials_locked(grant_id, expected_revision)
        })
    }

    fn forget_execution_credentials_locked(
        &self,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<ExecutionGrantView> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let staged = (|| {
            let grant: ExecutionGrant = self
                .by_id("execution_grants", grant_id)?
                .context("execution grant was not found")?;
            let grant = self.validate_execution_grant_owner(grant)?;
            if grant.status != ExecutionGrantStatus::CredentialsReady
                || grant.revision != expected_revision
            {
                bail!("execution grant changed after credential cleanup review");
            }
            if self
                .execution_credential_activations()?
                .iter()
                .any(|activation| {
                    activation.grant_id == grant.id
                        && activation.state != ExecutionCredentialActivationState::Completed
                })
            {
                bail!("execution credential lifecycle is already pending");
            }
            let activation = ExecutionCredentialActivation {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                grant_revision: grant.revision,
                kind: ExecutionCredentialActivationKind::Delete,
                credentials: grant
                    .required_credentials
                    .iter()
                    .map(|requirement| {
                        Ok(ExecutionCredentialWrite {
                            binding_id: requirement.binding_id,
                            name: requirement.name.clone(),
                            secret_ref: requirement
                                .secret_ref
                                .clone()
                                .context("stored credential reference was missing")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                state: ExecutionCredentialActivationState::CleanupPending,
                created_at: Utc::now(),
                completed_at: None,
            };
            crate::execution::validate_credential_activation(&activation)?;
            self.put(
                "execution_credential_activations",
                activation.id,
                &activation,
            )?;
            self.receipt(
                "execution_credentials.delete_started",
                &activation.id.to_string(),
                "blocked",
                &format!("grant:{};revision:{}", grant.id, grant.revision),
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match staged {
            Ok(()) => self.db.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        self.reconcile_execution_credential_activations_locked()?;
        let grant = self
            .execution_grant(grant_id)?
            .context("execution grant was not found after credential cleanup")?;
        Ok(ExecutionGrantView::from(&grant))
    }

    /// Cancels only an inert, credential-free grant using revision compare and
    /// swap semantics. The encrypted terminal record is retained for audit.
    pub fn cancel_execution_grant(
        &self,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<ExecutionGrant> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut grant: ExecutionGrant = self
                .by_id("execution_grants", grant_id)?
                .context("execution grant was not found")?;
            grant = self.validate_execution_grant_owner(grant)?;
            if self
                .execution_credential_activations()?
                .iter()
                .any(|activation| {
                    activation.grant_id == grant.id
                        && activation.state != ExecutionCredentialActivationState::Completed
                })
            {
                bail!("execution credential custody must finish before cancellation");
            }
            if grant.status != ExecutionGrantStatus::AwaitingCredentials
                || grant.revision != expected_revision
            {
                bail!("execution grant changed after it was reviewed");
            }
            grant.status = ExecutionGrantStatus::Cancelled;
            grant.revision += 1;
            grant.cancelled_at = Some(Utc::now());
            crate::execution::validate_execution_grant(&grant)?;
            let owner_key = crate::execution::owner_key(grant.connection_id, &grant.host);
            let removed = self.db.execute(
                "DELETE FROM execution_grant_owners WHERE owner_key=?1 AND grant_id=?2",
                params![owner_key, grant.id.to_string()],
            )?;
            if removed != 1 {
                bail!("execution grant ownership changed");
            }
            self.put("execution_grants", grant.id, &grant)?;
            self.receipt(
                "execution_grant.cancelled",
                &grant.id.to_string(),
                "success",
                "credential-free-intent",
            )?;
            Ok::<ExecutionGrant, anyhow::Error>(grant)
        })();
        match result {
            Ok(grant) => {
                self.db.execute_batch("COMMIT")?;
                Ok(grant)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn validate_execution_grant_owner(&self, grant: ExecutionGrant) -> Result<ExecutionGrant> {
        crate::execution::validate_execution_grant(&grant)?;
        let owner_key = crate::execution::owner_key(grant.connection_id, &grant.host);
        let owner: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT grant_id,connection_id FROM execution_grant_owners WHERE owner_key=?1",
                params![owner_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let grant_id = grant.id.to_string();
        let connection_id = grant.connection_id.to_string();
        match grant.status {
            ExecutionGrantStatus::AwaitingCredentials | ExecutionGrantStatus::CredentialsReady
                if owner.as_ref() == Some(&(grant_id.clone(), connection_id.clone())) => {}
            ExecutionGrantStatus::Cancelled
                if owner.as_ref() != Some(&(grant_id, connection_id)) => {}
            _ => bail!("execution grant ownership is corrupt or inconsistent"),
        }
        Ok(grant)
    }

    fn validate_execution_owner_index(&self) -> Result<()> {
        let mut statement = self
            .db
            .prepare("SELECT owner_key,grant_id,connection_id FROM execution_grant_owners")?;
        let owners: Vec<(String, String, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        drop(statement);
        for (owner_key, grant_id, connection_id) in owners {
            let grant_id =
                Uuid::parse_str(&grant_id).context("invalid execution owner grant ID")?;
            let connection_id =
                Uuid::parse_str(&connection_id).context("invalid execution owner connection ID")?;
            let grant: ExecutionGrant = self
                .by_id("execution_grants", grant_id)?
                .context("execution owner references a missing encrypted grant")?;
            crate::execution::validate_execution_grant(&grant)?;
            if !matches!(
                grant.status,
                ExecutionGrantStatus::AwaitingCredentials | ExecutionGrantStatus::CredentialsReady
            ) || grant.connection_id != connection_id
                || owner_key != crate::execution::owner_key(connection_id, &grant.host)
            {
                bail!("execution owner index is corrupt or inconsistent");
            }
        }
        Ok(())
    }

    pub fn provider_grants(&self) -> Result<Vec<ProviderGrant>> {
        self.all("provider_grants", true)
    }

    pub fn grant_activation_operations(&self) -> Result<Vec<GrantActivationOperation>> {
        self.all("grant_activations", true)
    }

    pub fn provider_grant(&self, id: Uuid) -> Result<Option<ProviderGrant>> {
        self.by_id("provider_grants", id)
    }

    fn claim_provider_lifecycle(&self, connection_id: Uuid, grant_id: Uuid) -> Result<()> {
        let changed = self.db.execute(
            "INSERT INTO provider_lifecycle_owners(connection_id, grant_id) VALUES (?1, ?2) \
             ON CONFLICT(connection_id) DO NOTHING",
            params![connection_id.to_string(), grant_id.to_string()],
        )?;
        if changed == 0 {
            let owner: String = self.db.query_row(
                "SELECT grant_id FROM provider_lifecycle_owners WHERE connection_id=?1",
                params![connection_id.to_string()],
                |row| row.get(0),
            )?;
            if owner != grant_id.to_string() {
                bail!("connection already has an unresolved provider authorization");
            }
        }
        Ok(())
    }

    fn release_provider_lifecycle(&self, connection_id: Uuid, grant_id: Uuid) -> Result<()> {
        self.db.execute(
            "DELETE FROM provider_lifecycle_owners WHERE connection_id=?1 AND grant_id=?2",
            params![connection_id.to_string(), grant_id.to_string()],
        )?;
        Ok(())
    }

    /// Loads credential material only for a Rust transport operation. Callers
    /// must never serialize, log, or return these values across an IPC boundary.
    pub fn provider_credentials_for_transport(
        &self,
        grant_id: Uuid,
    ) -> Result<(SecretString, Option<SecretString>)> {
        let grant = self
            .provider_grant(grant_id)?
            .context("provider grant was not found")?;
        if grant.status != crate::GrantStatus::Active {
            bail!("provider grant is not active");
        }
        let mut access_value = self.read_secret_value(&grant.access_secret_ref)?;
        let access = SecretString::from(std::mem::take(&mut *access_value));
        let refresh = grant
            .refresh_secret_ref
            .as_deref()
            .map(|reference| {
                self.read_secret_value(reference)
                    .map(|mut value| SecretString::from(std::mem::take(&mut *value)))
            })
            .transpose()?;
        Ok((access, refresh))
    }

    /// Loads credentials for the one matching durable revocation operation.
    /// The grant remains locally blocked; this cannot mint a normal token lease.
    pub fn provider_credentials_for_revocation(
        &self,
        operation_id: Uuid,
    ) -> Result<(ProviderGrant, SecretString, Option<SecretString>)> {
        let operation = self
            .revocation_operation(operation_id)?
            .context("revocation operation was not found")?;
        let grant = self
            .provider_grant(operation.grant_id)?
            .context("provider grant was not found")?;
        if grant.current_revocation_id != Some(operation_id)
            || !matches!(
                grant.status,
                crate::GrantStatus::RevocationPending
                    | crate::GrantStatus::ProviderRevokedUnverified
                    | crate::GrantStatus::Partial
                    | crate::GrantStatus::LocallyBlocked
            )
        {
            bail!("provider revocation operation does not own this blocked grant");
        }
        let mut access_value = self.read_secret_value(&grant.access_secret_ref)?;
        let access = SecretString::from(std::mem::take(&mut *access_value));
        let refresh = grant
            .refresh_secret_ref
            .as_deref()
            .map(|reference| {
                self.read_secret_value(reference)
                    .map(|mut value| SecretString::from(std::mem::take(&mut *value)))
            })
            .transpose()?;
        Ok((grant, access, refresh))
    }

    pub fn revocation_operations(&self) -> Result<Vec<RevocationOperation>> {
        self.all("revocations", true)
    }

    pub fn revocation_operation(&self, id: Uuid) -> Result<Option<RevocationOperation>> {
        self.by_id("revocations", id)
    }

    pub fn save_provider_grant(&self, grant: &ProviderGrant) -> Result<()> {
        crate::oauth::validate_provider_grant(grant)?;
        if self.connection(grant.connection_id)?.is_none() {
            bail!("provider grant references an unknown connection");
        }
        let existing = self.provider_grant(grant.id)?;
        if grant.status == crate::GrantStatus::Active && existing.is_none() {
            bail!("activate a new provider grant through the journaled credential-custody API");
        }
        if grant.status == crate::GrantStatus::Active {
            self.verify_secret_value(&grant.access_secret_ref)?;
            if let Some(reference) = &grant.refresh_secret_ref {
                self.verify_secret_value(reference)?;
            }
        }
        let transaction = self.db.unchecked_transaction()?;
        self.put("provider_grants", grant.id, grant)?;
        self.receipt(
            "provider_grant.saved",
            &grant.id.to_string(),
            "success",
            &format!("{}:{:?}", grant.resource, grant.status),
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Reserves one authorization lifecycle for a connection before the
    /// browser opens. The reservation contains no credential material, but it
    /// prevents two concurrent callbacks from creating competing grants.
    pub fn reserve_provider_authorization(&self, grant: &ProviderGrant) -> Result<()> {
        if grant.status != crate::GrantStatus::AuthorizationPending {
            bail!("provider authorization reservation must be pending");
        }
        if grant.refresh_secret_ref.is_some() || grant.current_revocation_id.is_some() {
            bail!("provider authorization reservation cannot contain refresh or revocation state");
        }
        crate::oauth::validate_provider_grant(grant)?;
        if self.connection(grant.connection_id)?.is_none() {
            bail!("provider grant references an unknown connection");
        }
        if self.provider_grant(grant.id)?.is_some() {
            bail!("connection already has an unresolved provider authorization");
        }
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            if self.connection(grant.connection_id)?.is_none() {
                bail!("provider grant references an unknown connection");
            }
            if self.provider_grant(grant.id)?.is_some() {
                bail!("connection already has an unresolved provider authorization");
            }
            self.claim_provider_lifecycle(grant.connection_id, grant.id)?;
            self.put("provider_grants", grant.id, grant)?;
            self.receipt(
                "provider_authorization.reserved",
                &grant.id.to_string(),
                "success",
                "no-credentials-issued",
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Removes a browser-flow reservation only while it is still known to
    /// contain no issued credentials.
    pub fn cancel_provider_authorization(&self, grant_id: Uuid) -> Result<()> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let grant = self
                .provider_grant(grant_id)?
                .context("provider authorization reservation was not found")?;
            if grant.status != crate::GrantStatus::AuthorizationPending
                || grant.current_revocation_id.is_some()
            {
                bail!("provider authorization can no longer be cancelled without revocation");
            }
            if self.grant_activation_operations()?.iter().any(|operation| {
                operation.grant_id == grant_id && operation.state != GrantActivationState::Completed
            }) {
                bail!("provider authorization has entered credential custody and must be revoked");
            }
            self.delete_row("provider_grants", grant.id)?;
            self.release_provider_lifecycle(grant.connection_id, grant.id)?;
            self.receipt(
                "provider_authorization.cancelled",
                &grant.id.to_string(),
                "success",
                "no-credentials-issued",
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Removes only old, credential-free browser reservations. Any grant with
    /// an activation journal is handled by `reconcile_grant_activations` and
    /// can never take this deletion path.
    fn reconcile_pending_provider_authorizations(&self) -> Result<()> {
        let activation_grants = self
            .grant_activation_operations()?
            .into_iter()
            .filter(|operation| operation.state != GrantActivationState::Completed)
            .map(|operation| operation.grant_id)
            .collect::<HashSet<_>>();
        for grant in self.provider_grants()? {
            if grant.status != crate::GrantStatus::AuthorizationPending
                || activation_grants.contains(&grant.id)
                || Utc::now() - grant.created_at < chrono::Duration::minutes(10)
            {
                continue;
            }
            let transaction = self.db.unchecked_transaction()?;
            self.delete_row("provider_grants", grant.id)?;
            self.release_provider_lifecycle(grant.connection_id, grant.id)?;
            self.receipt(
                "provider_authorization.expired",
                &grant.id.to_string(),
                "success",
                "credential-free-reservation",
            )?;
            transaction.commit()?;
        }
        Ok(())
    }

    /// Confirms that the platform credential store can complete a full
    /// write/read/delete cycle before an external provider is asked to mint a
    /// credential. This does not eliminate platform failure, but prevents
    /// beginning a browser flow against an already unavailable Keychain.
    pub fn preflight_provider_credential_store(&self) -> Result<()> {
        let label = format!("preflight/{}", Uuid::new_v4());
        self.put_secret_value(&label, &SecretString::from(Uuid::new_v4().to_string()))?;
        let verification = self.verify_secret_value(&label);
        let deletion = self.delete_secret_value(&label);
        verification.and(deletion)
    }

    /// Takes durable custody of every token returned by a completed browser
    /// flow. A refresh-bearing response is never converted into an access-only
    /// grant: it is immediately persisted as locally blocked with a durable,
    /// retryable provider-cleanup operation.
    pub fn complete_provider_authorization(
        &self,
        grant_id: Uuid,
        access_token: &SecretString,
        refresh_token: Option<&SecretString>,
        scopes: Vec<String>,
        access_expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<ProviderGrant> {
        let mut grant = self
            .provider_grant(grant_id)?
            .context("provider authorization reservation was not found")?;
        if grant.status != crate::GrantStatus::AuthorizationPending {
            bail!("provider authorization reservation is no longer pending");
        }
        let mut activation = self
            .grant_activation_operations()?
            .into_iter()
            .find(|operation| {
                operation.grant_id == grant.id && operation.state != GrantActivationState::Completed
            })
            .context("provider token exchange was not journaled before issuance")?;
        let refresh_reference = if refresh_token.is_some() {
            activation.refresh_secret_ref.clone()
        } else {
            None
        };
        grant.refresh_secret_ref = refresh_reference.clone();
        grant.scopes = scopes;
        grant.access_expires_at = access_expires_at;
        crate::oauth::validate_provider_grant(&grant)?;

        activation.refresh_secret_ref = refresh_reference;
        self.put("grant_activations", activation.id, &activation)?;

        if let Err(error) = self.put_secret_value(&grant.access_secret_ref, access_token) {
            activation.state = GrantActivationState::CleanupPending;
            let _ = self.put("grant_activations", activation.id, &activation);
            let _ = self.reconcile_grant_activations();
            return Err(error.context(
                "provider credential custody failed before activation; provider cleanup is required",
            ));
        }
        if let (Some(reference), Some(token)) = (grant.refresh_secret_ref.as_deref(), refresh_token)
            && let Err(error) = self.put_secret_value(reference, token)
        {
            activation.state = GrantActivationState::CleanupPending;
            let _ = self.put("grant_activations", activation.id, &activation);
            let _ = self.reconcile_grant_activations();
            return Err(error.context(
                "provider refresh credential custody failed; provider cleanup is required",
            ));
        }
        activation.state = GrantActivationState::CredentialsWritten;
        if let Err(error) = self.put("grant_activations", activation.id, &activation) {
            let recovery = self.reconcile_grant_activations();
            return match recovery {
                Ok(()) => Err(error.context(
                    "provider credential journal update failed; credentials were retained for retryable cleanup",
                )),
                Err(recovery_error) => Err(error.context(format!(
                    "provider credential journal update failed and reconciliation remains pending: {recovery_error}"
                ))),
            };
        }

        let result = (|| {
            let mut revocation = None;
            grant.status = crate::GrantStatus::Active;
            if grant.refresh_secret_ref.is_some() {
                revocation = Some(crate::oauth::begin_revocation(&mut grant, Utc::now())?);
            }
            let transaction = self.db.unchecked_transaction()?;
            self.put("provider_grants", grant.id, &grant)?;
            if let Some(operation) = &revocation {
                self.put("revocations", operation.id, operation)?;
            }
            activation.state = GrantActivationState::Completed;
            activation.completed_at = Some(Utc::now());
            self.put("grant_activations", activation.id, &activation)?;
            self.receipt(
                if revocation.is_some() {
                    "provider_authorization.cleanup_required"
                } else {
                    "provider_grant.activated"
                },
                &grant.id.to_string(),
                "success",
                if revocation.is_some() {
                    "all-issued-credentials-retained;local-use-blocked;provider-cleanup-pending"
                } else {
                    "access-only-credential-activated"
                },
            )?;
            transaction.commit()?;
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(error) = result {
            // The activation journal and pending grant were committed before
            // credential writes. Reconciliation promotes them to a blocked
            // cleanup lifecycle rather than deleting an unrevoked credential.
            let recovery = self.reconcile_grant_activations();
            return match recovery {
                Ok(()) => Err(error.context(
                    "provider authorization could not activate; credentials were retained for retryable cleanup",
                )),
                Err(recovery_error) => Err(error.context(format!(
                    "provider authorization could not activate and cleanup reconciliation remains pending: {recovery_error}"
                ))),
            };
        }
        self.provider_grant(grant.id)?
            .context("completed provider grant was not found")
    }

    /// Marks that the one-shot token request is about to be submitted. This
    /// journal is committed before external issuance can occur, closing the
    /// exchange-success/process-crash window. The refresh reference is
    /// preallocated because a conforming server may return a refresh token even
    /// when active refresh use is disabled by Cargo policy.
    pub fn begin_provider_token_exchange(&self, grant_id: Uuid) -> Result<()> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let grant = self
                .provider_grant(grant_id)?
                .context("provider authorization reservation was not found")?;
            if grant.status != crate::GrantStatus::AuthorizationPending {
                bail!("provider authorization reservation is no longer pending");
            }
            if self.grant_activation_operations()?.iter().any(|operation| {
                operation.grant_id == grant_id && operation.state != GrantActivationState::Completed
            }) {
                bail!("provider token exchange was already started");
            }
            let operation = GrantActivationOperation {
                id: Uuid::new_v4(),
                grant_id,
                access_secret_ref: grant.access_secret_ref.clone(),
                refresh_secret_ref: Some(crate::oauth::new_secret_reference(grant.id, "refresh")?),
                state: GrantActivationState::Staged,
                created_at: Utc::now(),
                completed_at: None,
            };
            self.put("grant_activations", operation.id, &operation)?;
            self.receipt(
                "provider_authorization.exchange_started",
                &operation.id.to_string(),
                "success",
                "issuance-may-occur;credential-references-only",
            )?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Conservatively reconciles a token request whose outcome is ambiguous.
    /// Once an exchange intent exists, no generic network or protocol error is
    /// treated as proof that the provider minted nothing.
    pub fn reconcile_provider_authorizations(&self) -> Result<()> {
        self.reconcile_grant_activations()?;
        self.reconcile_pending_provider_authorizations()
    }

    /// Commits token custody and active grant metadata as a compensating
    /// transaction. Secret values are verified in Keychain before the encrypted
    /// grant record becomes Active; DB failure removes both staged credentials.
    pub fn activate_provider_grant(
        &self,
        grant: &ProviderGrant,
        access_token: SecretString,
        refresh_token: Option<SecretString>,
    ) -> Result<()> {
        if grant.status != crate::GrantStatus::Active {
            bail!("newly activated provider grant must be Active");
        }
        if refresh_token.is_some() != grant.refresh_secret_ref.is_some() {
            bail!("refresh token and refresh secret reference must agree");
        }
        crate::oauth::validate_provider_grant(grant)?;
        if self.connection(grant.connection_id)?.is_none() {
            bail!("provider grant references an unknown connection");
        }
        if self.provider_grant(grant.id)?.is_some() {
            bail!("provider grant already exists");
        }
        if self.provider_grants()?.iter().any(|existing| {
            existing.connection_id == grant.connection_id && !existing.status.is_terminal()
        }) {
            bail!("connection already has an unresolved provider authorization");
        }
        let mut operation = GrantActivationOperation {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            access_secret_ref: grant.access_secret_ref.clone(),
            refresh_secret_ref: grant.refresh_secret_ref.clone(),
            state: GrantActivationState::Staged,
            created_at: Utc::now(),
            completed_at: None,
        };
        let transaction = self.db.unchecked_transaction()?;
        self.put("grant_activations", operation.id, &operation)?;
        self.receipt(
            "provider_grant.activation_staged",
            &operation.id.to_string(),
            "success",
            "credential-references-only",
        )?;
        transaction.commit()?;

        if let Err(error) = self.put_secret_value(&grant.access_secret_ref, &access_token) {
            operation.state = GrantActivationState::CleanupPending;
            self.put("grant_activations", operation.id, &operation)?;
            self.reconcile_grant_activations()?;
            return Err(error);
        }
        if let (Some(reference), Some(token)) = (grant.refresh_secret_ref.as_deref(), refresh_token)
            && let Err(error) = self.put_secret_value(reference, &token)
        {
            operation.state = GrantActivationState::CleanupPending;
            self.put("grant_activations", operation.id, &operation)?;
            self.reconcile_grant_activations()?;
            return Err(error);
        }
        operation.state = GrantActivationState::CredentialsWritten;
        self.put("grant_activations", operation.id, &operation)?;
        let result = (|| {
            let transaction = self.db.unchecked_transaction()?;
            self.put("provider_grants", grant.id, grant)?;
            operation.state = GrantActivationState::Completed;
            operation.completed_at = Some(Utc::now());
            self.put("grant_activations", operation.id, &operation)?;
            self.receipt(
                "provider_grant.activated",
                &grant.id.to_string(),
                "success",
                &format!("{}:{:?}", grant.resource, grant.status),
            )?;
            transaction.commit()?;
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(error) = result {
            operation.state = GrantActivationState::CleanupPending;
            let journal_result = self.put("grant_activations", operation.id, &operation);
            let cleanup_result = self.reconcile_grant_activations();
            if let Err(cleanup_error) = journal_result.and(cleanup_result) {
                return Err(error.context(format!(
                    "provider activation failed and credential cleanup remains pending: {cleanup_error}"
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    fn reconcile_grant_activations(&self) -> Result<()> {
        for mut operation in self.grant_activation_operations()? {
            if operation.state == GrantActivationState::Completed {
                continue;
            }
            if let Some(mut grant) = self.provider_grant(operation.grant_id)?
                && grant.status == crate::GrantStatus::AuthorizationPending
            {
                // A credential-store write can return an ambiguous error after
                // persisting. Once an issuance journal exists, never infer
                // "no credentials" from the journal phase or delete custody.
                // Inspect only to produce redacted recovery evidence; every
                // issued reference is retained in a blocked cleanup lifecycle.
                let access_present = self.secret_value_exists(&operation.access_secret_ref)?;
                let refresh_present = operation
                    .refresh_secret_ref
                    .as_deref()
                    .map(|reference| self.secret_value_exists(reference))
                    .transpose()?
                    .unwrap_or(false);
                grant.access_secret_ref = operation.access_secret_ref.clone();
                grant.refresh_secret_ref = operation.refresh_secret_ref.clone();
                grant.status = crate::GrantStatus::Active;
                let revocation = crate::oauth::begin_revocation(&mut grant, Utc::now())?;
                operation.state = GrantActivationState::Completed;
                operation.completed_at = Some(Utc::now());
                let transaction = self.db.unchecked_transaction()?;
                self.put("provider_grants", grant.id, &grant)?;
                self.put("revocations", revocation.id, &revocation)?;
                self.put("grant_activations", operation.id, &operation)?;
                self.receipt(
                    "provider_grant.activation_recovered",
                    &operation.id.to_string(),
                    "success",
                    &format!(
                        "local-use-blocked;provider-cleanup-pending;access-custody:{access_present};refresh-custody:{refresh_present}"
                    ),
                )?;
                transaction.commit()?;
                continue;
            }
            if let Some(grant) = self.provider_grant(operation.grant_id)?
                && grant.status != crate::GrantStatus::AuthorizationPending
            {
                bail!("incomplete activation journal conflicts with a provider grant");
            }
            operation.state = GrantActivationState::CleanupPending;
            self.put("grant_activations", operation.id, &operation)?;
            self.delete_secret_value(&operation.access_secret_ref)?;
            if let Some(reference) = &operation.refresh_secret_ref {
                self.delete_secret_value(reference)?;
            }
            if self
                .provider_grant(operation.grant_id)?
                .is_some_and(|grant| grant.status == crate::GrantStatus::AuthorizationPending)
            {
                if let Some(grant) = self.provider_grant(operation.grant_id)? {
                    self.release_provider_lifecycle(grant.connection_id, grant.id)?;
                }
                self.delete_row("provider_grants", operation.grant_id)?;
            }
            operation.state = GrantActivationState::Completed;
            operation.completed_at = Some(Utc::now());
            let transaction = self.db.unchecked_transaction()?;
            self.put("grant_activations", operation.id, &operation)?;
            self.receipt(
                "provider_grant.activation_reconciled",
                &operation.id.to_string(),
                "success",
                "orphaned-credential-references-deleted",
            )?;
            transaction.commit()?;
        }
        Ok(())
    }

    /// Durably blocks local use before the caller performs any provider I/O.
    pub fn begin_provider_revocation(&self, grant_id: Uuid) -> Result<RevocationOperation> {
        let mut grant = self
            .provider_grant(grant_id)?
            .context("provider grant was not found")?;
        let operation = crate::oauth::begin_revocation(&mut grant, Utc::now())?;
        let transaction = self.db.unchecked_transaction()?;
        self.put("provider_grants", grant.id, &grant)?;
        self.put("revocations", operation.id, &operation)?;
        self.receipt(
            "provider_revocation.local_blocked",
            &operation.id.to_string(),
            "success",
            "local-token-leases-denied;provider-pending",
        )?;
        transaction.commit()?;
        Ok(operation)
    }

    pub fn record_provider_revocation_attempt(
        &self,
        operation_id: Uuid,
        access_result: TokenRevocationResult,
        refresh_result: TokenRevocationResult,
        next_retry_at: Option<chrono::DateTime<Utc>>,
        safe_error_code: Option<&str>,
    ) -> Result<ProviderGrant> {
        let mut operation = self
            .revocation_operation(operation_id)?
            .context("revocation operation was not found")?;
        let mut grant = self
            .provider_grant(operation.grant_id)?
            .context("provider grant was not found")?;
        crate::oauth::record_provider_attempt(
            &mut grant,
            &mut operation,
            access_result,
            refresh_result,
            next_retry_at,
            safe_error_code,
        )?;
        let transaction = self.db.unchecked_transaction()?;
        self.put("provider_grants", grant.id, &grant)?;
        self.put("revocations", operation.id, &operation)?;
        if grant.status.is_terminal() {
            self.release_provider_lifecycle(grant.connection_id, grant.id)?;
        }
        self.receipt(
            "provider_revocation.attempted",
            &operation.id.to_string(),
            "success",
            &format!("attempt:{};status:{:?}", operation.attempts, grant.status),
        )?;
        transaction.commit()?;
        Ok(grant)
    }

    pub fn record_provider_revocation_verification(
        &self,
        operation_id: Uuid,
        verification: RevocationVerification,
    ) -> Result<ProviderGrant> {
        let mut operation = self
            .revocation_operation(operation_id)?
            .context("revocation operation was not found")?;
        let mut grant = self
            .provider_grant(operation.grant_id)?
            .context("provider grant was not found")?;
        crate::oauth::record_verification(&mut grant, &mut operation, verification, Utc::now())?;
        let transaction = self.db.unchecked_transaction()?;
        self.put("provider_grants", grant.id, &grant)?;
        self.put("revocations", operation.id, &operation)?;
        if grant.status.is_terminal() {
            self.release_provider_lifecycle(grant.connection_id, grant.id)?;
        }
        self.receipt(
            "provider_revocation.verified",
            &operation.id.to_string(),
            "success",
            &format!(
                "status:{:?};evidence:{:?}",
                grant.status, operation.verification
            ),
        )?;
        transaction.commit()?;
        Ok(grant)
    }

    /// Finalizes a verified provider revocation only after both local credential
    /// references have been idempotently removed from the OS credential store.
    pub fn finalize_provider_revocation(&self, operation_id: Uuid) -> Result<ProviderGrant> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut operation = self
                .revocation_operation(operation_id)?
                .context("revocation operation was not found")?;
            let mut grant = self
                .provider_grant(operation.grant_id)?
                .context("provider grant was not found")?;
            // Ownership, current operation ID, revision, and evidence state are
            // validated while the write lock is held and before Keychain is
            // touched. The in-memory terminal transition is persisted only
            // after idempotent credential deletion succeeds.
            crate::oauth::confirm_local_cleanup(&mut grant, &mut operation, Utc::now())?;
            self.delete_secret_value(&grant.access_secret_ref)?;
            if let Some(reference) = &grant.refresh_secret_ref {
                self.delete_secret_value(reference)?;
            }
            self.put("provider_grants", grant.id, &grant)?;
            self.put("revocations", operation.id, &operation)?;
            self.release_provider_lifecycle(grant.connection_id, grant.id)?;
            self.receipt(
                "provider_revocation.local_cleanup_complete",
                &operation.id.to_string(),
                "success",
                "credential-references-deleted",
            )?;
            Ok::<ProviderGrant, anyhow::Error>(grant)
        })();
        match result {
            Ok(grant) => {
                self.db.execute_batch("COMMIT")?;
                Ok(grant)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn deployment(&self, id: Uuid) -> Result<Option<ManagedDeployment>> {
        self.by_id("deployments", id)
    }

    pub fn save_deployment(&self, deployment: &ManagedDeployment) -> Result<()> {
        let transaction = self.db.unchecked_transaction()?;
        self.put("deployments", deployment.id, deployment)?;
        self.receipt(
            "deployment.state",
            &deployment.id.to_string(),
            "success",
            &format!("{}:{:?}", deployment.host, deployment.state),
        )?;
        transaction.commit()?;
        Ok(())
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

    fn delete_row(&self, table: &str, id: Uuid) -> Result<()> {
        let affected = self.db.execute(
            &format!("DELETE FROM {table} WHERE id=?1"),
            params![id.to_string()],
        )?;
        if affected != 1 {
            bail!("record was not found");
        }
        Ok(())
    }

    fn count(&self, table: &str) -> Result<usize> {
        let count: i64 =
            self.db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
        usize::try_from(count).context("record count was invalid")
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
        self.import_pack_transaction(pack, None)
    }

    /// Imports a previewed pack only if the profile visible inside the same
    /// immediate SQLite transaction still matches the preview precondition.
    pub fn import_pack_if_profile(
        &self,
        pack: &PortablePack,
        expected_profile_id: Option<Uuid>,
    ) -> Result<PackImportResult> {
        self.import_pack_transaction(pack, Some(expected_profile_id))
    }

    fn import_pack_transaction(
        &self,
        pack: &PortablePack,
        expected_profile_id: Option<Option<Uuid>>,
    ) -> Result<PackImportResult> {
        let pack = validate_portable_pack(pack)?;

        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            if let Some(expected_profile_id) = expected_profile_id {
                let current_profile_id = self.profile()?.map(|profile| profile.id);
                if current_profile_id != expected_profile_id {
                    bail!("the local profile changed after this preview; no records were imported");
                }
            }
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
                self.db.execute_batch("COMMIT")?;
                Ok(result)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn put_secret_value(&self, label: &str, secret: &SecretString) -> Result<()> {
        keyring::Entry::new(KEYRING_SERVICE, label)?.set_password(secret.expose_secret())?;
        self.verify_secret_value(label)
    }

    fn verify_secret_value(&self, label: &str) -> Result<()> {
        let mut secret = self.read_secret_value(label)?;
        if secret.is_empty() {
            bail!("provider credential is empty");
        }
        secret.zeroize();
        Ok(())
    }

    fn read_secret_value(&self, label: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            keyring::Entry::new(KEYRING_SERVICE, label)?
                .get_password()
                .context("provider credential is missing from the OS credential store")?,
        ))
    }

    fn secret_value_exists(&self, label: &str) -> Result<bool> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, label)?;
        match entry.get_password() {
            Ok(mut value) => {
                let present = !value.is_empty();
                value.zeroize();
                Ok(present)
            }
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn delete_secret_value(&self, label: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, label)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
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
            "execution_grants",
            "execution_credential_activations",
            "provider_grants",
            "grant_activations",
            "revocations",
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

fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.trim().is_empty() || display_name.chars().count() > 200 {
        bail!("display name must be between 1 and 200 characters");
    }
    Ok(())
}

fn validate_memory(memory: &MemoryRecord) -> Result<()> {
    if memory.title.trim().is_empty()
        || memory.title.chars().count() > 200
        || memory.body.trim().is_empty()
        || memory.body.len() > 256 * 1024
        || memory.allowed_hosts.len() > 64
        || memory.allowed_hosts.iter().any(|host| host.len() > 200)
    {
        bail!("memory record contains invalid or oversized fields");
    }
    Ok(())
}

pub fn validate_portable_pack(pack: &PortablePack) -> Result<PortablePack> {
    if pack.format != "cargo-ai-pack" || pack.version != 2 || pack.contains_secrets {
        bail!("unsupported portable pack format, version, or secret-content flag");
    }
    if pack.connections.len() > 2_000 || pack.memory.len() > 10_000 {
        bail!("portable pack exceeds record-count limits");
    }
    validate_display_name(&pack.profile.display_name)
        .context("portable pack contains an invalid profile")?;
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
        validate_memory(memory).context("portable pack contains an invalid memory record")?;
    }
    let mut validated = pack.clone();
    validated.profile.display_name = validated.profile.display_name.trim().into();
    validated.connections = connections;
    Ok(validated)
}

fn normalize_vault_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let file_name = absolute
        .file_name()
        .context("vault path must include a filename")?
        .to_os_string();
    let parent = absolute.parent().context("vault path has no parent")?;
    let existed = parent.exists();
    fs::create_dir_all(parent)?;
    if !existed {
        set_private_directory(parent)?;
    }
    let parent = fs::canonicalize(parent)?;
    validate_private_vault_parent(&parent)?;
    let normalized = parent.join(file_name);
    if normalized.exists() {
        let metadata = fs::symlink_metadata(&normalized)?;
        if metadata.file_type().is_symlink() {
            bail!("refusing a symlinked vault database");
        }
        if !metadata.is_file() {
            bail!("vault database path is not a regular file");
        }
        validate_existing_vault_file(&metadata)?;
    }
    Ok(normalized)
}

#[cfg(unix)]
fn validate_existing_vault_file(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("vault database must be private, current-user-owned, and have one filesystem link");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_existing_vault_file(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_vault_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("vault parent directory must be private and owned by the current user");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_vault_parent(path: &Path) -> Result<()> {
    if !fs::metadata(path)?.is_dir() {
        bail!("vault parent path is not a directory");
    }
    Ok(())
}

fn open_private_lock_file(path: &Path) -> Result<File> {
    let parent = path.parent().context("credential lock has no parent")?;
    validate_private_vault_parent(parent)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    set_private_file_handle(&file)?;
    validate_lock_file_identity(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn set_private_file_handle(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_handle(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_lock_file_identity(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let handle = file.metadata()?;
    let linked = fs::symlink_metadata(path)?;
    if !handle.is_file()
        || linked.file_type().is_symlink()
        || !linked.is_file()
        || handle.uid() != unsafe { libc::geteuid() }
        || handle.nlink() != 1
        || handle.permissions().mode() & 0o077 != 0
        || handle.dev() != linked.dev()
        || handle.ino() != linked.ino()
    {
        bail!("execution credential lock identity is unsafe or changed");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_lock_file_identity(file: &File, path: &Path) -> Result<()> {
    let handle = file.metadata()?;
    let linked = fs::symlink_metadata(path)?;
    if !handle.is_file() || linked.file_type().is_symlink() || !linked.is_file() {
        bail!("execution credential lock identity is unsafe or changed");
    }
    Ok(())
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
    fn profile_and_memory_lifecycle_is_receipted() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(dir.path().join("vault.db"), [12; 32]).unwrap();
        let original = vault.create_profile("Ada").unwrap();
        let renamed = vault.rename_profile("Ada Lovelace").unwrap();
        assert_eq!(renamed.id, original.id);
        assert_eq!(renamed.created_at, original.created_at);

        let mut memory = MemoryRecord {
            id: Uuid::new_v4(),
            title: "Working style".into(),
            body: "Be concise".into(),
            sensitivity: crate::Sensitivity::Private,
            allowed_hosts: vec!["Codex".into()],
            created_at: Utc::now(),
        };
        vault.add_memory(&memory).unwrap();
        memory.body = "Be concise and surface tradeoffs".into();
        vault.update_memory(&memory).unwrap();
        assert_eq!(
            vault.memory_record(memory.id).unwrap(),
            Some(memory.clone())
        );
        vault.delete_memory(memory.id).unwrap();
        assert!(vault.memory_record(memory.id).unwrap().is_none());
        let actions = vault
            .receipts()
            .unwrap()
            .into_iter()
            .map(|receipt| receipt.action)
            .collect::<Vec<_>>();
        assert!(actions.contains(&"profile.renamed".into()));
        assert!(actions.contains(&"memory.updated".into()));
        assert!(actions.contains(&"memory.deleted".into()));
        assert!(vault.verify_receipt_chain().unwrap());
    }

    #[test]
    fn manual_connection_creation_is_validated_and_receipted() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [49_u8; 32]).unwrap();
        vault.create_profile("Manual connection").unwrap();
        let definition = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "manual-remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: BTreeMap::from([
                ("source".into(), "manual".into()),
                ("source_path".into(), "/Users/example/private".into()),
            ]),
        };

        let created = vault.create_connection(&definition).unwrap();
        assert_eq!(created.url.as_deref(), Some("https://mcp.example/resource"));
        assert!(created.environment_keys.is_empty());
        assert!(!created.metadata.contains_key("source_path"));
        assert_eq!(vault.connections().unwrap(), vec![created]);
        assert!(
            vault
                .receipts()
                .unwrap()
                .iter()
                .any(|receipt| receipt.action == "connection.created")
        );
    }

    #[test]
    fn manual_connection_creation_rejects_invalid_definitions_without_writes() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [50_u8; 32]).unwrap();
        vault.create_profile("Invalid connection").unwrap();
        let invalid = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "--scope".into(),
            transport: "stdio".into(),
            command: Some("   ".into()),
            args: vec![],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::from([("source".into(), "manual".into())]),
        };
        assert!(vault.create_connection(&invalid).is_err());

        let insecure = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "insecure".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("http://example.com/mcp".into()),
            environment_keys: vec![],
            metadata: BTreeMap::from([("source".into(), "manual".into())]),
        };
        assert!(vault.create_connection(&insecure).is_err());

        for (name, command, args, url) in [
            (
                "signed-url",
                None,
                vec![],
                Some("https://mcp.example/mcp?X-Amz-Signature=opaquecredential".into()),
            ),
            (
                "header-secret",
                Some("mcp-server".into()),
                vec![
                    "--header".into(),
                    "Authorization: Bearer opaquecredential".into(),
                ],
                None,
            ),
            (
                "credential-flag",
                Some("mcp-server".into()),
                vec!["--credential".into(), "opaquecredential".into()],
                None,
            ),
            (
                "secret-command",
                Some("sk-opaquecredential".into()),
                vec![],
                None,
            ),
            (
                "private-inline-url",
                Some("mcp-server".into()),
                vec!["--endpoint=https://example.test/mcp?sig=opaquecredential".into()],
                None,
            ),
            (
                "cookie-secret",
                Some("mcp-server".into()),
                vec!["--cookie".into(), "session=opaquecredential".into()],
                None,
            ),
        ] {
            let transport = if command.is_some() {
                "stdio"
            } else {
                "streamable_http"
            };
            let secret_bearing = ConnectionDefinition {
                id: Uuid::new_v4(),
                name: name.into(),
                transport: transport.into(),
                command,
                args,
                url,
                environment_keys: vec![],
                metadata: BTreeMap::from([("source".into(), "manual".into())]),
            };
            assert!(vault.create_connection(&secret_bearing).is_err());
        }
        assert!(vault.connections().unwrap().is_empty());
    }

    #[test]
    fn manual_stdio_preserves_exact_nonsecret_arguments() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [52_u8; 32]).unwrap();
        vault.create_profile("Exact arguments").unwrap();
        let definition = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "manual-stdio".into(),
            transport: "stdio".into(),
            command: Some(" /usr/local/bin/mcp-server ".into()),
            args: vec![
                "  spaced value  ".into(),
                "".into(),
                "--read-only".into(),
                "--endpoint=https://example.test/mcp".into(),
            ],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::from([("source".into(), "manual".into())]),
        };

        let created = vault.create_connection(&definition).unwrap();
        assert_eq!(
            created.command.as_deref(),
            Some("/usr/local/bin/mcp-server")
        );
        assert_eq!(created.args, definition.args);
    }

    #[test]
    fn separate_vault_handles_cannot_create_duplicate_connection_names() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [51_u8; 32]).unwrap();
        first.create_profile("Connection race").unwrap();
        let second = Vault::open_with_key(&path, [51_u8; 32]).unwrap();
        let make_definition = || ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "unique-name".into(),
            transport: "stdio".into(),
            command: Some("/usr/bin/true".into()),
            args: vec![],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::from([("source".into(), "manual".into())]),
        };

        first.create_connection(&make_definition()).unwrap();
        assert!(second.create_connection(&make_definition()).is_err());
        assert_eq!(second.connection_count().unwrap(), 1);
    }

    #[test]
    fn connection_delete_refuses_active_managed_deployment() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(dir.path().join("vault.db"), [13; 32]).unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "example".into(),
            transport: "stdio".into(),
            command: Some("example-mcp".into()),
            args: vec![],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::new(),
        };
        vault.upsert_connection(&connection).unwrap();
        let mut deployment = ManagedDeployment {
            id: Uuid::new_v4(),
            connection_id: connection.id,
            host: "Cursor".into(),
            server_name: "example".into(),
            config_path: "/tmp/mcp.json".into(),
            preimage_sha256: None,
            installed_fragment_sha256: "abc".into(),
            backup_path: None,
            state: DeploymentState::Active,
            installed_at: Utc::now(),
        };
        vault.save_deployment(&deployment).unwrap();
        assert!(vault.delete_connection(connection.id).is_err());
        for state in [
            DeploymentState::LocalBlocked,
            DeploymentState::Conflict,
            DeploymentState::Failed,
        ] {
            deployment.state = state;
            vault.save_deployment(&deployment).unwrap();
            assert!(vault.delete_connection(connection.id).is_err());
        }
        deployment.state = DeploymentState::HostRemoved;
        vault.save_deployment(&deployment).unwrap();
        vault.delete_connection(connection.id).unwrap();
        assert!(vault.connection(connection.id).unwrap().is_none());
        assert!(vault.verify_receipt_chain().unwrap());
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
    fn conditional_pack_import_rejects_a_cross_process_profile_change() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Vault::open_with_key(source_dir.path().join("source.db"), [14; 32]).unwrap();
        source.create_profile("Source").unwrap();
        source
            .add_memory(&MemoryRecord {
                id: Uuid::new_v4(),
                title: "Conditional import".into(),
                body: "This record must not cross a stale preview".into(),
                sensitivity: crate::Sensitivity::Private,
                allowed_hosts: vec![],
                created_at: Utc::now(),
            })
            .unwrap();
        let pack = source.export_safe().unwrap();

        let target_dir = tempfile::tempdir().unwrap();
        let target_path = target_dir.path().join("target.db");
        let preview_handle = Vault::open_with_key(&target_path, [15; 32]).unwrap();
        let competing_handle = Vault::open_with_key(&target_path, [15; 32]).unwrap();
        competing_handle
            .create_profile("Competing Profile")
            .unwrap();

        let error = preview_handle
            .import_pack_if_profile(&pack, None)
            .unwrap_err();
        assert!(error.to_string().contains("profile changed"));
        assert!(preview_handle.memory().unwrap().is_empty());
        assert!(preview_handle.connections().unwrap().is_empty());
        assert_eq!(
            preview_handle.profile().unwrap().unwrap().display_name,
            "Competing Profile"
        );
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

    #[test]
    fn provider_revocation_is_encrypted_durable_and_honest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = [21; 32];
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote-tools".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example.com/tools".into()),
            environment_keys: vec![],
            metadata: BTreeMap::new(),
        };
        let grant_id = Uuid::new_v4();
        let grant = ProviderGrant {
            id: grant_id,
            connection_id: connection.id,
            resource: "https://mcp.example.com/tools".into(),
            issuer: "https://auth.example.com".into(),
            client_id: "cargo-public-client".into(),
            registration_kind: crate::ClientRegistrationKind::DynamicPublic,
            scopes: vec!["tools.read".into()],
            access_expires_at: None,
            access_secret_ref: crate::oauth::new_secret_reference(grant_id, "access").unwrap(),
            refresh_secret_ref: Some(
                crate::oauth::new_secret_reference(grant_id, "refresh").unwrap(),
            ),
            status: crate::GrantStatus::ReauthRequired,
            current_revocation_id: None,
            revision: 0,
            created_at: Utc::now(),
            last_verified_at: None,
        };
        let operation_id;
        {
            let vault = Vault::open_with_key(&path, key).unwrap();
            vault.create_profile("OAuth test").unwrap();
            vault.upsert_connection(&connection).unwrap();
            vault.save_provider_grant(&grant).unwrap();
            assert!(vault.delete_connection(connection.id).is_err());
            let operation = vault.begin_provider_revocation(grant.id).unwrap();
            operation_id = operation.id;
            let pending = vault
                .record_provider_revocation_attempt(
                    operation.id,
                    TokenRevocationResult::RetryableFailure,
                    TokenRevocationResult::NotAttempted,
                    Some(Utc::now() + chrono::Duration::minutes(1)),
                    Some("network_unavailable"),
                )
                .unwrap();
            assert_eq!(pending.status, crate::GrantStatus::RevocationPending);
            assert!(!vault.raw_documents_contain("cargo-public-client").unwrap());
            assert!(
                !serde_json::to_string(&vault.export_safe().unwrap())
                    .unwrap()
                    .contains("provider_grant")
            );
        }
        let reopened = Vault::open_with_key(&path, key).unwrap();
        let operation = reopened
            .revocation_operation(operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.attempts, 1);
        assert_eq!(
            reopened.provider_grant(grant.id).unwrap().unwrap().status,
            crate::GrantStatus::RevocationPending
        );
        assert!(reopened.verify_receipt_chain().unwrap());
    }

    #[test]
    fn activation_rejects_a_second_nonterminal_grant_for_one_connection() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [43_u8; 32]).unwrap();
        vault.create_profile("Uniqueness").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        vault.upsert_connection(&connection).unwrap();

        let make_grant = |id| ProviderGrant {
            id,
            connection_id: connection.id,
            resource: "https://mcp.example/resource".into(),
            issuer: "https://issuer.example".into(),
            client_id: "public-client".into(),
            registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
            scopes: vec!["read".into()],
            access_expires_at: Some(Utc::now() + chrono::Duration::minutes(5)),
            access_secret_ref: crate::oauth::new_secret_reference(id, "access").unwrap(),
            refresh_secret_ref: None,
            status: crate::GrantStatus::Active,
            current_revocation_id: None,
            revision: 0,
            created_at: Utc::now(),
            last_verified_at: None,
        };
        let first = make_grant(Uuid::new_v4());
        vault
            .activate_provider_grant(&first, SecretString::from("access-one"), None)
            .unwrap();
        let second = make_grant(Uuid::new_v4());
        assert!(
            vault
                .activate_provider_grant(&second, SecretString::from("access-two"), None)
                .is_err()
        );
        assert!(vault.provider_grant(second.id).unwrap().is_none());
    }

    #[test]
    fn refresh_issuance_is_custodied_and_locally_blocked_before_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [44_u8; 32]).unwrap();
        vault.create_profile("Provisional custody").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        vault.upsert_connection(&connection).unwrap();
        let grant_id = Uuid::new_v4();
        let reservation = ProviderGrant {
            id: grant_id,
            connection_id: connection.id,
            resource: "https://mcp.example/resource".into(),
            issuer: "https://issuer.example".into(),
            client_id: "public-client".into(),
            registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
            scopes: vec!["read".into()],
            access_expires_at: None,
            access_secret_ref: crate::oauth::new_secret_reference(grant_id, "access").unwrap(),
            refresh_secret_ref: None,
            status: crate::GrantStatus::AuthorizationPending,
            current_revocation_id: None,
            revision: 0,
            created_at: Utc::now(),
            last_verified_at: None,
        };
        vault.reserve_provider_authorization(&reservation).unwrap();
        vault.begin_provider_token_exchange(grant_id).unwrap();
        let access = SecretString::from("access-token");
        let refresh = SecretString::from("refresh-token");
        let grant = vault
            .complete_provider_authorization(
                grant_id,
                &access,
                Some(&refresh),
                vec!["read".into()],
                Some(Utc::now() + chrono::Duration::minutes(5)),
            )
            .unwrap();
        assert_eq!(grant.status, crate::GrantStatus::RevocationPending);
        let operation_id = grant.current_revocation_id.unwrap();
        let (_, stored_access, stored_refresh) = vault
            .provider_credentials_for_revocation(operation_id)
            .unwrap();
        assert_eq!(stored_access.expose_secret(), "access-token");
        assert_eq!(stored_refresh.unwrap().expose_secret(), "refresh-token");
        vault.delete_secret_value(&grant.access_secret_ref).unwrap();
        vault
            .delete_secret_value(grant.refresh_secret_ref.as_deref().unwrap())
            .unwrap();
    }

    #[test]
    fn staged_issuance_journal_is_promoted_to_blocked_cleanup_not_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [45_u8; 32]).unwrap();
        vault.create_profile("Crash recovery").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        vault.upsert_connection(&connection).unwrap();
        let grant_id = Uuid::new_v4();
        let access_ref = crate::oauth::new_secret_reference(grant_id, "access").unwrap();
        let refresh_ref = crate::oauth::new_secret_reference(grant_id, "refresh").unwrap();
        let reservation = ProviderGrant {
            id: grant_id,
            connection_id: connection.id,
            resource: "https://mcp.example/resource".into(),
            issuer: "https://issuer.example".into(),
            client_id: "public-client".into(),
            registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
            scopes: vec!["read".into()],
            access_expires_at: None,
            access_secret_ref: access_ref.clone(),
            refresh_secret_ref: None,
            status: crate::GrantStatus::AuthorizationPending,
            current_revocation_id: None,
            revision: 0,
            created_at: Utc::now(),
            last_verified_at: None,
        };
        vault.reserve_provider_authorization(&reservation).unwrap();
        let activation = GrantActivationOperation {
            id: Uuid::new_v4(),
            grant_id,
            access_secret_ref: access_ref.clone(),
            refresh_secret_ref: Some(refresh_ref.clone()),
            state: GrantActivationState::Staged,
            created_at: Utc::now(),
            completed_at: None,
        };
        vault
            .put("grant_activations", activation.id, &activation)
            .unwrap();
        vault
            .put_secret_value(&access_ref, &SecretString::from("access"))
            .unwrap();
        vault
            .put_secret_value(&refresh_ref, &SecretString::from("refresh"))
            .unwrap();
        vault.reconcile_grant_activations().unwrap();
        let recovered = vault.provider_grant(grant_id).unwrap().unwrap();
        assert_eq!(recovered.status, crate::GrantStatus::RevocationPending);
        assert_eq!(
            recovered.refresh_secret_ref.as_deref(),
            Some(refresh_ref.as_str())
        );
        assert!(recovered.current_revocation_id.is_some());
        assert!(vault.cancel_provider_authorization(grant_id).is_err());
        vault.delete_secret_value(&access_ref).unwrap();
        vault.delete_secret_value(&refresh_ref).unwrap();
    }

    #[test]
    fn stale_credential_free_authorization_reservation_expires() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [46_u8; 32]).unwrap();
        vault.create_profile("Expiry").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        vault.upsert_connection(&connection).unwrap();
        let grant_id = Uuid::new_v4();
        vault
            .reserve_provider_authorization(&ProviderGrant {
                id: grant_id,
                connection_id: connection.id,
                resource: "https://mcp.example/resource".into(),
                issuer: "https://issuer.example".into(),
                client_id: "public-client".into(),
                registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
                scopes: vec![],
                access_expires_at: None,
                access_secret_ref: crate::oauth::new_secret_reference(grant_id, "access").unwrap(),
                refresh_secret_ref: None,
                status: crate::GrantStatus::AuthorizationPending,
                current_revocation_id: None,
                revision: 0,
                created_at: Utc::now() - chrono::Duration::minutes(11),
                last_verified_at: None,
            })
            .unwrap();
        vault.reconcile_pending_provider_authorizations().unwrap();
        assert!(vault.provider_grant(grant_id).unwrap().is_none());
    }

    #[test]
    fn pre_exchange_intent_prevents_credential_free_expiry_after_crash() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [47_u8; 32]).unwrap();
        vault.create_profile("Exchange crash").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        vault.upsert_connection(&connection).unwrap();
        let grant_id = Uuid::new_v4();
        vault
            .reserve_provider_authorization(&ProviderGrant {
                id: grant_id,
                connection_id: connection.id,
                resource: "https://mcp.example/resource".into(),
                issuer: "https://issuer.example".into(),
                client_id: "public-client".into(),
                registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
                scopes: vec!["read".into()],
                access_expires_at: None,
                access_secret_ref: crate::oauth::new_secret_reference(grant_id, "access").unwrap(),
                refresh_secret_ref: None,
                status: crate::GrantStatus::AuthorizationPending,
                current_revocation_id: None,
                revision: 0,
                created_at: Utc::now() - chrono::Duration::minutes(11),
                last_verified_at: None,
            })
            .unwrap();
        vault.begin_provider_token_exchange(grant_id).unwrap();
        vault.reconcile_grant_activations().unwrap();
        vault.reconcile_pending_provider_authorizations().unwrap();
        let recovered = vault.provider_grant(grant_id).unwrap().unwrap();
        assert_eq!(recovered.status, crate::GrantStatus::RevocationPending);
        assert!(recovered.current_revocation_id.is_some());
    }

    #[test]
    fn separate_vault_handles_enforce_one_unresolved_provider_owner() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [48_u8; 32]).unwrap();
        first.create_profile("Multi process").unwrap();
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "remote".into(),
            transport: "streamable_http".into(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example/resource".into()),
            environment_keys: vec![],
            metadata: Default::default(),
        };
        first.upsert_connection(&connection).unwrap();
        let second = Vault::open_with_key(&path, [48_u8; 32]).unwrap();
        let make_pending = |id| ProviderGrant {
            id,
            connection_id: connection.id,
            resource: "https://mcp.example/resource".into(),
            issuer: "https://issuer.example".into(),
            client_id: "public-client".into(),
            registration_kind: crate::ClientRegistrationKind::UserSuppliedPublic,
            scopes: vec![],
            access_expires_at: None,
            access_secret_ref: crate::oauth::new_secret_reference(id, "access").unwrap(),
            refresh_secret_ref: None,
            status: crate::GrantStatus::AuthorizationPending,
            current_revocation_id: None,
            revision: 0,
            created_at: Utc::now(),
            last_verified_at: None,
        };
        let first_grant = make_pending(Uuid::new_v4());
        let second_grant = make_pending(Uuid::new_v4());
        first.reserve_provider_authorization(&first_grant).unwrap();
        assert!(second.delete_connection(connection.id).is_err());
        assert!(
            second
                .reserve_provider_authorization(&second_grant)
                .is_err()
        );
        assert!(second.provider_grant(second_grant.id).unwrap().is_none());
        first.cancel_provider_authorization(first_grant.id).unwrap();
        second
            .reserve_provider_authorization(&second_grant)
            .unwrap();
        second
            .cancel_provider_authorization(second_grant.id)
            .unwrap();
        second.delete_connection(connection.id).unwrap();
        assert!(first.reserve_provider_authorization(&first_grant).is_err());
    }

    fn environment_backed_stdio(name: &str) -> ConnectionDefinition {
        ConnectionDefinition {
            id: Uuid::new_v4(),
            name: name.into(),
            transport: "stdio".into(),
            command: Some("/Applications/Example Tools/mcp-server".into()),
            args: vec!["  exact whitespace  ".into(), "".into()],
            url: None,
            environment_keys: vec!["EXAMPLE_API_KEY".into()],
            metadata: BTreeMap::from([("source".into(), "test".into())]),
        }
    }

    #[test]
    fn execution_grant_is_inert_encrypted_immutable_and_not_exported() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [51_u8; 32]).unwrap();
        vault.create_profile("Broker foundation").unwrap();
        let mut connection = environment_backed_stdio("immutable-tools");
        vault.upsert_connection(&connection).unwrap();

        let preview = vault
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        let grant = vault.reserve_execution_grant(preview).unwrap();
        assert_eq!(grant.status, ExecutionGrantStatus::AwaitingCredentials);
        assert_eq!(grant.snapshot.args, vec!["  exact whitespace  ", ""]);
        assert_eq!(grant.required_credentials.len(), 1);
        assert_eq!(
            grant.required_credentials[0].status,
            ExecutionCredentialStatus::Missing
        );
        assert!(!vault.raw_documents_contain("EXAMPLE_API_KEY").unwrap());
        assert!(!vault.raw_documents_contain("exact whitespace").unwrap());

        connection.command = Some("/Applications/Changed/server".into());
        connection.args = vec!["changed".into()];
        vault.upsert_connection(&connection).unwrap();
        let reloaded = vault.execution_grant(grant.id).unwrap().unwrap();
        assert_eq!(reloaded.snapshot, grant.snapshot);
        assert_eq!(reloaded.snapshot_sha256, grant.snapshot_sha256);

        let pack = vault.export_selected(&[connection.id], &[]).unwrap();
        let json = serde_json::to_string(&pack).unwrap();
        assert!(!json.contains("execution_grant"));
        assert!(!json.contains(&grant.id.to_string()));
        assert!(!json.contains(&grant.required_credentials[0].binding_id.to_string()));
        assert!(vault.delete_connection(connection.id).is_err());
        let cancelled = vault.cancel_execution_grant(grant.id, 0).unwrap();
        assert_eq!(cancelled.status, ExecutionGrantStatus::Cancelled);
        assert_eq!(cancelled.revision, 1);
        assert!(vault.cancel_execution_grant(grant.id, 0).is_err());
        vault.delete_connection(connection.id).unwrap();
    }

    #[test]
    fn execution_preview_is_stale_safe_one_use_and_cross_process_owned() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [52_u8; 32]).unwrap();
        first.create_profile("Execution owner").unwrap();
        let mut connection = environment_backed_stdio("owned-tools");
        first.upsert_connection(&connection).unwrap();
        let stale = first
            .prepare_execution_grant(connection.id, "Claude Desktop")
            .unwrap();
        connection.args.push("changed-after-preview".into());
        first.upsert_connection(&connection).unwrap();
        assert!(first.reserve_execution_grant(stale).is_err());
        assert!(first.execution_grants().unwrap().is_empty());

        let second = Vault::open_with_key(&path, [52_u8; 32]).unwrap();
        let first_preview = first
            .prepare_execution_grant(connection.id, "Claude Desktop")
            .unwrap();
        let second_preview = second
            .prepare_execution_grant(connection.id, "Claude Desktop")
            .unwrap();
        let reusable_id = first_preview.id();
        let grant = first.reserve_execution_grant(first_preview).unwrap();
        assert!(second.reserve_execution_grant(second_preview).is_err());
        assert_eq!(second.execution_grants().unwrap().len(), 1);
        first.cancel_execution_grant(grant.id, 0).unwrap();

        // A different, newly reviewed intent may own the same connection and
        // host after cancellation; the consumed preview ID remains permanent.
        let replacement = second
            .prepare_execution_grant(connection.id, "Claude Desktop")
            .unwrap();
        let replacement = second.reserve_execution_grant(replacement).unwrap();
        assert_ne!(replacement.id, grant.id);
        assert_eq!(second.execution_grants().unwrap().len(), 2);
        let consumed: i64 = second
            .db
            .query_row(
                "SELECT COUNT(*) FROM consumed_execution_previews WHERE preview_id=?1",
                params![reusable_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(consumed, 1);
    }

    #[test]
    fn execution_grants_allow_distinct_hosts_but_reject_unsafe_reference_kinds() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [53_u8; 32]).unwrap();
        vault.create_profile("Multiple hosts").unwrap();
        let mut connection = environment_backed_stdio("multi-host-tools");
        vault.upsert_connection(&connection).unwrap();
        let cursor = vault
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        let codex = vault
            .prepare_execution_grant(connection.id, "Codex")
            .unwrap();
        vault.reserve_execution_grant(cursor).unwrap();
        vault.reserve_execution_grant(codex).unwrap();
        assert_eq!(vault.execution_grants().unwrap().len(), 2);

        connection.environment_keys = vec!["header:Authorization".into()];
        connection.id = Uuid::new_v4();
        connection.name = "unsupported-header".into();
        vault.upsert_connection(&connection).unwrap();
        assert!(
            vault
                .prepare_execution_grant(connection.id, "Cursor")
                .is_err()
        );
    }

    #[test]
    fn execution_owner_corruption_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [54_u8; 32]).unwrap();
        vault.create_profile("Owner integrity").unwrap();
        let connection = environment_backed_stdio("integrity-tools");
        vault.upsert_connection(&connection).unwrap();
        let preview = vault
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        vault.reserve_execution_grant(preview).unwrap();
        vault
            .db
            .execute(
                "UPDATE execution_grant_owners SET grant_id=?1",
                params![Uuid::new_v4().to_string()],
            )
            .unwrap();
        assert!(vault.execution_grants().is_err());
        assert!(vault.delete_connection(connection.id).is_err());
    }

    #[test]
    fn connection_delete_and_execution_reservation_are_serialized() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [55_u8; 32]).unwrap();
        first.create_profile("Delete serialization").unwrap();
        let connection = environment_backed_stdio("serialized-tools");
        first.upsert_connection(&connection).unwrap();
        let preview = first
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        let second = Vault::open_with_key(&path, [55_u8; 32]).unwrap();

        // If reservation wins the write lock, deletion must observe and refuse
        // the pending owner instead of deleting its source definition.
        let grant = first.reserve_execution_grant(preview).unwrap();
        assert!(second.delete_connection(connection.id).is_err());
        assert!(second.connection(connection.id).unwrap().is_some());
        assert_eq!(second.execution_grants().unwrap().len(), 1);
        first.cancel_execution_grant(grant.id, 0).unwrap();

        // If deletion wins, a preview prepared earlier cannot recreate a
        // grant for the now-missing definition.
        let stale = first
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        second.delete_connection(connection.id).unwrap();
        assert!(first.reserve_execution_grant(stale).is_err());
        assert!(first.connection(connection.id).unwrap().is_none());
        assert!(
            first
                .execution_grants()
                .unwrap()
                .iter()
                .all(|item| item.status.is_terminal())
        );
    }

    #[test]
    fn execution_preview_expiry_is_rechecked_after_waiting_for_write_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [56_u8; 32]).unwrap();
        first.create_profile("Preview expiry").unwrap();
        let connection = environment_backed_stdio("expiry-tools");
        first.upsert_connection(&connection).unwrap();
        let second = Vault::open_with_key(&path, [56_u8; 32]).unwrap();
        let mut preview = second
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        preview.set_expires_at(Utc::now() + chrono::Duration::milliseconds(100));

        first.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let reservation = std::thread::spawn(move || second.reserve_execution_grant(preview));
        std::thread::sleep(std::time::Duration::from_millis(200));
        first.db.execute_batch("ROLLBACK").unwrap();
        assert!(reservation.join().unwrap().is_err());
        assert!(first.execution_grants().unwrap().is_empty());
        let consumed: i64 = first
            .db
            .query_row(
                "SELECT COUNT(*) FROM consumed_execution_previews",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let owners: i64 = first
            .db
            .query_row("SELECT COUNT(*) FROM execution_grant_owners", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((consumed, owners), (0, 0));
    }

    #[test]
    fn execution_credentials_are_keychain_only_and_forgettable() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [57_u8; 32]).unwrap();
        vault.create_profile("Credential custody").unwrap();
        let connection = environment_backed_stdio("credential-tools");
        vault.upsert_connection(&connection).unwrap();
        let preview = vault
            .prepare_execution_grant(connection.id, "Cursor")
            .unwrap();
        let grant = vault.reserve_execution_grant(preview).unwrap();
        let sentinel = format!("cargo-test-secret-{}", Uuid::new_v4());
        let ready = vault
            .store_execution_credentials(
                grant.id,
                0,
                vec![(
                    "EXAMPLE_API_KEY".into(),
                    SecretString::from(sentinel.clone()),
                )],
            )
            .unwrap();
        assert_eq!(ready.status, ExecutionGrantStatus::CredentialsReady);
        assert_eq!(ready.revision, 1);
        assert_eq!(
            ready.required_credentials[0].status,
            ExecutionCredentialStatus::Stored
        );
        let reference = vault
            .execution_grant(ready.id)
            .unwrap()
            .unwrap()
            .required_credentials[0]
            .secret_ref
            .clone()
            .unwrap();
        assert!(vault.secret_value_exists(&reference).unwrap());
        assert!(!vault.raw_documents_contain(&sentinel).unwrap());
        assert!(
            !serde_json::to_string(&vault.export_safe().unwrap())
                .unwrap()
                .contains(&sentinel)
        );

        let missing = vault.forget_execution_credentials(ready.id, 1).unwrap();
        assert_eq!(missing.status, ExecutionGrantStatus::AwaitingCredentials);
        assert_eq!(missing.revision, 2);
        assert_eq!(
            missing.required_credentials[0].status,
            ExecutionCredentialStatus::Missing
        );
        assert!(
            vault
                .execution_grant(missing.id)
                .unwrap()
                .unwrap()
                .required_credentials[0]
                .secret_ref
                .is_none()
        );
        assert!(!vault.secret_value_exists(&reference).unwrap());
        vault.cancel_execution_grant(missing.id, 2).unwrap();
    }

    #[test]
    fn incomplete_execution_credential_write_is_cleaned_on_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let key = [58_u8; 32];
        let (grant_id, secret_ref) = {
            let vault = Vault::open_with_key(&path, key).unwrap();
            vault.create_profile("Credential recovery").unwrap();
            let connection = environment_backed_stdio("recovery-tools");
            vault.upsert_connection(&connection).unwrap();
            let grant = vault
                .reserve_execution_grant(
                    vault
                        .prepare_execution_grant(connection.id, "Cursor")
                        .unwrap(),
                )
                .unwrap();
            let requirement = &grant.required_credentials[0];
            let secret_ref =
                crate::execution::new_secret_reference(grant.id, requirement.binding_id);
            let activation = ExecutionCredentialActivation {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                grant_revision: grant.revision,
                kind: ExecutionCredentialActivationKind::Write,
                credentials: vec![ExecutionCredentialWrite {
                    binding_id: requirement.binding_id,
                    name: requirement.name.clone(),
                    secret_ref: secret_ref.clone(),
                }],
                state: ExecutionCredentialActivationState::Staged,
                created_at: Utc::now(),
                completed_at: None,
            };
            vault
                .put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                )
                .unwrap();
            vault
                .put_secret_value(
                    &secret_ref,
                    &SecretString::from(format!("ambiguous-{}", Uuid::new_v4())),
                )
                .unwrap();
            (grant.id, secret_ref)
        };
        let reopened = Vault::open_with_key(&path, key).unwrap();
        assert!(!reopened.secret_value_exists(&secret_ref).unwrap());
        let grant = reopened.execution_grant(grant_id).unwrap().unwrap();
        assert_eq!(grant.status, ExecutionGrantStatus::AwaitingCredentials);
        assert!(
            reopened
                .execution_credential_activations()
                .unwrap()
                .iter()
                .all(|item| item.state == ExecutionCredentialActivationState::Completed)
        );
        reopened.cancel_execution_grant(grant.id, 0).unwrap();
    }

    #[test]
    fn verified_execution_credentials_finalize_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let key = [59_u8; 32];
        let (grant_id, secret_ref) = {
            let vault = Vault::open_with_key(&path, key).unwrap();
            vault
                .create_profile("Credential finalize recovery")
                .unwrap();
            let connection = environment_backed_stdio("finalize-tools");
            vault.upsert_connection(&connection).unwrap();
            let grant = vault
                .reserve_execution_grant(
                    vault
                        .prepare_execution_grant(connection.id, "Cursor")
                        .unwrap(),
                )
                .unwrap();
            let requirement = &grant.required_credentials[0];
            let secret_ref =
                crate::execution::new_secret_reference(grant.id, requirement.binding_id);
            let activation = ExecutionCredentialActivation {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                grant_revision: grant.revision,
                kind: ExecutionCredentialActivationKind::Write,
                credentials: vec![ExecutionCredentialWrite {
                    binding_id: requirement.binding_id,
                    name: requirement.name.clone(),
                    secret_ref: secret_ref.clone(),
                }],
                state: ExecutionCredentialActivationState::CredentialsWritten,
                created_at: Utc::now(),
                completed_at: None,
            };
            vault
                .put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                )
                .unwrap();
            vault
                .put_secret_value(
                    &secret_ref,
                    &SecretString::from(format!("verified-{}", Uuid::new_v4())),
                )
                .unwrap();
            vault.verify_secret_value(&secret_ref).unwrap();
            (grant.id, secret_ref)
        };
        let reopened = Vault::open_with_key(&path, key).unwrap();
        let ready = reopened.execution_grant(grant_id).unwrap().unwrap();
        assert_eq!(ready.status, ExecutionGrantStatus::CredentialsReady);
        assert_eq!(ready.revision, 1);
        assert_eq!(
            reopened
                .execution_grant(ready.id)
                .unwrap()
                .unwrap()
                .required_credentials[0]
                .secret_ref
                .as_deref(),
            Some(secret_ref.as_str())
        );
        assert!(reopened.secret_value_exists(&secret_ref).unwrap());
        let missing = reopened.forget_execution_credentials(ready.id, 1).unwrap();
        assert_eq!(missing.status, ExecutionGrantStatus::AwaitingCredentials);
        assert!(!reopened.secret_value_exists(&secret_ref).unwrap());
        reopened.cancel_execution_grant(missing.id, 2).unwrap();
    }

    #[test]
    fn duplicate_execution_credential_input_is_rejected_before_custody() {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::open_with_key(temp.path().join("vault.db"), [60_u8; 32]).unwrap();
        vault.create_profile("Duplicate credentials").unwrap();
        let mut connection = environment_backed_stdio("duplicate-tools");
        connection.environment_keys = vec!["FIRST_KEY".into(), "SECOND_KEY".into()];
        vault.upsert_connection(&connection).unwrap();
        let grant = vault
            .reserve_execution_grant(
                vault
                    .prepare_execution_grant(connection.id, "Cursor")
                    .unwrap(),
            )
            .unwrap();
        let receipts_before = vault.receipts().unwrap().len();
        assert!(
            vault
                .store_execution_credentials(
                    grant.id,
                    0,
                    vec![
                        ("FIRST_KEY".into(), SecretString::from("first")),
                        ("FIRST_KEY".into(), SecretString::from("replacement")),
                        ("SECOND_KEY".into(), SecretString::from("second")),
                    ],
                )
                .is_err()
        );
        assert!(vault.execution_credential_activations().unwrap().is_empty());
        assert_eq!(vault.receipts().unwrap().len(), receipts_before);
        let unchanged = vault.execution_grant(grant.id).unwrap().unwrap();
        assert_eq!(unchanged.status, ExecutionGrantStatus::AwaitingCredentials);
        assert_eq!(unchanged.revision, 0);
        assert!(
            unchanged
                .required_credentials
                .iter()
                .all(|item| item.secret_ref.is_none())
        );
    }

    #[test]
    fn live_staged_execution_credential_write_is_not_reconciled_as_crash_residue() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let first = Vault::open_with_key(&path, [61_u8; 32]).unwrap();
        first.create_profile("Live credential writer").unwrap();
        let connection = environment_backed_stdio("live-writer-tools");
        first.upsert_connection(&connection).unwrap();
        let grant = first
            .reserve_execution_grant(
                first
                    .prepare_execution_grant(connection.id, "Cursor")
                    .unwrap(),
            )
            .unwrap();
        let requirement = grant.required_credentials[0].clone();
        let alias_directory = temp.path().join("alias");
        fs::create_dir(&alias_directory).unwrap();
        let alias_path = alias_directory.join("..").join("vault.db");
        let second = Vault::open_with_key(&alias_path, [61_u8; 32]).unwrap();
        assert_eq!(first.path, second.path);
        let activation = ExecutionCredentialActivation {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            grant_revision: grant.revision,
            kind: ExecutionCredentialActivationKind::Write,
            credentials: vec![ExecutionCredentialWrite {
                binding_id: requirement.binding_id,
                name: requirement.name,
                secret_ref: crate::execution::new_secret_reference(
                    grant.id,
                    requirement.binding_id,
                ),
            }],
            state: ExecutionCredentialActivationState::Staged,
            created_at: Utc::now(),
            completed_at: None,
        };
        let activation_id = activation.id;
        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (reconciled_tx, reconciled_rx) = std::sync::mpsc::channel();

        let writer = std::thread::spawn(move || {
            first.with_execution_credential_lock(|| {
                first.put(
                    "execution_credential_activations",
                    activation.id,
                    &activation,
                )?;
                staged_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                first.db.execute(
                    "DELETE FROM execution_credential_activations WHERE id=?1",
                    params![activation.id.to_string()],
                )?;
                Ok(())
            })
        });
        staged_rx.recv().unwrap();
        let reconciler = std::thread::spawn(move || {
            let result = second.reconcile_execution_credential_activations();
            reconciled_tx.send(()).unwrap();
            result
        });

        assert!(
            reconciled_rx
                .recv_timeout(std::time::Duration::from_millis(150))
                .is_err()
        );
        release_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
        reconciler.join().unwrap().unwrap();

        let reopened = Vault::open_with_key(&path, [61_u8; 32]).unwrap();
        let journal: Option<ExecutionCredentialActivation> = reopened
            .by_id("execution_credential_activations", activation_id)
            .unwrap();
        assert!(journal.is_none());
        assert_eq!(
            reopened.execution_grant(grant.id).unwrap().unwrap().status,
            ExecutionGrantStatus::AwaitingCredentials
        );
    }

    #[test]
    fn concurrent_reconcilers_do_not_delete_finalized_execution_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let key = [62_u8; 32];
        let first = Vault::open_with_key(&path, key).unwrap();
        first.create_profile("Concurrent reconciliation").unwrap();
        let connection = environment_backed_stdio("concurrent-reconcile-tools");
        first.upsert_connection(&connection).unwrap();
        let grant = first
            .reserve_execution_grant(
                first
                    .prepare_execution_grant(connection.id, "Cursor")
                    .unwrap(),
            )
            .unwrap();
        let second = Vault::open_with_key(&path, key).unwrap();
        let requirement = &grant.required_credentials[0];
        let secret_ref = crate::execution::new_secret_reference(grant.id, requirement.binding_id);
        let activation = ExecutionCredentialActivation {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            grant_revision: grant.revision,
            kind: ExecutionCredentialActivationKind::Write,
            credentials: vec![ExecutionCredentialWrite {
                binding_id: requirement.binding_id,
                name: requirement.name.clone(),
                secret_ref: secret_ref.clone(),
            }],
            state: ExecutionCredentialActivationState::CredentialsWritten,
            created_at: Utc::now(),
            completed_at: None,
        };
        first
            .put(
                "execution_credential_activations",
                activation.id,
                &activation,
            )
            .unwrap();
        first
            .put_secret_value(
                &secret_ref,
                &SecretString::from(format!("concurrent-{}", Uuid::new_v4())),
            )
            .unwrap();

        let one = std::thread::spawn(move || first.reconcile_execution_credential_activations());
        let two = std::thread::spawn(move || second.reconcile_execution_credential_activations());
        one.join().unwrap().unwrap();
        two.join().unwrap().unwrap();

        let reopened = Vault::open_with_key(&path, key).unwrap();
        let ready = reopened.execution_grant(grant.id).unwrap().unwrap();
        assert_eq!(ready.status, ExecutionGrantStatus::CredentialsReady);
        assert!(reopened.secret_value_exists(&secret_ref).unwrap());
        let missing = reopened
            .forget_execution_credentials(ready.id, ready.revision)
            .unwrap();
        reopened
            .cancel_execution_grant(missing.id, missing.revision)
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn execution_credential_lock_refuses_a_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let key = [63_u8; 32];
        let vault = Vault::open_with_key(&path, key).unwrap();
        let lock_path = vault.path.with_file_name(format!(
            "{}.execution-credentials.lock",
            vault.path.file_name().unwrap().to_str().unwrap()
        ));
        drop(vault);
        fs::remove_file(&lock_path).unwrap();
        let target = temp.path().join("attacker-controlled");
        fs::write(&target, b"not a lock").unwrap();
        symlink(&target, &lock_path).unwrap();

        assert!(Vault::open_with_key(&path, key).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"not a lock");
    }

    #[cfg(unix)]
    #[test]
    fn vault_refuses_a_hard_link_alias() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let key = [64_u8; 32];
        let vault = Vault::open_with_key(&path, key).unwrap();
        vault.create_profile("Hard-link identity").unwrap();
        drop(vault);

        let alias_directory = temp.path().join("other-private-directory");
        fs::create_dir(&alias_directory).unwrap();
        set_private_directory(&alias_directory).unwrap();
        let alias = alias_directory.join("alias.db");
        fs::hard_link(&path, &alias).unwrap();

        assert!(Vault::open_with_key(&path, key).is_err());
        assert!(Vault::open_with_key(&alias, key).is_err());
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
