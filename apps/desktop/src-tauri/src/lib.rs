use cargo_ai_core::{
    ClientRegistrationKind, ConnectionDefinition, GrantStatus, LocalProfile, ManagedDeployment,
    MemoryRecord, PackImportResult, PortablePack, ProviderGrant, RevocationVerification,
    Sensitivity, TokenRevocationResult, Vault,
    adapters::{HostSnapshot, discover_known},
    host_ops::{
        PlannedInstall, PlannedRemoval, apply_recorded_install, apply_recorded_removal,
        import_host_configuration as import_host, plan_install, plan_removal,
    },
    mutation::{MutationSummary, write_private_file},
    oauth::{
        AuthorizationTransaction, OAuthProviderTransport, TokenKind,
        ValidatedAuthorizationMetadata, new_secret_reference,
    },
    oauth_callback::LoopbackCallback,
    oauth_http::HttpOAuthTransport,
    transfer::{decrypt_pack, encrypt_pack},
    validate_portable_pack,
};
use chrono::Utc;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tauri_plugin_opener::OpenerExt;
use uuid::Uuid;

struct AppRuntime {
    vault: Mutex<VaultSession>,
    vault_path: PathBuf,
    startup_error: Mutex<Option<String>>,
    plans: Mutex<HashMap<Uuid, PendingPlan>>,
    removals: Mutex<HashMap<Uuid, PendingRemoval>>,
    imports: Mutex<HashMap<Uuid, PendingImport>>,
    provider_previews: Mutex<HashMap<Uuid, PendingProviderPreview>>,
}

struct VaultSession {
    vault: Option<Vault>,
    last_access: Instant,
}

struct PendingPlan {
    plan: PlannedInstall,
    created_at: Instant,
}

struct PendingRemoval {
    plan: PlannedRemoval,
    created_at: Instant,
}

struct PendingImport {
    pack: PortablePack,
    created_at: Instant,
}

struct PendingProviderPreview {
    connection_id: Uuid,
    metadata: ValidatedAuthorizationMetadata,
    created_at: Instant,
}

#[derive(Serialize)]
struct ImportPreview {
    import_id: Uuid,
    source_profile: String,
    exported_at: chrono::DateTime<Utc>,
    connections: Vec<ConnectionDefinition>,
    memory: Vec<MemoryRecord>,
    warnings: Vec<String>,
}

const IDLE_LOCK: Duration = Duration::from_secs(15 * 60);

fn active_vault(app: &AppRuntime) -> Result<MutexGuard<'_, VaultSession>, String> {
    app.plans
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.removals
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.imports
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.provider_previews
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    if let Some(error) = app.startup_error.lock().map_err(err)?.as_ref() {
        return Err(format!("Vault could not open: {error}"));
    }
    let mut session = app.vault.lock().map_err(err)?;
    if session.last_access.elapsed() >= IDLE_LOCK {
        session.vault = None;
    }
    if session.vault.is_none() {
        return Err("Vault is locked".into());
    }
    session.last_access = Instant::now();
    Ok(session)
}

fn vault_ref(session: &VaultSession) -> Result<&Vault, String> {
    session.vault.as_ref().ok_or("Vault is locked".into())
}

#[derive(Serialize)]
struct AppState {
    profile: Option<LocalProfile>,
    hosts: Vec<HostSnapshot>,
    deployments: Vec<ManagedDeployment>,
    connection_count: usize,
    memory_count: usize,
    provider_grants: Vec<ProviderGrantView>,
    receipts: Vec<cargo_ai_core::AuditReceipt>,
    receipt_chain_valid: bool,
    vault_path: String,
}

#[derive(Serialize)]
struct ProviderGrantView {
    id: Uuid,
    connection_id: Uuid,
    resource: String,
    issuer: String,
    scopes: Vec<String>,
    access_expires_at: Option<chrono::DateTime<Utc>>,
    status: String,
    created_at: chrono::DateTime<Utc>,
    last_verified_at: Option<chrono::DateTime<Utc>>,
}

impl From<ProviderGrant> for ProviderGrantView {
    fn from(grant: ProviderGrant) -> Self {
        let status = match grant.status {
            GrantStatus::AuthorizationPending => "authorization_pending",
            GrantStatus::Active => "active",
            GrantStatus::ReauthRequired => "reauth_required",
            GrantStatus::LocallyBlocked => "locally_blocked",
            GrantStatus::RevocationPending => "revocation_pending",
            GrantStatus::ProviderRevokedUnverified => "provider_revoked_unverified",
            GrantStatus::LocalCleanupPending => "local_cleanup_pending",
            GrantStatus::VerifiedRevoked => "verified_revoked",
            GrantStatus::Partial => "partial",
            GrantStatus::Failed => "failed",
        };
        Self {
            id: grant.id,
            connection_id: grant.connection_id,
            resource: grant.resource,
            issuer: grant.issuer,
            scopes: grant.scopes,
            access_expires_at: grant.access_expires_at,
            status: status.into(),
            created_at: grant.created_at,
            last_verified_at: grant.last_verified_at,
        }
    }
}

#[derive(Serialize)]
struct ProviderAuthorizationPreview {
    preview_id: Uuid,
    resource: String,
    issuer: String,
    scopes_supported: Vec<String>,
    refresh_persistence: &'static str,
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("Home directory is unavailable".into())
}
fn state(vault: &Vault) -> Result<AppState, String> {
    Ok(AppState {
        profile: vault.profile().map_err(err)?,
        hosts: discover_known(&home_dir()?),
        connection_count: vault.connection_count().map_err(err)?,
        deployments: vault.deployments().map_err(err)?,
        memory_count: vault.memory_count().map_err(err)?,
        provider_grants: vault
            .provider_grants()
            .map_err(err)?
            .into_iter()
            .map(ProviderGrantView::from)
            .collect(),
        receipts: vault.receipts().map_err(err)?,
        receipt_chain_valid: vault.verify_receipt_chain().map_err(err)?,
        vault_path: vault.path().display().to_string(),
    })
}

fn remote_connection(vault: &Vault, connection_id: Uuid) -> Result<ConnectionDefinition, String> {
    let connection = vault
        .connection(connection_id)
        .map_err(err)?
        .ok_or("Connection definition was not found")?;
    if connection.transport == "stdio" || connection.url.is_none() {
        return Err("Only remote HTTP MCP definitions can use provider authorization".into());
    }
    Ok(connection)
}

#[tauri::command]
fn preview_provider_authorization(
    connection_id: String,
    app: State<AppRuntime>,
) -> Result<ProviderAuthorizationPreview, String> {
    let connection_id = Uuid::parse_str(&connection_id).map_err(err)?;
    let connection = {
        let session = active_vault(&app)?;
        let vault = vault_ref(&session)?;
        if vault
            .provider_grants()
            .map_err(err)?
            .iter()
            .any(|grant| grant.connection_id == connection_id && !grant.status.is_terminal())
        {
            return Err("This connection already has an unresolved provider authorization".into());
        }
        remote_connection(vault, connection_id)?
    };
    let transport =
        HttpOAuthTransport::discover(connection.url.as_deref().unwrap()).map_err(err)?;
    let preview_id = Uuid::new_v4();
    let metadata = transport.metadata().clone();
    let mut previews = app.provider_previews.lock().map_err(err)?;
    previews.retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    if previews
        .values()
        .any(|pending| pending.connection_id == connection_id)
    {
        return Err("This connection already has a pending provider review".into());
    }
    if previews.len() >= 16 {
        return Err("Too many pending provider previews; finish or cancel one first".into());
    }
    previews.insert(
        preview_id,
        PendingProviderPreview {
            connection_id,
            metadata: metadata.clone(),
            created_at: Instant::now(),
        },
    );
    Ok(ProviderAuthorizationPreview {
        preview_id,
        resource: metadata.resource.to_string(),
        issuer: metadata.issuer.to_string(),
        scopes_supported: metadata.scopes_supported,
        refresh_persistence: "active-use-disabled;issued-refresh-retained-only-for-verified-provider-cleanup",
    })
}

#[tauri::command]
fn connect_provider(
    preview_id: String,
    client_id: String,
    scopes: Vec<String>,
    handle: AppHandle,
    app: State<AppRuntime>,
) -> Result<ProviderGrantView, String> {
    let preview_id = Uuid::parse_str(&preview_id).map_err(err)?;
    let pending = app
        .provider_previews
        .lock()
        .map_err(err)?
        .remove(&preview_id)
        .ok_or("Provider preview expired or was already used")?;
    if pending.created_at.elapsed() >= Duration::from_secs(300) {
        return Err("Provider preview expired; review the provider again".into());
    }
    let connection_id = pending.connection_id;
    let connection = {
        let session = active_vault(&app)?;
        remote_connection(vault_ref(&session)?, connection_id)?
    };
    if connection.url.as_deref() != Some(pending.metadata.resource.as_str()) {
        return Err("Connection resource changed after provider preview".into());
    }
    let mut transport =
        HttpOAuthTransport::discover(pending.metadata.resource.as_str()).map_err(err)?;
    if transport.metadata() != &pending.metadata {
        return Err("Provider metadata changed after preview; review it again".into());
    }
    let grant_id = Uuid::new_v4();
    let mut grant = ProviderGrant {
        id: grant_id,
        connection_id,
        resource: transport.metadata().resource.to_string(),
        issuer: transport.metadata().issuer.to_string(),
        client_id: client_id.trim().to_owned(),
        registration_kind: ClientRegistrationKind::UserSuppliedPublic,
        scopes: scopes.clone(),
        access_expires_at: None,
        access_secret_ref: new_secret_reference(grant_id, "access").map_err(err)?,
        refresh_secret_ref: None,
        status: GrantStatus::AuthorizationPending,
        current_revocation_id: None,
        revision: 0,
        created_at: Utc::now(),
        last_verified_at: None,
    };
    let mut callback = LoopbackCallback::bind().map_err(err)?;
    // Keep the vault session guard for the whole browser callback lifecycle.
    // This prevents a concurrent soft-lock from removing the only durable
    // credential-custody boundary after the provider has issued tokens.
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    vault.preflight_provider_credential_store().map_err(err)?;
    vault.reserve_provider_authorization(&grant).map_err(err)?;
    let authorization_result = (|| {
        let mut transaction = AuthorizationTransaction::new(
            transport.metadata(),
            client_id.trim(),
            callback.redirect_uri().clone(),
            scopes,
        )
        .map_err(err)?;
        handle
            .opener()
            .open_url(transaction.authorization_url().to_string(), None::<String>)
            .map_err(err)?;
        let exchange = callback.receive_exchange(&mut transaction).map_err(err)?;
        vault.begin_provider_token_exchange(grant_id).map_err(err)?;
        match transport.exchange(exchange) {
            Ok(issued) => Ok(issued),
            Err(exchange_error) => {
                vault.reconcile_provider_authorizations().map_err(err)?;
                Err(format!(
                    "Token exchange did not complete locally. Provider issuance is ambiguous, so Cargo retained a blocked cleanup record and will not call this authorization credential-free: {}",
                    err(exchange_error)
                ))
            }
        }
    })();
    let issued = match authorization_result {
        Ok(issued) => issued,
        Err(error) => {
            let issuance_started = vault
                .provider_grant(grant_id)
                .map_err(err)?
                .is_some_and(|grant| grant.current_revocation_id.is_some());
            if issuance_started {
                return Err(error);
            }
            return match vault.cancel_provider_authorization(grant_id) {
                Ok(()) => Err(error),
                Err(cancel_error) => Err(format!(
                    "{error}. The credential-free authorization reservation could not be cancelled and remains visible for explicit resolution: {cancel_error}"
                )),
            };
        }
    };
    let access_expires_at = Some(issued.expires_at);
    let granted_scopes = issued.scopes.clone();
    let (access_token, refresh_token) = issued.into_secrets();
    let custody_result = vault
        .complete_provider_authorization(
            grant_id,
            &access_token,
            refresh_token.as_ref(),
            granted_scopes,
            access_expires_at,
        )
        .map_err(err);
    match custody_result {
        Ok(saved) => grant = saved,
        Err(custody_error) => {
            // The vault normally retains issued credentials in a blocked,
            // durable cleanup lifecycle. If platform custody itself failed,
            // make a best-effort provider cut while the zeroizing token values
            // are still in this Rust stack. RFC 7009 acceptance is deliberately
            // not presented as verified cleanup.
            let refresh_result = if let Some(refresh_token) = &refresh_token {
                transport
                    .revoke(refresh_token, TokenKind::Refresh)
                    .unwrap_or(TokenRevocationResult::RetryableFailure)
            } else {
                TokenRevocationResult::NotAttempted
            };
            let access_result = transport
                .revoke(&access_token, TokenKind::Access)
                .unwrap_or(TokenRevocationResult::RetryableFailure);
            let verification = transport
                .probe_resource(&access_token, &transport.metadata().resource)
                .unwrap_or(RevocationVerification::Unsupported);
            if let Ok(Some(recovered)) = vault.provider_grant(grant_id)
                && let Some(operation_id) = recovered.current_revocation_id
            {
                let retryable = matches!(
                    access_result,
                    TokenRevocationResult::RetryableFailure
                        | TokenRevocationResult::PermanentFailure
                ) || matches!(
                    refresh_result,
                    TokenRevocationResult::RetryableFailure
                        | TokenRevocationResult::PermanentFailure
                );
                if let Ok(attempted) = vault.record_provider_revocation_attempt(
                    operation_id,
                    access_result,
                    refresh_result,
                    retryable.then(|| Utc::now() + chrono::Duration::minutes(5)),
                    retryable.then_some("provider_cleanup_incomplete"),
                ) && !retryable
                {
                    let evidence = if verification == RevocationVerification::ResourceRejected
                        && attempted.refresh_secret_ref.is_none()
                    {
                        RevocationVerification::AllIssuedTokensInactive
                    } else {
                        verification
                    };
                    if let Ok(verified) =
                        vault.record_provider_revocation_verification(operation_id, evidence)
                        && verified.status == GrantStatus::LocalCleanupPending
                    {
                        let _ = vault.finalize_provider_revocation(operation_id);
                    }
                }
            }
            return Err(format!(
                "Provider authorization was not activated. Issued credentials were retained for retryable cleanup when platform storage allowed it, and an immediate provider cleanup was attempted but is not claimed as verified: {custody_error}"
            ));
        }
    }
    Ok(grant.into())
}

#[tauri::command]
fn cancel_provider_authorization(grant_id: String, app: State<AppRuntime>) -> Result<(), String> {
    let grant_id = Uuid::parse_str(&grant_id).map_err(err)?;
    let session = active_vault(&app)?;
    vault_ref(&session)?
        .cancel_provider_authorization(grant_id)
        .map_err(err)
}

#[tauri::command]
fn disconnect_provider(
    grant_id: String,
    app: State<AppRuntime>,
) -> Result<ProviderGrantView, String> {
    let grant_id = Uuid::parse_str(&grant_id).map_err(err)?;
    let (grant, access_token, refresh_token, operation_id) = {
        let session = active_vault(&app)?;
        let vault = vault_ref(&session)?;
        let grant = vault
            .provider_grant(grant_id)
            .map_err(err)?
            .ok_or("Provider grant was not found")?;
        if let Some(operation_id) = grant.current_revocation_id {
            let (owned_grant, access_token, refresh_token) = vault
                .provider_credentials_for_revocation(operation_id)
                .map_err(err)?;
            (owned_grant, access_token, refresh_token, operation_id)
        } else {
            let (access_token, refresh_token) = vault
                .provider_credentials_for_transport(grant_id)
                .map_err(err)?;
            let operation = vault.begin_provider_revocation(grant_id).map_err(err)?;
            (grant, access_token, refresh_token, operation.id)
        }
    };

    let network = (|| {
        let mut transport = HttpOAuthTransport::discover(&grant.resource)?;
        if transport.metadata().issuer.as_str() != grant.issuer {
            anyhow::bail!("provider issuer changed");
        }
        let refresh_result = if let Some(refresh_token) = &refresh_token {
            transport.revoke(refresh_token, TokenKind::Refresh)?
        } else {
            TokenRevocationResult::NotAttempted
        };
        let access_result = transport.revoke(&access_token, TokenKind::Access)?;
        let verification =
            transport.probe_resource(&access_token, &transport.metadata().resource)?;
        Ok::<_, anyhow::Error>((access_result, refresh_result, verification))
    })();

    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let latest = match network {
        Ok((access_result, refresh_result, verification)) => {
            vault
                .record_provider_revocation_attempt(
                    operation_id,
                    access_result,
                    refresh_result,
                    None,
                    None,
                )
                .map_err(err)?;
            // Resource rejection proves only access-token inactivity. It can
            // cover the whole issued-token set only when the authorization
            // response demonstrably contained no refresh token.
            let evidence = if verification == RevocationVerification::ResourceRejected
                && grant.refresh_secret_ref.is_none()
            {
                RevocationVerification::AllIssuedTokensInactive
            } else {
                verification
            };
            let verified = vault
                .record_provider_revocation_verification(operation_id, evidence)
                .map_err(err)?;
            if verified.status == GrantStatus::LocalCleanupPending {
                vault
                    .finalize_provider_revocation(operation_id)
                    .map_err(err)?
            } else {
                verified
            }
        }
        Err(_) => vault
            .record_provider_revocation_attempt(
                operation_id,
                TokenRevocationResult::RetryableFailure,
                if grant.refresh_secret_ref.is_some() {
                    TokenRevocationResult::RetryableFailure
                } else {
                    TokenRevocationResult::NotAttempted
                },
                Some(Utc::now() + chrono::Duration::minutes(5)),
                Some("provider_network_failed"),
            )
            .map_err(err)?,
    };
    Ok(latest.into())
}

#[tauri::command]
fn memory_records(app: State<'_, AppRuntime>) -> Result<Vec<MemoryRecord>, String> {
    let session = active_vault(&app)?;
    vault_ref(&session)?.memory().map_err(err)
}

#[tauri::command]
fn connection_records(app: State<'_, AppRuntime>) -> Result<Vec<ConnectionDefinition>, String> {
    let session = active_vault(&app)?;
    vault_ref(&session)?.connections().map_err(err)
}

#[tauri::command]
fn touch_vault(app: State<'_, AppRuntime>) -> Result<(), String> {
    active_vault(&app).map(|_| ())
}

#[tauri::command]
fn purge_expired_previews(app: State<'_, AppRuntime>) -> Result<(), String> {
    app.plans
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.removals
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.imports
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    app.provider_previews
        .lock()
        .map_err(err)?
        .retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    Ok(())
}

fn read_transfer_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(err)?;
    if metadata.file_type().is_symlink() {
        return Err("Refusing a symlinked import file".into());
    }
    if metadata.len() > 32 * 1024 * 1024 {
        return Err("Import file exceeds 32 MiB limit".into());
    }
    std::fs::read(path).map_err(err)
}

fn local_path(selected: Option<FilePath>, extension: &str) -> Result<Option<PathBuf>, String> {
    let Some(selected) = selected else {
        return Ok(None);
    };
    let path = selected.into_path().map_err(err)?;
    let actual = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !actual.eq_ignore_ascii_case(extension) {
        return Err(format!("Choose a .{extension} file"));
    }
    Ok(Some(path))
}

async fn pick_import(app: AppHandle, extension: &'static str) -> Result<Option<PathBuf>, String> {
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Cargo portable pack", &[extension])
            .blocking_pick_file()
    })
    .await
    .map_err(err)?;
    local_path(selected, extension)
}

async fn pick_export(
    app: AppHandle,
    file_name: &'static str,
    label: &'static str,
    extension: &'static str,
) -> Result<Option<PathBuf>, String> {
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(file_name)
            .add_filter(label, &[extension])
            .blocking_save_file()
    })
    .await
    .map_err(err)?;
    local_path(selected, extension)
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn parse_ids(values: Vec<String>) -> Result<Vec<Uuid>, String> {
    values
        .iter()
        .map(|value| Uuid::parse_str(value).map_err(err))
        .collect()
}

#[tauri::command]
fn app_state(app: State<AppRuntime>) -> Result<AppState, String> {
    let session = active_vault(&app)?;
    state(vault_ref(&session)?)
}

#[tauri::command]
fn lock_vault(app: State<AppRuntime>) -> Result<(), String> {
    app.vault.lock().map_err(err)?.vault = None;
    app.plans.lock().map_err(err)?.clear();
    app.removals.lock().map_err(err)?.clear();
    app.imports.lock().map_err(err)?.clear();
    app.provider_previews.lock().map_err(err)?.clear();
    Ok(())
}

#[tauri::command]
fn unlock_vault(app: State<AppRuntime>) -> Result<(), String> {
    let vault = Vault::open(&app.vault_path).map_err(err)?;
    *app.startup_error.lock().map_err(err)? = None;
    let mut session = app.vault.lock().map_err(err)?;
    session.vault = Some(vault);
    session.last_access = Instant::now();
    Ok(())
}
#[tauri::command]
fn create_local_profile(
    display_name: String,
    app: State<AppRuntime>,
) -> Result<LocalProfile, String> {
    let session = active_vault(&app)?;
    vault_ref(&session)?
        .create_profile(&display_name)
        .map_err(err)
}

#[tauri::command]
fn rename_local_profile(
    display_name: String,
    app: State<AppRuntime>,
) -> Result<LocalProfile, String> {
    let session = active_vault(&app)?;
    vault_ref(&session)?
        .rename_profile(&display_name)
        .map_err(err)
}
#[tauri::command]
async fn export_safe_pack(
    connection_ids: Vec<String>,
    memory_ids: Vec<String>,
    handle: AppHandle,
    app: State<'_, AppRuntime>,
) -> Result<bool, String> {
    let Some(path) = pick_export(
        handle,
        "cargo-ai-portable-pack.json",
        "Cargo portable pack",
        "json",
    )
    .await?
    else {
        return Ok(false);
    };
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let pack = vault
        .export_selected(&parse_ids(connection_ids)?, &parse_ids(memory_ids)?)
        .map_err(err)?;
    let bytes = serde_json::to_vec_pretty(&pack).map_err(err)?;
    write_private_file(&path, &bytes).map_err(err)?;
    Ok(true)
}
#[tauri::command]
async fn export_encrypted_pack(
    passphrase: String,
    connection_ids: Vec<String>,
    memory_ids: Vec<String>,
    handle: AppHandle,
    app: State<'_, AppRuntime>,
) -> Result<bool, String> {
    if passphrase.len() < 12 {
        return Err("Passphrase must be at least 12 characters".into());
    }
    let Some(path) = pick_export(
        handle,
        "cargo-ai-portable-pack.age",
        "Encrypted Cargo portable pack",
        "age",
    )
    .await?
    else {
        return Ok(false);
    };
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let pack = vault
        .export_selected(&parse_ids(connection_ids)?, &parse_ids(memory_ids)?)
        .map_err(err)?;
    let bytes = encrypt_pack(&pack, passphrase.into()).map_err(err)?;
    write_private_file(&path, &bytes).map_err(err)?;
    Ok(true)
}

#[tauri::command]
fn import_host_configuration(host: String, app: State<AppRuntime>) -> Result<usize, String> {
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    import_host(vault, &home_dir()?, &host).map_err(err)
}

fn stage_import(pack: PortablePack, app: &State<'_, AppRuntime>) -> Result<ImportPreview, String> {
    let pack = validate_portable_pack(&pack).map_err(err)?;
    let import_id = Uuid::new_v4();
    let preview = ImportPreview {
        import_id,
        source_profile: pack.profile.display_name.clone(),
        exported_at: pack.exported_at,
        connections: pack.connections.clone(),
        memory: pack.memory.clone(),
        warnings: vec![
            "Imported executable definitions are untrusted until separately reviewed for installation.".into(),
            "Your current local profile is preserved; matching records are skipped during the transactional merge.".into(),
        ],
    };
    let mut imports = app.imports.lock().map_err(err)?;
    imports.retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    if imports.len() >= 8 {
        return Err("Too many pending imports; approve or cancel an existing preview".into());
    }
    imports.insert(
        import_id,
        PendingImport {
            pack,
            created_at: Instant::now(),
        },
    );
    Ok(preview)
}

#[tauri::command]
async fn prepare_safe_pack_import(
    handle: AppHandle,
    app: State<'_, AppRuntime>,
) -> Result<Option<ImportPreview>, String> {
    let Some(path) = pick_import(handle, "json").await? else {
        return Ok(None);
    };
    let bytes = read_transfer_file(&path)?;
    let pack: PortablePack = serde_json::from_slice(&bytes).map_err(err)?;
    stage_import(pack, &app).map(Some)
}

#[tauri::command]
async fn prepare_encrypted_pack_import(
    passphrase: String,
    handle: AppHandle,
    app: State<'_, AppRuntime>,
) -> Result<Option<ImportPreview>, String> {
    let Some(path) = pick_import(handle, "age").await? else {
        return Ok(None);
    };
    let pack = decrypt_pack(&read_transfer_file(&path)?, passphrase.into()).map_err(err)?;
    stage_import(pack, &app).map(Some)
}

#[tauri::command]
fn apply_pack_import(
    import_id: String,
    app: State<'_, AppRuntime>,
) -> Result<PackImportResult, String> {
    let import_id = Uuid::parse_str(&import_id).map_err(err)?;
    let pending = app
        .imports
        .lock()
        .map_err(err)?
        .remove(&import_id)
        .ok_or("Import preview expired or was already used")?;
    if pending.created_at.elapsed() >= Duration::from_secs(300) {
        return Err("Import preview expired; choose the file again".into());
    }
    let session = active_vault(&app)?;
    vault_ref(&session)?.import_pack(&pending.pack).map_err(err)
}

#[tauri::command]
fn add_memory_record(
    title: String,
    body: String,
    sensitivity: String,
    allowed_hosts: Vec<String>,
    app: State<AppRuntime>,
) -> Result<MemoryRecord, String> {
    let memory = MemoryRecord {
        id: Uuid::new_v4(),
        title: title.trim().into(),
        body: body.trim().into(),
        sensitivity: parse_sensitivity(&sensitivity)?,
        allowed_hosts,
        created_at: Utc::now(),
    };
    let session = active_vault(&app)?;
    vault_ref(&session)?.add_memory(&memory).map_err(err)?;
    Ok(memory)
}

#[tauri::command]
fn update_memory_record(
    memory_id: String,
    title: String,
    body: String,
    sensitivity: String,
    allowed_hosts: Vec<String>,
    app: State<AppRuntime>,
) -> Result<MemoryRecord, String> {
    let memory_id = Uuid::parse_str(&memory_id).map_err(err)?;
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let existing = vault
        .memory_record(memory_id)
        .map_err(err)?
        .ok_or("Memory record was not found")?;
    let memory = MemoryRecord {
        id: memory_id,
        title: title.trim().into(),
        body: body.trim().into(),
        sensitivity: parse_sensitivity(&sensitivity)?,
        allowed_hosts,
        created_at: existing.created_at,
    };
    vault.update_memory(&memory).map_err(err)?;
    Ok(memory)
}

#[tauri::command]
fn delete_memory_record(memory_id: String, app: State<AppRuntime>) -> Result<(), String> {
    let memory_id = Uuid::parse_str(&memory_id).map_err(err)?;
    let session = active_vault(&app)?;
    vault_ref(&session)?.delete_memory(memory_id).map_err(err)
}

#[tauri::command]
fn delete_connection_definition(
    connection_id: String,
    app: State<AppRuntime>,
) -> Result<(), String> {
    let connection_id = Uuid::parse_str(&connection_id).map_err(err)?;
    let session = active_vault(&app)?;
    vault_ref(&session)?
        .delete_connection(connection_id)
        .map_err(err)
}

fn parse_sensitivity(value: &str) -> Result<Sensitivity, String> {
    match value {
        "public" => Ok(Sensitivity::Public),
        "private" => Ok(Sensitivity::Private),
        "sensitive" => Ok(Sensitivity::Sensitive),
        _ => Err("Unsupported sensitivity".into()),
    }
}

#[tauri::command]
fn plan_connection_install(
    connection_id: String,
    host: String,
    app: State<AppRuntime>,
) -> Result<MutationSummary, String> {
    let connection_id = Uuid::parse_str(&connection_id).map_err(err)?;
    let session = active_vault(&app)?;
    let connection = vault_ref(&session)?
        .connection(connection_id)
        .map_err(err)?
        .ok_or("Connection was not found")?;
    let plan = plan_install(&home_dir()?, &host, &connection).map_err(err)?;
    let id = plan.id();
    let summary = plan.summary().clone();
    let mut plans = app.plans.lock().map_err(err)?;
    plans.retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    if plans.len() >= 32 {
        return Err("Too many pending install previews; approve or cancel one first".into());
    }
    plans.insert(
        id,
        PendingPlan {
            plan,
            created_at: Instant::now(),
        },
    );
    Ok(summary)
}

#[tauri::command]
fn apply_connection_install(
    plan_id: String,
    app: State<AppRuntime>,
) -> Result<ManagedDeployment, String> {
    let plan_id = Uuid::parse_str(&plan_id).map_err(err)?;
    let pending = app
        .plans
        .lock()
        .map_err(err)?
        .remove(&plan_id)
        .ok_or("Plan expired or was already used")?;
    if pending.created_at.elapsed() >= Duration::from_secs(300) {
        return Err("Install preview expired; review the change again".into());
    }
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    apply_recorded_install(vault, &home_dir()?, pending.plan).map_err(err)
}

#[tauri::command]
fn plan_connection_removal(
    deployment_id: String,
    app: State<AppRuntime>,
) -> Result<MutationSummary, String> {
    let deployment_id = Uuid::parse_str(&deployment_id).map_err(err)?;
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let plan = plan_removal(vault, &home_dir()?, deployment_id).map_err(err)?;
    let id = plan.id();
    let summary = plan.summary().clone();
    let mut removals = app.removals.lock().map_err(err)?;
    removals.retain(|_, pending| pending.created_at.elapsed() < Duration::from_secs(300));
    if removals.len() >= 32 {
        return Err("Too many pending removal previews; approve or cancel one first".into());
    }
    removals.insert(
        id,
        PendingRemoval {
            plan,
            created_at: Instant::now(),
        },
    );
    Ok(summary)
}

#[tauri::command]
fn apply_connection_removal(
    plan_id: String,
    app: State<AppRuntime>,
) -> Result<ManagedDeployment, String> {
    let plan_id = Uuid::parse_str(&plan_id).map_err(err)?;
    let pending = app
        .removals
        .lock()
        .map_err(err)?
        .remove(&plan_id)
        .ok_or("Removal preview expired or was already used")?;
    if pending.created_at.elapsed() >= Duration::from_secs(300) {
        return Err("Removal preview expired; review the change again".into());
    }
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    apply_recorded_removal(vault, &home_dir()?, pending.plan).map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vault_path = Vault::default_path().expect("app data path");
    let (vault, startup_error) = match Vault::open(&vault_path) {
        Ok(vault) => (Some(vault), None),
        Err(error) => (None, Some(error.to_string())),
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppRuntime {
            vault: Mutex::new(VaultSession {
                vault,
                last_access: Instant::now(),
            }),
            vault_path,
            startup_error: Mutex::new(startup_error),
            plans: Mutex::new(HashMap::new()),
            removals: Mutex::new(HashMap::new()),
            imports: Mutex::new(HashMap::new()),
            provider_previews: Mutex::new(HashMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            memory_records,
            connection_records,
            preview_provider_authorization,
            connect_provider,
            cancel_provider_authorization,
            disconnect_provider,
            touch_vault,
            purge_expired_previews,
            lock_vault,
            unlock_vault,
            create_local_profile,
            rename_local_profile,
            export_safe_pack,
            export_encrypted_pack,
            import_host_configuration,
            prepare_safe_pack_import,
            prepare_encrypted_pack_import,
            apply_pack_import,
            add_memory_record,
            update_memory_record,
            delete_memory_record,
            delete_connection_definition,
            plan_connection_install,
            apply_connection_install,
            plan_connection_removal,
            apply_connection_removal
        ])
        .run(tauri::generate_context!())
        .expect("run Cargo desktop")
}
