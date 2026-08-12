use cargo_ai_core::{
    ConnectionDefinition, LocalProfile, ManagedDeployment, MemoryRecord, PackImportResult,
    PortablePack, Sensitivity, Vault,
    adapters::{HostSnapshot, discover_known},
    host_ops::{
        PlannedInstall, PlannedRemoval, apply_recorded_install, apply_recorded_removal,
        import_host_configuration as import_host, plan_install, plan_removal,
    },
    mutation::{MutationSummary, write_private_file},
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
use uuid::Uuid;

struct AppRuntime {
    vault: Mutex<VaultSession>,
    vault_path: PathBuf,
    startup_error: Mutex<Option<String>>,
    plans: Mutex<HashMap<Uuid, PendingPlan>>,
    removals: Mutex<HashMap<Uuid, PendingRemoval>>,
    imports: Mutex<HashMap<Uuid, PendingImport>>,
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
    receipts: Vec<cargo_ai_core::AuditReceipt>,
    receipt_chain_valid: bool,
    vault_path: String,
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
        receipts: vault.receipts().map_err(err)?,
        receipt_chain_valid: vault.verify_receipt_chain().map_err(err)?,
        vault_path: vault.path().display().to_string(),
    })
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
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            memory_records,
            connection_records,
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
