use cargo_ai_core::{
    ConnectionDefinition, LocalProfile, ManagedDeployment, MemoryRecord, PackImportResult,
    PortablePack, Sensitivity, Vault,
    adapters::{HostSnapshot, discover_known, import_codex_toml, import_json_mcp},
    mutation::{
        MutationPlan, MutationSummary, apply_json_plan, plan_json_install, revoke_json_deployment,
        write_private_file,
    },
    transfer::{decrypt_pack, encrypt_pack},
    validate_portable_pack,
};
use chrono::Utc;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
    imports: Mutex<HashMap<Uuid, PendingImport>>,
}

struct VaultSession {
    vault: Option<Vault>,
    last_access: Instant,
}

struct PendingPlan {
    plan: InstallPlan,
    created_at: Instant,
}

enum InstallPlan {
    Json(MutationPlan),
    OfficialCli(CliInstallPlan),
}

struct CliInstallPlan {
    id: Uuid,
    connection_id: Uuid,
    host: String,
    server_name: String,
    executable: PathBuf,
    add_args: Vec<String>,
    get_args: Vec<String>,
    remove_args: Vec<String>,
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
    connections: Vec<ConnectionDefinition>,
    deployments: Vec<ManagedDeployment>,
    memory: Vec<MemoryRecord>,
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
    let connections = vault.connections().map_err(err)?;
    let memory = vault.memory().map_err(err)?;
    Ok(AppState {
        profile: vault.profile().map_err(err)?,
        hosts: discover_known(&home_dir()?),
        connection_count: connections.len(),
        connections,
        deployments: vault.deployments().map_err(err)?,
        memory_count: memory.len(),
        memory,
        receipts: vault.receipts().map_err(err)?,
        receipt_chain_valid: vault.verify_receipt_chain().map_err(err)?,
        vault_path: vault.path().display().to_string(),
    })
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
    let snapshot = discover_known(&home_dir()?)
        .into_iter()
        .find(|item| item.host == host)
        .ok_or("Unsupported AI client")?;
    if !snapshot.exists {
        return Err(format!("{} configuration was not found", snapshot.host));
    }
    if !snapshot.can_import {
        return Err(format!(
            "{} does not expose a supported credential-free import surface",
            snapshot.host
        ));
    }
    let definitions = if snapshot.host == "Codex" {
        import_codex_toml(&snapshot.path).map_err(err)?
    } else {
        import_json_mcp(&snapshot.path, &snapshot.host).map_err(err)?
    };
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    for definition in &definitions {
        vault.merge_imported_connection(definition).map_err(err)?;
    }
    Ok(definitions.len())
}

fn official_command(executable: &Path, args: &[String]) -> Command {
    let mut command = Command::new(executable);
    command.args(args).stdin(Stdio::null()).env_clear();
    for key in [
        "HOME", "PATH", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

fn registration_exists(executable: &Path, args: &[String]) -> Result<bool, String> {
    let status = official_command(executable, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(err)?;
    if status.success() {
        return Ok(true);
    }
    let output = official_command(executable, args).output().map_err(err)?;
    let mut diagnostic = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    diagnostic.push_str(&String::from_utf8_lossy(&output.stderr).to_ascii_lowercase());
    if diagnostic.contains("no mcp server named") || diagnostic.contains("not found") {
        Ok(false)
    } else {
        Err("The official host CLI could not safely determine whether this registration already exists".into())
    }
}

fn run_official_cli(executable: &Path, args: &[String], action: &str) -> Result<(), String> {
    let status = official_command(executable, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(err)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "The official host CLI failed to {action}; no CLI output was retained or logged"
        ))
    }
}

fn plan_cli_install(
    snapshot: &HostSnapshot,
    connection: &ConnectionDefinition,
) -> Result<(CliInstallPlan, MutationSummary), String> {
    let connection =
        cargo_ai_core::adapters::sanitize_connection_definition(connection).map_err(err)?;
    if !connection.environment_keys.is_empty() {
        return Err(format!(
            "{} requires fresh authorization before it can be installed",
            connection.name
        ));
    }
    let executable = snapshot
        .command_path
        .clone()
        .ok_or("Official host CLI was not found")?;
    let (add_args, get_args, remove_args) = match snapshot.host.as_str() {
        "Codex" => {
            let mut add = vec!["mcp".into(), "add".into(), connection.name.clone()];
            if let Some(command) = &connection.command {
                add.push("--".into());
                add.push(command.clone());
                add.extend(connection.args.clone());
            } else if let Some(url) = &connection.url {
                add.extend(["--url".into(), url.clone()]);
            }
            (
                add,
                vec![
                    "mcp".into(),
                    "get".into(),
                    connection.name.clone(),
                    "--json".into(),
                ],
                vec!["mcp".into(), "remove".into(), connection.name.clone()],
            )
        }
        "Claude Code" => {
            let mut add = vec!["mcp".into(), "add".into(), "--scope".into(), "user".into()];
            if let Some(command) = &connection.command {
                add.push(connection.name.clone());
                add.push("--".into());
                add.push(command.clone());
                add.extend(connection.args.clone());
            } else if let Some(url) = &connection.url {
                add.extend([
                    "--transport".into(),
                    "http".into(),
                    connection.name.clone(),
                    url.clone(),
                ]);
            }
            (
                add,
                vec!["mcp".into(), "get".into(), connection.name.clone()],
                vec![
                    "mcp".into(),
                    "remove".into(),
                    "--scope".into(),
                    "user".into(),
                    connection.name.clone(),
                ],
            )
        }
        _ => return Err("Unsupported official CLI adapter".into()),
    };
    if registration_exists(&executable, &get_args)? {
        return Err(format!(
            "{} already contains an MCP server named {}; Cargo will not overwrite it",
            snapshot.host, connection.name
        ));
    }
    let id = Uuid::new_v4();
    let plan = CliInstallPlan {
        id,
        connection_id: connection.id,
        host: snapshot.host.clone(),
        server_name: connection.name.clone(),
        executable: executable.clone(),
        add_args: add_args.clone(),
        get_args,
        remove_args,
    };
    let summary = MutationSummary {
        plan_id: id,
        host: snapshot.host.clone(),
        server_name: connection.name,
        config_path: format!("official CLI: {}", executable.display()),
        operation: "official_cli_install".into(),
        creates_config: false,
        preimage_sha256: None,
        result_sha256: id.as_simple().to_string().repeat(2),
        warnings: vec![
            "Cargo will invoke the signed host CLI directly without a shell and with a minimal environment.".into(),
            "Registration removal and OAuth credential logout are separate operations; this install does not copy credential values.".into(),
        ],
        transport: connection.transport,
        command: Some(executable.display().to_string()),
        args: add_args,
        url: connection.url,
        secret_references: vec![],
    };
    Ok((plan, summary))
}

fn apply_cli_plan(plan: CliInstallPlan) -> Result<ManagedDeployment, String> {
    run_official_cli(&plan.executable, &plan.add_args, "add the registration")?;
    if !registration_exists(&plan.executable, &plan.get_args)? {
        let rollback = run_official_cli(
            &plan.executable,
            &plan.remove_args,
            "roll back the registration",
        );
        return Err(format!(
            "The host CLI did not verify the new registration; automatic removal {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        ));
    }
    Ok(ManagedDeployment {
        id: Uuid::new_v4(),
        connection_id: plan.connection_id,
        host: plan.host,
        server_name: plan.server_name,
        config_path: format!("cli://{}/user", plan.executable.display()),
        preimage_sha256: None,
        installed_fragment_sha256: plan.id.as_simple().to_string().repeat(2),
        backup_path: None,
        state: cargo_ai_core::DeploymentState::Active,
        installed_at: Utc::now(),
    })
}

fn remove_cli_registration(deployment: &ManagedDeployment) -> Result<ManagedDeployment, String> {
    let snapshot = discover_known(&home_dir()?)
        .into_iter()
        .find(|item| item.host == deployment.host)
        .ok_or("Host adapter is unavailable")?;
    let executable = snapshot
        .command_path
        .ok_or("Official host CLI is unavailable")?;
    let (get_args, remove_args) = match deployment.host.as_str() {
        "Codex" => (
            vec![
                "mcp".into(),
                "get".into(),
                deployment.server_name.clone(),
                "--json".into(),
            ],
            vec![
                "mcp".into(),
                "remove".into(),
                deployment.server_name.clone(),
            ],
        ),
        "Claude Code" => (
            vec!["mcp".into(), "get".into(), deployment.server_name.clone()],
            vec![
                "mcp".into(),
                "remove".into(),
                "--scope".into(),
                "user".into(),
                deployment.server_name.clone(),
            ],
        ),
        _ => return Err("Unsupported official CLI adapter".into()),
    };
    if registration_exists(&executable, &get_args)? {
        run_official_cli(&executable, &remove_args, "remove the registration")?;
    }
    if registration_exists(&executable, &get_args)? {
        return Err("The official host CLI did not verify registration removal".into());
    }
    let mut removed = deployment.clone();
    removed.state = cargo_ai_core::DeploymentState::HostRemoved;
    Ok(removed)
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
    if title.trim().is_empty() || title.chars().count() > 200 {
        return Err("Memory title must be between 1 and 200 characters".into());
    }
    if body.trim().is_empty() || body.len() > 256 * 1024 {
        return Err("Memory body must be between 1 byte and 256 KiB".into());
    }
    let sensitivity = match sensitivity.as_str() {
        "public" => Sensitivity::Public,
        "private" => Sensitivity::Private,
        "sensitive" => Sensitivity::Sensitive,
        _ => return Err("Unsupported sensitivity".into()),
    };
    let memory = MemoryRecord {
        id: Uuid::new_v4(),
        title: title.trim().into(),
        body: body.trim().into(),
        sensitivity,
        allowed_hosts,
        created_at: Utc::now(),
    };
    let session = active_vault(&app)?;
    vault_ref(&session)?.add_memory(&memory).map_err(err)?;
    Ok(memory)
}

fn json_host(host: &str) -> Result<HostSnapshot, String> {
    if host == "Codex" {
        return Err("Codex installation must use the official codex mcp command and is not enabled in this build".into());
    }
    discover_known(&home_dir()?)
        .into_iter()
        .find(|item| item.host == host && matches!(host, "Claude Desktop" | "Cursor"))
        .ok_or("Unsupported JSON-based AI client".into())
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
    if host == "Claude Desktop" && connection.command.is_none() {
        return Err("Claude Desktop remote connectors must be added through Settings > Connectors; its local JSON file is supported only for stdio servers".into());
    }
    let snapshot = discover_known(&home_dir()?)
        .into_iter()
        .find(|item| item.host == host && item.can_install)
        .ok_or("Supported installation surface was not found")?;
    let (id, plan, summary) = if matches!(host.as_str(), "Codex" | "Claude Code") {
        let (plan, summary) = plan_cli_install(&snapshot, &connection)?;
        (plan.id, InstallPlan::OfficialCli(plan), summary)
    } else {
        let snapshot = json_host(&host)?;
        let plan = plan_json_install(&host, &snapshot.path, &connection).map_err(err)?;
        let summary = plan.summary();
        (plan.id, InstallPlan::Json(plan), summary)
    };
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
    let deployment = match pending.plan {
        InstallPlan::Json(plan) => apply_json_plan(plan).map_err(err)?,
        InstallPlan::OfficialCli(plan) => apply_cli_plan(plan)?,
    };
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    if let Err(save_error) = vault.save_deployment(&deployment) {
        let rollback = if deployment.config_path.starts_with("cli://") {
            remove_cli_registration(&deployment).map(|_| ())
        } else {
            revoke_json_deployment(&deployment).map(|_| ()).map_err(err)
        };
        return Err(format!(
            "Deployment record could not be saved ({save_error}); configuration rollback {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        ));
    }
    Ok(deployment)
}

#[tauri::command]
fn revoke_connection_deployment(
    deployment_id: String,
    app: State<AppRuntime>,
) -> Result<ManagedDeployment, String> {
    let deployment_id = Uuid::parse_str(&deployment_id).map_err(err)?;
    let session = active_vault(&app)?;
    let vault = vault_ref(&session)?;
    let deployment = vault
        .deployment(deployment_id)
        .map_err(err)?
        .ok_or("Deployment was not found")?;
    let mut blocked = deployment.clone();
    blocked.state = cargo_ai_core::DeploymentState::LocalBlocked;
    vault.save_deployment(&blocked).map_err(err)?;
    let removal = if deployment.config_path.starts_with("cli://") {
        remove_cli_registration(&blocked)
    } else {
        revoke_json_deployment(&blocked).map_err(err)
    };
    match removal {
        Ok(removed) => {
            vault.save_deployment(&removed).map_err(err)?;
            Ok(removed)
        }
        Err(remove_error) => {
            vault.save_deployment(&blocked).map_err(err)?;
            Err(format!(
                "New Cargo actions are locally blocked, but host removal could not be verified: {remove_error}. Retry after resolving the host error."
            ))
        }
    }
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
            imports: Mutex::new(HashMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            lock_vault,
            unlock_vault,
            create_local_profile,
            export_safe_pack,
            export_encrypted_pack,
            import_host_configuration,
            prepare_safe_pack_import,
            prepare_encrypted_pack_import,
            apply_pack_import,
            add_memory_record,
            plan_connection_install,
            apply_connection_install,
            revoke_connection_deployment
        ])
        .run(tauri::generate_context!())
        .expect("run Cargo desktop")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[cfg(unix)]
    #[test]
    fn official_cli_plan_apply_and_verify_use_exact_arguments() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("fake-host");
        let state = directory.path().join("registered");
        let script = format!(
            "#!/bin/sh\ncase \"$2\" in\n  add) touch '{}' ;;\n  get) test -f '{}' || {{ echo 'No MCP server named test found.'; exit 1; }} ;;\n  remove) rm -f '{}' ;;\n  *) exit 2 ;;\nesac\n",
            state.display(),
            state.display(),
            state.display()
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

        let snapshot = HostSnapshot {
            host: "Codex".into(),
            path: directory.path().join("config.toml"),
            exists: true,
            can_import: false,
            can_install: true,
            command_path: Some(executable.clone()),
            fingerprint: None,
        };
        let connection = ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "test".into(),
            transport: "stdio".into(),
            command: Some("safe-server".into()),
            args: vec!["--read-only".into()],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::new(),
        };
        let (plan, summary) = plan_cli_install(&snapshot, &connection).unwrap();
        assert_eq!(summary.command.as_deref(), executable.to_str());
        assert_eq!(
            summary.args,
            vec!["mcp", "add", "test", "--", "safe-server", "--read-only"]
        );
        let deployment = apply_cli_plan(plan).unwrap();
        assert!(state.exists());
        assert_eq!(deployment.state, cargo_ai_core::DeploymentState::Active);
        run_official_cli(
            &executable,
            &["mcp".into(), "remove".into(), "test".into()],
            "remove",
        )
        .unwrap();
        assert!(!state.exists());
    }
}
