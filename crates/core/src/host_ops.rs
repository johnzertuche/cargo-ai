use crate::{
    ConnectionDefinition, DeploymentState, ManagedDeployment, Vault,
    adapters::{HostSnapshot, discover_known, fingerprint, import_codex_toml, import_json_mcp},
    mutation::{
        MutationPlan, MutationSummary, apply_json_plan, plan_json_install, revoke_json_deployment,
    },
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct PlannedInstall {
    id: Uuid,
    plan: InstallPlan,
    summary: MutationSummary,
}

pub struct PlannedRemoval {
    id: Uuid,
    deployment: ManagedDeployment,
    plan: RemovalPlan,
    summary: MutationSummary,
}

enum InstallPlan {
    Json(MutationPlan),
    OfficialCli(OfficialCliPlan),
}

enum RemovalPlan {
    Json { expected_preimage: Option<String> },
    OfficialCli(OfficialCliRemovalPlan),
}

struct OfficialCliPlan {
    connection_id: Uuid,
    host: String,
    server_name: String,
    executable: PathBuf,
    executable_sha256: String,
    add_args: Vec<String>,
    get_args: Vec<String>,
    remove_args: Vec<String>,
}

struct OfficialCliRemovalPlan {
    executable: PathBuf,
    executable_sha256: String,
    get_args: Vec<String>,
    remove_args: Vec<String>,
}

struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

impl PlannedInstall {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn summary(&self) -> &MutationSummary {
        &self.summary
    }
}

impl PlannedRemoval {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn summary(&self) -> &MutationSummary {
        &self.summary
    }
}

pub fn import_host_configuration(vault: &Vault, home: &Path, host: &str) -> Result<usize> {
    let snapshot = supported_snapshot(home, host)?;
    if !snapshot.exists {
        bail!("{} configuration was not found", snapshot.host);
    }
    if !snapshot.can_import {
        bail!(
            "{} does not expose a supported credential-free import surface",
            snapshot.host
        );
    }
    let definitions = if snapshot.host == "Codex" {
        import_codex_toml(&snapshot.path)?
    } else {
        import_json_mcp(&snapshot.path, &snapshot.host)?
    };
    vault.merge_imported_connections(&definitions)
}

pub fn inspect_host_configuration(home: &Path, host: &str) -> Result<Vec<ConnectionDefinition>> {
    let snapshot = supported_snapshot(home, host)?;
    if !snapshot.exists || !snapshot.can_import {
        bail!(
            "{} does not expose a supported import surface",
            snapshot.host
        );
    }
    if snapshot.host == "Codex" {
        import_codex_toml(&snapshot.path)
    } else {
        import_json_mcp(&snapshot.path, &snapshot.host)
    }
}

pub fn plan_install(
    home: &Path,
    host: &str,
    connection: &ConnectionDefinition,
) -> Result<PlannedInstall> {
    if host == "Claude Desktop" && connection.command.is_none() {
        bail!(
            "Claude Desktop remote connectors must be added through Settings > Connectors; its local JSON file is supported only for stdio servers"
        );
    }
    let snapshot = supported_snapshot(home, host)?;
    if !snapshot.can_install {
        bail!("Supported installation surface was not found");
    }
    if matches!(host, "Codex" | "Claude Code") {
        plan_official_cli(&snapshot, connection, |host, executable| {
            verify_official_executable(home, host, executable)
        })
    } else {
        let plan = plan_json_install(host, &snapshot.path, connection)?;
        let id = plan.id;
        let summary = plan.summary();
        Ok(PlannedInstall {
            id,
            plan: InstallPlan::Json(plan),
            summary,
        })
    }
}

pub fn apply_recorded_install(
    vault: &Vault,
    home: &Path,
    planned: PlannedInstall,
) -> Result<ManagedDeployment> {
    let deployment = match planned.plan {
        InstallPlan::Json(plan) => apply_json_plan(plan)?,
        InstallPlan::OfficialCli(plan) => apply_official_cli(&plan, |host, executable| {
            verify_official_executable(home, host, executable)
        })?,
    };
    if let Err(save_error) = vault.save_deployment(&deployment) {
        let rollback = remove_external(home, &deployment).map(|_| ());
        bail!(
            "Deployment record could not be saved ({save_error}); configuration rollback {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        );
    }
    Ok(deployment)
}

pub fn plan_removal(vault: &Vault, home: &Path, deployment_id: Uuid) -> Result<PlannedRemoval> {
    let deployment = vault
        .deployment(deployment_id)?
        .context("Deployment was not found")?;
    if !matches!(
        deployment.state,
        DeploymentState::Active | DeploymentState::LocalBlocked
    ) {
        bail!("only an active or pending host deployment can be removed");
    }
    let id = Uuid::new_v4();
    let (plan, summary) = if deployment.config_path.starts_with("cli://") {
        let snapshot = supported_snapshot(home, &deployment.host)?;
        let executable = snapshot
            .command_path
            .context("The current trusted host CLI was not found")?;
        let executable_sha256 = verify_official_executable(home, &deployment.host, &executable)?;
        let (_, get_args, remove_args) =
            cli_arguments_for_name(&deployment.host, &deployment.server_name)?;
        let summary = MutationSummary {
            plan_id: id,
            host: deployment.host.clone(),
            server_name: deployment.server_name.clone(),
            config_path: format!("official CLI: {}", executable.display()),
            operation: "official_cli_remove".into(),
            creates_config: false,
            preimage_sha256: Some(executable_sha256.clone()),
            result_sha256: "0".repeat(64),
            warnings: vec![
                "Cargo rediscovered and verified the current signed host CLI. The exact removal command below is one-use and expires with the preview.".into(),
                "This removes the host registration only. It does not terminate processes, log out OAuth, or revoke provider access.".into(),
            ],
            transport: "host_registration".into(),
            command: Some(executable.display().to_string()),
            args: remove_args.clone(),
            url: None,
            secret_references: vec![],
        };
        (
            RemovalPlan::OfficialCli(OfficialCliRemovalPlan {
                executable,
                executable_sha256,
                get_args,
                remove_args,
            }),
            summary,
        )
    } else {
        let path = PathBuf::from(&deployment.config_path);
        let expected_preimage = if path.exists() {
            Some(fingerprint(&path)?)
        } else {
            None
        };
        let summary = MutationSummary {
            plan_id: id,
            host: deployment.host.clone(),
            server_name: deployment.server_name.clone(),
            config_path: deployment.config_path.clone(),
            operation: "remove_managed_entry".into(),
            creates_config: false,
            preimage_sha256: expected_preimage.clone(),
            result_sha256: "0".repeat(64),
            warnings: vec![
                "Cargo will remove only the entry it owns and will stop if the host file or managed fragment changed after this preview.".into(),
                "This does not terminate existing sessions or revoke provider credentials.".into(),
            ],
            transport: "host_registration".into(),
            command: None,
            args: vec![],
            url: None,
            secret_references: vec![],
        };
        (RemovalPlan::Json { expected_preimage }, summary)
    };
    Ok(PlannedRemoval {
        id,
        deployment,
        plan,
        summary,
    })
}

pub fn apply_recorded_removal(
    vault: &Vault,
    home: &Path,
    planned: PlannedRemoval,
) -> Result<ManagedDeployment> {
    let mut pending = planned.deployment.clone();
    pending.state = DeploymentState::LocalBlocked;
    vault.save_deployment(&pending)?;
    let removal = match planned.plan {
        RemovalPlan::Json { expected_preimage } => {
            let path = PathBuf::from(&pending.config_path);
            let current = path.exists().then(|| fingerprint(&path)).transpose()?;
            if current != expected_preimage {
                bail!("host configuration changed after removal preview; review it again");
            }
            if path.exists() {
                revoke_json_deployment(&pending)
            } else {
                let mut removed = pending.clone();
                removed.state = DeploymentState::HostRemoved;
                Ok(removed)
            }
        }
        RemovalPlan::OfficialCli(plan) => remove_official_cli_plan(home, &pending, plan),
    };
    match removal {
        Ok(removed) => {
            vault.save_deployment(&removed)?;
            Ok(removed)
        }
        Err(remove_error) => {
            vault.save_deployment(&pending)?;
            bail!(
                "Host removal is pending and could not be verified: {remove_error}. Cargo has not terminated existing client sessions or provider access. Retry after resolving the host error."
            )
        }
    }
}

fn supported_snapshot(home: &Path, host: &str) -> Result<HostSnapshot> {
    discover_known(home)
        .into_iter()
        .find(|item| item.host == host)
        .with_context(|| format!("Unsupported AI client: {host}"))
}

fn official_command(executable: &Path, args: &[String]) -> Command {
    let mut command = Command::new(executable);
    command.args(args).stdin(Stdio::null()).env_clear();
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

fn verify_official_executable(home: &Path, host: &str, executable: &Path) -> Result<String> {
    #[cfg(not(target_os = "macos"))]
    bail!(
        "official CLI adapters are disabled until native publisher verification is implemented on this operating system"
    );
    let canonical = executable.canonicalize()?;
    let (trusted_root, team_id) = match host {
        "Codex" => (
            home.join(".codex/packages/standalone/releases"),
            "2DC432GLL2",
        ),
        "Claude Code" => (home.join(".local/share/claude/versions"), "Q6L2SF6YDW"),
        _ => bail!("Unsupported official CLI adapter"),
    };
    let trusted_root = trusted_root.canonicalize().with_context(|| {
        format!("The trusted {host} installation directory could not be verified")
    })?;
    if !canonical.starts_with(&trusted_root) || !canonical.is_file() {
        bail!(
            "Refusing to execute {host}: its resolved binary is outside the trusted installation directory"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&canonical)?.permissions().mode() & 0o022 != 0 {
            bail!("Refusing to execute a group/world-writable {host} binary");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let validation = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&canonical)
            .env_clear()
            .output()?;
        if !validation.status.success() {
            bail!("Refusing to execute {host}: the macOS code signature did not validate");
        }
        let output = Command::new("/usr/bin/codesign")
            .args(["-dv", "--verbose=2"])
            .arg(&canonical)
            .env_clear()
            .output()?;
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        if !output.status.success()
            || !diagnostic
                .lines()
                .any(|line| line == format!("TeamIdentifier={team_id}"))
        {
            bail!("Refusing to execute {host}: the macOS publisher signature did not match");
        }
    }
    fingerprint(&canonical)
}

fn bounded_output(executable: &Path, args: &[String]) -> Result<BoundedOutput> {
    const MAX_DIAGNOSTIC: u64 = 64 * 1024;
    let mut child = official_command(executable, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("host CLI stdout unavailable")?;
    let stderr = child.stderr.take().context("host CLI stderr unavailable")?;
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_DIAGNOSTIC + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(MAX_DIAGNOSTIC + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = child.wait()?;
    let stdout = Zeroizing::new(
        stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("host CLI stdout reader failed"))??,
    );
    let stderr = Zeroizing::new(
        stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("host CLI stderr reader failed"))??,
    );
    if stdout.len() as u64 > MAX_DIAGNOSTIC || stderr.len() as u64 > MAX_DIAGNOSTIC {
        bail!("host CLI diagnostic exceeded the 64 KiB safety limit");
    }
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn registration_exists(executable: &Path, args: &[String], server_name: &str) -> Result<bool> {
    let output = bounded_output(executable, args)?;
    if output.status.success() {
        return Ok(true);
    }
    let mut diagnostic =
        Zeroizing::new(String::from_utf8_lossy(&output.stdout).to_ascii_lowercase());
    diagnostic.push_str(&String::from_utf8_lossy(&output.stderr).to_ascii_lowercase());
    let name = server_name.to_ascii_lowercase();
    let codex = format!("error: no mcp server named '{name}' found.");
    let claude = format!("no mcp server named \"{name}\". run `claude mcp add` to add one.");
    let test_fixture = format!("no mcp server named {name} found.");
    if diagnostic
        .lines()
        .map(str::trim)
        .any(|line| line == codex || line == claude || line == test_fixture)
    {
        Ok(false)
    } else {
        bail!(
            "The official host CLI could not safely determine whether this registration already exists"
        )
    }
}

fn run_official_cli(executable: &Path, args: &[String], action: &str) -> Result<()> {
    let status = official_command(executable, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("The official host CLI failed to {action}; no CLI output was retained or logged")
    }
}

fn plan_official_cli<F>(
    snapshot: &HostSnapshot,
    connection: &ConnectionDefinition,
    verifier: F,
) -> Result<PlannedInstall>
where
    F: Fn(&str, &Path) -> Result<String>,
{
    let connection = crate::adapters::sanitize_connection_definition(connection)?;
    if !connection.environment_keys.is_empty() {
        bail!(
            "{} requires fresh authorization before it can be installed",
            connection.name
        );
    }
    let executable = snapshot
        .command_path
        .clone()
        .context("Official host CLI was not found")?;
    let executable_sha256 = verifier(&snapshot.host, &executable)?;
    let (add_args, get_args, remove_args) = cli_arguments(&snapshot.host, &connection)?;
    let id = Uuid::new_v4();
    let summary = MutationSummary {
        plan_id: id,
        host: snapshot.host.clone(),
        server_name: connection.name.clone(),
        config_path: format!("official CLI: {}", executable.display()),
        operation: "official_cli_install".into(),
        creates_config: false,
        preimage_sha256: None,
        result_sha256: executable_sha256.clone(),
        warnings: vec![
            "Cargo verified the host CLI's trusted install location, publisher Team ID, and executable fingerprint. It will invoke that exact binary directly without a shell and with a minimal environment.".into(),
            "Registration removal and OAuth credential logout are separate operations; this install does not copy credential values.".into(),
        ],
        transport: connection.transport.clone(),
        command: Some(executable.display().to_string()),
        args: add_args.clone(),
        url: connection.url.clone(),
        secret_references: vec![],
    };
    Ok(PlannedInstall {
        id,
        plan: InstallPlan::OfficialCli(OfficialCliPlan {
            connection_id: connection.id,
            host: snapshot.host.clone(),
            server_name: connection.name,
            executable,
            executable_sha256,
            add_args,
            get_args,
            remove_args,
        }),
        summary,
    })
}

fn cli_arguments(
    host: &str,
    connection: &ConnectionDefinition,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    crate::adapters::validate_server_identifier(&connection.name)?;
    match host {
        "Codex" => {
            let mut add = vec!["mcp".into(), "add".into(), connection.name.clone()];
            if let Some(command) = &connection.command {
                add.extend(["--".into(), command.clone()]);
                add.extend(connection.args.clone());
            } else if let Some(url) = &connection.url {
                add.extend(["--url".into(), url.clone()]);
            }
            Ok((
                add,
                vec![
                    "mcp".into(),
                    "get".into(),
                    connection.name.clone(),
                    "--json".into(),
                ],
                vec!["mcp".into(), "remove".into(), connection.name.clone()],
            ))
        }
        "Claude Code" => {
            let mut add = vec!["mcp".into(), "add".into(), "--scope".into(), "user".into()];
            if let Some(command) = &connection.command {
                add.extend([connection.name.clone(), "--".into(), command.clone()]);
                add.extend(connection.args.clone());
            } else if let Some(url) = &connection.url {
                add.extend([
                    "--transport".into(),
                    "http".into(),
                    connection.name.clone(),
                    url.clone(),
                ]);
            }
            Ok((
                add,
                vec!["mcp".into(), "get".into(), connection.name.clone()],
                vec![
                    "mcp".into(),
                    "remove".into(),
                    "--scope".into(),
                    "user".into(),
                    connection.name.clone(),
                ],
            ))
        }
        _ => bail!("Unsupported official CLI adapter"),
    }
}

fn cli_arguments_for_name(
    host: &str,
    name: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    crate::adapters::validate_server_identifier(name)?;
    cli_arguments(
        host,
        &ConnectionDefinition {
            id: Uuid::nil(),
            name: name.into(),
            transport: "stdio".into(),
            command: Some("placeholder".into()),
            args: vec![],
            url: None,
            environment_keys: vec![],
            metadata: Default::default(),
        },
    )
}

fn apply_official_cli<F>(plan: &OfficialCliPlan, verifier: F) -> Result<ManagedDeployment>
where
    F: Fn(&str, &Path) -> Result<String>,
{
    let current_sha256 = verifier(&plan.host, &plan.executable)?;
    if current_sha256 != plan.executable_sha256 {
        bail!("The verified host CLI changed after preview; create a new plan");
    }
    if registration_exists(&plan.executable, &plan.get_args, &plan.server_name)? {
        bail!(
            "{} already contains an MCP server named {}; Cargo will not overwrite it",
            plan.host,
            plan.server_name
        );
    }
    run_official_cli(&plan.executable, &plan.add_args, "add the registration")?;
    if !registration_exists(&plan.executable, &plan.get_args, &plan.server_name)? {
        let rollback = run_official_cli(
            &plan.executable,
            &plan.remove_args,
            "roll back the registration",
        );
        bail!(
            "The host CLI did not verify the new registration; automatic removal {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        );
    }
    Ok(ManagedDeployment {
        id: Uuid::new_v4(),
        connection_id: plan.connection_id,
        host: plan.host.clone(),
        server_name: plan.server_name.clone(),
        config_path: format!("cli://{}/user", plan.executable.display()),
        preimage_sha256: None,
        installed_fragment_sha256: plan.executable_sha256.clone(),
        backup_path: None,
        state: DeploymentState::Active,
        installed_at: Utc::now(),
    })
}

fn remove_external(home: &Path, deployment: &ManagedDeployment) -> Result<ManagedDeployment> {
    if deployment.config_path.starts_with("cli://") {
        remove_official_cli(home, deployment)
    } else {
        revoke_json_deployment(deployment)
    }
}

fn remove_official_cli(home: &Path, deployment: &ManagedDeployment) -> Result<ManagedDeployment> {
    let raw_path = deployment
        .config_path
        .strip_prefix("cli://")
        .and_then(|value| value.strip_suffix("/user"))
        .context("Managed CLI deployment does not contain a verified executable path")?;
    let executable = PathBuf::from(raw_path);
    let current_sha256 = verify_official_executable(home, &deployment.host, &executable)?;
    if current_sha256 != deployment.installed_fragment_sha256 {
        bail!(
            "The verified host CLI changed since installation; preview removal again after reviewing the new binary"
        );
    }
    let (_, get_args, remove_args) =
        cli_arguments_for_name(&deployment.host, &deployment.server_name)?;
    if registration_exists(&executable, &get_args, &deployment.server_name)? {
        run_official_cli(&executable, &remove_args, "remove the registration")?;
    }
    if registration_exists(&executable, &get_args, &deployment.server_name)? {
        bail!("The official host CLI did not verify registration removal");
    }
    let mut removed = deployment.clone();
    removed.state = DeploymentState::HostRemoved;
    Ok(removed)
}

fn remove_official_cli_plan(
    home: &Path,
    deployment: &ManagedDeployment,
    plan: OfficialCliRemovalPlan,
) -> Result<ManagedDeployment> {
    let current_sha256 = verify_official_executable(home, &deployment.host, &plan.executable)?;
    if current_sha256 != plan.executable_sha256 {
        bail!("the verified host CLI changed after removal preview; review removal again");
    }
    if registration_exists(&plan.executable, &plan.get_args, &deployment.server_name)? {
        run_official_cli(
            &plan.executable,
            &plan.remove_args,
            "remove the registration",
        )?;
    }
    if registration_exists(&plan.executable, &plan.get_args, &deployment.server_name)? {
        bail!("the official host CLI did not verify registration removal");
    }
    let mut removed = deployment.clone();
    removed.state = DeploymentState::HostRemoved;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn definition() -> ConnectionDefinition {
        ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "test".into(),
            transport: "stdio".into(),
            command: Some("safe-server".into()),
            args: vec!["--read-only".into()],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn json_plan_apply_and_recorded_removal_share_one_core_flow() {
        let directory = tempfile::tempdir().unwrap();
        let config_dir = directory.path().join(".cursor");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config = config_dir.join("mcp.json");
        std::fs::write(
            &config,
            br#"{"theme":"light","mcpServers":{"existing":{"command":"keep"}}}"#,
        )
        .unwrap();
        let vault = Vault::open_with_key(directory.path().join("vault.sqlite3"), [17; 32]).unwrap();
        let connection = definition();
        vault.upsert_connection(&connection).unwrap();

        let plan = plan_install(directory.path(), "Cursor", &connection).unwrap();
        assert_eq!(plan.summary().command.as_deref(), Some("safe-server"));
        let deployment = apply_recorded_install(&vault, directory.path(), plan).unwrap();
        assert_eq!(deployment.state, DeploymentState::Active);
        assert_eq!(vault.deployments().unwrap(), vec![deployment.clone()]);

        let installed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(installed["theme"], "light");
        assert_eq!(installed["mcpServers"]["test"]["command"], "safe-server");

        let removal = plan_removal(&vault, directory.path(), deployment.id).unwrap();
        assert_eq!(removal.summary().operation, "remove_managed_entry");
        let removed = apply_recorded_removal(&vault, directory.path(), removal).unwrap();
        assert_eq!(removed.state, DeploymentState::HostRemoved);
        let final_config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(final_config["mcpServers"]["existing"]["command"], "keep");
        assert!(final_config["mcpServers"].get("test").is_none());
        assert!(vault.verify_receipt_chain().unwrap());
    }

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
        let connection = definition();
        let planned =
            plan_official_cli(&snapshot, &connection, |_, path| fingerprint(path)).unwrap();
        assert_eq!(
            planned.summary.args,
            vec!["mcp", "add", "test", "--", "safe-server", "--read-only"]
        );
        let InstallPlan::OfficialCli(plan) = planned.plan else {
            panic!("expected official CLI plan")
        };
        let deployment = apply_official_cli(&plan, |_, path| fingerprint(path)).unwrap();
        assert!(state.exists());
        assert_eq!(deployment.state, DeploymentState::Active);
    }

    #[test]
    fn hostile_server_names_never_reach_official_cli_arguments() {
        for name in ["--help", "--scope", "two words", "../escape", "line\nbreak"] {
            assert!(
                cli_arguments_for_name("Codex", name).is_err(),
                "accepted {name:?}"
            );
            assert!(
                cli_arguments_for_name("Claude Code", name).is_err(),
                "accepted {name:?}"
            );
        }
        assert!(cli_arguments_for_name("Codex", "safe.server_2-test").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn unrelated_not_found_diagnostic_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("fake-host");
        std::fs::write(
            &executable,
            "#!/bin/sh\necho 'configuration not found' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            registration_exists(
                &executable,
                &["mcp".into(), "get".into(), "test".into()],
                "test"
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_registration_requires_exact_delimited_server_name() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("fake-host");
        std::fs::write(
            &executable,
            "#!/bin/sh\necho \"No MCP server named 'foobar' found.\" >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            registration_exists(
                &executable,
                &["mcp".into(), "get".into(), "foo".into()],
                "foo"
            )
            .is_err()
        );
    }
}
