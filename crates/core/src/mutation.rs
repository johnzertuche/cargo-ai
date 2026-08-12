use crate::{ConnectionDefinition, DeploymentState, ManagedDeployment};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct MutationSummary {
    pub plan_id: Uuid,
    pub host: String,
    pub server_name: String,
    pub config_path: String,
    pub operation: String,
    pub creates_config: bool,
    pub preimage_sha256: Option<String>,
    pub result_sha256: String,
    pub warnings: Vec<String>,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub secret_references: Vec<String>,
}

pub struct MutationPlan {
    pub id: Uuid,
    host: String,
    path: PathBuf,
    connection: ConnectionDefinition,
    before: Option<Zeroizing<Vec<u8>>>,
    after: Zeroizing<Vec<u8>>,
    preimage_sha256: Option<String>,
    fragment_sha256: String,
}

impl MutationPlan {
    pub fn summary(&self) -> MutationSummary {
        MutationSummary {
            plan_id: self.id,
            host: self.host.clone(),
            server_name: self.connection.name.clone(),
            config_path: self.path.display().to_string(),
            operation: "install_connection".into(),
            creates_config: self.before.is_none(),
            preimage_sha256: self.preimage_sha256.clone(),
            result_sha256: sha256(&self.after),
            warnings: vec![
                "This untrusted definition may execute when the destination AI client starts. Review every command and argument.".into(),
                "The entire JSON file is rewritten; unrelated fields are semantically preserved. Cargo does not retain a plaintext copy of the host file.".into(),
            ],
            transport: self.connection.transport.clone(),
            command: self.connection.command.clone(),
            args: self.connection.args.clone(),
            url: self.connection.url.clone(),
            secret_references: self.connection.environment_keys.clone(),
        }
    }
}

pub fn plan_json_install(
    host: &str,
    path: &Path,
    connection: &ConnectionDefinition,
) -> Result<MutationPlan> {
    validate_definition(connection)?;
    validate_target_path(path)?;

    let before = if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.len() > MAX_CONFIG_BYTES {
            bail!("configuration exceeds 4 MiB limit");
        }
        Some(Zeroizing::new(fs::read(path)?))
    } else {
        None
    };
    let mut root: Value = match &before {
        Some(bytes) => serde_json::from_slice(bytes).context("configuration is not valid JSON")?,
        None => json!({}),
    };
    let object = root
        .as_object_mut()
        .context("configuration root must be a JSON object")?;
    if !object.contains_key("mcpServers") {
        object.insert("mcpServers".into(), Value::Object(Map::new()));
    }
    let servers = object
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .context("mcpServers must be a JSON object")?;
    if servers.contains_key(&connection.name) {
        bail!(
            "{} already contains an MCP server named {}; Cargo will not overwrite it",
            host,
            connection.name
        );
    }
    let fragment = connection_fragment(connection)?;
    let fragment_sha256 = sha256(&serde_json::to_vec(&fragment)?);
    servers.insert(connection.name.clone(), fragment);
    let mut after = serde_json::to_vec_pretty(&root)?;
    after.push(b'\n');
    let preimage_sha256 = before.as_ref().map(|bytes| sha256(bytes));

    Ok(MutationPlan {
        id: Uuid::new_v4(),
        host: host.into(),
        path: path.to_path_buf(),
        connection: connection.clone(),
        before,
        after: Zeroizing::new(after),
        preimage_sha256,
        fragment_sha256,
    })
}

pub fn apply_json_plan(plan: MutationPlan) -> Result<ManagedDeployment> {
    validate_target_path(&plan.path)?;
    assert_preimage(&plan.path, plan.preimage_sha256.as_deref())?;
    atomic_write(
        &plan.path,
        &plan.after,
        plan.preimage_sha256.as_deref(),
        true,
    )?;

    let verification = (|| -> Result<()> {
        let written: Value = serde_json::from_slice(&fs::read(&plan.path)?)?;
        let fragment = written
            .get("mcpServers")
            .and_then(Value::as_object)
            .and_then(|servers| servers.get(&plan.connection.name))
            .context("installed entry could not be verified")?;
        if sha256(&serde_json::to_vec(fragment)?) != plan.fragment_sha256 {
            bail!("installed entry fingerprint did not verify");
        }
        Ok(())
    })();
    if let Err(verify_error) = verification {
        let expected = sha256(&plan.after);
        let rollback = restore_preimage(
            &plan.path,
            plan.before.as_deref().map(Vec::as_slice),
            &expected,
        );
        bail!(
            "installation verification failed ({verify_error}); automatic restoration {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        );
    }

    Ok(ManagedDeployment {
        id: Uuid::new_v4(),
        connection_id: plan.connection.id,
        host: plan.host,
        server_name: plan.connection.name,
        config_path: plan.path.display().to_string(),
        preimage_sha256: plan.preimage_sha256,
        installed_fragment_sha256: plan.fragment_sha256,
        backup_path: None,
        state: DeploymentState::Active,
        installed_at: Utc::now(),
    })
}

pub fn revoke_json_deployment(deployment: &ManagedDeployment) -> Result<ManagedDeployment> {
    if !matches!(
        deployment.state,
        DeploymentState::Active | DeploymentState::LocalBlocked
    ) {
        bail!("only an active or locally blocked deployment can be removed");
    }
    let path = PathBuf::from(&deployment.config_path);
    validate_target_path(&path)?;
    let before = Zeroizing::new(fs::read(&path).context("host configuration is missing")?);
    if before.len() as u64 > MAX_CONFIG_BYTES {
        bail!("configuration exceeds 4 MiB limit");
    }
    let mut root: Value = serde_json::from_slice(&before)?;
    let Some(servers) = root.get_mut("mcpServers").and_then(Value::as_object_mut) else {
        let mut removed = deployment.clone();
        removed.state = DeploymentState::HostRemoved;
        return Ok(removed);
    };
    let Some(current) = servers.get(&deployment.server_name) else {
        let mut removed = deployment.clone();
        removed.state = DeploymentState::HostRemoved;
        return Ok(removed);
    };
    if sha256(&serde_json::to_vec(current)?) != deployment.installed_fragment_sha256 {
        bail!("managed entry changed after installation; refusing to remove user edits");
    }
    servers.remove(&deployment.server_name);
    let mut after = Zeroizing::new(serde_json::to_vec_pretty(&root)?);
    after.push(b'\n');
    let current_sha256 = sha256(&before);
    atomic_write(&path, &after, Some(&current_sha256), true)?;

    let verification = (|| -> Result<()> {
        let verified: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if verified
            .get("mcpServers")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(&deployment.server_name))
        {
            bail!("managed entry removal could not be verified");
        }
        Ok(())
    })();
    if let Err(verify_error) = verification {
        let expected = sha256(&after);
        let rollback = restore_preimage(&path, Some(&before), &expected);
        bail!(
            "managed entry removal verification failed ({verify_error}); automatic restoration {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        );
    }
    let mut result = deployment.clone();
    result.state = DeploymentState::HostRemoved;
    result.backup_path = None;
    Ok(result)
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_target_path(path)?;
    let expected = path
        .exists()
        .then(|| fs::read(path))
        .transpose()?
        .map(|v| sha256(&v));
    atomic_write(path, bytes, expected.as_deref(), false)
}

fn validate_definition(connection: &ConnectionDefinition) -> Result<()> {
    if connection.name.trim().is_empty() {
        bail!("connection name cannot be empty");
    }
    if connection.command.is_some() == connection.url.is_some() {
        bail!("connection must contain exactly one of command or url");
    }
    if !connection.environment_keys.is_empty() {
        bail!(
            "{} references credentials; add them to the destination host through its secure authorization flow",
            connection.name
        );
    }
    if let Some(url) = &connection.url {
        crate::adapters::validate_url(url)?;
    }
    Ok(())
}

fn connection_fragment(connection: &ConnectionDefinition) -> Result<Value> {
    if let Some(command) = &connection.command {
        Ok(json!({ "command": command, "args": connection.args }))
    } else if let Some(url) = &connection.url {
        Ok(json!({ "url": url }))
    } else {
        bail!("connection has no transport")
    }
}

fn validate_target_path(path: &Path) -> Result<()> {
    let parent = path.parent().context("configuration path has no parent")?;
    if parent.exists() {
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() {
            bail!("refusing symlinked configuration directory");
        }
        reject_symlink_components(&parent.canonicalize()?)?;
    } else {
        bail!("configuration directory does not exist");
    }
    if path.exists() && fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("refusing symlinked configuration");
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.exists() && fs::symlink_metadata(&current)?.file_type().is_symlink() {
            bail!("refusing a path containing a symlinked directory");
        }
    }
    Ok(())
}

fn assert_preimage(path: &Path, expected: Option<&str>) -> Result<()> {
    match (expected, path.exists()) {
        (None, false) => Ok(()),
        (Some(expected), true) if sha256(&fs::read(path)?) == expected => Ok(()),
        _ => bail!("configuration changed after preview; review a new plan before applying"),
    }
}

fn restore_preimage(path: &Path, before: Option<&[u8]>, expected_current: &str) -> Result<()> {
    match before {
        Some(bytes) => atomic_write(path, bytes, Some(expected_current), true),
        None => {
            assert_preimage(path, Some(expected_current))?;
            fs::remove_file(path)?;
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
    }
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    expected_preimage: Option<&str>,
    preserve_permissions: bool,
) -> Result<()> {
    let parent = path.parent().context("configuration path has no parent")?;
    let filename = path
        .file_name()
        .context("configuration path has no filename")?;
    let temporary = parent.join(format!(
        ".{}.cargo-ai-{}.tmp",
        filename.to_string_lossy(),
        Uuid::new_v4()
    ));
    let original_permissions = if preserve_permissions && path.exists() {
        Some(fs::metadata(path)?.permissions())
    } else {
        None
    };
    let write_result = (|| -> Result<()> {
        write_private_new(&temporary, bytes)?;
        if let Some(permissions) = original_permissions {
            fs::set_permissions(&temporary, permissions)?;
        }
        assert_preimage(path, expected_preimage)?;
        fs::rename(&temporary, path)?;
        if !preserve_permissions {
            set_private_file(path)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn definition() -> ConnectionDefinition {
        ConnectionDefinition {
            id: Uuid::new_v4(),
            name: "docs".into(),
            transport: "stdio".into(),
            command: Some("server-docs".into()),
            args: vec!["--safe".into()],
            url: None,
            environment_keys: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn install_and_revoke_preserve_unrelated_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp.json");
        fs::write(
            &path,
            br#"{"theme":"light","mcpServers":{"existing":{"command":"keep-me"}}}"#,
        )
        .unwrap();
        let deployment =
            apply_json_plan(plan_json_install("Cursor", &path, &definition()).unwrap()).unwrap();
        assert!(deployment.backup_path.is_none());
        assert!(!directory.path().join(".cargo-ai-backups").exists());
        let installed: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(installed["theme"], "light");
        assert_eq!(installed["mcpServers"]["existing"]["command"], "keep-me");
        assert_eq!(installed["mcpServers"]["docs"]["command"], "server-docs");

        let removed = revoke_json_deployment(&deployment).unwrap();
        assert_eq!(removed.state, DeploymentState::HostRemoved);
        assert!(removed.backup_path.is_none());
        let final_value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(final_value["theme"], "light");
        assert_eq!(final_value["mcpServers"]["existing"]["command"], "keep-me");
        assert!(final_value["mcpServers"].get("docs").is_none());

        let retried = revoke_json_deployment(&deployment).unwrap();
        assert_eq!(retried.state, DeploymentState::HostRemoved);
    }

    #[test]
    fn rejects_stale_plan() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp.json");
        fs::write(&path, br#"{"mcpServers":{}}"#).unwrap();
        let plan = plan_json_install("Cursor", &path, &definition()).unwrap();
        fs::write(&path, br#"{"mcpServers":{},"external":true}"#).unwrap();
        assert!(apply_json_plan(plan).is_err());
    }

    #[test]
    fn refuses_to_remove_a_drifted_managed_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp.json");
        fs::write(&path, br#"{"mcpServers":{}}"#).unwrap();
        let deployment =
            apply_json_plan(plan_json_install("Cursor", &path, &definition()).unwrap()).unwrap();
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["mcpServers"]["docs"]["args"] = json!(["--changed"]);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(revoke_json_deployment(&deployment).is_err());
    }

    #[test]
    fn refuses_to_materialize_discarded_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp.json");
        fs::write(&path, br#"{"mcpServers":{}}"#).unwrap();
        let mut item = definition();
        item.environment_keys.push("API_KEY".into());
        assert!(plan_json_install("Cursor", &path, &item).is_err());
    }
}
