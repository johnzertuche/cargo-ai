use crate::{
    ConnectionDefinition, ExecutionCredentialActivation, ExecutionCredentialActivationKind,
    ExecutionCredentialActivationState, ExecutionCredentialStatus, ExecutionGrant,
    ExecutionGrantStatus, StdioExecutionSnapshot,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PREVIEW_LIFETIME: Duration = Duration::minutes(5);

/// A backend-created, bounded preview. Its fields are private so callers
/// cannot construct an arbitrary executable snapshot or lifecycle state.
pub struct ExecutionGrantPreview {
    id: Uuid,
    expected_profile_id: Uuid,
    connection_id: Uuid,
    host: String,
    source_fingerprint: String,
    snapshot: StdioExecutionSnapshot,
    snapshot_sha256: String,
    expires_at: DateTime<Utc>,
}

impl ExecutionGrantPreview {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn snapshot(&self) -> &StdioExecutionSnapshot {
        &self.snapshot
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub(crate) fn expected_profile_id(&self) -> Uuid {
        self.expected_profile_id
    }

    pub(crate) fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    pub(crate) fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[cfg(test)]
    pub(crate) fn set_expires_at(&mut self, expires_at: DateTime<Utc>) {
        self.expires_at = expires_at;
    }
}

pub fn prepare_execution_grant_preview(
    expected_profile_id: Uuid,
    connection: &ConnectionDefinition,
    host: &str,
) -> Result<ExecutionGrantPreview> {
    validate_host(host)?;
    let connection = crate::adapters::sanitize_connection_definition(connection)?;
    if connection.transport != "stdio" || connection.url.is_some() {
        bail!("the local broker foundation supports stdio definitions only");
    }
    let command = connection
        .command
        .clone()
        .context("stdio definition does not contain a command")?;
    if connection.environment_keys.is_empty() {
        bail!("this definition does not contain unresolved environment credentials");
    }
    for name in &connection.environment_keys {
        validate_environment_name(name)?;
    }
    let snapshot = StdioExecutionSnapshot {
        schema_version: 1,
        command,
        args: connection.args.clone(),
        credential_names: connection.environment_keys.clone(),
        working_directory_policy: "none".into(),
    };
    let source_fingerprint = connection_fingerprint(&connection);
    let snapshot_sha256 = snapshot_fingerprint(connection.id, host, &snapshot);
    Ok(ExecutionGrantPreview {
        id: Uuid::new_v4(),
        expected_profile_id,
        connection_id: connection.id,
        host: host.into(),
        source_fingerprint,
        snapshot,
        snapshot_sha256,
        expires_at: Utc::now() + PREVIEW_LIFETIME,
    })
}

pub(crate) fn validate_host(host: &str) -> Result<()> {
    if !matches!(host, "Claude Desktop" | "Cursor" | "Codex" | "Claude Code") {
        bail!("unsupported execution host");
    }
    Ok(())
}

pub(crate) fn validate_environment_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && (index > 0 || byte.is_ascii_alphabetic())
        })
    {
        bail!("credential references must be portable environment variable names");
    }
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("DYLD_")
        || upper.starts_with("LD_")
        || upper.starts_with("PYTHON")
        || matches!(
            upper.as_str(),
            "NODE_OPTIONS"
                | "NODE_PATH"
                | "RUSTC_WRAPPER"
                | "SSLKEYLOGFILE"
                | "PATH"
                | "HOME"
                | "TMPDIR"
                | "SHELL"
                | "IFS"
                | "ENV"
                | "BASH_ENV"
                | "CDPATH"
                | "PERL5LIB"
                | "RUBYLIB"
                | "GEM_HOME"
                | "CLASSPATH"
                | "JAVA_TOOL_OPTIONS"
                | "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NO_PROXY"
        )
    {
        bail!("this environment variable can alter the broker runtime and is not allowed");
    }
    Ok(())
}

pub(crate) fn validate_snapshot(snapshot: &StdioExecutionSnapshot) -> Result<()> {
    if snapshot.schema_version != 1
        || snapshot.command.trim().is_empty()
        || snapshot.command.len() > 16 * 1024
        || snapshot.args.len() > 128
        || snapshot.args.iter().any(|value| value.len() > 16 * 1024)
        || snapshot.credential_names.is_empty()
        || snapshot.credential_names.len() > 128
        || snapshot.working_directory_policy != "none"
    {
        bail!("execution snapshot is invalid or oversized");
    }
    let mut names = std::collections::HashSet::new();
    for name in &snapshot.credential_names {
        validate_environment_name(name)?;
        if !names.insert(name) {
            bail!("execution snapshot contains duplicate credential names");
        }
    }
    Ok(())
}

pub(crate) fn validate_execution_grant(grant: &ExecutionGrant) -> Result<()> {
    validate_host(&grant.host)?;
    validate_snapshot(&grant.snapshot)?;
    if grant.source_fingerprint.len() != 64
        || !grant
            .source_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || grant.snapshot_sha256
            != snapshot_fingerprint(grant.connection_id, &grant.host, &grant.snapshot)
        || grant.required_credentials.len() != grant.snapshot.credential_names.len()
    {
        bail!("execution grant fingerprint or credential requirements are invalid");
    }
    let mut binding_ids = std::collections::HashSet::new();
    for (requirement, name) in grant
        .required_credentials
        .iter()
        .zip(&grant.snapshot.credential_names)
    {
        if requirement.name != *name || !binding_ids.insert(requirement.binding_id) {
            bail!("execution grant credential requirements are invalid");
        }
    }
    match grant.status {
        ExecutionGrantStatus::AwaitingCredentials
            if grant.revision.is_multiple_of(2)
                && grant.cancelled_at.is_none()
                && grant.required_credentials.iter().all(|item| {
                    item.status == ExecutionCredentialStatus::Missing && item.secret_ref.is_none()
                }) => {}
        ExecutionGrantStatus::CredentialsReady
            if !grant.revision.is_multiple_of(2)
                && grant.cancelled_at.is_none()
                && grant.required_credentials.iter().all(|item| {
                    item.status == ExecutionCredentialStatus::Stored
                        && item.secret_ref.as_deref().is_some_and(|reference| {
                            secret_reference_matches(reference, grant.id, item.binding_id)
                        })
                }) => {}
        ExecutionGrantStatus::Cancelled
            if grant.revision >= 1
                && grant
                    .cancelled_at
                    .is_some_and(|cancelled_at| cancelled_at >= grant.created_at)
                && grant.required_credentials.iter().all(|item| {
                    item.status == ExecutionCredentialStatus::Missing && item.secret_ref.is_none()
                }) => {}
        _ => bail!("execution grant lifecycle state is invalid"),
    }
    Ok(())
}

pub(crate) fn validate_credential_activation(
    activation: &ExecutionCredentialActivation,
) -> Result<()> {
    if activation.credentials.is_empty() || activation.credentials.len() > 128 {
        bail!("execution credential activation has an invalid credential count");
    }
    let mut bindings = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut references = std::collections::HashSet::new();
    for credential in &activation.credentials {
        validate_environment_name(&credential.name)?;
        if !bindings.insert(credential.binding_id)
            || !names.insert(credential.name.as_str())
            || !references.insert(credential.secret_ref.as_str())
            || !secret_reference_matches(
                &credential.secret_ref,
                activation.grant_id,
                credential.binding_id,
            )
        {
            bail!("execution credential activation contains invalid or duplicate fields");
        }
    }
    match (&activation.kind, &activation.state) {
        (
            ExecutionCredentialActivationKind::Write,
            ExecutionCredentialActivationState::Staged
            | ExecutionCredentialActivationState::CredentialsWritten
            | ExecutionCredentialActivationState::CleanupPending,
        ) if activation.completed_at.is_none() => {}
        (
            ExecutionCredentialActivationKind::Delete,
            ExecutionCredentialActivationState::CleanupPending,
        ) if activation.completed_at.is_none() => {}
        (_, ExecutionCredentialActivationState::Completed)
            if activation
                .completed_at
                .is_some_and(|completed_at| completed_at >= activation.created_at) => {}
        _ => bail!("execution credential activation lifecycle is invalid"),
    }
    Ok(())
}

pub(crate) fn new_secret_reference(grant_id: Uuid, binding_id: Uuid) -> String {
    format!("execution/{grant_id}/{binding_id}/{}", Uuid::new_v4())
}

fn secret_reference_matches(value: &str, grant_id: Uuid, binding_id: Uuid) -> bool {
    let mut parts = value.split('/');
    parts.next() == Some("execution")
        && parts.next().and_then(|part| Uuid::parse_str(part).ok()) == Some(grant_id)
        && parts.next().and_then(|part| Uuid::parse_str(part).ok()) == Some(binding_id)
        && parts
            .next()
            .and_then(|part| Uuid::parse_str(part).ok())
            .is_some()
        && parts.next().is_none()
}

pub(crate) fn connection_fingerprint(connection: &ConnectionDefinition) -> String {
    let mut canonical = Vec::new();
    field(&mut canonical, b"cargo:execution-connection:v1");
    field(&mut canonical, connection.id.as_bytes());
    field(&mut canonical, connection.name.as_bytes());
    field(&mut canonical, connection.transport.as_bytes());
    optional_field(&mut canonical, connection.command.as_deref());
    fields(&mut canonical, &connection.args);
    optional_field(&mut canonical, connection.url.as_deref());
    fields(&mut canonical, &connection.environment_keys);
    length(&mut canonical, connection.metadata.len());
    for (key, value) in &connection.metadata {
        field(&mut canonical, key.as_bytes());
        field(&mut canonical, value.as_bytes());
    }
    format!("{:x}", Sha256::digest(canonical))
}

pub(crate) fn snapshot_fingerprint(
    connection_id: Uuid,
    host: &str,
    snapshot: &StdioExecutionSnapshot,
) -> String {
    let mut canonical = Vec::new();
    field(&mut canonical, b"cargo:stdio-execution-snapshot:v1");
    field(&mut canonical, connection_id.as_bytes());
    field(&mut canonical, host.as_bytes());
    length(&mut canonical, snapshot.schema_version as usize);
    field(&mut canonical, snapshot.command.as_bytes());
    fields(&mut canonical, &snapshot.args);
    fields(&mut canonical, &snapshot.credential_names);
    field(&mut canonical, snapshot.working_directory_policy.as_bytes());
    format!("{:x}", Sha256::digest(canonical))
}

pub(crate) fn owner_key(connection_id: Uuid, host: &str) -> String {
    let mut canonical = Vec::new();
    field(&mut canonical, b"cargo:execution-owner:v1");
    field(&mut canonical, connection_id.as_bytes());
    field(&mut canonical, host.as_bytes());
    format!("{:x}", Sha256::digest(canonical))
}

fn fields(target: &mut Vec<u8>, values: &[String]) {
    length(target, values.len());
    for value in values {
        field(target, value.as_bytes());
    }
}

fn optional_field(target: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            target.push(1);
            field(target, value.as_bytes());
        }
        None => target.push(0),
    }
}

fn field(target: &mut Vec<u8>, value: &[u8]) {
    length(target, value.len());
    target.extend_from_slice(value);
}

fn length(target: &mut Vec<u8>, value: usize) {
    target.extend_from_slice(&(value as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn definition(args: Vec<String>) -> ConnectionDefinition {
        ConnectionDefinition {
            id: Uuid::from_u128(7),
            name: "local-tools".into(),
            transport: "stdio".into(),
            command: Some("/Applications/Tools/server".into()),
            args,
            url: None,
            environment_keys: vec!["API_KEY".into()],
            metadata: BTreeMap::from([("source".into(), "test".into())]),
        }
    }

    #[test]
    fn exact_argv_and_host_are_hash_significant() {
        let profile = Uuid::from_u128(1);
        let empty =
            prepare_execution_grant_preview(profile, &definition(vec!["".into()]), "Cursor")
                .unwrap();
        let whitespace =
            prepare_execution_grant_preview(profile, &definition(vec![" ".into()]), "Cursor")
                .unwrap();
        let reordered = prepare_execution_grant_preview(
            profile,
            &definition(vec!["second".into(), "first".into()]),
            "Cursor",
        )
        .unwrap();
        let other_host =
            prepare_execution_grant_preview(profile, &definition(vec!["".into()]), "Codex")
                .unwrap();
        assert_ne!(empty.snapshot_sha256(), whitespace.snapshot_sha256());
        assert_ne!(empty.snapshot_sha256(), reordered.snapshot_sha256());
        assert_ne!(empty.snapshot_sha256(), other_host.snapshot_sha256());
        assert_eq!(empty.snapshot().args, vec![""]);
    }

    #[test]
    fn only_plain_nondangerous_environment_names_are_accepted() {
        for name in [
            "header:Authorization",
            "arg:--key",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "HTTP_PROXY",
            "PATH",
            "9TOKEN",
        ] {
            let mut value = definition(vec![]);
            value.environment_keys = vec![name.into()];
            assert!(prepare_execution_grant_preview(Uuid::new_v4(), &value, "Cursor").is_err());
        }
        let mut value = definition(vec![]);
        value.environment_keys = vec!["MY_API_TOKEN_2".into()];
        assert!(prepare_execution_grant_preview(Uuid::new_v4(), &value, "Cursor").is_ok());
    }
}
