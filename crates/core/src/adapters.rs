use crate::ConnectionDefinition;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use url::{Host, Url};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub host: String,
    pub path: PathBuf,
    pub exists: bool,
    pub can_import: bool,
    pub can_install: bool,
    pub command_path: Option<PathBuf>,
    pub fingerprint: Option<String>,
}

pub fn fingerprint(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

pub fn discover_known(home: &Path) -> Vec<HostSnapshot> {
    let json_hosts = [
        (
            "Claude Desktop",
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        ),
        ("Cursor", home.join(".cursor/mcp.json")),
    ]
    .into_iter()
    .map(|(host, path)| {
        let exists = path.is_file();
        HostSnapshot {
            host: host.into(),
            exists,
            can_import: exists,
            can_install: path.parent().is_some_and(Path::exists),
            command_path: None,
            fingerprint: exists.then(|| fingerprint(&path).ok()).flatten(),
            path,
        }
    });
    let codex_config = home.join(".codex/config.toml");
    let codex_cli = trusted_command_path(home, "codex");
    let claude_cli = trusted_command_path(home, "claude");
    json_hosts
        .chain([
            HostSnapshot {
                host: "Codex".into(),
                path: codex_config.clone(),
                exists: codex_config.is_file() || codex_cli.is_some(),
                can_import: codex_config.is_file(),
                can_install: codex_cli.is_some(),
                command_path: codex_cli,
                fingerprint: codex_config
                    .is_file()
                    .then(|| fingerprint(&codex_config).ok())
                    .flatten(),
            },
            HostSnapshot {
                host: "Claude Code".into(),
                path: claude_cli
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("claude")),
                exists: claude_cli.is_some(),
                can_import: false,
                can_install: claude_cli.is_some(),
                command_path: claude_cli,
                fingerprint: None,
            },
        ])
        .collect()
}

fn trusted_command_path(home: &Path, name: &str) -> Option<PathBuf> {
    home.join(".local/bin")
        .join(name)
        .canonicalize()
        .ok()
        .filter(|candidate| candidate.is_file())
}

pub fn read_json_config(path: &Path) -> Result<serde_json::Value> {
    let metadata = fs::symlink_metadata(path).context("cannot inspect configuration")?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symlinked configuration");
    }
    if metadata.len() > 4 * 1024 * 1024 {
        bail!("configuration exceeds 4 MiB limit");
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn import_json_mcp(path: &Path, source: &str) -> Result<Vec<ConnectionDefinition>> {
    let config = read_json_config(path)?;
    let servers = config
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .context("configuration does not contain an mcpServers object")?;
    let mut imported = Vec::new();
    for (name, raw) in servers {
        let object = raw
            .as_object()
            .context("MCP server entry must be an object")?;
        let command = object
            .get("command")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let raw_url = object.get("url").and_then(|v| v.as_str());
        if command.is_some() == raw_url.is_some() {
            bail!("MCP server {name} must contain exactly one of command or url");
        }
        let (url, mut secret_refs) = match raw_url {
            Some(raw) => {
                let (safe, refs) = sanitize_url(raw)?;
                (Some(safe), refs)
            }
            None => (None, vec![]),
        };
        let raw_args = json_string_array(object.get("args"), name)?;
        let (args, mut arg_refs) = sanitize_args(&raw_args)?;
        secret_refs.append(&mut arg_refs);
        if let Some(env) = object.get("env") {
            let env = env.as_object().context("MCP env must be an object")?;
            secret_refs.extend(env.keys().cloned());
        }
        if let Some(headers) = object.get("headers") {
            let headers = headers
                .as_object()
                .context("MCP headers must be an object")?;
            secret_refs.extend(headers.keys().map(|key| format!("header:{key}")));
        }
        secret_refs.sort();
        secret_refs.dedup();
        imported.push(ConnectionDefinition {
            id: uuid::Uuid::new_v4(),
            name: name.clone(),
            transport: if command.is_some() {
                "stdio".into()
            } else {
                "streamable_http".into()
            },
            command,
            args,
            url,
            environment_keys: secret_refs,
            metadata: BTreeMap::from([
                ("source".into(), source.into()),
                ("source_path".into(), path.display().to_string()),
            ]),
        });
    }
    imported.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(imported)
}

pub fn import_codex_toml(path: &Path) -> Result<Vec<ConnectionDefinition>> {
    let metadata = fs::symlink_metadata(path).context("cannot inspect Codex configuration")?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symlinked configuration");
    }
    if metadata.len() > 4 * 1024 * 1024 {
        bail!("configuration exceeds 4 MiB limit");
    }
    let config: toml::Value = toml::from_str(&fs::read_to_string(path)?)?;
    let servers = config
        .get("mcp_servers")
        .and_then(|v| v.as_table())
        .context("configuration does not contain mcp_servers")?;
    let mut imported = Vec::new();
    for (name, raw) in servers {
        let object = raw
            .as_table()
            .context("Codex MCP server entry must be a table")?;
        let command = object
            .get("command")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let raw_url = object.get("url").and_then(|v| v.as_str());
        if command.is_some() == raw_url.is_some() {
            bail!("MCP server {name} must contain exactly one of command or url");
        }
        let (url, mut secret_refs) = match raw_url {
            Some(raw) => {
                let (safe, refs) = sanitize_url(raw)?;
                (Some(safe), refs)
            }
            None => (None, vec![]),
        };
        let raw_args = toml_string_array(object.get("args"), name)?;
        let (args, mut arg_refs) = sanitize_args(&raw_args)?;
        secret_refs.append(&mut arg_refs);
        if let Some(env) = object.get("env") {
            let env = env.as_table().context("Codex MCP env must be a table")?;
            secret_refs.extend(env.keys().cloned());
        }
        if let Some(key) = object.get("bearer_token_env_var").and_then(|v| v.as_str()) {
            secret_refs.push(key.into());
        }
        secret_refs.sort();
        secret_refs.dedup();
        imported.push(ConnectionDefinition {
            id: uuid::Uuid::new_v4(),
            name: name.clone(),
            transport: if command.is_some() {
                "stdio".into()
            } else {
                "streamable_http".into()
            },
            command,
            args,
            url,
            environment_keys: secret_refs,
            metadata: BTreeMap::from([
                ("source".into(), "Codex".into()),
                ("source_path".into(), path.display().to_string()),
            ]),
        });
    }
    imported.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(imported)
}

pub fn validate_url(raw: &str) -> Result<()> {
    sanitize_url(raw).map(|_| ())
}

pub fn sanitize_connection_definition(
    definition: &ConnectionDefinition,
) -> Result<ConnectionDefinition> {
    if definition.name.trim().is_empty() || definition.name.chars().count() > 200 {
        bail!("connection name must be between 1 and 200 characters");
    }
    validate_server_identifier(&definition.name)?;
    if definition.command.is_some() == definition.url.is_some() {
        bail!("connection must contain exactly one of command or url");
    }
    if definition
        .command
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("stdio connection command cannot be empty");
    }
    if definition.args.len() > 128 || definition.environment_keys.len() > 128 {
        bail!("connection contains too many arguments or credential references");
    }
    if definition.args.iter().any(|value| value.len() > 8 * 1024)
        || definition
            .command
            .as_ref()
            .is_some_and(|value| value.len() > 8 * 1024)
        || definition
            .url
            .as_ref()
            .is_some_and(|value| value.len() > 16 * 1024)
    {
        bail!("connection contains an oversized command, argument, or URL");
    }

    let (args, mut discovered) = sanitize_args(&definition.args)?;
    let url = definition
        .url
        .as_deref()
        .map(sanitize_url)
        .transpose()?
        .map(|(url, mut refs)| {
            discovered.append(&mut refs);
            url
        });
    let command = definition.command.as_ref().map(|value| value.trim().into());
    let expected_transport = if command.is_some() {
        "stdio"
    } else {
        "streamable_http"
    };
    if definition.transport != expected_transport {
        bail!("connection transport does not match its command or URL");
    }

    let mut environment_keys = definition.environment_keys.clone();
    environment_keys.append(&mut discovered);
    if environment_keys
        .iter()
        .any(|value| value.trim().is_empty() || value.len() > 512)
    {
        bail!("connection contains an invalid credential reference");
    }
    environment_keys.sort();
    environment_keys.dedup();

    let mut metadata = definition.metadata.clone();
    metadata.remove("source_path");
    if metadata.len() > 32
        || metadata
            .iter()
            .any(|(key, value)| key.len() > 128 || value.len() > 2048)
    {
        bail!("connection metadata exceeds portable pack limits");
    }

    Ok(ConnectionDefinition {
        id: definition.id,
        name: definition.name.trim().into(),
        transport: expected_transport.into(),
        command,
        args,
        url,
        environment_keys,
        metadata,
    })
}

/// Applies a deliberately narrower grammar to definitions typed directly by
/// a user. Manual entry has no provider schema that could reliably distinguish
/// configuration from credentials, so ambiguous secret-bearing forms fail
/// closed instead of relying only on heuristic redaction.
pub fn sanitize_manual_connection_definition(
    definition: &ConnectionDefinition,
) -> Result<ConnectionDefinition> {
    let sanitized = sanitize_connection_definition(definition)?;
    if sanitized.environment_keys != definition.environment_keys
        || sanitized.args != definition.args
    {
        bail!(
            "manual definitions cannot contain secret-shaped values; add credentials through a dedicated authorization flow"
        );
    }
    if let Some(raw_url) = definition.url.as_deref() {
        let url = Url::parse(raw_url).context("invalid MCP URL")?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!(
                "manual remote URLs cannot contain user information, query parameters, or fragments"
            );
        }
    }
    if let Some(command) = sanitized.command.as_deref() {
        let normalized = command.to_ascii_lowercase();
        if command.chars().any(char::is_control)
            || command.contains("://")
            || looks_like_token(command)
            || normalized.contains("authorization:")
        {
            bail!("manual stdio commands must be plain executable names or paths");
        }
    }
    for argument in &definition.args {
        if argument.chars().any(char::is_control)
            || is_manual_credential_argument(argument)
            || argument.to_ascii_lowercase().contains("authorization:")
        {
            bail!(
                "manual stdio arguments cannot contain header, environment, credential, or secret injection forms"
            );
        }
        let url_values = std::iter::once(argument.as_str())
            .chain(argument.split_once('=').map(|(_, value)| value));
        for value in url_values {
            if let Ok(url) = Url::parse(value)
                && (!url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some())
            {
                bail!("manual stdio URL arguments cannot contain private URL components");
            }
        }
    }
    Ok(sanitized)
}

pub fn validate_server_identifier(name: &str) -> Result<()> {
    if name.len() > 128
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "connection name must be a safe 1-128 character identifier using only letters, numbers, dot, underscore, or hyphen, and cannot start with a hyphen"
        );
    }
    Ok(())
}

fn sanitize_url(raw: &str) -> Result<(String, Vec<String>)> {
    let mut url = Url::parse(raw).context("invalid MCP URL")?;
    if url.fragment().is_some() {
        bail!("MCP URLs cannot contain fragments");
    }
    let allowed = match url.scheme() {
        "https" => url.host().is_some(),
        "http" => {
            matches!(url.host(), Some(Host::Domain("localhost")))
                || matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        }
        _ => false,
    };
    if !allowed {
        bail!("remote MCP URLs must use HTTPS; HTTP is limited to exact loopback hosts");
    }
    let mut refs = Vec::new();
    if !url.username().is_empty() || url.password().is_some() {
        refs.push("url:userinfo".into());
        url.set_username("")
            .map_err(|_| anyhow::anyhow!("cannot sanitize URL userinfo"))?;
        url.set_password(None)
            .map_err(|_| anyhow::anyhow!("cannot sanitize URL password"))?;
    }
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if !pairs.is_empty() {
        url.set_query(None);
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            if is_sensitive_name(&key) || looks_like_token(&value) {
                refs.push(format!("url_query:{key}"));
                query.append_pair(&key, "<redacted>");
            } else {
                query.append_pair(&key, &value);
            }
        }
    }
    refs.sort();
    refs.dedup();
    Ok((url.into(), refs))
}

fn sanitize_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut result = args.to_vec();
    let mut refs = Vec::new();
    let mut redact_next: Option<String> = None;
    for (index, value) in args.iter().enumerate() {
        if let Some(flag) = redact_next.take() {
            result[index] = "<redacted>".into();
            refs.push(format!("arg:{flag}"));
            continue;
        }
        if let Some((flag, supplied)) = value.split_once('=') {
            if is_sensitive_name(flag) {
                if supplied.is_empty() {
                    bail!("sensitive argument {flag} has an empty value");
                }
                result[index] = format!("{flag}=<redacted>");
                refs.push(format!("arg:{flag}"));
                continue;
            }
            if supplied.contains("://") {
                match sanitize_url(supplied) {
                    Ok((safe, mut url_refs)) => {
                        result[index] = format!("{flag}={safe}");
                        refs.append(&mut url_refs);
                    }
                    Err(_) => {
                        result[index] = format!("{flag}=<redacted>");
                        refs.push(format!("arg:{flag}:url"));
                    }
                }
                continue;
            }
        }
        if value.starts_with('-') && is_sensitive_name(value) {
            redact_next = Some(value.clone());
            continue;
        }
        if value.contains("://") {
            match sanitize_url(value) {
                Ok((safe, mut url_refs)) => {
                    result[index] = safe;
                    refs.append(&mut url_refs);
                }
                Err(_) => {
                    result[index] = "<redacted>".into();
                    refs.push(format!("arg:{index}:url"));
                }
            }
        } else if looks_like_token(value) {
            result[index] = "<redacted>".into();
            refs.push(format!("arg:{index}"));
        }
    }
    if let Some(flag) = redact_next {
        bail!("sensitive argument {flag} is missing its value");
    }
    refs.sort();
    refs.dedup();
    Ok((result, refs))
}

fn json_string_array(value: Option<&serde_json::Value>, name: &str) -> Result<Vec<String>> {
    match value {
        None => Ok(vec![]),
        Some(value) => value
            .as_array()
            .context("MCP args must be an array")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("MCP server {name} has a non-string argument"))
            })
            .collect(),
    }
}

fn toml_string_array(value: Option<&toml::Value>, name: &str) -> Result<Vec<String>> {
    match value {
        None => Ok(vec![]),
        Some(value) => value
            .as_array()
            .context("Codex MCP args must be an array")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("Codex MCP server {name} has a non-string argument"))
            })
            .collect(),
    }
}

fn is_sensitive_name(value: &str) -> bool {
    let normalized = value
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['_', '.'], "-");
    [
        "token",
        "secret",
        "password",
        "passwd",
        "api-key",
        "apikey",
        "authorization",
        "auth-key",
        "private-key",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn looks_like_token(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.starts_with("bearer ")
        || value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("github_pat_")
}

fn is_manual_credential_argument(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if looks_like_token(value) {
        return true;
    }
    let key = lower.split_once('=').map_or(lower.as_str(), |(key, _)| key);
    let pieces: Vec<&str> = key
        .trim_start_matches('-')
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|piece| !piece.is_empty())
        .collect();
    if pieces.iter().any(|piece| {
        matches!(
            *piece,
            "authorization"
                | "auth"
                | "bearer"
                | "credential"
                | "credentials"
                | "cookie"
                | "cookies"
                | "certificate"
                | "cert"
                | "env"
                | "environment"
                | "header"
                | "headers"
                | "key"
                | "password"
                | "passwd"
                | "session"
                | "sessionid"
                | "secret"
                | "token"
        )
    }) {
        return true;
    }
    let assignment_key = value.split_once('=').map(|(key, _)| key).unwrap_or("");
    !assignment_key.is_empty()
        && assignment_key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && assignment_key.bytes().any(|byte| byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_read_only_and_deterministic() {
        let d = tempfile::tempdir().unwrap();
        let a = discover_known(d.path());
        let b = discover_known(d.path());
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        assert_eq!(a.len(), 4);
        assert!(a.iter().take(2).all(|x| !x.exists));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::write(&real, "{}").unwrap();
        let link = d.path().join("link");
        symlink(real, &link).unwrap();
        assert!(read_json_config(&link).is_err());
    }

    #[test]
    fn imports_json_without_secret_values() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("mcp.json");
        fs::write(&path, r#"{"mcpServers":{"docs":{"command":"npx","args":["-y","server"],"env":{"API_KEY":"super-secret"}}}}"#).unwrap();
        let items = import_json_mcp(&path, "test").unwrap();
        let serialized = serde_json::to_string(&items).unwrap();
        assert_eq!(items[0].environment_keys, vec!["API_KEY"]);
        assert!(!serialized.contains("super-secret"));
    }

    #[test]
    fn rejects_insecure_and_lookalike_urls() {
        assert!(validate_url("http://evil.example/mcp").is_err());
        assert!(validate_url("http://localhost.evil.example/mcp").is_err());
        assert!(validate_url("http://127.0.0.1.attacker/mcp").is_err());
        assert!(validate_url("http://localhost:8787/mcp").is_ok());
        assert!(validate_url("http://[::1]:8787/mcp").is_ok());
    }

    #[test]
    fn redacts_secrets_in_arguments_and_url_queries() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("mcp.json");
        fs::write(
            &path,
            r#"{"mcpServers":{"docs":{"command":"server","args":["--api-key","sk-supersecret"]}}}"#,
        )
        .unwrap();
        let items = import_json_mcp(&path, "test").unwrap();
        let serialized = serde_json::to_string(&items).unwrap();
        assert!(!serialized.contains("sk-supersecret"));
        assert!(items[0].environment_keys.contains(&"arg:--api-key".into()));

        let (url, refs) =
            sanitize_url("https://example.com/mcp?api_key=sk-hidden&tenant=one").unwrap();
        assert!(!url.contains("sk-hidden"));
        assert!(url.contains("tenant=one"));
        assert_eq!(refs, vec!["url_query:api_key"]);
    }
}
