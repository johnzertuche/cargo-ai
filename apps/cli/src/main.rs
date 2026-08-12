use anyhow::Result;
use cargo_ai_core::{
    ClientRegistrationKind, GrantStatus, MemoryRecord, ProviderGrant, RevocationVerification,
    Sensitivity, TokenRevocationResult, Vault,
    adapters::discover_known,
    host_ops::{
        apply_recorded_install, apply_recorded_removal, inspect_host_configuration, plan_install,
        plan_removal,
    },
    mutation::write_private_file,
    oauth::{AuthorizationTransaction, OAuthProviderTransport, TokenKind, new_secret_reference},
    oauth_callback::LoopbackCallback,
    oauth_http::HttpOAuthTransport,
    transfer::{decrypt_pack, encrypt_pack},
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "cargo-ai",
    about = "Local-first AI connection and memory vault"
)]
struct Cli {
    #[arg(long)]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        name: String,
    },
    Status,
    RenameProfile {
        #[arg(long)]
        name: String,
    },
    Discover {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    ImportHost {
        #[arg(long)]
        host: String,
        #[arg(
            long,
            help = "Apply the displayed import without an interactive confirmation"
        )]
        yes: bool,
    },
    Deployments,
    Install {
        connection_id: Uuid,
        #[arg(long)]
        host: String,
        #[arg(
            long,
            help = "Reveal exact argument values for interactive review; incompatible with --yes"
        )]
        show_values: bool,
        #[arg(
            long,
            help = "Apply the displayed plan without an interactive confirmation"
        )]
        yes: bool,
    },
    RemoveDeployment {
        deployment_id: Uuid,
        #[arg(
            long,
            help = "Apply the displayed removal without an interactive confirmation"
        )]
        yes: bool,
    },
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    ExportSafe {
        output: PathBuf,
    },
    #[command(alias = "backup")]
    ExportEncrypted {
        output: PathBuf,
    },
    #[command(alias = "inspect-backup")]
    InspectEncrypted {
        input: PathBuf,
    },
    ImportSafe {
        input: PathBuf,
    },
    #[command(alias = "restore-backup")]
    ImportEncrypted {
        input: PathBuf,
    },
    Connections {
        #[arg(
            long,
            help = "Print full argument values; output may contain secrets the heuristic scanner missed"
        )]
        show_values: bool,
    },
    DeleteConnection {
        id: Uuid,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    Receipts,
}

#[derive(Subcommand)]
enum ProviderCommand {
    List,
    Authorize {
        connection_id: Uuid,
        #[arg(long)]
        client_id: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(
            long,
            help = "Proceed after printing the exact authorization preview without typed confirmation"
        )]
        yes: bool,
    },
    Disconnect {
        grant_id: Uuid,
        #[arg(
            long,
            help = "Proceed after printing the provider lifecycle state without typed confirmation"
        )]
        yes: bool,
    },
    Cancel {
        grant_id: Uuid,
    },
}

#[derive(Subcommand)]
enum MemoryCommand {
    List,
    Add {
        #[arg(long)]
        title: String,
        #[arg(
            long,
            value_name = "PATH",
            help = "Read the body from a file; otherwise read standard input"
        )]
        body_file: Option<PathBuf>,
        #[arg(long, default_value = "private")]
        sensitivity: String,
        #[arg(long = "host")]
        allowed_hosts: Vec<String>,
    },
    Edit {
        id: Uuid,
        #[arg(long)]
        title: String,
        #[arg(
            long,
            value_name = "PATH",
            help = "Read the body from a file; otherwise read standard input"
        )]
        body_file: Option<PathBuf>,
        #[arg(long, default_value = "private")]
        sensitivity: String,
        #[arg(long = "host")]
        allowed_hosts: Vec<String>,
    },
    Delete {
        id: Uuid,
    },
}

fn parse_sensitivity(value: &str) -> Result<Sensitivity> {
    Ok(match value {
        "public" => Sensitivity::Public,
        "private" => Sensitivity::Private,
        "sensitive" => Sensitivity::Sensitive,
        _ => anyhow::bail!("sensitivity must be public, private, or sensitive"),
    })
}

fn read_memory_body(body_file: Option<PathBuf>) -> Result<String> {
    let body = if let Some(path) = body_file {
        String::from_utf8(read_bounded(&path, 256 * 1024)?)?
    } else {
        eprintln!("Reading memory body from standard input (finish with EOF)…");
        let mut body = String::new();
        std::io::stdin()
            .take(256 * 1024 + 1)
            .read_to_string(&mut body)?;
        if body.len() > 256 * 1024 {
            anyhow::bail!("memory body exceeds 256 KiB");
        }
        body
    };
    if body.trim().is_empty() {
        anyhow::bail!("memory body must be non-empty");
    }
    Ok(body.trim().into())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing a symlinked input file");
    }
    if metadata.len() > maximum {
        anyhow::bail!("input exceeds the size limit");
    }
    Ok(fs::read(path)?)
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("home unavailable"))
}

fn require_confirmation(expected: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "interactive confirmation is required; review the preview above and rerun with --yes only if it is exact"
        );
    }
    eprint!("Type {expected:?} to continue: ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim() != expected {
        anyhow::bail!("confirmation did not match; no changes were made");
    }
    Ok(())
}

fn redacted_connection_previews(
    definitions: &[cargo_ai_core::ConnectionDefinition],
) -> Vec<serde_json::Value> {
    definitions
        .iter()
        .map(|definition| {
            serde_json::json!({
                "id": definition.id,
                "name": definition.name,
                "transport": definition.transport,
                "command": definition.command,
                "argument_count": definition.args.len(),
                "url": definition.url,
                "credential_references": definition.environment_keys,
                "source": definition.metadata.get("source"),
                "argument_values_redacted": !definition.args.is_empty(),
            })
        })
        .collect()
}

fn provider_grant_preview(grant: &ProviderGrant) -> serde_json::Value {
    serde_json::json!({
        "id": grant.id,
        "connection_id": grant.connection_id,
        "resource": grant.resource,
        "issuer": grant.issuer,
        "scopes": grant.scopes,
        "access_expires_at": grant.access_expires_at,
        "status": grant.status,
        "has_refresh_credential": grant.refresh_secret_ref.is_some(),
        "created_at": grant.created_at,
        "last_verified_at": grant.last_verified_at,
        "secret_values_redacted": true,
    })
}

#[cfg(target_os = "macos")]
fn open_authorization_url(url: &url::Url) -> Result<()> {
    let status = ProcessCommand::new("/usr/bin/open")
        .env_clear()
        .arg(url.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("the system browser launcher rejected the authorization URL");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn open_authorization_url(_url: &url::Url) -> Result<()> {
    anyhow::bail!("CLI provider authorization is currently enabled only on macOS")
}

fn authorize_provider(
    vault: &Vault,
    connection_id: Uuid,
    client_id: String,
    scopes: Vec<String>,
    yes: bool,
) -> Result<()> {
    let connection = vault
        .connection(connection_id)?
        .ok_or_else(|| anyhow::anyhow!("connection not found"))?;
    let resource = connection
        .url
        .as_deref()
        .filter(|_| connection.transport != "stdio")
        .ok_or_else(|| anyhow::anyhow!("only remote HTTP MCP definitions can be authorized"))?;
    if vault
        .provider_grants()?
        .iter()
        .any(|grant| grant.connection_id == connection_id && !grant.status.is_terminal())
    {
        anyhow::bail!("connection already has an unresolved provider authorization");
    }
    let mut transport = HttpOAuthTransport::discover(resource)?;
    let preview = serde_json::json!({
        "connection": connection.name,
        "resource": transport.metadata().resource,
        "issuer": transport.metadata().issuer,
        "authorization_endpoint": transport.metadata().authorization_endpoint,
        "client_id": client_id,
        "requested_scopes": scopes,
        "supported_scopes": transport.metadata().scopes_supported,
        "client_type": "public",
        "refresh_policy": "active use disabled; any issued refresh credential is retained only in Keychain for blocked provider cleanup",
    });
    eprintln!("Review the exact provider authorization boundary. No token value will be printed:");
    println!("{}", serde_json::to_string_pretty(&preview)?);
    require_confirmation("AUTHORIZE", yes)?;

    let grant_id = Uuid::new_v4();
    let pending = ProviderGrant {
        id: grant_id,
        connection_id,
        resource: transport.metadata().resource.to_string(),
        issuer: transport.metadata().issuer.to_string(),
        client_id: client_id.trim().to_owned(),
        registration_kind: ClientRegistrationKind::UserSuppliedPublic,
        scopes: scopes.clone(),
        access_expires_at: None,
        access_secret_ref: new_secret_reference(grant_id, "access")?,
        refresh_secret_ref: None,
        status: GrantStatus::AuthorizationPending,
        current_revocation_id: None,
        revision: 0,
        created_at: Utc::now(),
        last_verified_at: None,
    };
    let mut callback = LoopbackCallback::bind()?;
    vault.preflight_provider_credential_store()?;
    vault.reserve_provider_authorization(&pending)?;
    let flow = (|| {
        let mut transaction = AuthorizationTransaction::new(
            transport.metadata(),
            client_id.trim(),
            callback.redirect_uri().clone(),
            scopes,
        )?;
        open_authorization_url(&transaction.authorization_url())?;
        eprintln!(
            "The validated authorization URL opened in your system browser. Cargo is listening only on {}. The state and PKCE values were not printed.",
            callback.redirect_uri()
        );
        let exchange = callback.receive_exchange(&mut transaction)?;
        vault.begin_provider_token_exchange(grant_id)?;
        match transport.exchange(exchange) {
            Ok(issued) => Ok(issued),
            Err(error) => {
                vault.reconcile_provider_authorizations()?;
                Err(error.context(
                    "token exchange outcome is ambiguous; Cargo retained a locally blocked cleanup record",
                ))
            }
        }
    })();
    let issued = match flow {
        Ok(issued) => issued,
        Err(error) => {
            if !vault
                .provider_grant(grant_id)?
                .is_some_and(|grant| grant.current_revocation_id.is_some())
            {
                vault.cancel_provider_authorization(grant_id)?;
            }
            return Err(error);
        }
    };
    let expires_at = issued.expires_at;
    let granted_scopes = issued.scopes.clone();
    let (access, refresh) = issued.into_secrets();
    let grant = match vault.complete_provider_authorization(
        grant_id,
        &access,
        refresh.as_ref(),
        granted_scopes,
        Some(expires_at),
    ) {
        Ok(grant) => grant,
        Err(error) => {
            if let Some(refresh) = &refresh {
                let _ = transport.revoke(refresh, TokenKind::Refresh);
            }
            let _ = transport.revoke(&access, TokenKind::Access);
            return Err(error.context(
                "authorization was not activated; immediate provider cleanup was attempted without claiming verification",
            ));
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&provider_grant_preview(&grant))?
    );
    Ok(())
}

fn disconnect_provider(vault: &Vault, grant_id: Uuid, yes: bool) -> Result<()> {
    let grant = vault
        .provider_grant(grant_id)?
        .ok_or_else(|| anyhow::anyhow!("provider grant not found"))?;
    eprintln!(
        "Review the provider lifecycle state. Local use is blocked before network I/O; RFC 7009 acceptance alone is never called verified:"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&provider_grant_preview(&grant))?
    );
    require_confirmation("DISCONNECT", yes)?;
    if grant.status == GrantStatus::LocalCleanupPending {
        let operation_id = grant
            .current_revocation_id
            .ok_or_else(|| anyhow::anyhow!("provider cleanup operation not found"))?;
        let latest = vault.finalize_provider_revocation(operation_id)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&provider_grant_preview(&latest))?
        );
        return Ok(());
    }
    let (grant, access, refresh, operation_id) = if let Some(operation_id) =
        grant.current_revocation_id
    {
        let (owned, access, refresh) = vault.provider_credentials_for_revocation(operation_id)?;
        (owned, access, refresh, operation_id)
    } else {
        let (access, refresh) = vault.provider_credentials_for_transport(grant_id)?;
        let operation = vault.begin_provider_revocation(grant_id)?;
        (grant, access, refresh, operation.id)
    };
    let network = (|| {
        let mut transport = HttpOAuthTransport::discover(&grant.resource)?;
        if transport.metadata().issuer.as_str() != grant.issuer {
            anyhow::bail!("provider issuer changed");
        }
        let refresh_result = if let Some(refresh) = &refresh {
            transport.revoke(refresh, TokenKind::Refresh)?
        } else {
            TokenRevocationResult::NotAttempted
        };
        let access_result = transport.revoke(&access, TokenKind::Access)?;
        let verification = transport.probe_resource(&access, &transport.metadata().resource)?;
        Ok::<_, anyhow::Error>((access_result, refresh_result, verification))
    })();
    let latest = match network {
        Ok((access_result, refresh_result, verification)) => {
            vault.record_provider_revocation_attempt(
                operation_id,
                access_result,
                refresh_result,
                None,
                None,
            )?;
            let evidence = if verification == RevocationVerification::ResourceRejected
                && grant.refresh_secret_ref.is_none()
            {
                RevocationVerification::AllIssuedTokensInactive
            } else {
                verification
            };
            let verified = vault.record_provider_revocation_verification(operation_id, evidence)?;
            if verified.status == GrantStatus::LocalCleanupPending {
                vault.finalize_provider_revocation(operation_id)?
            } else {
                verified
            }
        }
        Err(_) => vault.record_provider_revocation_attempt(
            operation_id,
            TokenRevocationResult::RetryableFailure,
            if grant.refresh_secret_ref.is_some() {
                TokenRevocationResult::RetryableFailure
            } else {
                TokenRevocationResult::NotAttempted
            },
            Some(Utc::now() + chrono::Duration::minutes(5)),
            Some("provider_network_failed"),
        )?,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&provider_grant_preview(&latest))?
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.vault.unwrap_or(Vault::default_path()?);
    let vault = Vault::open(path)?;
    match cli.command {
        Command::Init { name } => println!(
            "{}",
            serde_json::to_string_pretty(&vault.create_profile(&name)?)?
        ),
        Command::Status => println!("{}", serde_json::to_string_pretty(&vault.profile()?)?),
        Command::RenameProfile { name } => println!(
            "{}",
            serde_json::to_string_pretty(&vault.rename_profile(&name)?)?
        ),
        Command::Discover { home } => {
            let home = home
                .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
                .ok_or_else(|| anyhow::anyhow!("home unavailable"))?;
            println!("{}", serde_json::to_string_pretty(&discover_known(&home))?);
        }
        Command::ImportHost { host, yes } => {
            let definitions = inspect_host_configuration(&home_dir()?, &host)?;
            eprintln!(
                "Known credential fields were removed. Argument values are hidden because heuristic scanning cannot guarantee that every provider-specific secret was recognized:"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&redacted_connection_previews(&definitions))?
            );
            require_confirmation("IMPORT", yes)?;
            let merged = vault.merge_imported_connections(&definitions)?;
            println!(
                "{{\"merged\":{merged},\"inspected\":{}}}",
                definitions.len()
            );
        }
        Command::Deployments => {
            println!("{}", serde_json::to_string_pretty(&vault.deployments()?)?)
        }
        Command::Install {
            connection_id,
            host,
            show_values,
            yes,
        } => {
            let connection = vault
                .connection(connection_id)?
                .ok_or_else(|| anyhow::anyhow!("connection not found"))?;
            let planned = plan_install(&home_dir()?, &host, &connection)?;
            let confirmation = planned.summary().server_name.clone();
            let contains_argument_values = !planned.summary().args.is_empty();
            if show_values && (yes || !std::io::stdin().is_terminal()) {
                anyhow::bail!(
                    "--show-values requires an interactive terminal and cannot be combined with --yes"
                );
            }
            if contains_argument_values && !show_values {
                let mut preview = serde_json::to_value(planned.summary())?;
                preview["args"] = serde_json::json!({
                    "redacted": true,
                    "count": planned.summary().args.len(),
                });
                eprintln!(
                    "Argument values are hidden because they may contain a provider-specific secret. No changes were made. Review the redacted plan below, then rerun interactively with --show-values to inspect and approve the exact values:"
                );
                println!("{}", serde_json::to_string_pretty(&preview)?);
                anyhow::bail!("exact interactive argument review is required before installation");
            }
            eprintln!("Review the exact registration plan:");
            println!("{}", serde_json::to_string_pretty(planned.summary())?);
            require_confirmation(&confirmation, yes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&apply_recorded_install(
                    &vault,
                    &home_dir()?,
                    planned,
                )?)?
            );
        }
        Command::RemoveDeployment { deployment_id, yes } => {
            let planned = plan_removal(&vault, &home_dir()?, deployment_id)?;
            eprintln!(
                "This removes Cargo's managed host registration only. It does not terminate an existing process, log out OAuth, or revoke provider access."
            );
            let confirmation = planned.summary().server_name.clone();
            println!("{}", serde_json::to_string_pretty(planned.summary())?);
            require_confirmation(&confirmation, yes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&apply_recorded_removal(
                    &vault,
                    &home_dir()?,
                    planned,
                )?)?
            );
        }
        Command::Provider { command } => match command {
            ProviderCommand::List => {
                let grants = vault
                    .provider_grants()?
                    .iter()
                    .map(provider_grant_preview)
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&grants)?)
            }
            ProviderCommand::Authorize {
                connection_id,
                client_id,
                scopes,
                yes,
            } => authorize_provider(&vault, connection_id, client_id, scopes, yes)?,
            ProviderCommand::Disconnect { grant_id, yes } => {
                disconnect_provider(&vault, grant_id, yes)?
            }
            ProviderCommand::Cancel { grant_id } => {
                vault.cancel_provider_authorization(grant_id)?
            }
        },
        Command::ExportSafe { output } => {
            write_private_file(&output, &serde_json::to_vec_pretty(&vault.export_safe()?)?)?
        }
        Command::ExportEncrypted { output } => {
            let pass = rpassword::prompt_password("Portable pack passphrase: ")?;
            if pass.len() < 12 {
                anyhow::bail!("portable pack passphrase must be at least 12 characters");
            }
            write_private_file(&output, &encrypt_pack(&vault.export_safe()?, pass.into())?)?;
        }
        Command::InspectEncrypted { input } => {
            let pass = rpassword::prompt_password("Portable pack passphrase: ")?;
            let pack = decrypt_pack(&read_bounded(&input, 32 * 1024 * 1024)?, pass.into())?;
            println!(
                "profile={} connections={} memory={}",
                pack.profile.display_name,
                pack.connections.len(),
                pack.memory.len()
            );
        }
        Command::ImportSafe { input } => {
            let pack = serde_json::from_slice(&read_bounded(&input, 32 * 1024 * 1024)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&vault.import_pack(&pack)?)?
            );
        }
        Command::ImportEncrypted { input } => {
            let pass = rpassword::prompt_password("Portable pack passphrase: ")?;
            let pack = decrypt_pack(&read_bounded(&input, 32 * 1024 * 1024)?, pass.into())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&vault.import_pack(&pack)?)?
            );
        }
        Command::Connections { show_values } => {
            let definitions = vault.connections()?;
            if show_values {
                eprintln!(
                    "Warning: full argument values may contain secrets missed by heuristic scanning."
                );
                println!("{}", serde_json::to_string_pretty(&definitions)?)
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&redacted_connection_previews(&definitions))?
                )
            }
        }
        Command::DeleteConnection { id } => vault.delete_connection(id)?,
        Command::Memory { command } => match command {
            MemoryCommand::List => println!("{}", serde_json::to_string_pretty(&vault.memory()?)?),
            MemoryCommand::Add {
                title,
                body_file,
                sensitivity,
                allowed_hosts,
            } => {
                let sensitivity = parse_sensitivity(&sensitivity)?;
                let body = read_memory_body(body_file)?;
                if title.trim().is_empty() || title.chars().count() > 200 || body.trim().is_empty()
                {
                    anyhow::bail!("memory title and body must be non-empty and within size limits");
                }
                let record = MemoryRecord {
                    id: Uuid::new_v4(),
                    title: title.trim().into(),
                    body: body.trim().into(),
                    sensitivity,
                    allowed_hosts,
                    created_at: Utc::now(),
                };
                vault.add_memory(&record)?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
            MemoryCommand::Edit {
                id,
                title,
                body_file,
                sensitivity,
                allowed_hosts,
            } => {
                let existing = vault
                    .memory_record(id)?
                    .ok_or_else(|| anyhow::anyhow!("memory record not found"))?;
                let record = MemoryRecord {
                    id,
                    title: title.trim().into(),
                    body: read_memory_body(body_file)?,
                    sensitivity: parse_sensitivity(&sensitivity)?,
                    allowed_hosts,
                    created_at: existing.created_at,
                };
                vault.update_memory(&record)?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
            MemoryCommand::Delete { id } => vault.delete_memory(id)?,
        },
        Command::Receipts => println!("{}", serde_json::to_string_pretty(&vault.receipts()?)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headless_adapter_commands_and_explicit_approval() {
        let connection_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();

        let install = Cli::try_parse_from([
            "cargo-ai",
            "install",
            &connection_id.to_string(),
            "--host",
            "Cursor",
            "--show-values",
        ])
        .unwrap();
        assert!(matches!(
            install.command,
            Command::Install {
                show_values: true,
                yes: false,
                ..
            }
        ));

        let remove = Cli::try_parse_from([
            "cargo-ai",
            "remove-deployment",
            &deployment_id.to_string(),
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            remove.command,
            Command::RemoveDeployment { yes: true, .. }
        ));

        let import =
            Cli::try_parse_from(["cargo-ai", "import-host", "--host", "Claude Desktop"]).unwrap();
        assert!(matches!(
            import.command,
            Command::ImportHost { yes: false, .. }
        ));

        let connections = Cli::try_parse_from(["cargo-ai", "connections"]).unwrap();
        assert!(matches!(
            connections.command,
            Command::Connections { show_values: false }
        ));

        let provider = Cli::try_parse_from([
            "cargo-ai",
            "provider",
            "authorize",
            &connection_id.to_string(),
            "--client-id",
            "public-client",
            "--scope",
            "tools.read",
        ])
        .unwrap();
        assert!(matches!(
            provider.command,
            Command::Provider {
                command: ProviderCommand::Authorize { yes: false, .. }
            }
        ));
    }
}
