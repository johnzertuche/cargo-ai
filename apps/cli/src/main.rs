use anyhow::Result;
use cargo_ai_core::{
    MemoryRecord, Sensitivity, Vault,
    adapters::discover_known,
    host_ops::{
        apply_recorded_install, apply_recorded_removal, inspect_host_configuration, plan_install,
        plan_removal,
    },
    mutation::write_private_file,
    transfer::{decrypt_pack, encrypt_pack},
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
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
    }
}
