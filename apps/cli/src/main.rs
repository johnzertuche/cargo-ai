use anyhow::Result;
use cargo_ai_core::{
    MemoryRecord, Sensitivity, Vault,
    adapters::discover_known,
    mutation::write_private_file,
    transfer::{decrypt_pack, encrypt_pack},
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::Read,
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
    Connections,
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
        Command::Connections => {
            println!("{}", serde_json::to_string_pretty(&vault.connections()?)?)
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
