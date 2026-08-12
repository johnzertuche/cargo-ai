use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalProfile {
    pub id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDefinition {
    pub id: Uuid,
    pub name: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub environment_keys: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecord {
    pub id: Uuid,
    pub title: String,
    pub body: String,
    pub sensitivity: Sensitivity,
    pub allowed_hosts: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Private,
    Sensitive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditReceipt {
    pub id: Uuid,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub evidence_sha256: String,
    pub previous_hash: Option<String>,
    pub record_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedDeployment {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub host: String,
    pub server_name: String,
    pub config_path: String,
    pub preimage_sha256: Option<String>,
    pub installed_fragment_sha256: String,
    pub backup_path: Option<String>,
    pub state: DeploymentState,
    pub installed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    Active,
    LocalBlocked,
    HostRemoved,
    Conflict,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PortablePack {
    pub format: String,
    pub version: u32,
    pub contains_secrets: bool,
    pub exported_at: DateTime<Utc>,
    pub profile: LocalProfile,
    pub connections: Vec<ConnectionDefinition>,
    pub memory: Vec<MemoryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackImportResult {
    pub connections_added: usize,
    pub connections_skipped: usize,
    pub memory_added: usize,
    pub memory_skipped: usize,
}
