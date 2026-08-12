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

/// A provider authorization is independent from a host configuration deployment.
/// Secret references are opaque identifiers; token values never belong in this model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderGrant {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub resource: String,
    pub issuer: String,
    pub client_id: String,
    pub registration_kind: ClientRegistrationKind,
    pub scopes: Vec<String>,
    pub access_expires_at: Option<DateTime<Utc>>,
    pub access_secret_ref: String,
    pub refresh_secret_ref: Option<String>,
    pub status: GrantStatus,
    pub current_revocation_id: Option<Uuid>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub last_verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantActivationOperation {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub access_secret_ref: String,
    pub refresh_secret_ref: Option<String>,
    pub state: GrantActivationState,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantActivationState {
    Staged,
    CredentialsWritten,
    Completed,
    CleanupPending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientRegistrationKind {
    PreconfiguredPublic,
    ClientIdMetadataDocument,
    DynamicPublic,
    UserSuppliedPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Active,
    ReauthRequired,
    LocallyBlocked,
    RevocationPending,
    ProviderRevokedUnverified,
    LocalCleanupPending,
    VerifiedRevoked,
    Partial,
    Failed,
}

impl GrantStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::VerifiedRevoked)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RevocationOperation {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub requested_at: DateTime<Utc>,
    pub local_blocked_at: DateTime<Utc>,
    pub access_result: TokenRevocationResult,
    pub refresh_result: TokenRevocationResult,
    pub verification: RevocationVerification,
    pub attempts: u32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_safe_error: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenRevocationResult {
    NotAttempted,
    AcceptedUnverified,
    Unsupported,
    RetryableFailure,
    PermanentFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RevocationVerification {
    NotAttempted,
    AccessInactive,
    RefreshInactive,
    AllIssuedTokensInactive,
    ProviderGrantRevoked,
    ResourceRejected,
    AccessRejectedRefreshUnverified,
    StillActive,
    Unsupported,
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
