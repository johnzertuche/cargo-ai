//! Provider-neutral OAuth foundations for remote MCP authorization.
//!
//! This module deliberately performs no network or browser I/O. It validates
//! discovered metadata and owns one-shot PKCE/state material so transports can
//! be tested without ever serializing secrets into renderer-facing types.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    GrantStatus, ProviderGrant, RevocationOperation, RevocationVerification, TokenRevocationResult,
};

const MAX_URI_LENGTH: usize = 2_048;
const MAX_SCOPE_COUNT: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedAuthorizationMetadata {
    pub resource: Url,
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub revocation_endpoint: Option<Url>,
    pub introspection_endpoint: Option<Url>,
    pub registration_endpoint: Option<Url>,
    pub scopes_supported: Vec<String>,
}

pub fn validate_remote_resource(input: &str) -> Result<Url> {
    if input.len() > MAX_URI_LENGTH {
        bail!("resource URI exceeds the length limit");
    }
    let resource = Url::parse(input).context("resource URI is invalid")?;
    validate_https_endpoint(&resource, "resource")?;
    if resource.query().is_some() || resource.fragment().is_some() {
        bail!("resource URI must not contain a query or fragment");
    }
    Ok(resource)
}

pub fn validate_discovery(
    requested_resource: &Url,
    resource_metadata: &ProtectedResourceMetadata,
    authorization_metadata: &AuthorizationServerMetadata,
) -> Result<ValidatedAuthorizationMetadata> {
    let advertised_resource = validate_remote_resource(&resource_metadata.resource)?;
    if advertised_resource != *requested_resource {
        bail!("protected-resource metadata does not match the requested resource");
    }
    if resource_metadata.authorization_servers.is_empty() {
        bail!("protected-resource metadata has no authorization server");
    }
    if resource_metadata.authorization_servers.len() > 16
        || resource_metadata.scopes_supported.len() > MAX_SCOPE_COUNT
    {
        bail!("authorization metadata exceeds supported limits");
    }

    let issuer = parse_https_endpoint(&authorization_metadata.issuer, "issuer")?;
    let advertised_issuers = resource_metadata
        .authorization_servers
        .iter()
        .map(|value| parse_https_endpoint(value, "authorization server"))
        .collect::<Result<Vec<_>>>()?;
    if !advertised_issuers
        .iter()
        .any(|candidate| candidate == &issuer)
    {
        bail!("authorization-server issuer was not advertised by the resource");
    }
    if !authorization_metadata
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        bail!("authorization server does not advertise PKCE S256");
    }
    if !authorization_metadata
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|method| method == "none")
    {
        bail!("authorization server does not advertise public-client token authentication");
    }
    if !authorization_metadata.grant_types_supported.is_empty()
        && !authorization_metadata
            .grant_types_supported
            .iter()
            .any(|value| value == "authorization_code")
    {
        bail!("authorization server does not support authorization_code");
    }
    if !authorization_metadata.response_types_supported.is_empty()
        && !authorization_metadata
            .response_types_supported
            .iter()
            .any(|value| value == "code")
    {
        bail!("authorization server does not support the code response type");
    }

    Ok(ValidatedAuthorizationMetadata {
        resource: requested_resource.clone(),
        issuer,
        authorization_endpoint: parse_https_endpoint(
            &authorization_metadata.authorization_endpoint,
            "authorization endpoint",
        )?,
        token_endpoint: parse_https_endpoint(
            &authorization_metadata.token_endpoint,
            "token endpoint",
        )?,
        revocation_endpoint: optional_https_endpoint(
            authorization_metadata.revocation_endpoint.as_deref(),
            "revocation endpoint",
        )?,
        introspection_endpoint: optional_https_endpoint(
            authorization_metadata.introspection_endpoint.as_deref(),
            "introspection endpoint",
        )?,
        registration_endpoint: optional_https_endpoint(
            authorization_metadata.registration_endpoint.as_deref(),
            "registration endpoint",
        )?,
        scopes_supported: resource_metadata.scopes_supported.clone(),
    })
}

fn parse_https_endpoint(value: &str, label: &str) -> Result<Url> {
    if value.len() > MAX_URI_LENGTH {
        bail!("{label} exceeds the length limit");
    }
    let endpoint = Url::parse(value).with_context(|| format!("{label} is invalid"))?;
    validate_https_endpoint(&endpoint, label)?;
    Ok(endpoint)
}

fn optional_https_endpoint(value: Option<&str>, label: &str) -> Result<Option<Url>> {
    value
        .map(|value| parse_https_endpoint(value, label))
        .transpose()
}

fn validate_https_endpoint(endpoint: &Url, label: &str) -> Result<()> {
    if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
        bail!("{label} must use HTTPS and include a host");
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        bail!("{label} must not contain user information");
    }
    Ok(())
}

pub struct AuthorizationTransaction {
    id: Uuid,
    resource: Url,
    issuer: Url,
    authorization_endpoint: Url,
    client_id: String,
    redirect_uri: Url,
    requested_scopes: Vec<String>,
    state: Zeroizing<String>,
    state_hash: [u8; 32],
    code_verifier: Zeroizing<String>,
    consumed: bool,
    exchange_consumed: bool,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl fmt::Debug for AuthorizationTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationTransaction")
            .field("id", &self.id)
            .field("resource", &self.resource)
            .field("issuer", &self.issuer)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("requested_scopes", &self.requested_scopes)
            .field("state", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("consumed", &self.consumed)
            .field("exchange_consumed", &self.exchange_consumed)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AuthorizationTransaction {
    pub fn new(
        metadata: &ValidatedAuthorizationMetadata,
        client_id: &str,
        redirect_uri: Url,
        requested_scopes: Vec<String>,
    ) -> Result<Self> {
        Self::new_at(
            metadata,
            client_id,
            redirect_uri,
            requested_scopes,
            chrono::Utc::now(),
        )
    }

    pub fn new_at(
        metadata: &ValidatedAuthorizationMetadata,
        client_id: &str,
        redirect_uri: Url,
        requested_scopes: Vec<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        validate_loopback_redirect(&redirect_uri)?;
        if client_id.trim().is_empty() || client_id.len() > 2_048 {
            bail!("client ID is empty or oversized");
        }
        if requested_scopes.len() > MAX_SCOPE_COUNT
            || requested_scopes.iter().any(|scope| {
                scope.is_empty() || scope.len() > 200 || scope.contains(char::is_whitespace)
            })
        {
            bail!("requested scopes are invalid or oversized");
        }
        if !metadata.scopes_supported.is_empty()
            && requested_scopes
                .iter()
                .any(|scope| !metadata.scopes_supported.contains(scope))
        {
            bail!("a requested scope is not advertised by the resource");
        }

        let mut state_bytes = [0_u8; 32];
        let mut verifier_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut state_bytes);
        rand::rng().fill_bytes(&mut verifier_bytes);
        let state = Zeroizing::new(URL_SAFE_NO_PAD.encode(state_bytes));
        let code_verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_bytes));
        state_bytes.zeroize();
        verifier_bytes.zeroize();
        let state_hash = Sha256::digest(state.as_bytes()).into();
        Ok(Self {
            id: Uuid::new_v4(),
            resource: metadata.resource.clone(),
            issuer: metadata.issuer.clone(),
            authorization_endpoint: metadata.authorization_endpoint.clone(),
            client_id: client_id.to_owned(),
            redirect_uri,
            requested_scopes,
            state,
            state_hash,
            code_verifier,
            consumed: false,
            exchange_consumed: false,
            expires_at: now + chrono::Duration::from_std(Duration::from_secs(5 * 60))?,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn authorization_url(&self) -> Url {
        let mut url = self.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("resource", self.resource.as_str())
            .append_pair("state", &self.state)
            .append_pair("code_challenge", &self.code_challenge())
            .append_pair("code_challenge_method", "S256");
        if !self.requested_scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &self.requested_scopes.join(" "));
        }
        url
    }

    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    pub fn consume_callback(&mut self, returned_state: &str) -> Result<()> {
        self.consume_callback_at(returned_state, chrono::Utc::now())
    }

    pub fn consume_callback_at(
        &mut self,
        returned_state: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        if now >= self.expires_at {
            bail!("authorization transaction expired");
        }
        if self.consumed {
            bail!("authorization callback was already consumed");
        }
        let candidate: [u8; 32] = Sha256::digest(returned_state.as_bytes()).into();
        if !constant_time_equal(&self.state_hash, &candidate) {
            bail!("authorization state did not match");
        }
        self.consumed = true;
        self.state.zeroize();
        Ok(())
    }

    pub fn token_exchange(&mut self, code: &str) -> Result<TokenExchangeRequest> {
        self.token_exchange_at(code, chrono::Utc::now())
    }

    pub fn token_exchange_at(
        &mut self,
        code: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenExchangeRequest> {
        if now >= self.expires_at {
            bail!("authorization transaction expired");
        }
        if !self.consumed {
            bail!("authorization callback has not been consumed");
        }
        if self.exchange_consumed {
            bail!("authorization code exchange was already created");
        }
        if code.is_empty() || code.len() > 8_192 {
            bail!("authorization code is empty or oversized");
        }
        self.exchange_consumed = true;
        Ok(TokenExchangeRequest {
            code: Zeroizing::new(code.into()),
            code_verifier: Zeroizing::new(std::mem::take(&mut *self.code_verifier)),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            resource: self.resource.clone(),
            requested_scopes: self.requested_scopes.clone(),
        })
    }

    fn code_challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.code_verifier.as_bytes()))
    }
}

/// A single-use, non-serializable secret request. Transport code should call
/// `into_form_body` directly and borrow its bytes only for the HTTP write.
pub struct TokenExchangeRequest {
    code: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
    client_id: String,
    redirect_uri: Url,
    resource: Url,
    requested_scopes: Vec<String>,
}

pub struct IssuedTokens {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub scopes: Vec<String>,
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl IssuedTokens {
    pub fn new(
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        expires_at: chrono::DateTime<chrono::Utc>,
        scopes: Vec<String>,
    ) -> Result<Self> {
        if scopes.len() > MAX_SCOPE_COUNT
            || scopes
                .iter()
                .any(|scope| scope.is_empty() || scope.len() > 200)
        {
            bail!("issued token scopes are invalid or oversized");
        }
        Ok(Self {
            access_token,
            refresh_token,
            expires_at,
            scopes,
        })
    }

    pub fn into_secrets(self) -> (SecretString, Option<SecretString>) {
        (self.access_token, self.refresh_token)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenKind {
    Access,
    Refresh,
}

/// Network implementations live behind this token-safe boundary. Implementors
/// must cap and redact all provider diagnostics before converting them to errors.
pub trait OAuthProviderTransport {
    fn exchange(&mut self, request: TokenExchangeRequest) -> Result<IssuedTokens>;
    fn refresh(
        &mut self,
        refresh_token: &SecretString,
        resource: &Url,
        granted_scopes: &[String],
    ) -> Result<IssuedTokens>;
    fn revoke(&mut self, token: &SecretString, kind: TokenKind) -> Result<TokenRevocationResult>;
    fn probe_resource(
        &self,
        access_token: &SecretString,
        resource: &Url,
    ) -> Result<RevocationVerification>;
}

impl fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenExchangeRequest")
            .field("code", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("resource", &self.resource)
            .field("requested_scopes", &self.requested_scopes)
            .finish()
    }
}

impl TokenExchangeRequest {
    pub fn requested_scopes(&self) -> &[String] {
        &self.requested_scopes
    }

    pub fn into_form_body(mut self) -> SecretFormBody {
        let pairs = [
            ("grant_type", "authorization_code"),
            ("code", self.code.as_str()),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", self.code_verifier.as_str()),
            ("resource", self.resource.as_str()),
        ];
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish(),
        );
        self.code.zeroize();
        self.code_verifier.zeroize();
        SecretFormBody(form)
    }
}

pub struct SecretFormBody(Zeroizing<String>);

impl fmt::Debug for SecretFormBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted OAuth form body>")
    }
}

impl SecretFormBody {
    /// Borrow only while writing the request body. This type intentionally
    /// implements neither Display nor AsRef to reduce accidental logging.
    pub fn with_bytes<T>(&self, writer: impl FnOnce(&[u8]) -> T) -> T {
        writer(self.0.as_bytes())
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_loopback_redirect(redirect: &Url) -> Result<()> {
    if redirect.scheme() != "http"
        || !matches!(
            redirect.host_str(),
            Some("127.0.0.1") | Some("[::1]") | Some("::1")
        )
        || redirect.port().is_none()
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        bail!("redirect URI must be an HTTP loopback IP literal with an explicit ephemeral port");
    }
    Ok(())
}

pub fn validate_provider_grant(grant: &ProviderGrant) -> Result<()> {
    let resource = validate_remote_resource(&grant.resource)?;
    let issuer = parse_https_endpoint(&grant.issuer, "issuer")?;
    if resource.as_str().len() > MAX_URI_LENGTH || issuer.as_str().len() > MAX_URI_LENGTH {
        bail!("grant endpoints exceed supported limits");
    }
    if grant.client_id.trim().is_empty()
        || grant.client_id.len() > 2_048
        || grant.scopes.len() > MAX_SCOPE_COUNT
        || grant.scopes.iter().any(|scope| {
            scope.is_empty() || scope.len() > 200 || scope.contains(char::is_whitespace)
        })
    {
        bail!("grant client or scope metadata is invalid");
    }
    validate_secret_reference(grant.id, &grant.access_secret_ref, "access")?;
    if let Some(reference) = &grant.refresh_secret_ref {
        validate_secret_reference(grant.id, reference, "refresh")?;
    }
    if matches!(
        grant.status,
        GrantStatus::Active | GrantStatus::AuthorizationPending
    ) && grant.current_revocation_id.is_some()
    {
        bail!("an active grant cannot reference a revocation operation");
    }
    Ok(())
}

fn validate_secret_reference(grant_id: Uuid, reference: &str, kind: &str) -> Result<()> {
    let expected = format!("grant/{grant_id}/{kind}/");
    let suffix = reference
        .strip_prefix(&expected)
        .context("grant secret reference has the wrong namespace")?;
    if suffix.len() != 36 || Uuid::parse_str(suffix).is_err() {
        bail!("grant secret reference is not an opaque identifier");
    }
    Ok(())
}

pub fn new_secret_reference(grant_id: Uuid, kind: &str) -> Result<String> {
    if !matches!(kind, "access" | "refresh") {
        bail!("unsupported grant secret kind");
    }
    Ok(format!("grant/{grant_id}/{kind}/{}", Uuid::new_v4()))
}

/// Atomically persisted by `Vault::begin_provider_revocation` before network I/O.
pub fn begin_revocation(
    grant: &mut ProviderGrant,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RevocationOperation> {
    validate_provider_grant(grant)?;
    if !matches!(
        grant.status,
        GrantStatus::Active
            | GrantStatus::ReauthRequired
            | GrantStatus::Partial
            | GrantStatus::Failed
    ) {
        bail!("provider grant is already blocked or revoked");
    }
    grant.status = GrantStatus::LocallyBlocked;
    grant.revision = grant
        .revision
        .checked_add(1)
        .context("provider grant revision overflowed")?;
    let operation = RevocationOperation {
        id: Uuid::new_v4(),
        grant_id: grant.id,
        grant_revision: grant.revision,
        requested_at: now,
        local_blocked_at: now,
        access_result: TokenRevocationResult::NotAttempted,
        refresh_result: TokenRevocationResult::NotAttempted,
        verification: RevocationVerification::NotAttempted,
        attempts: 0,
        next_retry_at: None,
        last_safe_error: None,
        completed_at: None,
    };
    // The local cut is complete. Network work is now durable and pending.
    grant.status = GrantStatus::RevocationPending;
    grant.current_revocation_id = Some(operation.id);
    Ok(operation)
}

pub fn record_provider_attempt(
    grant: &mut ProviderGrant,
    operation: &mut RevocationOperation,
    access_result: TokenRevocationResult,
    refresh_result: TokenRevocationResult,
    next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    safe_error_code: Option<&str>,
) -> Result<()> {
    ensure_operation_matches(grant, operation)?;
    if grant.status.is_terminal() {
        bail!("verified revocation is terminal");
    }
    if let Some(code) = safe_error_code
        && (code.is_empty()
            || code.len() > 120
            || !code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            }))
    {
        bail!("revocation error must be a bounded safe error code");
    }
    operation.attempts = operation
        .attempts
        .checked_add(1)
        .context("revocation attempt counter overflowed")?;
    operation.access_result = access_result;
    operation.refresh_result = refresh_result;
    operation.next_retry_at = next_retry_at;
    operation.last_safe_error = safe_error_code.map(str::to_owned);
    operation.completed_at = None;

    if matches!(
        operation.access_result,
        TokenRevocationResult::RetryableFailure
    ) || matches!(
        operation.refresh_result,
        TokenRevocationResult::RetryableFailure
    ) {
        if operation.next_retry_at.is_none() {
            bail!("a retryable provider result requires a retry time");
        }
        grant.status = GrantStatus::RevocationPending;
    } else if matches!(
        operation.access_result,
        TokenRevocationResult::PermanentFailure
    ) || matches!(
        operation.refresh_result,
        TokenRevocationResult::PermanentFailure
    ) {
        grant.status = GrantStatus::Partial;
    } else if matches!(
        operation.access_result,
        TokenRevocationResult::AcceptedUnverified
    ) || matches!(
        operation.refresh_result,
        TokenRevocationResult::AcceptedUnverified
    ) {
        // RFC 7009 acceptance (and lack of an endpoint) is not verification.
        grant.status = GrantStatus::ProviderRevokedUnverified;
        operation.next_retry_at = None;
    } else {
        grant.status = GrantStatus::LocallyBlocked;
    }
    grant.revision = grant
        .revision
        .checked_add(1)
        .context("provider grant revision overflowed")?;
    operation.grant_revision = grant.revision;
    Ok(())
}

pub fn record_verification(
    grant: &mut ProviderGrant,
    operation: &mut RevocationOperation,
    verification: RevocationVerification,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure_operation_matches(grant, operation)?;
    if matches!(
        grant.status,
        GrantStatus::LocalCleanupPending | GrantStatus::VerifiedRevoked
    ) {
        bail!("provider evidence is already complete");
    }
    if matches!(grant.status, GrantStatus::RevocationPending) {
        bail!("provider revocation attempt is still pending");
    }
    operation.verification = verification.clone();
    operation.next_retry_at = None;
    match verification {
        RevocationVerification::AllIssuedTokensInactive
        | RevocationVerification::ProviderGrantRevoked => {
            // Provider evidence is complete. Terminal VerifiedRevoked is persisted
            // only after the vault confirms local Keychain cleanup.
            grant.status = GrantStatus::LocalCleanupPending;
            grant.last_verified_at = Some(now);
        }
        RevocationVerification::AccessInactive
        | RevocationVerification::RefreshInactive
        | RevocationVerification::ResourceRejected
        | RevocationVerification::AccessRejectedRefreshUnverified => {
            grant.status = GrantStatus::ProviderRevokedUnverified;
        }
        RevocationVerification::Unsupported => grant.status = GrantStatus::LocallyBlocked,
        RevocationVerification::StillActive => grant.status = GrantStatus::Partial,
        RevocationVerification::NotAttempted => {
            bail!("verification result must contain evidence")
        }
    }
    grant.revision = grant
        .revision
        .checked_add(1)
        .context("provider grant revision overflowed")?;
    operation.grant_revision = grant.revision;
    Ok(())
}

pub fn confirm_local_cleanup(
    grant: &mut ProviderGrant,
    operation: &mut RevocationOperation,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure_operation_matches(grant, operation)?;
    if grant.status != GrantStatus::LocalCleanupPending {
        bail!("provider evidence is incomplete or local cleanup is not pending");
    }
    grant.status = GrantStatus::VerifiedRevoked;
    grant.revision = grant
        .revision
        .checked_add(1)
        .context("provider grant revision overflowed")?;
    grant.current_revocation_id = None;
    operation.grant_revision = grant.revision;
    operation.completed_at = Some(now);
    Ok(())
}

fn ensure_operation_matches(grant: &ProviderGrant, operation: &RevocationOperation) -> Result<()> {
    if operation.grant_id != grant.id {
        bail!("revocation operation does not belong to this grant");
    }
    if grant.current_revocation_id != Some(operation.id) {
        bail!("revocation operation was superseded");
    }
    if grant.revision != operation.grant_revision {
        bail!("revocation operation has a stale grant revision");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::collections::{HashMap, HashSet};

    struct FakeOAuthMcpProvider {
        resource: Url,
        pending_codes: HashMap<String, String>,
        access_tokens: HashSet<String>,
        refresh_tokens: HashSet<String>,
        retired_refresh_tokens: HashSet<String>,
        counter: u64,
    }

    impl FakeOAuthMcpProvider {
        fn new(resource: Url) -> Self {
            Self {
                resource,
                pending_codes: HashMap::new(),
                access_tokens: HashSet::new(),
                refresh_tokens: HashSet::new(),
                retired_refresh_tokens: HashSet::new(),
                counter: 0,
            }
        }

        fn authorize(&mut self, resource: &str, code_challenge: &str) -> Result<String> {
            if resource != self.resource.as_str() || code_challenge.len() != 43 {
                bail!("authorization request failed resource or PKCE validation");
            }
            self.counter += 1;
            let code = format!("code-{}", self.counter);
            self.pending_codes
                .insert(code.clone(), code_challenge.to_owned());
            Ok(code)
        }

        fn issue_tokens(&mut self) -> Result<IssuedTokens> {
            self.counter += 1;
            let access = format!("access-secret-{}", self.counter);
            let refresh = format!("refresh-secret-{}", self.counter);
            self.access_tokens.insert(access.clone());
            self.refresh_tokens.insert(refresh.clone());
            IssuedTokens::new(
                SecretString::from(access),
                Some(SecretString::from(refresh)),
                chrono::Utc::now() + chrono::Duration::minutes(10),
                vec!["tools.read".into()],
            )
        }
    }

    impl OAuthProviderTransport for FakeOAuthMcpProvider {
        fn exchange(&mut self, request: TokenExchangeRequest) -> Result<IssuedTokens> {
            let form = request.into_form_body();
            let parameters = form.with_bytes(|bytes| {
                url::form_urlencoded::parse(bytes)
                    .into_owned()
                    .collect::<HashMap<_, _>>()
            });
            let code = parameters
                .get("code")
                .context("missing authorization code")?;
            let verifier = parameters
                .get("code_verifier")
                .context("missing code verifier")?;
            let resource = parameters.get("resource").context("missing resource")?;
            if resource != self.resource.as_str() {
                bail!("token request resource did not match");
            }
            let expected = self
                .pending_codes
                .remove(code)
                .context("authorization code is invalid or already consumed")?;
            let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if actual != expected {
                bail!("PKCE verification failed");
            }
            self.issue_tokens()
        }

        fn refresh(
            &mut self,
            refresh_token: &SecretString,
            resource: &Url,
            _granted_scopes: &[String],
        ) -> Result<IssuedTokens> {
            if resource != &self.resource {
                bail!("refresh resource did not match");
            }
            let value = refresh_token.expose_secret();
            if self.retired_refresh_tokens.contains(value) {
                // Rotation replay invalidates this test provider's token family.
                self.refresh_tokens.clear();
                self.access_tokens.clear();
                bail!("refresh token reuse detected");
            }
            if !self.refresh_tokens.remove(value) {
                bail!("refresh token is invalid");
            }
            self.retired_refresh_tokens.insert(value.to_owned());
            self.issue_tokens()
        }

        fn revoke(
            &mut self,
            token: &SecretString,
            kind: TokenKind,
        ) -> Result<TokenRevocationResult> {
            let value = token.expose_secret();
            match kind {
                TokenKind::Access => {
                    self.access_tokens.remove(value);
                }
                TokenKind::Refresh => {
                    self.refresh_tokens.remove(value);
                }
            }
            // RFC 7009 is idempotent; this is acceptance, not evidence.
            Ok(TokenRevocationResult::AcceptedUnverified)
        }

        fn probe_resource(
            &self,
            access_token: &SecretString,
            resource: &Url,
        ) -> Result<RevocationVerification> {
            if resource != &self.resource {
                bail!("probe resource did not match");
            }
            Ok(
                if self.access_tokens.contains(access_token.expose_secret()) {
                    RevocationVerification::StillActive
                } else {
                    RevocationVerification::ResourceRejected
                },
            )
        }
    }

    fn metadata() -> ValidatedAuthorizationMetadata {
        validate_discovery(
            &Url::parse("https://mcp.example.com/tools").unwrap(),
            &ProtectedResourceMetadata {
                resource: "https://mcp.example.com/tools".into(),
                authorization_servers: vec!["https://auth.example.com/tenant".into()],
                scopes_supported: vec!["tools.read".into()],
            },
            &AuthorizationServerMetadata {
                issuer: "https://auth.example.com/tenant".into(),
                authorization_endpoint: "https://auth.example.com/authorize".into(),
                token_endpoint: "https://auth.example.com/token".into(),
                revocation_endpoint: Some("https://auth.example.com/revoke".into()),
                introspection_endpoint: Some("https://auth.example.com/introspect".into()),
                registration_endpoint: None,
                grant_types_supported: vec!["authorization_code".into()],
                response_types_supported: vec!["code".into()],
                code_challenge_methods_supported: vec!["S256".into()],
                token_endpoint_auth_methods_supported: vec!["none".into()],
            },
        )
        .unwrap()
    }

    #[test]
    fn discovery_binds_resource_issuer_and_s256() {
        let valid = metadata();
        assert_eq!(valid.resource.as_str(), "https://mcp.example.com/tools");

        let mut resource = ProtectedResourceMetadata {
            resource: "https://other.example.com/tools".into(),
            authorization_servers: vec![valid.issuer.to_string()],
            scopes_supported: vec![],
        };
        let mut server = AuthorizationServerMetadata {
            issuer: valid.issuer.to_string(),
            authorization_endpoint: valid.authorization_endpoint.to_string(),
            token_endpoint: valid.token_endpoint.to_string(),
            revocation_endpoint: None,
            introspection_endpoint: None,
            registration_endpoint: None,
            grant_types_supported: vec!["authorization_code".into()],
            response_types_supported: vec!["code".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: vec![],
        };
        assert!(validate_discovery(&valid.resource, &resource, &server).is_err());
        resource.resource = valid.resource.to_string();
        server.code_challenge_methods_supported.clear();
        assert!(validate_discovery(&valid.resource, &resource, &server).is_err());

        server.code_challenge_methods_supported.push("S256".into());
        server.token_endpoint_auth_methods_supported = vec!["client_secret_basic".into()];
        assert!(validate_discovery(&valid.resource, &resource, &server).is_err());
    }

    #[test]
    fn pkce_flow_binds_resource_and_is_one_shot() {
        let mut transaction = AuthorizationTransaction::new(
            &metadata(),
            "cargo-public-client",
            Url::parse("http://127.0.0.1:49152/callback").unwrap(),
            vec!["tools.read".into()],
        )
        .unwrap();
        let url = transaction.authorization_url();
        let parameters = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            parameters.get("resource").unwrap(),
            "https://mcp.example.com/tools"
        );
        assert_eq!(parameters.get("code_challenge_method").unwrap(), "S256");
        let state = parameters.get("state").unwrap().to_string();
        assert!(transaction.consume_callback("wrong").is_err());
        transaction.consume_callback(&state).unwrap();
        assert!(transaction.consume_callback(&state).is_err());
        let exchange = transaction.token_exchange("one-time-code").unwrap();
        assert!(format!("{exchange:?}").contains("<redacted>"));
        assert!(!format!("{exchange:?}").contains("one-time-code"));
        let form = exchange.into_form_body();
        assert_eq!(format!("{form:?}"), "<redacted OAuth form body>");
        assert!(form.with_bytes(|bytes| {
            String::from_utf8_lossy(bytes)
                .contains("resource=https%3A%2F%2Fmcp.example.com%2Ftools")
        }));
        assert!(transaction.token_exchange("second-code").is_err());
        assert!(format!("{transaction:?}").contains("<redacted>"));
        assert!(!format!("{transaction:?}").contains(&state));
    }

    #[test]
    fn remote_and_redirect_uri_policies_fail_closed() {
        assert!(validate_remote_resource("http://mcp.example.com").is_err());
        assert!(validate_remote_resource("https://user@mcp.example.com").is_err());
        assert!(validate_remote_resource("https://mcp.example.com#fragment").is_err());
        assert!(
            AuthorizationTransaction::new(
                &metadata(),
                "client",
                Url::parse("http://localhost:49152/callback").unwrap(),
                vec![],
            )
            .is_err()
        );
    }

    fn grant(with_refresh: bool) -> ProviderGrant {
        let id = Uuid::new_v4();
        ProviderGrant {
            id,
            connection_id: Uuid::new_v4(),
            resource: "https://mcp.example.com/tools".into(),
            issuer: "https://auth.example.com".into(),
            client_id: "cargo-public-client".into(),
            registration_kind: crate::ClientRegistrationKind::DynamicPublic,
            scopes: vec!["tools.read".into()],
            access_expires_at: None,
            access_secret_ref: new_secret_reference(id, "access").unwrap(),
            refresh_secret_ref: with_refresh.then(|| new_secret_reference(id, "refresh").unwrap()),
            status: GrantStatus::Active,
            current_revocation_id: None,
            revision: 0,
            created_at: chrono::Utc::now(),
            last_verified_at: None,
        }
    }

    #[test]
    fn revoke_acceptance_is_not_verification() {
        let mut grant = grant(true);
        let mut operation = begin_revocation(&mut grant, chrono::Utc::now()).unwrap();
        assert_eq!(grant.status, GrantStatus::RevocationPending);
        record_provider_attempt(
            &mut grant,
            &mut operation,
            TokenRevocationResult::AcceptedUnverified,
            TokenRevocationResult::AcceptedUnverified,
            None,
            None,
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::ProviderRevokedUnverified);
        record_verification(
            &mut grant,
            &mut operation,
            RevocationVerification::ResourceRejected,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::ProviderRevokedUnverified);
        record_verification(
            &mut grant,
            &mut operation,
            RevocationVerification::AllIssuedTokensInactive,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::LocalCleanupPending);
        confirm_local_cleanup(&mut grant, &mut operation, chrono::Utc::now()).unwrap();
        assert_eq!(grant.status, GrantStatus::VerifiedRevoked);
    }

    #[test]
    fn offline_revoke_stays_blocked_and_pending() {
        let mut grant = grant(false);
        let mut operation = begin_revocation(&mut grant, chrono::Utc::now()).unwrap();
        record_provider_attempt(
            &mut grant,
            &mut operation,
            TokenRevocationResult::RetryableFailure,
            TokenRevocationResult::NotAttempted,
            Some(chrono::Utc::now() + chrono::Duration::minutes(1)),
            Some("network_unavailable"),
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::RevocationPending);
        assert_eq!(operation.attempts, 1);
        assert!(operation.next_retry_at.is_some());
    }

    #[test]
    fn unsupported_revoke_and_partial_evidence_never_claim_provider_revoked() {
        let mut grant = grant(true);
        let mut operation = begin_revocation(&mut grant, chrono::Utc::now()).unwrap();
        record_provider_attempt(
            &mut grant,
            &mut operation,
            TokenRevocationResult::Unsupported,
            TokenRevocationResult::Unsupported,
            None,
            None,
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::LocallyBlocked);
        record_verification(
            &mut grant,
            &mut operation,
            RevocationVerification::Unsupported,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::LocallyBlocked);

        grant.status = GrantStatus::Partial;
        let mut newer = begin_revocation(&mut grant, chrono::Utc::now()).unwrap();
        assert!(
            record_provider_attempt(
                &mut grant,
                &mut operation,
                TokenRevocationResult::AcceptedUnverified,
                TokenRevocationResult::AcceptedUnverified,
                None,
                None,
            )
            .is_err()
        );
        record_provider_attempt(
            &mut grant,
            &mut newer,
            TokenRevocationResult::AcceptedUnverified,
            TokenRevocationResult::AcceptedUnverified,
            None,
            None,
        )
        .unwrap();
        record_verification(
            &mut grant,
            &mut newer,
            RevocationVerification::AccessInactive,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(grant.status, GrantStatus::ProviderRevokedUnverified);
    }

    #[test]
    fn authorization_transaction_expires() {
        let now = chrono::Utc::now();
        let mut transaction = AuthorizationTransaction::new_at(
            &metadata(),
            "client",
            Url::parse("http://127.0.0.1:49152/callback").unwrap(),
            vec![],
            now,
        )
        .unwrap();
        let state = transaction
            .authorization_url()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        assert!(
            transaction
                .consume_callback_at(&state, now + chrono::Duration::minutes(5))
                .is_err()
        );
    }

    #[test]
    fn fake_provider_conformance_covers_exchange_rotation_replay_and_revoke() {
        let metadata = metadata();
        let mut provider = FakeOAuthMcpProvider::new(metadata.resource.clone());
        let mut transaction = AuthorizationTransaction::new(
            &metadata,
            "cargo-public-client",
            Url::parse("http://127.0.0.1:49152/callback").unwrap(),
            vec!["tools.read".into()],
        )
        .unwrap();
        let authorization_url = transaction.authorization_url();
        let parameters = authorization_url.query_pairs().collect::<HashMap<_, _>>();
        let state = parameters.get("state").unwrap().to_string();
        let code = provider
            .authorize(
                parameters.get("resource").unwrap(),
                parameters.get("code_challenge").unwrap(),
            )
            .unwrap();
        transaction.consume_callback(&state).unwrap();
        let issued = provider
            .exchange(transaction.token_exchange(&code).unwrap())
            .unwrap();
        let issued_debug = format!("{issued:?}");
        assert!(issued_debug.contains("<redacted>"));
        assert!(!issued_debug.contains("access-secret"));
        let (access, refresh) = issued.into_secrets();
        let refresh = refresh.unwrap();
        assert_eq!(
            provider
                .probe_resource(&access, &metadata.resource)
                .unwrap(),
            RevocationVerification::StillActive
        );

        let rotated = provider
            .refresh(&refresh, &metadata.resource, &["read".into()])
            .unwrap();
        let (rotated_access, rotated_refresh) = rotated.into_secrets();
        let rotated_refresh = rotated_refresh.unwrap();
        assert!(
            provider
                .refresh(&refresh, &metadata.resource, &["read".into()])
                .is_err()
        );
        assert_eq!(
            provider
                .probe_resource(&rotated_access, &metadata.resource)
                .unwrap(),
            RevocationVerification::ResourceRejected
        );

        // Re-authorize after family invalidation, then prove RFC 7009 acceptance
        // and resource rejection are separate pieces of evidence.
        let fresh = provider.issue_tokens().unwrap();
        let (fresh_access, fresh_refresh) = fresh.into_secrets();
        let fresh_refresh = fresh_refresh.unwrap();
        assert_eq!(
            provider.revoke(&fresh_refresh, TokenKind::Refresh).unwrap(),
            TokenRevocationResult::AcceptedUnverified
        );
        assert_eq!(
            provider.revoke(&fresh_access, TokenKind::Access).unwrap(),
            TokenRevocationResult::AcceptedUnverified
        );
        assert_eq!(
            provider
                .probe_resource(&fresh_access, &metadata.resource)
                .unwrap(),
            RevocationVerification::ResourceRejected
        );

        // Keep the rotated secret live in the test until this point so any
        // accidental Debug inclusion above would have been observable.
        assert!(!rotated_refresh.expose_secret().is_empty());
    }
}
