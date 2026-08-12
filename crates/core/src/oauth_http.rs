//! Bounded synchronous HTTP transport for provider-neutral MCP OAuth.

use crate::oauth::{
    AuthorizationServerMetadata, IssuedTokens, OAuthProviderTransport, ProtectedResourceMetadata,
    TokenExchangeRequest, TokenKind, ValidatedAuthorizationMetadata, validate_discovery,
    validate_remote_resource,
};
use crate::{RevocationVerification, TokenRevocationResult};
use anyhow::{Context, Result, bail};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::blocking::{Body, Client, Response};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_METADATA_BODY: usize = 128 * 1024;
const MAX_TOKEN_BODY: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
enum EndpointPolicy {
    HttpsOnly,
    #[cfg(test)]
    TestLoopbackHttp,
}

pub struct HttpOAuthTransport {
    metadata: ValidatedAuthorizationMetadata,
    policy: EndpointPolicy,
}

impl HttpOAuthTransport {
    pub fn discover(resource: &str) -> Result<Self> {
        Self::discover_with_policy(resource, EndpointPolicy::HttpsOnly)
    }

    #[cfg(test)]
    fn discover_test_loopback(resource: &str) -> Result<Self> {
        Self::discover_with_policy(resource, EndpointPolicy::TestLoopbackHttp)
    }

    fn discover_with_policy(resource: &str, policy: EndpointPolicy) -> Result<Self> {
        let resource = parse_resource(resource, policy)?;
        let resource_metadata_url = well_known(&resource, "oauth-protected-resource")?;
        let resource_metadata_url = checked_endpoint(&resource_metadata_url, policy)?;
        let protected: ProtectedResourceMetadata = get_json(
            &client_for(&resource_metadata_url, policy)?,
            resource_metadata_url,
            MAX_METADATA_BODY,
        )?;
        if protected.resource != resource.as_str() {
            bail!("protected-resource metadata does not match the requested resource");
        }
        let issuer_text = protected
            .authorization_servers
            .first()
            .context("protected-resource metadata has no authorization server")?;
        let issuer = checked_endpoint(&Url::parse(issuer_text)?, policy)?;
        let authorization_metadata_url = well_known(&issuer, "oauth-authorization-server")?;
        let authorization_metadata_url = checked_endpoint(&authorization_metadata_url, policy)?;
        let authorization: AuthorizationServerMetadata = get_json(
            &client_for(&authorization_metadata_url, policy)?,
            authorization_metadata_url,
            MAX_METADATA_BODY,
        )?;
        let metadata = match policy {
            EndpointPolicy::HttpsOnly => validate_discovery(&resource, &protected, &authorization)?,
            #[cfg(test)]
            EndpointPolicy::TestLoopbackHttp => {
                validate_test_discovery(&resource, &protected, &authorization)?
            }
        };
        for endpoint in [
            Some(&metadata.resource),
            Some(&metadata.issuer),
            Some(&metadata.authorization_endpoint),
            Some(&metadata.token_endpoint),
            metadata.revocation_endpoint.as_ref(),
            metadata.introspection_endpoint.as_ref(),
            metadata.registration_endpoint.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            checked_endpoint(endpoint, policy)?;
        }
        Ok(Self { metadata, policy })
    }

    pub fn metadata(&self) -> &ValidatedAuthorizationMetadata {
        &self.metadata
    }

    fn endpoint(&self, endpoint: &Url) -> Result<Url> {
        checked_endpoint(endpoint, self.policy)
    }
}

impl OAuthProviderTransport for HttpOAuthTransport {
    fn exchange(&mut self, request: TokenExchangeRequest) -> Result<IssuedTokens> {
        let requested_scopes = request.requested_scopes().to_vec();
        let body = request.into_form_body();
        let endpoint = self.endpoint(&self.metadata.token_endpoint)?;
        let client = client_for(&endpoint, self.policy)?;
        let response = body.with_bytes(|bytes| {
            client
                .post(endpoint)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(secret_body(bytes))
                .send()
        })?;
        parse_token_response(response, &requested_scopes)
    }

    fn refresh(
        &mut self,
        refresh_token: &SecretString,
        resource: &Url,
        granted_scopes: &[String],
    ) -> Result<IssuedTokens> {
        if resource != &self.metadata.resource {
            bail!("refresh resource did not match discovered resource");
        }
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "refresh_token")
                .append_pair("refresh_token", refresh_token.expose_secret())
                .append_pair("resource", resource.as_str())
                .finish(),
        );
        let endpoint = self.endpoint(&self.metadata.token_endpoint)?;
        let response = client_for(&endpoint, self.policy)?
            .post(endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(secret_body(body.as_bytes()))
            .send()?;
        parse_token_response(response, granted_scopes)
    }

    fn revoke(&mut self, token: &SecretString, kind: TokenKind) -> Result<TokenRevocationResult> {
        let Some(endpoint) = self.metadata.revocation_endpoint.clone() else {
            return Ok(TokenRevocationResult::Unsupported);
        };
        let hint = match kind {
            TokenKind::Access => "access_token",
            TokenKind::Refresh => "refresh_token",
        };
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("token", token.expose_secret())
                .append_pair("token_type_hint", hint)
                .finish(),
        );
        let endpoint = self.endpoint(&endpoint)?;
        let response = client_for(&endpoint, self.policy)?
            .post(endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(secret_body(body.as_bytes()))
            .send()?;
        Ok(if response.status().is_success() {
            TokenRevocationResult::AcceptedUnverified
        } else if response.status().is_server_error() || response.status().as_u16() == 429 {
            TokenRevocationResult::RetryableFailure
        } else {
            TokenRevocationResult::PermanentFailure
        })
    }

    fn probe_resource(
        &self,
        access_token: &SecretString,
        resource: &Url,
    ) -> Result<RevocationVerification> {
        if resource != &self.metadata.resource {
            bail!("probe resource did not match discovered resource");
        }
        let endpoint = self.endpoint(resource)?;
        let mut bearer = Zeroizing::new(format!("Bearer {}", access_token.expose_secret()));
        let mut header = HeaderValue::from_bytes(bearer.as_bytes())
            .context("access token is not header-safe")?;
        header.set_sensitive(true);
        let response = client_for(&endpoint, self.policy)?
            .get(endpoint)
            .header(AUTHORIZATION, header)
            .send()?;
        bearer.zeroize();
        if response.status().is_success() {
            Ok(RevocationVerification::StillActive)
        } else if matches!(response.status().as_u16(), 401 | 403) {
            Ok(RevocationVerification::ResourceRejected)
        } else {
            bail!("protected-resource probe returned an inconclusive status")
        }
    }
}

struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl SecretText {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn into_secret(mut self) -> SecretString {
        SecretString::from(std::mem::take(&mut *self.0))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretText,
    #[serde(default)]
    refresh_token: Option<SecretText>,
    expires_in: u64,
    token_type: String,
    #[serde(default)]
    scope: String,
}

fn parse_token_response(response: Response, allowed_scopes: &[String]) -> Result<IssuedTokens> {
    if !response.status().is_success() {
        bail!("OAuth token endpoint rejected the request");
    }
    require_json(&response)?;
    let body = read_bounded(response, MAX_TOKEN_BODY)?;
    parse_token_payload(&body, allowed_scopes)
}

fn parse_token_payload(body: &[u8], allowed_scopes: &[String]) -> Result<IssuedTokens> {
    let token: TokenResponse =
        parse_strict_json(body).context("OAuth token response was invalid")?;
    if !token.token_type.eq_ignore_ascii_case("bearer")
        || token.access_token.is_empty()
        || token.access_token.len() > 16 * 1024
        || token
            .refresh_token
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 16 * 1024)
        || token.expires_in == 0
        || token.expires_in > 366 * 24 * 60 * 60
    {
        bail!("OAuth token response failed security validation");
    }
    let seconds = i64::try_from(token.expires_in).context("OAuth token lifetime is too large")?;
    let scopes = if token.scope.trim().is_empty() {
        allowed_scopes.to_vec()
    } else {
        token
            .scope
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    if scopes.iter().any(|scope| !allowed_scopes.contains(scope)) {
        bail!("OAuth token response expanded the approved scope");
    }
    IssuedTokens::new(
        token.access_token.into_secret(),
        token.refresh_token.map(SecretText::into_secret),
        Utc::now() + ChronoDuration::seconds(seconds),
        scopes,
    )
}

fn get_json<T: DeserializeOwned>(client: &Client, url: Url, limit: usize) -> Result<T> {
    let response = client.get(url).send()?;
    if !response.status().is_success() {
        bail!("OAuth metadata endpoint rejected the request");
    }
    require_json(&response)?;
    let body = read_bounded(response, limit)?;
    parse_strict_json(&body).context("OAuth metadata was invalid")
}

fn read_bounded(mut response: Response, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        bail!("HTTP response exceeded the body limit");
    }
    let mut body = Zeroizing::new(Vec::new());
    response
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        bail!("HTTP response exceeded the body limit");
    }
    Ok(body)
}

fn parse_strict_json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    let mut validator = serde_json::Deserializer::from_slice(body);
    NoDuplicateKeys
        .deserialize(&mut validator)
        .context("JSON contains a duplicate key or unsupported value")?;
    validator.end().context("JSON has trailing data")?;
    serde_json::from_slice(body).context("JSON schema is invalid")
}

struct NoDuplicateKeys;

impl<'de> DeserializeSeed<'de> for NoDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(NoDuplicateKeys)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(NoDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_char<E>(self, _: char) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_bytes<E>(self, _: &[u8]) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_byte_buf<E>(self, _: Vec<u8>) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateKeys.deserialize(deserializer)
    }
    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_newtype_struct<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateKeys.deserialize(deserializer)
    }
}

fn well_known(base: &Url, suffix: &str) -> Result<Url> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let path = base.path().trim_start_matches('/');
    let target = if path.is_empty() {
        format!("/.well-known/{suffix}")
    } else {
        format!("/.well-known/{suffix}/{path}")
    };
    url.set_path(&target);
    Ok(url)
}

fn parse_resource(input: &str, policy: EndpointPolicy) -> Result<Url> {
    match policy {
        EndpointPolicy::HttpsOnly => validate_remote_resource(input),
        #[cfg(test)]
        EndpointPolicy::TestLoopbackHttp => checked_endpoint(&Url::parse(input)?, policy),
    }
}

fn checked_endpoint(url: &Url, policy: EndpointPolicy) -> Result<Url> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("OAuth endpoint is unsafe");
    }
    match policy {
        EndpointPolicy::HttpsOnly => {
            if url.scheme() != "https" {
                bail!("OAuth endpoint must use HTTPS");
            }
            validate_public_host(url)?;
        }
        #[cfg(test)]
        EndpointPolicy::TestLoopbackHttp => {
            let exact_loopback =
                url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "::1"));
            if !exact_loopback && url.scheme() != "https" {
                bail!("OAuth endpoint is unsafe");
            }
        }
    }
    Ok(url.clone())
}

fn validate_public_host(url: &Url) -> Result<()> {
    let host = url.host_str().context("OAuth endpoint has no host")?;
    let port = url
        .port_or_known_default()
        .context("OAuth endpoint has no port")?;
    resolve_public(host, port)?;
    Ok(())
}

fn client_for(url: &Url, policy: EndpointPolicy) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    match policy {
        EndpointPolicy::HttpsOnly => {
            let host = url.host_str().context("OAuth endpoint has no host")?;
            let port = url
                .port_or_known_default()
                .context("OAuth endpoint has no port")?;
            let addresses = resolve_public(host, port)?;
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        #[cfg(test)]
        EndpointPolicy::TestLoopbackHttp => {}
    }
    Ok(builder.build()?)
}

struct SecretReader {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}

impl Read for SecretReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.bytes[self.position..];
        let count = remaining.len().min(output.len());
        output[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        Ok(count)
    }
}

fn secret_body(bytes: &[u8]) -> Body {
    let reader = SecretReader {
        bytes: Zeroizing::new(bytes.to_vec()),
        position: 0,
    };
    Body::sized(reader, bytes.len() as u64)
}

fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let octets = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19)))
        }
        IpAddr::V6(v) => {
            let segments = v.segments();
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || !global_unicast
                // Conservatively reject IANA special-purpose and transition
                // allocations inside 2000::/3. Cargo would rather refuse an
                // unusual provider than permit an internal-route ambiguity.
                || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || segments[0] == 0x2002
                || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
                || v.to_ipv4_mapped()
                    .is_some_and(|mapped| !is_global(IpAddr::V4(mapped))))
        }
    }
}

fn resolve_public(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
    let addresses = (host, port)
        .to_socket_addrs()
        .context("OAuth endpoint DNS resolution failed")?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_global(address.ip())) {
        bail!("OAuth endpoint DNS resolved to a non-public address");
    }
    Ok(addresses)
}

fn require_json(response: &Response) -> Result<()> {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .context("HTTP response omitted Content-Type")?;
    let media = value
        .to_str()
        .context("HTTP response Content-Type was invalid")?
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if media != "application/json" && !media.ends_with("+json") {
        bail!("HTTP response was not JSON");
    }
    Ok(())
}

#[cfg(test)]
fn validate_test_discovery(
    resource: &Url,
    protected: &ProtectedResourceMetadata,
    auth: &AuthorizationServerMetadata,
) -> Result<ValidatedAuthorizationMetadata> {
    if protected.resource != resource.as_str() || protected.authorization_servers.len() != 1 {
        bail!("test discovery binding failed");
    }
    if auth.issuer != protected.authorization_servers[0]
        || !auth
            .code_challenge_methods_supported
            .iter()
            .any(|v| v == "S256")
        || !auth
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|v| v == "none")
    {
        bail!("test authorization metadata failed validation");
    }
    Ok(ValidatedAuthorizationMetadata {
        resource: resource.clone(),
        issuer: checked_endpoint(&Url::parse(&auth.issuer)?, EndpointPolicy::TestLoopbackHttp)?,
        authorization_endpoint: checked_endpoint(
            &Url::parse(&auth.authorization_endpoint)?,
            EndpointPolicy::TestLoopbackHttp,
        )?,
        token_endpoint: checked_endpoint(
            &Url::parse(&auth.token_endpoint)?,
            EndpointPolicy::TestLoopbackHttp,
        )?,
        revocation_endpoint: auth
            .revocation_endpoint
            .as_deref()
            .map(Url::parse)
            .transpose()?
            .map(|u| checked_endpoint(&u, EndpointPolicy::TestLoopbackHttp))
            .transpose()?,
        introspection_endpoint: None,
        registration_endpoint: None,
        scopes_supported: protected.scopes_supported.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        oauth::{AuthorizationTransaction, OAuthProviderTransport},
        oauth_callback::LoopbackCallback,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use reqwest::StatusCode;
    use sha2::{Digest, Sha256};
    use std::{
        collections::{HashMap, HashSet},
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    #[derive(Default)]
    struct ProviderState {
        sequence: u64,
        codes: HashMap<String, CodeRecord>,
        refresh_families: HashMap<String, u64>,
        used_refresh: HashSet<String>,
        access_families: HashMap<String, u64>,
        invalid_families: HashSet<u64>,
    }

    struct CodeRecord {
        challenge: String,
        redirect_uri: String,
    }

    struct FakeProvider {
        base: Url,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl FakeProvider {
        fn start() -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let base = Url::parse(&format!("http://127.0.0.1:{}", address.port())).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let state = Arc::new(Mutex::new(ProviderState::default()));
            let worker_stop = stop.clone();
            let worker_base = base.clone();
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer)) if peer.ip().is_loopback() => {
                            let response = handle_request(&mut stream, &worker_base, &state);
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                        }
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                base,
                stop,
                worker: Some(worker),
            }
        }

        fn resource(&self) -> Url {
            self.base.join("mcp").unwrap()
        }
    }

    impl Drop for FakeProvider {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.base.port().unwrap()));
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    struct Request {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: Zeroizing<Vec<u8>>,
    }

    fn read_request(stream: &mut TcpStream) -> Result<Request> {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                bail!("request ended before headers");
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > 32 * 1024 {
                bail!("request too large");
            }
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let header_text = std::str::from_utf8(&bytes[..header_end])?;
        let mut lines = header_text.split("\r\n");
        let mut first = lines.next().unwrap_or("").split(' ');
        let method = first.next().unwrap_or("").to_owned();
        let target = first.next().unwrap_or("").to_owned();
        let mut headers = HashMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').context("malformed request header")?;
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + length {
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                bail!("request body was truncated");
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > 512 * 1024 {
                bail!("request body too large");
            }
        }
        Ok(Request {
            method,
            target,
            headers,
            body: Zeroizing::new(bytes[header_end..header_end + length].to_vec()),
        })
    }

    fn handle_request(
        stream: &mut TcpStream,
        base: &Url,
        state: &Arc<Mutex<ProviderState>>,
    ) -> Vec<u8> {
        let request = match read_request(stream) {
            Ok(value) => value,
            Err(_) => return response(400, "text/plain", "bad request", &[]),
        };
        let url = match base.join(&request.target) {
            Ok(value) => value,
            Err(_) => return response(400, "text/plain", "bad request", &[]),
        };
        match (request.method.as_str(), url.path()) {
            ("GET", "/.well-known/oauth-protected-resource/mcp") => response(
                200,
                "application/json",
                &serde_json::json!({
                    "resource": base.join("mcp").unwrap().to_string(),
                    "authorization_servers": [base.as_str()],
                    "scopes_supported": ["read"]
                })
                .to_string(),
                &[],
            ),
            ("GET", "/.well-known/oauth-authorization-server") => response(
                200,
                "application/json",
                &serde_json::json!({
                    "issuer": base.as_str(),
                    "authorization_endpoint": base.join("authorize").unwrap().to_string(),
                    "token_endpoint": base.join("token").unwrap().to_string(),
                    "revocation_endpoint": base.join("revoke").unwrap().to_string(),
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none"]
                })
                .to_string(),
                &[],
            ),
            ("GET", "/authorize") => authorize_endpoint(base, &url, state),
            ("POST", "/token") => token(base, &request.body, state),
            ("POST", "/revoke") => revoke(&request.body, state),
            ("GET", "/mcp") => resource(&request.headers, state),
            _ => response(404, "text/plain", "not found", &[]),
        }
    }

    fn authorize_endpoint(base: &Url, url: &Url, state: &Arc<Mutex<ProviderState>>) -> Vec<u8> {
        let params = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        let required = ["state", "redirect_uri", "code_challenge", "resource"];
        if required.iter().any(|key| !params.contains_key(*key))
            || params.get("resource") != Some(&base.join("mcp").unwrap().to_string())
            || params.get("code_challenge_method").map(String::as_str) != Some("S256")
        {
            return response(400, "text/plain", "invalid authorization request", &[]);
        }
        let mut provider = state.lock().unwrap();
        provider.sequence += 1;
        let code = format!("code-{}", provider.sequence);
        provider.codes.insert(
            code.clone(),
            CodeRecord {
                challenge: params["code_challenge"].clone(),
                redirect_uri: params["redirect_uri"].clone(),
            },
        );
        let mut redirect = match Url::parse(&params["redirect_uri"]) {
            Ok(value) => value,
            Err(_) => return response(400, "text/plain", "invalid redirect", &[]),
        };
        redirect
            .query_pairs_mut()
            .append_pair("state", &params["state"])
            .append_pair("code", &code);
        response(
            302,
            "text/plain",
            "continue",
            &[("Location", redirect.as_str())],
        )
    }

    fn token(base: &Url, body: &[u8], state: &Arc<Mutex<ProviderState>>) -> Vec<u8> {
        let params = url::form_urlencoded::parse(body)
            .into_owned()
            .collect::<HashMap<_, _>>();
        if params.get("resource") != Some(&base.join("mcp").unwrap().to_string()) {
            return response(
                400,
                "application/json",
                "{\"error\":\"invalid_target\"}",
                &[],
            );
        }
        let mut provider = state.lock().unwrap();
        match params.get("grant_type").map(String::as_str) {
            Some("authorization_code") => {
                let Some(code) = params.get("code") else {
                    return oauth_error();
                };
                let Some(record) = provider.codes.remove(code) else {
                    return oauth_error();
                };
                let Some(verifier) = params.get("code_verifier") else {
                    return oauth_error();
                };
                if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != record.challenge
                    || params.get("redirect_uri") != Some(&record.redirect_uri)
                {
                    return oauth_error();
                }
                provider.sequence += 1;
                let family = provider.sequence;
                issue_tokens(&mut provider, family)
            }
            Some("refresh_token") => {
                let Some(refresh) = params.get("refresh_token") else {
                    return oauth_error();
                };
                let Some(family) = provider.refresh_families.get(refresh).copied() else {
                    return oauth_error();
                };
                if provider.used_refresh.contains(refresh)
                    || provider.invalid_families.contains(&family)
                {
                    provider.invalid_families.insert(family);
                    return oauth_error();
                }
                provider.used_refresh.insert(refresh.clone());
                issue_tokens(&mut provider, family)
            }
            _ => oauth_error(),
        }
    }

    fn issue_tokens(provider: &mut ProviderState, family: u64) -> Vec<u8> {
        provider.sequence += 1;
        let access = format!("access-{}", provider.sequence);
        let refresh = format!("refresh-{}", provider.sequence);
        provider.access_families.insert(access.clone(), family);
        provider.refresh_families.insert(refresh.clone(), family);
        response(
            200,
            "application/json",
            &serde_json::json!({
                "access_token": access,
                "refresh_token": refresh,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "read"
            })
            .to_string(),
            &[],
        )
    }

    fn oauth_error() -> Vec<u8> {
        response(
            400,
            "application/json",
            "{\"error\":\"invalid_grant\"}",
            &[],
        )
    }

    fn revoke(body: &[u8], state: &Arc<Mutex<ProviderState>>) -> Vec<u8> {
        let params = url::form_urlencoded::parse(body)
            .into_owned()
            .collect::<HashMap<_, _>>();
        if let Some(token) = params.get("token") {
            let mut provider = state.lock().unwrap();
            provider.access_families.remove(token);
            provider.refresh_families.remove(token);
        }
        response(200, "application/json", "{}", &[])
    }

    fn resource(headers: &HashMap<String, String>, state: &Arc<Mutex<ProviderState>>) -> Vec<u8> {
        let token = headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "));
        let provider = state.lock().unwrap();
        let active = token
            .and_then(|value| provider.access_families.get(value))
            .is_some_and(|family| !provider.invalid_families.contains(family));
        if active {
            response(200, "application/json", "{}", &[])
        } else {
            response(
                401,
                "application/json",
                "{\"error\":\"invalid_token\"}",
                &[],
            )
        }
    }

    fn response(status: u16, content_type: &str, body: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let label = match status {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            _ => "Not Found",
        };
        let mut value = format!(
            "HTTP/1.1 {status} {label}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, content) in headers {
            value.push_str(&format!("{name}: {content}\r\n"));
        }
        value.push_str("\r\n");
        value.push_str(body);
        value.into_bytes()
    }

    fn browser_authorize(transaction: &AuthorizationTransaction) -> Url {
        let response = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(transaction.authorization_url())
            .send()
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        Url::parse(
            response
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap()
    }

    fn follow_callback(callback: Url) {
        let port = callback.port().unwrap();
        let target = match callback.query() {
            Some(query) => format!("{}?{query}", callback.path()),
            None => callback.path().to_owned(),
        };
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    fn authorize_flow(provider: &FakeProvider, transport: &HttpOAuthTransport) -> IssuedTokens {
        let mut callback = LoopbackCallback::bind().unwrap();
        let mut transaction = AuthorizationTransaction::new(
            transport.metadata(),
            "cargo-test-public-client",
            callback.redirect_uri().clone(),
            vec!["read".into()],
        )
        .unwrap();
        let redirect = browser_authorize(&transaction);
        let browser = thread::spawn(move || follow_callback(redirect));
        let exchange = callback.receive_exchange(&mut transaction).unwrap();
        browser.join().unwrap();
        let mut fresh =
            HttpOAuthTransport::discover_test_loopback(provider.resource().as_str()).unwrap();
        fresh.exchange(exchange).unwrap()
    }

    #[test]
    fn strict_json_rejects_duplicate_security_fields() {
        let duplicate = br#"{"issuer":"https://one.example","issuer":"https://two.example"}"#;
        assert!(parse_strict_json::<serde_json::Value>(duplicate).is_err());
        assert!(parse_strict_json::<serde_json::Value>(br#"{"outer":{"key":1,"key":2}}"#).is_err());
    }

    #[test]
    fn token_scope_omission_inherits_and_expansion_is_rejected() {
        let allowed = vec!["read".to_owned()];
        let omitted = br#"{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":300}"#;
        let issued = parse_token_payload(omitted, &allowed).unwrap();
        assert_eq!(issued.scopes, allowed);
        assert!(!format!("{issued:?}").contains("access-secret"));
        assert!(!format!("{issued:?}").contains("refresh-secret"));

        let expanded = br#"{"access_token":"access-secret","token_type":"Bearer","expires_in":300,"scope":"read admin"}"#;
        assert!(parse_token_payload(expanded, &["read".to_owned()]).is_err());
    }

    #[test]
    fn private_and_special_addresses_are_not_public() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "fec0::1",
            "100::1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(
                !is_global(value.parse().unwrap()),
                "{value} must be rejected"
            );
        }
        assert!(is_global("1.1.1.1".parse().unwrap()));
        assert!(is_global("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn http_conformance_covers_exchange_rotation_replay_and_revocation() {
        let provider = FakeProvider::start();
        let mut transport =
            HttpOAuthTransport::discover_test_loopback(provider.resource().as_str()).unwrap();

        let issued = authorize_flow(&provider, &transport);
        let (access_one, refresh_one) = issued.into_secrets();
        let refresh_one = refresh_one.unwrap();
        assert_eq!(
            transport
                .probe_resource(&access_one, &provider.resource())
                .unwrap(),
            RevocationVerification::StillActive
        );

        let rotated = transport
            .refresh(&refresh_one, &provider.resource(), &["read".into()])
            .unwrap();
        let (access_two, refresh_two) = rotated.into_secrets();
        let refresh_two = refresh_two.unwrap();
        assert_eq!(
            transport
                .probe_resource(&access_two, &provider.resource())
                .unwrap(),
            RevocationVerification::StillActive
        );
        assert!(
            transport
                .refresh(&refresh_one, &provider.resource(), &["read".into()])
                .is_err()
        );
        assert_eq!(
            transport
                .probe_resource(&access_two, &provider.resource())
                .unwrap(),
            RevocationVerification::ResourceRejected
        );

        let reauthorized = authorize_flow(&provider, &transport);
        let (access_three, refresh_three) = reauthorized.into_secrets();
        let refresh_three = refresh_three.unwrap();
        assert_eq!(
            transport
                .revoke(&refresh_three, TokenKind::Refresh)
                .unwrap(),
            TokenRevocationResult::AcceptedUnverified
        );
        assert_eq!(
            transport.revoke(&access_three, TokenKind::Access).unwrap(),
            TokenRevocationResult::AcceptedUnverified
        );
        assert_eq!(
            transport
                .probe_resource(&access_three, &provider.resource())
                .unwrap(),
            RevocationVerification::ResourceRejected
        );

        // The newest refresh token is intentionally unused here; the prior
        // replay invalidated its whole family, and no token value is logged.
        drop(refresh_two);
    }
}
