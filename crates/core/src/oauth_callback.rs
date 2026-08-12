//! A one-shot native OAuth callback receiver bound to an ephemeral loopback port.

use crate::oauth::{AuthorizationTransaction, TokenExchangeRequest};
use anyhow::{Context, Result, bail};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_ATTEMPTS: usize = 16;

/// Owns the callback port before an authorization URL is constructed. It is
/// intentionally neither Clone nor serializable and accepts only one terminal
/// callback.
pub struct LoopbackCallback {
    listener: TcpListener,
    redirect_uri: Url,
    host_header: String,
    deadline: Instant,
    finished: bool,
}

impl std::fmt::Debug for LoopbackCallback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoopbackCallback")
            .field("redirect_uri", &self.redirect_uri)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl LoopbackCallback {
    pub fn bind() -> Result<Self> {
        Self::bind_with_timeout(CALLBACK_TIMEOUT)
    }

    fn bind_with_timeout(timeout: Duration) -> Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .context("OAuth callback could not bind a loopback port")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let path = format!("/oauth/callback/{}", Uuid::new_v4());
        let redirect_uri = Url::parse(&format!("http://127.0.0.1:{}{path}", address.port()))?;
        let host_header = format!("127.0.0.1:{}", address.port());
        Ok(Self {
            listener,
            redirect_uri,
            host_header,
            deadline: Instant::now() + timeout,
            finished: false,
        })
    }

    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Waits for one exact state-bearing success callback and consumes the
    /// transaction into a single-use token exchange request. Invalid requests
    /// receive a generic response and do not consume the transaction.
    pub fn receive_exchange(
        &mut self,
        transaction: &mut AuthorizationTransaction,
    ) -> Result<TokenExchangeRequest> {
        if self.finished {
            bail!("OAuth callback receiver was already consumed");
        }
        if transaction.redirect_uri() != &self.redirect_uri {
            bail!("OAuth transaction redirect does not match the bound callback");
        }

        let mut attempts = 0;
        while Instant::now() < self.deadline && attempts < MAX_ATTEMPTS {
            let (mut stream, peer) = match self.listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            attempts += 1;
            if !peer.ip().is_loopback() {
                send_response(&mut stream, 400);
                continue;
            }
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            match read_callback(&mut stream, &self.redirect_uri, &self.host_header) {
                Ok(CallbackResult::Code { state, code }) => {
                    if transaction.consume_callback(&state).is_err() {
                        send_response(&mut stream, 400);
                        continue;
                    }
                    self.finished = true;
                    let exchange = match transaction.token_exchange(&code) {
                        Ok(value) => value,
                        Err(error) => {
                            send_response(&mut stream, 400);
                            return Err(error);
                        }
                    };
                    send_response(&mut stream, 200);
                    return Ok(exchange);
                }
                Ok(CallbackResult::Denied { state }) => {
                    if transaction.consume_callback(&state).is_err() {
                        send_response(&mut stream, 400);
                        continue;
                    }
                    self.finished = true;
                    send_response(&mut stream, 200);
                    bail!("authorization was denied or cancelled");
                }
                Err(_) => send_response(&mut stream, 400),
            }
        }
        self.finished = true;
        bail!("OAuth callback expired or exceeded the invalid-request limit")
    }
}

enum CallbackResult {
    Code {
        state: Zeroizing<String>,
        code: Zeroizing<String>,
    },
    Denied {
        state: Zeroizing<String>,
    },
}

fn read_callback(
    stream: &mut TcpStream,
    redirect: &Url,
    expected_host: &str,
) -> Result<CallbackResult> {
    let mut request = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 1024]);
    loop {
        let count = stream.read(&mut chunk[..])?;
        if count == 0 {
            bail!("callback request ended before its headers");
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > MAX_REQUEST_BYTES {
            bail!("callback request exceeds its size limit");
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = std::str::from_utf8(&request).context("callback request is not UTF-8")?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().context("callback request line is absent")?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().unwrap_or("");
    let target = request_parts.next().unwrap_or("");
    let version = request_parts.next().unwrap_or("");
    if method != "GET"
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || request_parts.next().is_some()
    {
        bail!("callback request line is invalid");
    }

    let mut host = None;
    let mut header_count = 0;
    for line in lines.take_while(|line| !line.is_empty()) {
        header_count += 1;
        if header_count > 64 || line.len() > 8 * 1024 {
            bail!("callback headers exceed their limit");
        }
        let (name, value) = line
            .split_once(':')
            .context("callback header is malformed")?;
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim()).is_some() {
                bail!("callback contains duplicate Host headers");
            }
        } else if name.eq_ignore_ascii_case("content-length") && value.trim() != "0" {
            bail!("callback must not contain a body");
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("callback must not be transfer encoded");
        }
    }
    if host != Some(expected_host) {
        bail!("callback Host header does not match the bound listener");
    }

    let (path, query) = target.split_once('?').context("callback query is absent")?;
    if path != redirect.path() || target.contains('#') {
        bail!("callback path does not match the authorization transaction");
    }
    let mut state: Option<Zeroizing<String>> = None;
    let mut code: Option<Zeroizing<String>> = None;
    let mut error: Option<Zeroizing<String>> = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "state" => {
                if state.replace(Zeroizing::new(value.into_owned())).is_some() {
                    bail!("callback contains a duplicate security parameter");
                }
            }
            "code" => {
                if code.replace(Zeroizing::new(value.into_owned())).is_some() {
                    bail!("callback contains a duplicate security parameter");
                }
            }
            "error" if error.replace(Zeroizing::new(value.into_owned())).is_some() => {
                bail!("callback contains a duplicate security parameter");
            }
            "error" => {}
            _ => {}
        }
    }
    let state = state.context("callback state is absent")?;
    match (code, error) {
        (Some(code), None) if !code.is_empty() => Ok(CallbackResult::Code { state, code }),
        (None, Some(error)) if !error.is_empty() => Ok(CallbackResult::Denied { state }),
        _ => bail!("callback must contain exactly one code or error"),
    }
}

fn send_response(stream: &mut TcpStream, status: u16) {
    let label = if status == 200 { "OK" } else { "Bad Request" };
    let body = if status == 200 {
        "Authorization received. You can close this window."
    } else {
        "Authorization callback was not accepted."
    };
    let response = format!(
        "HTTP/1.1 {status} {label}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{
        AuthorizationServerMetadata, ProtectedResourceMetadata, validate_discovery,
    };
    use std::sync::mpsc;

    fn metadata(resource: &str) -> crate::oauth::ValidatedAuthorizationMetadata {
        validate_discovery(
            &Url::parse(resource).unwrap(),
            &ProtectedResourceMetadata {
                resource: resource.into(),
                authorization_servers: vec!["https://issuer.example".into()],
                scopes_supported: vec!["read".into()],
            },
            &AuthorizationServerMetadata {
                issuer: "https://issuer.example".into(),
                authorization_endpoint: "https://issuer.example/authorize".into(),
                token_endpoint: "https://issuer.example/token".into(),
                revocation_endpoint: None,
                introspection_endpoint: None,
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
    fn wrong_state_does_not_consume_the_real_callback_and_receiver_is_one_shot() {
        let mut callback = LoopbackCallback::bind_with_timeout(Duration::from_secs(2)).unwrap();
        let redirect = callback.redirect_uri().clone();
        let mut transaction = AuthorizationTransaction::new(
            &metadata("https://mcp.example/resource"),
            "public-client",
            redirect.clone(),
            vec!["read".into()],
        )
        .unwrap();
        let state = transaction
            .authorization_url()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let port = redirect.port().unwrap();
        let path = redirect.path().to_owned();
        let (sent, received) = mpsc::channel();
        let sender = thread::spawn(move || {
            for (candidate, code) in [("wrong", "attacker"), (&state, "real-code")] {
                let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                write!(stream, "GET {path}?state={candidate}&code={code} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                sent.send(response).unwrap();
            }
        });
        let exchange = callback.receive_exchange(&mut transaction).unwrap();
        assert!(!format!("{exchange:?}").contains("real-code"));
        assert!(received.recv().unwrap().starts_with("HTTP/1.1 400"));
        assert!(received.recv().unwrap().starts_with("HTTP/1.1 200"));
        sender.join().unwrap();
        assert!(callback.receive_exchange(&mut transaction).is_err());
    }
}
