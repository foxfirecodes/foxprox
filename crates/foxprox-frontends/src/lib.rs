//! Frontend contracts and small alpha parsers that emit normalized events.
//!
//! Frontends produce `foxprox-core` normalized events. They do not evaluate
//! policy and do not own host egress.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

use foxprox_core::{
    DestinationHost, FrontendKind, Hostname, HttpMethod, HttpRequest, HttpScheme, HttpsConnect,
    NormalizedEvent, SandboxId, SocksConnect, UnsupportedNetworkEvent, UnsupportedReason,
};

/// Generic frontend event producer contract.
pub trait EventProducer {
    fn frontend_kind(&self) -> FrontendKind;
    fn next_event(&mut self) -> Option<NormalizedEvent>;
}

/// In-memory frontend used by policy/audit/egress contract tests.
#[derive(Clone, Debug)]
pub struct MockFrontend {
    kind: FrontendKind,
    events: Vec<NormalizedEvent>,
}

impl MockFrontend {
    pub fn new(kind: FrontendKind, events: Vec<NormalizedEvent>) -> Self {
        Self { kind, events }
    }
}

impl EventProducer for MockFrontend {
    fn frontend_kind(&self) -> FrontendKind {
        self.kind
    }

    fn next_event(&mut self) -> Option<NormalizedEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }
}

/// Opaque inbound IP packet. The raw bytes stay in the frontend/network adapter;
/// policy and audit receive only normalized events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundIpPacket {
    bytes: Vec<u8>,
}

impl InboundIpPacket {
    pub fn new(bytes: Vec<u8>) -> Result<Self, FrontendError> {
        if bytes.is_empty() {
            return Err(FrontendError::EmptyPacket);
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Minimal TUN normalizer for unsupported-path alpha tests. Full IP/TCP/UDP/ICMP
/// parsing belongs behind the network adapter, not in policy.
pub fn normalize_unknown_tun_packet(
    sandbox_id: SandboxId,
    packet: Result<InboundIpPacket, FrontendError>,
) -> NormalizedEvent {
    match packet {
        Ok(packet) => {
            let reason = match packet.bytes().first().map(|byte| byte >> 4) {
                Some(4 | 6) => {
                    UnsupportedReason::Other("packet requires network adapter parsing".into())
                }
                _ => UnsupportedReason::MalformedPacket,
            };
            NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                sandbox_id,
                frontend: FrontendKind::Tun,
                reason,
                safe_metadata: Some(format!("{} bytes", packet.bytes().len())),
            })
        }
        Err(_) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend: FrontendKind::Tun,
            reason: UnsupportedReason::MalformedPacket,
            safe_metadata: None,
        }),
    }
}

/// Parse a plaintext HTTP proxy or transparent HTTP request into a normalized
/// event. The parser is deliberately small and returns an unsupported event for
/// malformed input rather than guessing.
pub fn parse_http_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> NormalizedEvent {
    match parse_http_request_inner(sandbox_id.clone(), frontend, bytes) {
        Ok(event) => event,
        Err(error) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend,
            reason: UnsupportedReason::MalformedProxyRequest,
            safe_metadata: Some(error.to_string()),
        }),
    }
}

fn parse_http_request_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<NormalizedEvent, FrontendError> {
    let text = std::str::from_utf8(bytes).map_err(|_| FrontendError::MalformedHttp("utf8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(FrontendError::MalformedHttp("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method_text = parts
        .next()
        .ok_or(FrontendError::MalformedHttp("missing method"))?;
    let target = parts
        .next()
        .ok_or(FrontendError::MalformedHttp("missing target"))?;
    let _version = parts
        .next()
        .ok_or(FrontendError::MalformedHttp("missing version"))?;
    let method = HttpMethod::parse(method_text);

    if method == HttpMethod::Connect {
        let (host, port) = parse_host_port(target, 443)?;
        return Ok(NormalizedEvent::HttpsConnect(HttpsConnect {
            sandbox_id,
            frontend,
            host,
            port,
        }));
    }

    let mut host_header = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                host_header = Some(value.trim());
            }
        }
    }

    let (scheme, host, port, path_query) = if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = split_authority_path(rest);
        let (host, port) = parse_host_port(authority, 80)?;
        (HttpScheme::Http, host, port, path.to_string())
    } else if let Some(rest) = target.strip_prefix("https://") {
        let (authority, path) = split_authority_path(rest);
        let (host, port) = parse_host_port(authority, 443)?;
        (HttpScheme::Https, host, port, path.to_string())
    } else {
        let host_header = host_header.ok_or(FrontendError::MalformedHttp("missing host"))?;
        let (host, port) = parse_host_port(host_header, 80)?;
        (HttpScheme::Http, host, port, target.to_string())
    };

    let DestinationHost::Hostname(host) = host else {
        return Err(FrontendError::MalformedHttp(
            "HTTP host must be hostname for alpha policy",
        ));
    };

    Ok(NormalizedEvent::HttpRequest(HttpRequest {
        sandbox_id,
        frontend,
        method,
        scheme,
        host,
        port,
        path_query,
    }))
}

fn split_authority_path(rest: &str) -> (&str, &str) {
    match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    }
}

fn parse_host_port(
    value: &str,
    default_port: u16,
) -> Result<(DestinationHost, u16), FrontendError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(FrontendError::MalformedHttp("empty host"));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(']') {
            let port = port
                .parse()
                .map_err(|_| FrontendError::MalformedHttp("bad port"))?;
            return Ok((parse_destination_host(host)?, port));
        }
    }
    Ok((parse_destination_host(value)?, default_port))
}

fn parse_destination_host(value: &str) -> Result<DestinationHost, FrontendError> {
    let value = value.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = value.parse::<IpAddr>() {
        Ok(DestinationHost::Ip(ip))
    } else {
        Ok(DestinationHost::Hostname(
            Hostname::new(value).map_err(FrontendError::Contract)?,
        ))
    }
}

/// Parse one SOCKS5 TCP CONNECT request after method negotiation.
pub fn parse_socks5_connect(sandbox_id: SandboxId, bytes: &[u8]) -> NormalizedEvent {
    match parse_socks5_connect_inner(sandbox_id.clone(), bytes) {
        Ok(event) => NormalizedEvent::SocksConnect(event),
        Err(error) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend: FrontendKind::Socks5,
            reason: UnsupportedReason::MalformedProxyRequest,
            safe_metadata: Some(error.to_string()),
        }),
    }
}

fn parse_socks5_connect_inner(
    sandbox_id: SandboxId,
    bytes: &[u8],
) -> Result<SocksConnect, FrontendError> {
    if bytes.len() < 7 {
        return Err(FrontendError::MalformedSocks("too short"));
    }
    if bytes[0] != 0x05 || bytes[1] != 0x01 {
        return Err(FrontendError::MalformedSocks("not a SOCKS5 CONNECT"));
    }
    let atyp = bytes[3];
    let (destination, port_index) = match atyp {
        0x01 => {
            if bytes.len() < 10 {
                return Err(FrontendError::MalformedSocks("short IPv4 request"));
            }
            let ip = IpAddr::from([bytes[4], bytes[5], bytes[6], bytes[7]]);
            (DestinationHost::Ip(ip), 8)
        }
        0x03 => {
            let len = bytes[4] as usize;
            if bytes.len() < 5 + len + 2 {
                return Err(FrontendError::MalformedSocks("short domain request"));
            }
            let host = std::str::from_utf8(&bytes[5..5 + len])
                .map_err(|_| FrontendError::MalformedSocks("domain utf8"))?;
            (
                DestinationHost::Hostname(Hostname::new(host).map_err(FrontendError::Contract)?),
                5 + len,
            )
        }
        0x04 => {
            if bytes.len() < 22 {
                return Err(FrontendError::MalformedSocks("short IPv6 request"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[4..20]);
            (DestinationHost::Ip(IpAddr::from(octets)), 20)
        }
        _ => return Err(FrontendError::MalformedSocks("unsupported address type")),
    };
    let port = u16::from_be_bytes([bytes[port_index], bytes[port_index + 1]]);
    Ok(SocksConnect {
        sandbox_id,
        frontend: FrontendKind::Socks5,
        destination,
        port,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FrontendError {
    EmptyPacket,
    MalformedHttp(&'static str),
    MalformedSocks(&'static str),
    Contract(foxprox_core::ContractError),
}

impl fmt::Display for FrontendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPacket => f.write_str("empty packet"),
            Self::MalformedHttp(reason) => write!(f, "malformed HTTP request: {reason}"),
            Self::MalformedSocks(reason) => write!(f, "malformed SOCKS request: {reason}"),
            Self::Contract(error) => write!(f, "contract error: {error}"),
        }
    }
}

impl std::error::Error for FrontendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Protocol, UnsupportedReason};

    fn sandbox() -> SandboxId {
        SandboxId::new("s1").unwrap()
    }

    #[test]
    fn parses_explicit_http_request_to_normalized_event() {
        let event = parse_http_request(
            sandbox(),
            FrontendKind::HttpProxy,
            b"GET http://Example.com:8080/a?b=c HTTP/1.1\r\nHost: ignored\r\n\r\n",
        );

        let NormalizedEvent::HttpRequest(request) = event else {
            panic!("expected HTTP request");
        };
        assert_eq!(request.host.as_str(), "example.com");
        assert_eq!(request.port, 8080);
        assert_eq!(request.path_query, "/a?b=c");
    }

    #[test]
    fn parses_https_connect_to_normalized_event() {
        let event = parse_http_request(
            sandbox(),
            FrontendKind::HttpProxy,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );

        assert_eq!(event.protocol(), Protocol::HttpsConnect);
    }

    #[test]
    fn malformed_http_fails_closed_as_unsupported_event() {
        let event = parse_http_request(
            sandbox(),
            FrontendKind::HttpProxy,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::MalformedProxyRequest);
    }

    #[test]
    fn parses_socks5_domain_connect() {
        let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443_u16.to_be_bytes());

        let event = parse_socks5_connect(sandbox(), &request);
        let NormalizedEvent::SocksConnect(connect) = event else {
            panic!("expected SOCKS connect");
        };
        assert_eq!(connect.port, 443);
        assert_eq!(
            connect.destination.hostname().unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn tun_frontend_wraps_bad_packets_as_unsupported() {
        let event = normalize_unknown_tun_packet(sandbox(), InboundIpPacket::new(Vec::new()));
        assert_eq!(event.protocol(), Protocol::Unsupported);
    }
}
