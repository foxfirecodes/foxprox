//! Frontend contracts and small alpha parsers that emit normalized events.
//!
//! Frontends produce `foxprox-core` normalized events. They do not evaluate
//! policy and do not own host egress.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

use foxprox_core::{
    DestinationHost, FrontendKind, Hostname, HttpMethod, HttpRequest, HttpScheme, HttpsConnect,
    NormalizedEvent, ParserLimits, SandboxId, SocksConnect, UnsupportedNetworkEvent,
    UnsupportedReason,
};

/// Maximum request head bytes accepted by the alpha HTTP proxy parser.
pub const MAX_HTTP_REQUEST_HEAD_BYTES: usize = 8192;

/// Maximum SOCKS5 greeting or request bytes accepted by alpha SOCKS helpers.
pub const MAX_SOCKS5_MESSAGE_BYTES: usize = 512;

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
    parse_http_request_with_limits(sandbox_id, frontend, bytes, ParserLimits::default())
}

/// Parse an HTTP request while enforcing caller-provided normalized parser
/// limits before UTF-8 conversion or request-line parsing.
pub fn parse_http_request_with_limits(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    limits: ParserLimits,
) -> NormalizedEvent {
    match parse_http_request_inner(sandbox_id.clone(), frontend, bytes, limits) {
        Ok(event) => event,
        Err(error) => {
            let reason = match error {
                FrontendError::RequestTooLarge => UnsupportedReason::ParserLimitExceeded,
                _ => UnsupportedReason::MalformedProxyRequest,
            };
            NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                sandbox_id,
                frontend,
                reason,
                safe_metadata: Some(error.to_string()),
            })
        }
    }
}

fn parse_http_request_inner(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
    limits: ParserLimits,
) -> Result<NormalizedEvent, FrontendError> {
    if bytes.len() > limits.max_http_request_head_bytes {
        return Err(FrontendError::RequestTooLarge);
    }
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

    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(FrontendError::MalformedHttp("unterminated IPv6 authority"));
        };
        let host = &rest[..end];
        let remainder = &rest[end + 1..];
        let port = if let Some(port) = remainder.strip_prefix(':') {
            port.parse()
                .map_err(|_| FrontendError::MalformedHttp("bad port"))?
        } else if remainder.is_empty() {
            default_port
        } else {
            return Err(FrontendError::MalformedHttp("bad bracketed authority"));
        };
        return Ok((parse_destination_host(host)?, port));
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok((DestinationHost::Ip(ip), default_port));
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        let port = port
            .parse()
            .map_err(|_| FrontendError::MalformedHttp("bad port"))?;
        return Ok((parse_destination_host(host)?, port));
    }
    Ok((parse_destination_host(value)?, default_port))
}

fn parse_destination_host(value: &str) -> Result<DestinationHost, FrontendError> {
    let value = value.trim();
    if let Ok(ip) = value.parse::<IpAddr>() {
        Ok(DestinationHost::Ip(ip))
    } else {
        Ok(DestinationHost::Hostname(
            Hostname::new(value).map_err(FrontendError::Contract)?,
        ))
    }
}

/// SOCKS5 reply code used for frontend-local wire responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Socks5ReplyCode {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Socks5ReplyCode {
    fn as_byte(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

/// Select SOCKS5 no-authentication when offered by the client.
///
/// This helper returns the two-byte method-selection response and keeps SOCKS
/// wire negotiation out of core policy contracts.
pub fn select_socks5_no_auth_method(bytes: &[u8]) -> Result<[u8; 2], FrontendError> {
    select_socks5_no_auth_method_with_limits(bytes, ParserLimits::default())
}

/// Select SOCKS5 no-authentication while enforcing normalized parser limits.
pub fn select_socks5_no_auth_method_with_limits(
    bytes: &[u8],
    limits: ParserLimits,
) -> Result<[u8; 2], FrontendError> {
    if bytes.len() > limits.max_socks5_message_bytes {
        return Err(FrontendError::RequestTooLarge);
    }
    if bytes.len() < 2 || bytes[0] != 0x05 {
        return Err(FrontendError::MalformedSocks("bad greeting"));
    }
    let method_count = usize::from(bytes[1]);
    if method_count == 0 || bytes.len() < 2 + method_count {
        return Err(FrontendError::MalformedSocks("short greeting"));
    }
    let methods = &bytes[2..2 + method_count];
    if methods.contains(&0x00) {
        Ok([0x05, 0x00])
    } else {
        Ok([0x05, 0xff])
    }
}

/// Build a SOCKS5 CONNECT reply bound to 0.0.0.0:0 for alpha frontends.
pub fn build_socks5_connect_reply(code: Socks5ReplyCode) -> [u8; 10] {
    [0x05, code.as_byte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Parse one SOCKS5 TCP CONNECT request after method negotiation.
pub fn parse_socks5_connect(sandbox_id: SandboxId, bytes: &[u8]) -> NormalizedEvent {
    parse_socks5_connect_with_limits(sandbox_id, bytes, ParserLimits::default())
}

/// Parse one SOCKS5 TCP CONNECT request while enforcing normalized parser
/// limits before address-specific parsing.
pub fn parse_socks5_connect_with_limits(
    sandbox_id: SandboxId,
    bytes: &[u8],
    limits: ParserLimits,
) -> NormalizedEvent {
    match parse_socks5_connect_inner(sandbox_id.clone(), bytes, limits) {
        Ok(event) => NormalizedEvent::SocksConnect(event),
        Err(error) => {
            let reason = match error {
                FrontendError::RequestTooLarge => UnsupportedReason::ParserLimitExceeded,
                _ => UnsupportedReason::MalformedProxyRequest,
            };
            NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                sandbox_id,
                frontend: FrontendKind::Socks5,
                reason,
                safe_metadata: Some(error.to_string()),
            })
        }
    }
}

fn parse_socks5_connect_inner(
    sandbox_id: SandboxId,
    bytes: &[u8],
    limits: ParserLimits,
) -> Result<SocksConnect, FrontendError> {
    if bytes.len() > limits.max_socks5_message_bytes {
        return Err(FrontendError::RequestTooLarge);
    }
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
    RequestTooLarge,
    MalformedHttp(&'static str),
    MalformedSocks(&'static str),
    Contract(foxprox_core::ContractError),
}

impl fmt::Display for FrontendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPacket => f.write_str("empty packet"),
            Self::RequestTooLarge => write!(
                f,
                "HTTP request head exceeds {MAX_HTTP_REQUEST_HEAD_BYTES} bytes"
            ),
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
        assert_eq!(request.host.hostname().unwrap().as_str(), "example.com");
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
    fn parses_bracketed_ipv6_proxy_authorities() {
        let connect = parse_http_request(
            sandbox(),
            FrontendKind::HttpProxy,
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n",
        );
        let NormalizedEvent::HttpsConnect(connect) = connect else {
            panic!("expected CONNECT");
        };
        assert_eq!(
            connect.host.ip().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(connect.port, 443);

        let request = parse_http_request(
            sandbox(),
            FrontendKind::HttpProxy,
            b"GET http://[2001:db8::2]:8080/path HTTP/1.1\r\nHost: [2001:db8::2]\r\n\r\n",
        );
        let NormalizedEvent::HttpRequest(request) = request else {
            panic!("expected HTTP request");
        };
        assert_eq!(
            request.host.ip().unwrap(),
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(request.port, 8080);
        assert_eq!(request.path_query, "/path");
    }

    #[test]
    fn oversized_http_request_fails_closed_as_parser_limit() {
        let oversized = vec![b'a'; MAX_HTTP_REQUEST_HEAD_BYTES + 1];
        let event = parse_http_request(sandbox(), FrontendKind::HttpProxy, &oversized);
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::ParserLimitExceeded);
    }

    #[test]
    fn http_parser_enforces_normalized_runtime_limit() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = parse_http_request_with_limits(
            sandbox(),
            FrontendKind::HttpProxy,
            request,
            ParserLimits {
                max_http_request_head_bytes: request.len() - 1,
                ..ParserLimits::default()
            },
        );
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::ParserLimitExceeded);

        let event = parse_http_request_with_limits(
            sandbox(),
            FrontendKind::HttpProxy,
            request,
            ParserLimits {
                max_http_request_head_bytes: request.len(),
                ..ParserLimits::default()
            },
        );
        assert!(matches!(event, NormalizedEvent::HttpRequest(_)));
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
    fn socks5_handshake_helpers_stay_frontend_local() {
        assert_eq!(
            select_socks5_no_auth_method(&[0x05, 0x02, 0x02, 0x00]).unwrap(),
            [0x05, 0x00]
        );
        assert_eq!(
            select_socks5_no_auth_method(&[0x05, 0x01, 0x02]).unwrap(),
            [0x05, 0xff]
        );
        assert_eq!(
            build_socks5_connect_reply(Socks5ReplyCode::ConnectionNotAllowed),
            [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn socks5_helpers_enforce_normalized_runtime_limit() {
        let greeting = [0x05, 0x02, 0x02, 0x00];
        assert!(matches!(
            select_socks5_no_auth_method_with_limits(
                &greeting,
                ParserLimits {
                    max_socks5_message_bytes: greeting.len() - 1,
                    ..ParserLimits::default()
                }
            ),
            Err(FrontendError::RequestTooLarge)
        ));

        let request = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb];
        let event = parse_socks5_connect_with_limits(
            sandbox(),
            &request,
            ParserLimits {
                max_socks5_message_bytes: request.len() - 1,
                ..ParserLimits::default()
            },
        );
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::ParserLimitExceeded);
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
