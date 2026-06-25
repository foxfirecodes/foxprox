//! Transparent protocol inspection helpers for alpha policy metadata.
//!
//! This crate extracts narrow normalized metadata only. It is not a TLS or QUIC
//! stack, and parser-local details must not leak into policy models.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;

use foxprox_core::{
    DestinationHost, FrontendKind, Hostname, HostnameAttribution, HostnameMismatch, HttpMethod,
    HttpRequest, HttpScheme, NormalizedEvent, SandboxId, TlsClientHello, UnsupportedNetworkEvent,
    UnsupportedReason,
};

const TLS_HANDSHAKE: u8 = 22;
const TLS_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Inspect one transparent plaintext HTTP request head and emit a normalized
/// `HttpRequest` event. This function is intentionally independent from the
/// HTTP proxy frontend: transparent stream bytes are already on a TCP bridge and
/// must be policy/audit checked without proxy egress dispatch.
pub fn inspect_plaintext_http_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> NormalizedEvent {
    match parse_plaintext_http_request(sandbox_id.clone(), frontend, bytes) {
        Ok(event) => NormalizedEvent::HttpRequest(event),
        Err(error) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend,
            reason: UnsupportedReason::MalformedPacket,
            safe_metadata: Some(error.to_string()),
        }),
    }
}

fn parse_plaintext_http_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<HttpRequest, InspectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InspectError::Malformed("HTTP utf8"))?;
    let head = text
        .split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .unwrap_or(text);
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(InspectError::Malformed("missing HTTP request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(InspectError::Malformed("missing HTTP method"))?;
    let target = parts
        .next()
        .ok_or(InspectError::Malformed("missing HTTP target"))?;
    let _version = parts
        .next()
        .ok_or(InspectError::Malformed("missing HTTP version"))?;
    let mut host = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.trim());
                break;
            }
        }
    }
    let host = host.ok_or(InspectError::Malformed("missing HTTP Host"))?;
    let (host, port) = parse_host_port(host, 80)?;
    Ok(HttpRequest {
        sandbox_id,
        frontend,
        method: HttpMethod::parse(method),
        scheme: HttpScheme::Http,
        host,
        port,
        path_query: target.to_string(),
    })
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(DestinationHost, u16), InspectError> {
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let port = port
                .parse()
                .map_err(|_| InspectError::Malformed("bad HTTP Host port"))?;
            return Ok((parse_destination_host(host)?, port));
        }
    }
    Ok((parse_destination_host(value)?, default_port))
}

fn parse_destination_host(value: &str) -> Result<DestinationHost, InspectError> {
    if let Ok(ip) = value.parse() {
        Ok(DestinationHost::Ip(ip))
    } else {
        Hostname::new(value)
            .map(DestinationHost::Hostname)
            .map_err(|_| InspectError::Malformed("invalid HTTP Host"))
    }
}

/// Inspect a TLS ClientHello and emit normalized SNI/mismatch metadata. Malformed
/// handshakes and visible ECH extension use unsupported fail-closed events.
pub fn inspect_tls_client_hello(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    destination: SocketAddr,
    dns_hostname: Option<HostnameAttribution>,
    bytes: &[u8],
) -> NormalizedEvent {
    match parse_tls_client_hello_sni(bytes) {
        Ok(ParsedClientHello { sni, ech_present }) => {
            if ech_present {
                return NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
                    sandbox_id,
                    frontend,
                    reason: UnsupportedReason::HiddenSniOrEch,
                    safe_metadata: Some("ECH extension present".to_string()),
                });
            }
            let mismatch = match (&sni, &dns_hostname) {
                (Some(sni), Some(dns)) if sni == dns.hostname() => HostnameMismatch::Matches,
                (Some(_), Some(_)) => HostnameMismatch::Mismatch,
                (None, _) | (_, None) => HostnameMismatch::Unavailable,
            };
            NormalizedEvent::TlsClientHello(TlsClientHello {
                sandbox_id,
                frontend,
                destination,
                sni,
                dns_hostname,
                mismatch,
            })
        }
        Err(error) => NormalizedEvent::UnsupportedNetworkEvent(UnsupportedNetworkEvent {
            sandbox_id,
            frontend,
            reason: UnsupportedReason::MalformedPacket,
            safe_metadata: Some(error.to_string()),
        }),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedClientHello {
    pub sni: Option<Hostname>,
    pub ech_present: bool,
}

/// Extract SNI and ECH presence from one TLS ClientHello record.
pub fn parse_tls_client_hello_sni(bytes: &[u8]) -> Result<ParsedClientHello, InspectError> {
    if bytes.len() < 5 {
        return Err(InspectError::Malformed("short TLS record"));
    }
    if bytes[0] != TLS_HANDSHAKE {
        return Err(InspectError::Malformed("not a TLS handshake record"));
    }
    let record_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if bytes.len() < 5 + record_len || record_len < 4 {
        return Err(InspectError::Malformed("bad TLS record length"));
    }
    let body = &bytes[5..5 + record_len];
    if body[0] != TLS_CLIENT_HELLO {
        return Err(InspectError::Malformed("not a ClientHello"));
    }
    let handshake_len = read_u24(&body[1..4]);
    if body.len() < 4 + handshake_len {
        return Err(InspectError::Malformed("bad ClientHello length"));
    }
    let hello = &body[4..4 + handshake_len];
    let mut cursor = Cursor::new(hello);
    cursor.take(2)?; // legacy_version
    cursor.take(32)?; // random
    let session_id_len = cursor.take_u8()? as usize;
    cursor.take(session_id_len)?;
    let cipher_suites_len = cursor.take_u16()? as usize;
    cursor.take(cipher_suites_len)?;
    let compression_len = cursor.take_u8()? as usize;
    cursor.take(compression_len)?;
    if cursor.remaining() == 0 {
        return Ok(ParsedClientHello {
            sni: None,
            ech_present: false,
        });
    }
    let extensions_len = cursor.take_u16()? as usize;
    let extensions = cursor.take(extensions_len)?;
    parse_extensions(extensions)
}

fn parse_extensions(mut extensions: &[u8]) -> Result<ParsedClientHello, InspectError> {
    let mut sni = None;
    let mut ech_present = false;
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return Err(InspectError::Malformed("short TLS extension"));
        }
        let extension_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let extension_len = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
        extensions = &extensions[4..];
        if extensions.len() < extension_len {
            return Err(InspectError::Malformed("bad TLS extension length"));
        }
        let data = &extensions[..extension_len];
        extensions = &extensions[extension_len..];

        match extension_type {
            EXT_SERVER_NAME => sni = parse_sni_extension(data)?,
            EXT_ENCRYPTED_CLIENT_HELLO => ech_present = true,
            _ => {}
        }
    }
    Ok(ParsedClientHello { sni, ech_present })
}

fn parse_sni_extension(data: &[u8]) -> Result<Option<Hostname>, InspectError> {
    if data.len() < 2 {
        return Err(InspectError::Malformed("short SNI extension"));
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if data.len() < 2 + list_len {
        return Err(InspectError::Malformed("bad SNI list length"));
    }
    let mut names = &data[2..2 + list_len];
    while !names.is_empty() {
        if names.len() < 3 {
            return Err(InspectError::Malformed("short SNI name"));
        }
        let name_type = names[0];
        let name_len = usize::from(u16::from_be_bytes([names[1], names[2]]));
        names = &names[3..];
        if names.len() < name_len {
            return Err(InspectError::Malformed("bad SNI name length"));
        }
        let value = &names[..name_len];
        names = &names[name_len..];
        if name_type == 0 {
            let host =
                std::str::from_utf8(value).map_err(|_| InspectError::Malformed("SNI utf8"))?;
            return Hostname::new(host)
                .map(Some)
                .map_err(|_| InspectError::Malformed("invalid SNI hostname"));
        }
    }
    Ok(None)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], InspectError> {
        if self.remaining() < len {
            return Err(InspectError::Malformed("unexpected end of ClientHello"));
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn take_u8(&mut self) -> Result<u8, InspectError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, InspectError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

/// Heuristic QUIC classification: UDP/443 plus a QUIC-looking first byte.
pub fn is_quic_candidate_payload(destination: SocketAddr, payload: &[u8]) -> bool {
    destination.port() == 443 && payload.first().is_some_and(|byte| byte & 0xc0 != 0)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InspectError {
    Malformed(&'static str),
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed TLS ClientHello: {reason}"),
        }
    }
}

impl std::error::Error for InspectError {}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        HostnameAttributionSource, HostnameConfidence, Protocol, UnsupportedReason,
    };

    fn sandbox() -> SandboxId {
        SandboxId::new("s1").unwrap()
    }

    #[test]
    fn malformed_tls_corpus_fails_closed_without_panics() {
        let corpus: &[&[u8]] = &[
            b"",
            &[TLS_HANDSHAKE],
            &[TLS_HANDSHAKE, 0x03, 0x03, 0xff, 0xff],
            &[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0],
        ];

        for bytes in corpus {
            let event = inspect_tls_client_hello(
                sandbox(),
                FrontendKind::Tun,
                "203.0.113.10:443".parse().unwrap(),
                None,
                bytes,
            );
            assert!(matches!(event, NormalizedEvent::UnsupportedNetworkEvent(_)));
        }
    }

    #[test]
    fn transparent_http_inspection_emits_normalized_request() {
        let event = inspect_plaintext_http_request(
            sandbox(),
            FrontendKind::Tun,
            b"GET /allowed/path HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n",
        );

        let NormalizedEvent::HttpRequest(request) = event else {
            panic!("expected HTTP request");
        };
        assert_eq!(request.frontend, FrontendKind::Tun);
        assert_eq!(request.host.hostname().unwrap().as_str(), "example.com");
        assert_eq!(request.port, 8080);
        assert_eq!(request.path_query, "/allowed/path");
    }

    #[test]
    fn malformed_transparent_http_fails_closed() {
        let event =
            inspect_plaintext_http_request(sandbox(), FrontendKind::Tun, b"GET / HTTP/1.1\r\n\r\n");
        let NormalizedEvent::UnsupportedNetworkEvent(event) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(event.reason, UnsupportedReason::MalformedPacket);
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello(Some("Example.COM"), false);
        let parsed = parse_tls_client_hello_sni(&hello).unwrap();
        assert_eq!(parsed.sni.unwrap().as_str(), "example.com");
        assert!(!parsed.ech_present);
    }

    #[test]
    fn emits_mismatch_when_dns_and_sni_disagree() {
        let dns = HostnameAttribution::new(
            Hostname::new("other.example").unwrap(),
            HostnameAttributionSource::BrokerDns,
            HostnameConfidence::Medium,
        );
        let event = inspect_tls_client_hello(
            sandbox(),
            FrontendKind::Tun,
            "203.0.113.10:443".parse().unwrap(),
            Some(dns),
            &client_hello(Some("example.com"), false),
        );

        let NormalizedEvent::TlsClientHello(tls) = event else {
            panic!("expected TLS event");
        };
        assert_eq!(tls.mismatch, HostnameMismatch::Mismatch);
    }

    #[test]
    fn ech_extension_fails_closed() {
        let event = inspect_tls_client_hello(
            sandbox(),
            FrontendKind::Tun,
            "203.0.113.10:443".parse().unwrap(),
            None,
            &client_hello(Some("example.com"), true),
        );

        assert_eq!(event.protocol(), Protocol::Unsupported);
        let NormalizedEvent::UnsupportedNetworkEvent(unsupported) = event else {
            panic!("expected unsupported event");
        };
        assert_eq!(unsupported.reason, UnsupportedReason::HiddenSniOrEch);
    }

    #[test]
    fn detects_quic_candidate_payload() {
        assert!(is_quic_candidate_payload(
            "203.0.113.10:443".parse().unwrap(),
            &[0xc3]
        ));
        assert!(!is_quic_candidate_payload(
            "203.0.113.10:80".parse().unwrap(),
            &[0xc3]
        ));
    }

    fn client_hello(host: Option<&str>, ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(host) = host {
            let host = host.as_bytes();
            let mut sni_data = Vec::new();
            let list_len = 1 + 2 + host.len();
            sni_data.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni_data.push(0);
            sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_data.extend_from_slice(host);
            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_data);
        }
        if ech {
            extensions.extend_from_slice(&EXT_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
            extensions.extend_from_slice(&0_u16.to_be_bytes());
        }

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0); // session id len
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_CLIENT_HELLO);
        let len = hello.len();
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
