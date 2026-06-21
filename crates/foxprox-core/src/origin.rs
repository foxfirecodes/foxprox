use crate::audit::{AttributionConfidence, AttributionSource};
use crate::dns::normalize_hostname;

/// Parsed plaintext HTTP request metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestMeta {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Parse the first plaintext HTTP request line and Host header.
pub fn parse_http_request(bytes: &[u8]) -> Result<HttpRequestMeta, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "HTTP request is not UTF-8".to_string())?;
    let header_end = text
        .find("\r\n\r\n")
        .or_else(|| text.find("\n\n"))
        .ok_or_else(|| "HTTP headers are incomplete".to_string())?;
    let headers = &text[..header_end];
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "HTTP request line missing".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "HTTP method missing".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "HTTP target missing".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "HTTP version missing".to_string())?;
    if !version.starts_with("HTTP/") {
        return Err("HTTP version missing".to_string());
    }
    if !method.chars().all(|c| c.is_ascii_uppercase()) {
        return Err("HTTP method must be uppercase token".to_string());
    }

    let mut host_header = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                host_header = Some(value.trim());
                break;
            }
        }
    }
    let host_header = host_header.ok_or_else(|| "HTTP Host header missing".to_string())?;
    let (host, port) = split_host_port(host_header, 80)?;
    let path = if target.starts_with("http://") || target.starts_with("https://") {
        absolute_uri_path(target).unwrap_or_else(|| "/".to_string())
    } else {
        target.to_string()
    };
    if !path.starts_with('/') {
        return Err("HTTP origin-form path must start with '/'".to_string());
    }
    Ok(HttpRequestMeta {
        method: method.to_string(),
        host: normalize_hostname(&host)?,
        port,
        path,
    })
}

/// Parsed CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

pub fn parse_connect_target(target: &str) -> Result<ConnectTarget, String> {
    let (host, port) = split_host_port(target, 443)?;
    Ok(ConnectTarget {
        host: normalize_hostname(&host)?,
        port,
    })
}

/// Parsed SOCKS5 TCP CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksConnectRequest {
    pub destination_host: String,
    pub destination_port: u16,
}

/// Parse a complete SOCKS5 request packet after greeting negotiation.
pub fn parse_socks5_connect_request(bytes: &[u8]) -> Result<SocksConnectRequest, String> {
    if bytes.len() < 7 {
        return Err("SOCKS5 request too short".to_string());
    }
    if bytes[0] != 0x05 {
        return Err("SOCKS version must be 5".to_string());
    }
    if bytes[1] != 0x01 {
        return Err("only SOCKS5 TCP CONNECT is supported".to_string());
    }
    if bytes[2] != 0x00 {
        return Err("SOCKS5 reserved byte must be zero".to_string());
    }
    let atyp = bytes[3];
    let (host, port_offset) = match atyp {
        0x01 => {
            if bytes.len() < 10 {
                return Err("SOCKS5 IPv4 request too short".to_string());
            }
            (
                format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]),
                8,
            )
        }
        0x03 => {
            let len = bytes[4] as usize;
            if bytes.len() < 5 + len + 2 {
                return Err("SOCKS5 domain request too short".to_string());
            }
            let host = std::str::from_utf8(&bytes[5..5 + len])
                .map_err(|_| "SOCKS5 domain is not UTF-8".to_string())?;
            (normalize_hostname(host)?, 5 + len)
        }
        0x04 => {
            if bytes.len() < 22 {
                return Err("SOCKS5 IPv6 request too short".to_string());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[4..20]);
            (std::net::Ipv6Addr::from(octets).to_string(), 20)
        }
        _ => return Err("unsupported SOCKS5 address type".to_string()),
    };
    if bytes.len() != port_offset + 2 {
        return Err("SOCKS5 request has trailing bytes".to_string());
    }
    let port = u16::from_be_bytes([bytes[port_offset], bytes[port_offset + 1]]);
    Ok(SocksConnectRequest {
        destination_host: host,
        destination_port: port,
    })
}

/// TLS ClientHello metadata visible without MITM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloMeta {
    pub sni: Option<String>,
    pub hidden_sni: bool,
    pub attribution_source: AttributionSource,
    pub attribution_confidence: AttributionConfidence,
}

/// Extract SNI from a single TLS ClientHello record. This intentionally accepts only complete,
/// well-formed records so malformed input fails closed in callers.
pub fn parse_tls_client_hello(bytes: &[u8]) -> Result<TlsClientHelloMeta, String> {
    if bytes.len() < 5 {
        return Err("TLS record too short".to_string());
    }
    if bytes[0] != 0x16 {
        return Err("TLS record is not a handshake".to_string());
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return Err("TLS record is incomplete".to_string());
    }
    let body = &bytes[5..5 + record_len];
    if body.len() < 4 || body[0] != 0x01 {
        return Err("TLS handshake is not ClientHello".to_string());
    }
    let handshake_len = read_u24(&body[1..4]);
    if body.len() < 4 + handshake_len {
        return Err("TLS ClientHello is incomplete".to_string());
    }
    let hello = &body[4..4 + handshake_len];
    let sni = parse_client_hello_sni(hello)?;
    Ok(TlsClientHelloMeta {
        hidden_sni: sni.is_none(),
        sni,
        attribution_source: AttributionSource::TlsSni,
        attribution_confidence: AttributionConfidence::High,
    })
}

fn parse_client_hello_sni(hello: &[u8]) -> Result<Option<String>, String> {
    let mut offset = 0usize;
    take(hello, &mut offset, 2)?; // legacy_version
    take(hello, &mut offset, 32)?; // random
    let session_id_len = *take(hello, &mut offset, 1)?.first().unwrap() as usize;
    take(hello, &mut offset, session_id_len)?;
    let cipher_len = read_u16(take(hello, &mut offset, 2)?) as usize;
    take(hello, &mut offset, cipher_len)?;
    let compression_len = *take(hello, &mut offset, 1)?.first().unwrap() as usize;
    take(hello, &mut offset, compression_len)?;
    if offset == hello.len() {
        return Ok(None);
    }
    let extensions_len = read_u16(take(hello, &mut offset, 2)?) as usize;
    let extensions = take(hello, &mut offset, extensions_len)?;
    let mut ext_offset = 0usize;
    while ext_offset < extensions.len() {
        let ext_type = read_u16(take(extensions, &mut ext_offset, 2)?);
        let ext_len = read_u16(take(extensions, &mut ext_offset, 2)?) as usize;
        let ext = take(extensions, &mut ext_offset, ext_len)?;
        if ext_type == 0x0000 {
            return parse_sni_extension(ext).map(Some);
        }
    }
    Ok(None)
}

fn parse_sni_extension(ext: &[u8]) -> Result<String, String> {
    let mut offset = 0usize;
    let list_len = read_u16(take(ext, &mut offset, 2)?) as usize;
    let list = take(ext, &mut offset, list_len)?;
    let mut list_offset = 0usize;
    while list_offset < list.len() {
        let name_type = *take(list, &mut list_offset, 1)?.first().unwrap();
        let name_len = read_u16(take(list, &mut list_offset, 2)?) as usize;
        let name = take(list, &mut list_offset, name_len)?;
        if name_type == 0 {
            let host =
                std::str::from_utf8(name).map_err(|_| "SNI hostname is not UTF-8".to_string())?;
            return normalize_hostname(host);
        }
    }
    Err("SNI extension contained no DNS hostname".to_string())
}

/// Best-effort QUIC candidate classification. This is classification, not decryption.
pub fn classify_quic_candidate(destination_port: u16, payload: &[u8]) -> bool {
    destination_port == 443 && payload.first().is_some_and(|first| first & 0x80 != 0)
}

fn split_host_port(input: &str, default_port: u16) -> Result<(String, u16), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("host is empty".to_string());
    }
    if let Some(stripped) = input.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| "IPv6 literal missing ']'".to_string())?;
        let port = if let Some(port) = rest.strip_prefix(':') {
            port.parse::<u16>()
                .map_err(|err| format!("invalid port: {err}"))?
        } else if rest.is_empty() {
            default_port
        } else {
            return Err("invalid bracketed host/port".to_string());
        };
        return Ok((host.to_string(), port));
    }
    if let Some((host, port)) = input.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Ok((
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|err| format!("invalid port: {err}"))?,
            ));
        }
    }
    Ok((input.to_string(), default_port))
}

fn absolute_uri_path(target: &str) -> Option<String> {
    let (_, after_scheme) = target.split_once("://")?;
    let slash = after_scheme.find('/')?;
    Some(after_scheme[slash..].to_string())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
    if bytes.len().saturating_sub(*offset) < len {
        return Err("buffer ended while parsing".to_string());
    }
    let start = *offset;
    *offset += len;
    Ok(&bytes[start..start + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plaintext_http_host_method_and_path() {
        let req = b"GET /allowed?q=1 HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n";
        let meta = parse_http_request(req).unwrap();
        assert_eq!(meta.method, "GET");
        assert_eq!(meta.host, "example.com");
        assert_eq!(meta.port, 8080);
        assert_eq!(meta.path, "/allowed?q=1");
    }

    #[test]
    fn malformed_http_fails_closed_for_callers() {
        assert!(parse_http_request(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn parses_connect_target() {
        let target = parse_connect_target("Example.COM:8443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn parses_socks5_domain_connect() {
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        let parsed = parse_socks5_connect_request(&req).unwrap();
        assert_eq!(parsed.destination_host, "example.com");
        assert_eq!(parsed.destination_port, 443);
    }

    #[test]
    fn rejects_socks5_udp_associate() {
        let req = [0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53];
        assert!(parse_socks5_connect_request(&req).is_err());
    }

    #[test]
    fn classifies_quic_long_header_on_udp_443() {
        assert!(classify_quic_candidate(443, &[0xc3, 0, 0, 0]));
        assert!(!classify_quic_candidate(443, &[0x43, 0, 0, 0]));
        assert!(!classify_quic_candidate(53, &[0xc3, 0, 0, 0]));
    }

    #[test]
    fn parses_tls_client_hello_sni_fixture() {
        let fixture = tls_client_hello_fixture("example.com");
        let meta = parse_tls_client_hello(&fixture).unwrap();
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert!(!meta.hidden_sni);
    }

    fn tls_client_hello_fixture(host: &str) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0); // session id len
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0); // null compression

        let host_bytes = host.as_bytes();
        let mut sni = Vec::new();
        let list_len = 1 + 2 + host_bytes.len();
        sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni.extend_from_slice(host_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = hello.len();
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
