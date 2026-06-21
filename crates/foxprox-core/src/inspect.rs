use crate::types::{
    normalize_hostname, AttributionConfidence, AttributionSource, HostnameAttribution,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestMetadata {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path_query: String,
    pub attribution: HostnameAttribution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpParseError {
    NotUtf8,
    MissingRequestLine,
    MissingHost,
    MalformedRequestLine,
}

pub fn parse_plaintext_http_request(bytes: &[u8]) -> Result<HttpRequestMetadata, HttpParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpParseError::NotUtf8)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(HttpParseError::MissingRequestLine)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let path_query = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let _version = parts.next().ok_or(HttpParseError::MalformedRequestLine)?;
    let host_header = lines
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("host")
                    .then(|| value.trim().to_string())
            })
        })
        .ok_or(HttpParseError::MissingHost)?;
    let (host, port) = split_host_port(&host_header, 80);
    let host = normalize_hostname(&host);
    Ok(HttpRequestMetadata {
        method: method.to_ascii_uppercase(),
        host: host.clone(),
        port,
        path_query: path_query.to_string(),
        attribution: HostnameAttribution::new(
            host,
            AttributionSource::PlaintextHttpHost,
            AttributionConfidence::High,
        ),
    })
}

pub fn parse_connect_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port) = split_host_port(authority, 443);
    (!host.trim().is_empty()).then(|| (normalize_hostname(&host), port))
}

fn split_host_port(value: &str, default_port: u16) -> (String, u16) {
    if let Some(stripped) = value.strip_prefix('[') {
        if let Some((host, rest)) = stripped.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (value.to_string(), default_port)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsClientHelloError {
    NotTlsHandshake,
    NotClientHello,
    Truncated,
    MissingSni,
    Malformed,
}

pub fn parse_tls_client_hello_sni(
    bytes: &[u8],
) -> Result<HostnameAttribution, TlsClientHelloError> {
    if bytes.len() < 5 || bytes[0] != 22 {
        return Err(TlsClientHelloError::NotTlsHandshake);
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return Err(TlsClientHelloError::Truncated);
    }
    let body = &bytes[5..5 + record_len];
    if body.len() < 4 || body[0] != 1 {
        return Err(TlsClientHelloError::NotClientHello);
    }
    let handshake_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + handshake_len {
        return Err(TlsClientHelloError::Truncated);
    }
    let hello = &body[4..4 + handshake_len];
    let mut cursor = 0usize;
    take(hello, &mut cursor, 2)?; // legacy_version
    take(hello, &mut cursor, 32)?; // random
    let session_len = *take(hello, &mut cursor, 1)?
        .first()
        .ok_or(TlsClientHelloError::Malformed)? as usize;
    take(hello, &mut cursor, session_len)?;
    let cipher_len = read_u16(hello, &mut cursor)? as usize;
    take(hello, &mut cursor, cipher_len)?;
    let compression_len = *take(hello, &mut cursor, 1)?
        .first()
        .ok_or(TlsClientHelloError::Malformed)? as usize;
    take(hello, &mut cursor, compression_len)?;
    let extensions_len = read_u16(hello, &mut cursor)? as usize;
    let extensions = take(hello, &mut cursor, extensions_len)?;

    let mut ext_cursor = 0usize;
    while ext_cursor < extensions.len() {
        let ext_type = read_u16(extensions, &mut ext_cursor)?;
        let ext_len = read_u16(extensions, &mut ext_cursor)? as usize;
        let ext = take(extensions, &mut ext_cursor, ext_len)?;
        if ext_type == 0 {
            return parse_sni_extension(ext).map(|hostname| {
                HostnameAttribution::new(
                    hostname,
                    AttributionSource::TlsSni,
                    AttributionConfidence::High,
                )
            });
        }
    }
    Err(TlsClientHelloError::MissingSni)
}

fn parse_sni_extension(ext: &[u8]) -> Result<String, TlsClientHelloError> {
    let mut cursor = 0usize;
    let list_len = read_u16(ext, &mut cursor)? as usize;
    let list = take(ext, &mut cursor, list_len)?;
    let mut list_cursor = 0usize;
    while list_cursor < list.len() {
        let name_type = *take(list, &mut list_cursor, 1)?
            .first()
            .ok_or(TlsClientHelloError::Malformed)?;
        let name_len = read_u16(list, &mut list_cursor)? as usize;
        let name = take(list, &mut list_cursor, name_len)?;
        if name_type == 0 {
            let hostname = std::str::from_utf8(name).map_err(|_| TlsClientHelloError::Malformed)?;
            return Ok(normalize_hostname(hostname));
        }
    }
    Err(TlsClientHelloError::MissingSni)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, TlsClientHelloError> {
    let slice = take(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], TlsClientHelloError> {
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(TlsClientHelloError::Truncated);
    }
    let start = *cursor;
    *cursor += len;
    Ok(&bytes[start..start + len])
}

pub fn is_quic_candidate(destination_port: u16, payload: &[u8]) -> bool {
    destination_port == 443 || payload.first().is_some_and(|first| first & 0x80 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn plaintext_http_parser_extracts_host_method_and_path() {
        let meta = parse_plaintext_http_request(
            b"GET /v1/resource?x=1 HTTP/1.1\r\nHost: API.Example.test:8080\r\nUser-Agent: t\r\n\r\n",
        )
        .unwrap();
        assert_eq!(meta.method, "GET");
        assert_eq!(meta.host, "api.example.test");
        assert_eq!(meta.port, 8080);
        assert_eq!(meta.path_query, "/v1/resource?x=1");
        assert_eq!(
            meta.attribution.source,
            AttributionSource::PlaintextHttpHost
        );
        assert_eq!(meta.attribution.confidence, AttributionConfidence::High);
    }

    #[test]
    fn connect_authority_defaults_to_https_port() {
        assert_eq!(
            parse_connect_authority("Example.COM").unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn tls_client_hello_parser_extracts_sni() {
        let hello = test_client_hello("Example.COM");
        let attribution = parse_tls_client_hello_sni(&hello).unwrap();
        assert_eq!(attribution.hostname, "example.com");
        assert_eq!(attribution.source, AttributionSource::TlsSni);
        assert_eq!(attribution.confidence, AttributionConfidence::High);
    }

    #[test]
    fn quic_candidate_detects_udp_443_and_long_header() {
        assert!(is_quic_candidate(443, b""));
        assert!(is_quic_candidate(4443, &[0b1100_0000]));
        assert!(!is_quic_candidate(4443, &[0b0100_0000]));
    }

    fn test_client_hello(hostname: &str) -> Vec<u8> {
        let mut sni_ext = Vec::new();
        let hostname_bytes = hostname.as_bytes();
        let server_name_len = 1 + 2 + hostname_bytes.len();
        sni_ext.extend_from_slice(&(server_name_len as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0); // session id len
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.push(1);
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.extend_from_slice(&[
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
