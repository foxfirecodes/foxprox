//! Dependency-free transparent traffic inspection helpers.
//!
//! These parsers extract only the metadata needed for alpha policy decisions.
//! Malformed or unsupported inputs return structured errors so callers can fail
//! closed instead of guessing.

use crate::event::{
    Attribution, AttributionConfidence, AttributionSource, Hostname, HttpMethod, Origin, Protocol,
};

const TLS_HANDSHAKE_RECORD: u8 = 22;
const TLS_CLIENT_HELLO: u8 = 1;
const TLS_EXT_SERVER_NAME: u16 = 0;
const TLS_EXT_ECH: u16 = 0xfe0d;

/// Transparent plaintext HTTP request metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpInspection {
    /// HTTP method.
    pub method: HttpMethod,
    /// Parsed HTTP origin from the Host header.
    pub origin: Origin,
    /// Path and optional query string from the request target.
    pub path_and_query: String,
    /// High-confidence Host-header attribution.
    pub attribution: Attribution,
}

/// TLS ClientHello metadata relevant to policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsClientHelloInspection {
    /// Visible Server Name Indication, when present.
    pub sni: Option<Hostname>,
    /// Whether an Encrypted ClientHello extension was present.
    pub ech_present: bool,
}

impl TlsClientHelloInspection {
    /// Returns true when SNI is hidden or absent.
    pub const fn hidden_sni(&self) -> bool {
        self.sni.is_none() || self.ech_present
    }

    /// Builds high-confidence TLS SNI attribution when SNI is visible.
    pub fn attribution(&self) -> Attribution {
        match self.sni.clone() {
            Some(hostname) => Attribution {
                hostname: Some(hostname),
                source: AttributionSource::TlsSni,
                confidence: AttributionConfidence::High,
            },
            None => Attribution::ip_only(),
        }
    }

    /// Compares visible SNI with DNS attribution.
    pub fn mismatches_dns(&self, dns_hostname: Option<&Hostname>) -> bool {
        matches!((self.sni.as_ref(), dns_hostname), (Some(sni), Some(dns)) if sni != dns)
    }
}

/// Transparent inspection parse error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionError {
    /// Input was incomplete.
    Truncated,
    /// Input was malformed.
    Malformed(String),
    /// Input is not the expected protocol.
    Unsupported(String),
}

/// Parses a plaintext HTTP/1 request head.
pub fn parse_http_request_head(
    input: &[u8],
    default_port: u16,
) -> Result<HttpInspection, InspectionError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| InspectionError::Malformed("HTTP head is not UTF-8".to_string()))?;
    let head_end = text.find("\r\n\r\n").ok_or(InspectionError::Truncated)?;
    let mut lines = text[..head_end].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| InspectionError::Malformed("missing request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = HttpMethod::parse(parts.next().unwrap_or_default())
        .map_err(|error| InspectionError::Malformed(error.to_string()))?;
    let target = parts
        .next()
        .ok_or_else(|| InspectionError::Malformed("missing request target".to_string()))?;
    let version = parts
        .next()
        .ok_or_else(|| InspectionError::Malformed("missing HTTP version".to_string()))?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(InspectionError::Malformed(
            "invalid request line".to_string(),
        ));
    }

    let mut host_header = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            host_header = Some(value.trim());
            break;
        }
    }
    let host_header =
        host_header.ok_or_else(|| InspectionError::Malformed("missing Host header".to_string()))?;
    let (host, port) = parse_host_port(host_header, default_port)?;
    let origin = Origin {
        scheme: "http".to_string(),
        host: host.clone(),
        port,
    };
    let attribution = Attribution {
        hostname: Some(host),
        source: AttributionSource::HttpHostHeader,
        confidence: AttributionConfidence::High,
    };
    Ok(HttpInspection {
        method,
        origin,
        path_and_query: http_path_and_query(target),
        attribution,
    })
}

/// Parses visible SNI and ECH presence from a TLS ClientHello record.
pub fn parse_tls_client_hello(input: &[u8]) -> Result<TlsClientHelloInspection, InspectionError> {
    if input.len() < 9 {
        return Err(InspectionError::Truncated);
    }
    if input[0] != TLS_HANDSHAKE_RECORD {
        return Err(InspectionError::Unsupported(
            "not a TLS handshake record".to_string(),
        ));
    }
    let record_len = read_u16(input, 3)? as usize;
    if input.len() < 5 + record_len {
        return Err(InspectionError::Truncated);
    }
    if input[5] != TLS_CLIENT_HELLO {
        return Err(InspectionError::Unsupported(
            "not a TLS ClientHello".to_string(),
        ));
    }
    let handshake_len = read_u24(input, 6)?;
    if handshake_len + 9 > input.len() {
        return Err(InspectionError::Truncated);
    }

    let mut offset = 9 + 2 + 32;
    let session_len = *input.get(offset).ok_or(InspectionError::Truncated)? as usize;
    offset += 1 + session_len;
    let cipher_len = read_u16(input, offset)? as usize;
    offset += 2 + cipher_len;
    let compression_len = *input.get(offset).ok_or(InspectionError::Truncated)? as usize;
    offset += 1 + compression_len;
    if offset == 5 + record_len {
        return Ok(TlsClientHelloInspection {
            sni: None,
            ech_present: false,
        });
    }
    let extensions_len = read_u16(input, offset)? as usize;
    offset += 2;
    let extensions_end = offset
        .checked_add(extensions_len)
        .ok_or(InspectionError::Truncated)?;
    if extensions_end > input.len() {
        return Err(InspectionError::Truncated);
    }

    let mut sni = None;
    let mut ech_present = false;
    while offset + 4 <= extensions_end {
        let ext_type = read_u16(input, offset)?;
        let ext_len = read_u16(input, offset + 2)? as usize;
        offset += 4;
        let ext_end = offset
            .checked_add(ext_len)
            .ok_or(InspectionError::Truncated)?;
        if ext_end > extensions_end {
            return Err(InspectionError::Truncated);
        }
        if ext_type == TLS_EXT_SERVER_NAME {
            sni = parse_sni_extension(&input[offset..ext_end])?;
        } else if ext_type == TLS_EXT_ECH {
            ech_present = true;
        }
        offset = ext_end;
    }
    Ok(TlsClientHelloInspection { sni, ech_present })
}

/// Classifies UDP traffic as a QUIC candidate when it targets the QUIC default port.
pub const fn classify_udp_candidate(destination_port: u16) -> Protocol {
    if destination_port == 443 {
        Protocol::Quic
    } else {
        Protocol::Udp
    }
}

fn parse_sni_extension(input: &[u8]) -> Result<Option<Hostname>, InspectionError> {
    if input.len() < 2 {
        return Err(InspectionError::Truncated);
    }
    let list_len = read_u16(input, 0)? as usize;
    if input.len() < 2 + list_len {
        return Err(InspectionError::Truncated);
    }
    let mut offset = 2;
    let end = 2 + list_len;
    while offset + 3 <= end {
        let name_type = input[offset];
        let name_len = read_u16(input, offset + 1)? as usize;
        offset += 3;
        let name_end = offset
            .checked_add(name_len)
            .ok_or(InspectionError::Truncated)?;
        if name_end > end {
            return Err(InspectionError::Truncated);
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&input[offset..name_end])
                .map_err(|_| InspectionError::Malformed("SNI is not UTF-8".to_string()))?;
            return Hostname::parse(host)
                .map(Some)
                .map_err(|error| InspectionError::Malformed(error.to_string()));
        }
        offset = name_end;
    }
    Ok(None)
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(Hostname, u16), InspectionError> {
    let value = value.trim();
    if value.starts_with('[') {
        return Err(InspectionError::Unsupported(
            "IPv6 literal Host is not hostname attribution".to_string(),
        ));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let parsed_port = port
                .parse()
                .map_err(|_| InspectionError::Malformed("invalid Host port".to_string()))?;
            (host, parsed_port)
        }
        _ => (value, default_port),
    };
    let host =
        Hostname::parse(host).map_err(|error| InspectionError::Malformed(error.to_string()))?;
    Ok((host, port))
}

fn http_path_and_query(target: &str) -> String {
    if let Some(after_scheme) = target.strip_prefix("http://") {
        match after_scheme.find('/') {
            Some(index) => after_scheme[index..].to_string(),
            None => "/".to_string(),
        }
    } else if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, InspectionError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(InspectionError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u24(input: &[u8], offset: usize) -> Result<usize, InspectionError> {
    let bytes = input
        .get(offset..offset + 3)
        .ok_or(InspectionError::Truncated)?;
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_host_method_and_path() {
        let request = b"get /hello?x=1 HTTP/1.1\r\nHost: WWW.Example.COM:8080\r\n\r\n";
        let parsed = parse_http_request_head(request, 80).unwrap();
        assert_eq!(parsed.method.as_str(), "GET");
        assert_eq!(parsed.origin.host.as_str(), "www.example.com");
        assert_eq!(parsed.origin.port, 8080);
        assert_eq!(parsed.path_and_query, "/hello?x=1");
        assert_eq!(parsed.attribution.source, AttributionSource::HttpHostHeader);
    }

    #[test]
    fn rejects_http_without_host() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
        assert!(matches!(
            parse_http_request_head(request, 80),
            Err(InspectionError::Malformed(_))
        ));
    }

    #[test]
    fn parses_tls_sni_and_ech_presence() {
        let packet = tls_client_hello_with_extensions(&[
            sni_extension("www.example.com"),
            extension(TLS_EXT_ECH, &[0, 1, 2]),
        ]);
        let parsed = parse_tls_client_hello(&packet).unwrap();
        assert_eq!(parsed.sni.as_ref().unwrap().as_str(), "www.example.com");
        assert!(parsed.ech_present);
        assert!(parsed.hidden_sni());
        assert_eq!(parsed.attribution().source, AttributionSource::TlsSni);
    }

    #[test]
    fn tls_mismatch_compares_visible_sni_to_dns() {
        let packet = tls_client_hello_with_extensions(&[sni_extension("a.example")]);
        let parsed = parse_tls_client_hello(&packet).unwrap();
        let dns = Hostname::parse("b.example").unwrap();
        assert!(parsed.mismatches_dns(Some(&dns)));
    }

    #[test]
    fn quic_candidate_uses_udp_443() {
        assert_eq!(classify_udp_candidate(443), Protocol::Quic);
        assert_eq!(classify_udp_candidate(53), Protocol::Udp);
    }

    #[test]
    fn fuzz_smoke_http_and_tls_parsers_are_total() {
        let seeds: &[&[u8]] = &[
            b"",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"\x16\x03\x03\x00\x04\x01\x00\x00\x00",
            &tls_client_hello_with_extensions(&[sni_extension("www.example.com")]),
        ];
        for seed in seeds {
            for input in mutated_inputs(seed) {
                let _ = parse_http_request_head(&input, 80);
                let _ = parse_tls_client_hello(&input);
            }
        }
    }

    fn mutated_inputs(seed: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        out.push(seed.to_vec());
        for len in 0..=seed.len().min(16) {
            out.push(seed[..len].to_vec());
        }
        for index in 0..seed.len().min(32) {
            let mut mutated = seed.to_vec();
            mutated[index] ^= 0xff;
            out.push(mutated);
        }
        let mut generated = Vec::new();
        let mut state = seed.len() as u32 ^ 0xa5a5_5a5a;
        for _ in 0..64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            generated.push((state >> 24) as u8);
        }
        out.push(generated);
        out
    }

    fn sni_extension(hostname: &str) -> Vec<u8> {
        let mut list = Vec::new();
        list.push(0);
        list.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        list.extend_from_slice(hostname.as_bytes());
        let mut payload = Vec::new();
        payload.extend_from_slice(&(list.len() as u16).to_be_bytes());
        payload.extend_from_slice(&list);
        extension(TLS_EXT_SERVER_NAME, &payload)
    }

    fn extension(ext_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn tls_client_hello_with_extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut ext_bytes = Vec::new();
        for extension in extensions {
            ext_bytes.extend_from_slice(extension);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        let mut packet = Vec::new();
        packet.push(TLS_HANDSHAKE_RECORD);
        packet.extend_from_slice(&[0x03, 0x03]);
        packet.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        packet.push(TLS_CLIENT_HELLO);
        packet.push(((body.len() >> 16) & 0xff) as u8);
        packet.push(((body.len() >> 8) & 0xff) as u8);
        packet.push((body.len() & 0xff) as u8);
        packet.extend_from_slice(&body);
        packet
    }
}
