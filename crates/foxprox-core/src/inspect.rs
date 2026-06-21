use crate::origin::{parse_http_origin, split_host_port, OriginError};
use crate::types::{Hostname, HttpRequestMetadata, Scheme};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InspectError {
    NeedMoreData,
    MalformedHttp,
    MissingHostHeader,
    InvalidOrigin(OriginError),
    MalformedTls,
    NotClientHello,
    MissingSni,
    InvalidHostname,
}

pub fn parse_http_request(bytes: &[u8]) -> Result<HttpRequestMetadata, InspectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InspectError::MalformedHttp)?;
    let header_end = text.find("\r\n\r\n").ok_or(InspectError::NeedMoreData)?;
    let headers = &text[..header_end];
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().ok_or(InspectError::MalformedHttp)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(InspectError::MalformedHttp)?;
    let target = parts.next().ok_or(InspectError::MalformedHttp)?;
    let version = parts.next().ok_or(InspectError::MalformedHttp)?;
    if parts.next().is_some() || !version.starts_with("HTTP/") || method.is_empty() {
        return Err(InspectError::MalformedHttp);
    }

    if target.starts_with("http://") || target.starts_with("https://") {
        let origin = parse_http_origin(target).map_err(InspectError::InvalidOrigin)?;
        let path_query = absolute_target_path_query(target);
        return Ok(HttpRequestMetadata {
            method: method.to_ascii_uppercase(),
            host: origin.host,
            port: origin.port,
            path_query,
            scheme: origin.scheme,
        });
    }

    if !target.starts_with('/') && target != "*" {
        return Err(InspectError::MalformedHttp);
    }

    let host_value = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .ok_or(InspectError::MissingHostHeader)?;
    let (host, port) =
        split_host_port(host_value, Some(80)).map_err(InspectError::InvalidOrigin)?;
    Ok(HttpRequestMetadata {
        method: method.to_ascii_uppercase(),
        host,
        port,
        path_query: target.to_string(),
        scheme: Scheme::Http,
    })
}

fn absolute_target_path_query(target: &str) -> String {
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    match without_scheme.find('/') {
        Some(index) => without_scheme[index..].to_string(),
        None => "/".to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsClientHello {
    pub sni: Hostname,
}

pub fn parse_tls_client_hello_sni(bytes: &[u8]) -> Result<TlsClientHello, InspectError> {
    // TLS record header: content type, legacy version, length.
    if bytes.len() < 5 {
        return Err(InspectError::NeedMoreData);
    }
    if bytes[0] != 22 {
        return Err(InspectError::NotClientHello);
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return Err(InspectError::NeedMoreData);
    }
    let record = &bytes[5..5 + record_len];
    if record.len() < 4 || record[0] != 1 {
        return Err(InspectError::NotClientHello);
    }
    let handshake_len = read_u24(&record[1..4])?;
    if record.len() < 4 + handshake_len {
        return Err(InspectError::NeedMoreData);
    }
    let body = &record[4..4 + handshake_len];
    let mut cursor = Cursor::new(body);
    cursor.take(2)?; // legacy_version
    cursor.take(32)?; // random
    let session_id_len = cursor.read_u8()? as usize;
    cursor.take(session_id_len)?;
    let cipher_len = cursor.read_u16()? as usize;
    if cipher_len == 0 || cipher_len % 2 != 0 {
        return Err(InspectError::MalformedTls);
    }
    cursor.take(cipher_len)?;
    let compression_len = cursor.read_u8()? as usize;
    cursor.take(compression_len)?;
    if cursor.remaining() == 0 {
        return Err(InspectError::MissingSni);
    }
    let extensions_len = cursor.read_u16()? as usize;
    let extensions = cursor.take(extensions_len)?;
    parse_sni_extension_block(extensions)
}

fn parse_sni_extension_block(mut extensions: &[u8]) -> Result<TlsClientHello, InspectError> {
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return Err(InspectError::MalformedTls);
        }
        let extension_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let extension_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        extensions = &extensions[4..];
        if extensions.len() < extension_len {
            return Err(InspectError::MalformedTls);
        }
        let extension_data = &extensions[..extension_len];
        extensions = &extensions[extension_len..];
        if extension_type == 0 {
            return parse_sni_extension(extension_data);
        }
    }
    Err(InspectError::MissingSni)
}

fn parse_sni_extension(data: &[u8]) -> Result<TlsClientHello, InspectError> {
    if data.len() < 2 {
        return Err(InspectError::MalformedTls);
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + list_len {
        return Err(InspectError::MalformedTls);
    }
    let mut names = &data[2..];
    while !names.is_empty() {
        if names.len() < 3 {
            return Err(InspectError::MalformedTls);
        }
        let name_type = names[0];
        let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
        names = &names[3..];
        if names.len() < name_len {
            return Err(InspectError::MalformedTls);
        }
        let name = &names[..name_len];
        names = &names[name_len..];
        if name_type == 0 {
            let hostname = std::str::from_utf8(name).map_err(|_| InspectError::InvalidHostname)?;
            let hostname =
                Hostname::normalize(hostname).map_err(|_| InspectError::InvalidHostname)?;
            return Ok(TlsClientHello { sni: hostname });
        }
    }
    Err(InspectError::MissingSni)
}

fn read_u24(bytes: &[u8]) -> Result<usize, InspectError> {
    if bytes.len() < 3 {
        return Err(InspectError::MalformedTls);
    }
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
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
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], InspectError> {
        if self.remaining() < len {
            return Err(InspectError::MalformedTls);
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..self.offset])
    }

    fn read_u8(&mut self) -> Result<u8, InspectError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, InspectError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_plaintext_http_request() {
        let request = b"GET /path?q=1 HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n";
        let parsed = parse_http_request(request).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.host.as_str(), "example.com");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path_query, "/path?q=1");
    }

    #[test]
    fn incomplete_http_request_needs_more_data() {
        assert_eq!(
            parse_http_request(b"GET / HTTP/1.1\r\n"),
            Err(InspectError::NeedMoreData)
        );
    }

    #[test]
    fn parses_tls_client_hello_sni() {
        let hello = build_client_hello("Example.com");
        let parsed = parse_tls_client_hello_sni(&hello).unwrap();
        assert_eq!(parsed.sni.as_str(), "example.com");
    }

    #[test]
    fn tls_without_sni_is_explicitly_reported() {
        let hello = build_client_hello_without_extensions();
        assert_eq!(
            parse_tls_client_hello_sni(&hello),
            Err(InspectError::MissingSni)
        );
    }

    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        wrap_client_hello_body(&body)
    }

    fn build_client_hello_without_extensions() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        wrap_client_hello_body(&body)
    }

    fn wrap_client_hello_body(body: &[u8]) -> Vec<u8> {
        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
