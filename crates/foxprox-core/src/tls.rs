use std::net::IpAddr;

use crate::attribution::{HostAttribution, Hostname};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsClientHelloMetadata {
    pub sni: Option<Hostname>,
    pub attribution: Option<HostAttribution>,
    pub ech_present: bool,
}

impl TlsClientHelloMetadata {
    pub fn hidden_sni(&self) -> bool {
        self.sni.is_none() || self.ech_present
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TlsParseError {
    HeaderTooLarge,
    Incomplete,
    NotTlsHandshake,
    NotClientHello,
    InvalidLength,
    InvalidExtension,
    DuplicateSni,
    InvalidSni,
}

pub fn parse_tls_client_hello(
    bytes: &[u8],
    max_client_hello_bytes: usize,
) -> Result<TlsClientHelloMetadata, TlsParseError> {
    if bytes.len() < 5 {
        return Err(TlsParseError::Incomplete);
    }
    if bytes[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(TlsParseError::NotTlsHandshake);
    }

    let record_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let record_total = 5usize
        .checked_add(record_len)
        .ok_or(TlsParseError::InvalidLength)?;
    if record_total > max_client_hello_bytes {
        return Err(TlsParseError::HeaderTooLarge);
    }
    if bytes.len() < record_total {
        return Err(TlsParseError::Incomplete);
    }

    let record = &bytes[5..record_total];
    if record.len() < 4 {
        return Err(TlsParseError::InvalidLength);
    }
    if record[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(TlsParseError::NotClientHello);
    }
    let handshake_len = read_u24(&record[1..4]);
    if handshake_len != record.len() - 4 {
        return Err(TlsParseError::InvalidLength);
    }

    parse_client_hello_body(&record[4..])
}

fn parse_client_hello_body(body: &[u8]) -> Result<TlsClientHelloMetadata, TlsParseError> {
    let mut cursor = Cursor::new(body);
    cursor.take(2)?; // legacy_version
    cursor.take(32)?; // random

    let session_id_len = usize::from(cursor.take_u8()?);
    cursor.take(session_id_len)?;

    let cipher_suites_len = usize::from(cursor.take_u16()?);
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return Err(TlsParseError::InvalidLength);
    }
    cursor.take(cipher_suites_len)?;

    let compression_methods_len = usize::from(cursor.take_u8()?);
    if compression_methods_len == 0 {
        return Err(TlsParseError::InvalidLength);
    }
    cursor.take(compression_methods_len)?;

    if cursor.remaining() == 0 {
        return Ok(TlsClientHelloMetadata {
            sni: None,
            attribution: None,
            ech_present: false,
        });
    }

    let extensions_len = usize::from(cursor.take_u16()?);
    let extensions = cursor.take(extensions_len)?;
    if cursor.remaining() != 0 {
        return Err(TlsParseError::InvalidLength);
    }

    parse_extensions(extensions)
}

fn parse_extensions(extensions: &[u8]) -> Result<TlsClientHelloMetadata, TlsParseError> {
    let mut cursor = Cursor::new(extensions);
    let mut sni = None;
    let mut ech_present = false;

    while cursor.remaining() > 0 {
        let extension_type = cursor.take_u16()?;
        let extension_len = usize::from(cursor.take_u16()?);
        let extension_data = cursor.take(extension_len)?;

        match extension_type {
            EXT_SERVER_NAME => {
                let hostname = parse_sni_extension(extension_data)?;
                if sni.replace(hostname).is_some() {
                    return Err(TlsParseError::DuplicateSni);
                }
            }
            EXT_ENCRYPTED_CLIENT_HELLO => {
                ech_present = true;
            }
            _ => {}
        }
    }

    let attribution = sni.clone().map(HostAttribution::tls_sni);
    Ok(TlsClientHelloMetadata {
        sni,
        attribution,
        ech_present,
    })
}

fn parse_sni_extension(extension_data: &[u8]) -> Result<Hostname, TlsParseError> {
    let mut cursor = Cursor::new(extension_data);
    let list_len = usize::from(cursor.take_u16()?);
    let list = cursor.take(list_len)?;
    if cursor.remaining() != 0 {
        return Err(TlsParseError::InvalidExtension);
    }

    let mut list_cursor = Cursor::new(list);
    let mut hostname = None;
    while list_cursor.remaining() > 0 {
        let name_type = list_cursor.take_u8()?;
        let name_len = usize::from(list_cursor.take_u16()?);
        let name_bytes = list_cursor.take(name_len)?;
        if name_type == 0 {
            if hostname.is_some() {
                return Err(TlsParseError::DuplicateSni);
            }
            let name = std::str::from_utf8(name_bytes).map_err(|_| TlsParseError::InvalidSni)?;
            if !name.is_ascii() || name.parse::<IpAddr>().is_ok() {
                return Err(TlsParseError::InvalidSni);
            }
            hostname = Some(Hostname::parse(name).map_err(|_| TlsParseError::InvalidSni)?);
        }
    }

    hostname.ok_or(TlsParseError::InvalidExtension)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TlsParseError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(TlsParseError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(TlsParseError::InvalidLength);
        }
        let out = &self.bytes[self.position..end];
        self.position = end;
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, TlsParseError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, TlsParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{HostnameConfidence, HostnameSource};

    use super::*;

    fn sni_extension(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();
        let mut list = Vec::new();
        list.push(0);
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);

        let mut data = Vec::new();
        data.extend_from_slice(&(list.len() as u16).to_be_bytes());
        data.extend_from_slice(&list);

        extension(EXT_SERVER_NAME, &data)
    }

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&extension_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x002fu16.to_be_bytes());
        body.push(1);
        body.push(0);

        let extensions_len: usize = extensions.iter().map(Vec::len).sum();
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        for extension in extensions {
            body.extend_from_slice(extension);
        }

        let mut handshake = vec![
            TLS_HANDSHAKE_CLIENT_HELLO,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_normalized_tls_sni_as_high_confidence_attribution() {
        let parsed =
            parse_tls_client_hello(&client_hello(&[sni_extension("Example.COM")]), 4096).unwrap();

        assert_eq!(parsed.sni.as_ref().unwrap().as_str(), "example.com");
        assert!(!parsed.hidden_sni());
        let attribution = parsed.attribution.unwrap();
        assert_eq!(attribution.source, HostnameSource::TlsSni);
        assert_eq!(attribution.confidence, HostnameConfidence::High);
    }

    #[test]
    fn missing_sni_is_explicit_hidden_sni_metadata() {
        let parsed = parse_tls_client_hello(&client_hello(&[]), 4096).unwrap();
        assert_eq!(parsed.sni, None);
        assert_eq!(parsed.attribution, None);
        assert!(parsed.hidden_sni());
    }

    #[test]
    fn ech_extension_marks_hidden_sni_even_when_sni_exists() {
        let parsed = parse_tls_client_hello(
            &client_hello(&[
                sni_extension("example.com"),
                extension(EXT_ENCRYPTED_CLIENT_HELLO, &[]),
            ]),
            4096,
        )
        .unwrap();
        assert_eq!(parsed.sni.as_ref().unwrap().as_str(), "example.com");
        assert!(parsed.ech_present);
        assert!(parsed.hidden_sni());
    }

    #[test]
    fn rejects_duplicate_or_invalid_sni() {
        assert_eq!(
            parse_tls_client_hello(
                &client_hello(&[sni_extension("a.example"), sni_extension("b.example")]),
                4096,
            ),
            Err(TlsParseError::DuplicateSni)
        );
        assert_eq!(
            parse_tls_client_hello(&client_hello(&[sni_extension("bad_host.example")]), 4096),
            Err(TlsParseError::InvalidSni)
        );
        assert_eq!(
            parse_tls_client_hello(&client_hello(&[sni_extension("127.0.0.1")]), 4096),
            Err(TlsParseError::InvalidSni)
        );
    }

    #[test]
    fn rejects_non_tls_or_non_client_hello_records() {
        let mut not_handshake = client_hello(&[]);
        not_handshake[0] = 23;
        assert_eq!(
            parse_tls_client_hello(&not_handshake, 4096),
            Err(TlsParseError::NotTlsHandshake)
        );

        let mut server_hello = client_hello(&[]);
        server_hello[5] = 2;
        assert_eq!(
            parse_tls_client_hello(&server_hello, 4096),
            Err(TlsParseError::NotClientHello)
        );
    }

    #[test]
    fn rejects_truncated_invalid_or_oversized_client_hello() {
        assert_eq!(
            parse_tls_client_hello(&[22, 3], 4096),
            Err(TlsParseError::Incomplete)
        );

        let hello = client_hello(&[sni_extension("example.com")]);
        assert_eq!(
            parse_tls_client_hello(&hello[..hello.len() - 1], 4096),
            Err(TlsParseError::Incomplete)
        );
        assert_eq!(
            parse_tls_client_hello(&hello, hello.len() - 1),
            Err(TlsParseError::HeaderTooLarge)
        );

        let mut invalid_len = hello;
        invalid_len[6] ^= 0xff;
        assert_eq!(
            parse_tls_client_hello(&invalid_len, 4096),
            Err(TlsParseError::InvalidLength)
        );
    }
}
