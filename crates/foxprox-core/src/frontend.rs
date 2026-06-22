use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use crate::origin::HttpRequestMeta;

pub const HTTP_CONNECT_ESTABLISHED_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
pub const HTTP_FORBIDDEN_CLOSE_RESPONSE: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const SOCKS5_NO_AUTH_RESPONSE: &[u8] = &[0x05, 0x00];

pub fn read_http_headers(reader: &mut impl Read, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 256];
    while bytes.len() < max_bytes {
        let n = reader
            .read(&mut buf)
            .map_err(|err| format!("HTTP header read failed: {err}"))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if let Some(header_len) = http_header_end(&bytes) {
            bytes.truncate(header_len);
            return Ok(bytes);
        }
    }
    Err("HTTP headers were incomplete".to_string())
}

fn http_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|idx| idx + 2)
        })
}

pub fn build_http_origin_request(meta: &HttpRequestMeta) -> Vec<u8> {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        meta.method, meta.path, meta.host
    )
    .into_bytes()
}

pub fn parse_socks5_no_auth_greeting(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 2 {
        return Err("SOCKS5 greeting too short".to_string());
    }
    if bytes[0] != 0x05 {
        return Err("SOCKS greeting version must be 5".to_string());
    }
    let method_count = bytes[1] as usize;
    if bytes.len() != 2 + method_count {
        return Err("SOCKS5 greeting length mismatch".to_string());
    }
    if !bytes[2..].contains(&0x00) {
        return Err("SOCKS5 no-auth method is required".to_string());
    }
    Ok(())
}

pub fn socks5_connect_success_response(bound_addr: SocketAddr) -> [u8; 10] {
    let (octets, port) = match bound_addr.ip() {
        IpAddr::V4(addr) => (addr.octets(), bound_addr.port()),
        IpAddr::V6(_) => ([0, 0, 0, 0], 0),
    };
    let port = port.to_be_bytes();
    [
        0x05, 0x00, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], port[0], port[1],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_complete_http_headers_only_until_header_end() {
        let mut input = std::io::Cursor::new(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\npayload".to_vec(),
        );
        let headers = read_http_headers(&mut input, 8192).unwrap();
        assert_eq!(
            headers,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );

        let mut incomplete = std::io::Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());
        assert!(read_http_headers(&mut incomplete, 8192).is_err());
    }

    #[test]
    fn builds_http_origin_form_request() {
        let request = build_http_origin_request(&HttpRequestMeta {
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/ok".to_string(),
        });
        assert_eq!(
            request,
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn validates_socks5_no_auth_greeting() {
        assert!(parse_socks5_no_auth_greeting(&[0x05, 0x01, 0x00]).is_ok());
        assert!(parse_socks5_no_auth_greeting(&[0x05, 0x01, 0x02]).is_err());
        assert!(parse_socks5_no_auth_greeting(&[0x04, 0x01, 0x00]).is_err());
    }

    #[test]
    fn formats_socks5_success_reply() {
        let reply = socks5_connect_success_response("127.0.0.1:8080".parse().unwrap());
        assert_eq!(reply, [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    }
}
