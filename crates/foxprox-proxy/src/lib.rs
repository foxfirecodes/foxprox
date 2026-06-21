//! Explicit proxy frontend parsing and normalization.
//!
//! This crate contains dependency-light protocol parsers that turn explicit
//! HTTP proxy, HTTPS CONNECT, and SOCKS5 CONNECT request bytes into the same
//! normalized policy events used by transparent frontends. It does not open
//! host sockets or perform forwarding.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use foxprox_core::{
    Frontend, Hostname, HttpMethod, NetworkEvent, Origin, SandboxId, SocksDestination,
    TransportEndpoint,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Explicit proxy parse error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyParseError {
    /// More bytes are needed before a complete request can be parsed.
    Truncated,
    /// The request is malformed and should fail closed.
    Malformed(String),
    /// The request uses an unsupported proxy feature.
    Unsupported(String),
}

/// Parses an HTTP proxy request head into a normalized HTTP or CONNECT event.
///
/// Plain HTTP proxy requests must use absolute-form `http://host[:port]/path`.
/// HTTPS tunnels must use `CONNECT host:port HTTP/1.x`.
pub fn parse_http_proxy_request_head(
    sandbox_id: SandboxId,
    input: &[u8],
) -> Result<NetworkEvent, ProxyParseError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| ProxyParseError::Malformed("HTTP proxy head is not UTF-8".to_string()))?;
    let head_end = text.find("\r\n\r\n").ok_or(ProxyParseError::Truncated)?;
    let request_line = text[..head_end]
        .split("\r\n")
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing request target".to_string()))?;
    let version = parts
        .next()
        .ok_or_else(|| ProxyParseError::Malformed("missing HTTP version".to_string()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return Err(ProxyParseError::Unsupported(
            "only HTTP/1.0 and HTTP/1.1 proxy requests are supported".to_string(),
        ));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, None)?;
        return Ok(NetworkEvent::HttpsConnect {
            sandbox_id,
            frontend: Frontend::HttpProxy,
            host,
            port,
        });
    }

    let method =
        HttpMethod::parse(method).map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
    let (origin, path_and_query) = parse_absolute_http_target(target)?;
    Ok(NetworkEvent::HttpRequest {
        sandbox_id,
        frontend: Frontend::HttpProxy,
        method,
        origin,
        path_and_query,
    })
}

/// Parses a complete SOCKS5 greeting plus CONNECT request into a normalized event.
///
/// This alpha parser supports no-authentication TCP CONNECT only. It returns
/// `Unsupported` for UDP ASSOCIATE, BIND, and unsupported address families.
pub fn parse_socks5_connect(
    sandbox_id: SandboxId,
    input: &[u8],
) -> Result<NetworkEvent, ProxyParseError> {
    if input.len() < 2 {
        return Err(ProxyParseError::Truncated);
    }
    if input[0] != 0x05 {
        return Err(ProxyParseError::Malformed(
            "SOCKS version is not 5".to_string(),
        ));
    }
    let method_count = input[1] as usize;
    let methods_end = 2 + method_count;
    if input.len() < methods_end + 4 {
        return Err(ProxyParseError::Truncated);
    }
    if !input[2..methods_end].contains(&0x00) {
        return Err(ProxyParseError::Unsupported(
            "SOCKS5 no-auth method was not offered".to_string(),
        ));
    }
    let request = &input[methods_end..];
    if request[0] != 0x05 {
        return Err(ProxyParseError::Malformed(
            "SOCKS request version is not 5".to_string(),
        ));
    }
    if request[2] != 0x00 {
        return Err(ProxyParseError::Malformed(
            "SOCKS reserved byte is non-zero".to_string(),
        ));
    }
    if request[1] != 0x01 {
        return Err(ProxyParseError::Unsupported(
            "only SOCKS5 CONNECT is alpha-supported".to_string(),
        ));
    }

    let (target, consumed) = parse_socks_address(request)?;
    if input.len() < methods_end + consumed {
        return Err(ProxyParseError::Truncated);
    }
    Ok(NetworkEvent::SocksConnect { sandbox_id, target })
}

fn parse_absolute_http_target(target: &str) -> Result<(Origin, String), ProxyParseError> {
    let without_scheme = target.strip_prefix("http://").ok_or_else(|| {
        ProxyParseError::Unsupported(
            "only absolute-form http:// proxy targets are supported".into(),
        )
    })?;
    let (authority, path) = match without_scheme.find('/') {
        Some(index) => (&without_scheme[..index], &without_scheme[index..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = parse_host_port(authority, Some(80))?;
    Ok((
        Origin {
            scheme: "http".to_string(),
            host,
            port,
        },
        path.to_string(),
    ))
}

fn parse_host_port(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(Hostname, u16), ProxyParseError> {
    if authority.starts_with('[') {
        return Err(ProxyParseError::Unsupported(
            "IPv6 literal authorities are not supported by hostname-only proxy events".into(),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let port = port
                .parse()
                .map_err(|_| ProxyParseError::Malformed("invalid port".to_string()))?;
            (host, port)
        }
        _ => {
            let Some(default_port) = default_port else {
                return Err(ProxyParseError::Malformed("missing explicit port".into()));
            };
            (authority, default_port)
        }
    };
    if host.parse::<Ipv4Addr>().is_ok() {
        return Err(ProxyParseError::Unsupported(
            "IPv4 literal authorities are not supported by hostname-only proxy events".into(),
        ));
    }
    let host =
        Hostname::parse(host).map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
    Ok((host, port))
}

fn parse_socks_address(request: &[u8]) -> Result<(SocksDestination, usize), ProxyParseError> {
    match request.get(3).copied() {
        Some(0x01) => {
            if request.len() < 10 {
                return Err(ProxyParseError::Truncated);
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                request[4], request[5], request[6], request[7],
            ));
            let port = u16::from_be_bytes([request[8], request[9]]);
            Ok((SocksDestination::Ip(TransportEndpoint::new(ip, port)), 10))
        }
        Some(0x03) => {
            let len = *request.get(4).ok_or(ProxyParseError::Truncated)? as usize;
            if request.len() < 5 + len + 2 {
                return Err(ProxyParseError::Truncated);
            }
            let host = std::str::from_utf8(&request[5..5 + len])
                .map_err(|_| ProxyParseError::Malformed("SOCKS hostname is not UTF-8".into()))?;
            let host = Hostname::parse(host)
                .map_err(|error| ProxyParseError::Malformed(error.to_string()))?;
            let port_offset = 5 + len;
            let port = u16::from_be_bytes([request[port_offset], request[port_offset + 1]]);
            Ok((SocksDestination::Host { host, port }, port_offset + 2))
        }
        Some(0x04) => {
            if request.len() < 22 {
                return Err(ProxyParseError::Truncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&request[4..20]);
            let port = u16::from_be_bytes([request[20], request[21]]);
            Ok((
                SocksDestination::Ip(TransportEndpoint::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )),
                22,
            ))
        }
        Some(_) => Err(ProxyParseError::Unsupported(
            "unsupported SOCKS address type".into(),
        )),
        None => Err(ProxyParseError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{Protocol, SocksDestination};

    fn sandbox_id() -> SandboxId {
        SandboxId::new("proxy-test").unwrap()
    }

    #[test]
    fn parses_http_absolute_form_request() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://Example.com:8080/path?q=1 HTTP/1.1\r\nHost: ignored\r\n\r\n",
        )
        .unwrap();
        match event {
            NetworkEvent::HttpRequest {
                frontend,
                method,
                origin,
                path_and_query,
                ..
            } => {
                assert_eq!(frontend, Frontend::HttpProxy);
                assert_eq!(method.as_str(), "GET");
                assert_eq!(origin.host.as_str(), "example.com");
                assert_eq!(origin.port, 8080);
                assert_eq!(path_and_query, "/path?q=1");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_https_connect() {
        let event = parse_http_proxy_request_head(
            sandbox_id(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap();
        match event {
            NetworkEvent::HttpsConnect {
                frontend,
                host,
                port,
                ..
            } => {
                assert_eq!(frontend, Frontend::HttpProxy);
                assert_eq!(host.as_str(), "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_http_proxy_request() {
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"GET /relative HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"CONNECT example.com HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_http_proxy_ip_literal_authorities() {
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"GET http://127.0.0.1/ HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(sandbox_id(), b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n"),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_unsupported_http_proxy_versions() {
        assert!(matches!(
            parse_http_proxy_request_head(
                sandbox_id(),
                b"GET http://example.com/ HTTP/2.0\r\n\r\n"
            ),
            Err(ProxyParseError::Unsupported(_))
        ));
        assert!(matches!(
            parse_http_proxy_request_head(
                sandbox_id(),
                b"CONNECT example.com:443 HTTP/not-a-version\r\n\r\n"
            ),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn parses_socks5_host_connect() {
        let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443_u16.to_be_bytes());
        let event = parse_socks5_connect(sandbox_id(), &request).unwrap();
        match event {
            NetworkEvent::SocksConnect {
                target: SocksDestination::Host { host, port },
                ..
            } => {
                assert_eq!(host.as_str(), "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_socks5_ipv4_connect() {
        let request = [
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0, 80,
        ];
        let event = parse_socks5_connect(sandbox_id(), &request).unwrap();
        match event {
            NetworkEvent::SocksConnect {
                target: SocksDestination::Ip(endpoint),
                ..
            } => {
                assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
                assert_eq!(endpoint.port, 80);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn rejects_socks_udp_associate() {
        let request = [
            0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53,
        ];
        assert!(matches!(
            parse_socks5_connect(sandbox_id(), &request),
            Err(ProxyParseError::Unsupported(_))
        ));
    }

    #[test]
    fn normalized_proxy_events_have_expected_protocols() {
        let http = parse_http_proxy_request_head(
            sandbox_id(),
            b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let connect = parse_http_proxy_request_head(
            sandbox_id(),
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(http.protocol(), Protocol::Http);
        assert_eq!(connect.protocol(), Protocol::HttpsConnect);
    }
}
