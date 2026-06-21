use crate::origin::{parse_connect_target, OriginError};
use crate::types::{Endpoint, Hostname, HostnameAttribution, Origin, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    NeedMoreData,
    Malformed,
    UnsupportedVersion { version: u8 },
    UnsupportedCommand { command: u8 },
    UnsupportedAddressType { atyp: u8 },
    NoAcceptableSocksAuth,
    InvalidHostname,
    InvalidConnectTarget(OriginError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksGreeting {
    pub accepts_no_auth: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksDestination {
    Ip(Endpoint),
    Host { host: Hostname, port: u16 },
}

impl SocksDestination {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(endpoint) => endpoint.port,
            Self::Host { port, .. } => *port,
        }
    }

    pub fn hostname_attribution(&self) -> Option<HostnameAttribution> {
        match self {
            Self::Ip(_) => None,
            Self::Host { host, .. } => Some(HostnameAttribution::explicit_proxy(host.clone())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksConnectRequest {
    pub destination: SocksDestination,
}

pub fn parse_socks5_greeting(bytes: &[u8]) -> Result<SocksGreeting, ProxyParseError> {
    if bytes.len() < 2 {
        return Err(ProxyParseError::NeedMoreData);
    }
    if bytes[0] != 5 {
        return Err(ProxyParseError::UnsupportedVersion { version: bytes[0] });
    }
    let nmethods = bytes[1] as usize;
    if bytes.len() < 2 + nmethods {
        return Err(ProxyParseError::NeedMoreData);
    }
    let methods = &bytes[2..2 + nmethods];
    let accepts_no_auth = methods.contains(&0);
    if !accepts_no_auth {
        return Err(ProxyParseError::NoAcceptableSocksAuth);
    }
    Ok(SocksGreeting { accepts_no_auth })
}

pub fn parse_socks5_connect(bytes: &[u8]) -> Result<SocksConnectRequest, ProxyParseError> {
    if bytes.len() < 4 {
        return Err(ProxyParseError::NeedMoreData);
    }
    if bytes[0] != 5 {
        return Err(ProxyParseError::UnsupportedVersion { version: bytes[0] });
    }
    if bytes[1] != 1 {
        return Err(ProxyParseError::UnsupportedCommand { command: bytes[1] });
    }
    if bytes[2] != 0 {
        return Err(ProxyParseError::Malformed);
    }
    let atyp = bytes[3];
    let mut offset = 4;
    let destination = match atyp {
        1 => {
            if bytes.len() < offset + 4 + 2 {
                return Err(ProxyParseError::NeedMoreData);
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ));
            offset += 4;
            let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            SocksDestination::Ip(Endpoint::new(ip, port))
        }
        3 => {
            if bytes.len() < offset + 1 {
                return Err(ProxyParseError::NeedMoreData);
            }
            let len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + len + 2 {
                return Err(ProxyParseError::NeedMoreData);
            }
            let hostname = std::str::from_utf8(&bytes[offset..offset + len])
                .map_err(|_| ProxyParseError::InvalidHostname)?;
            let host =
                Hostname::normalize(hostname).map_err(|_| ProxyParseError::InvalidHostname)?;
            offset += len;
            let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            SocksDestination::Host { host, port }
        }
        4 => {
            if bytes.len() < offset + 16 + 2 {
                return Err(ProxyParseError::NeedMoreData);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            SocksDestination::Ip(Endpoint::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => return Err(ProxyParseError::UnsupportedAddressType { atyp: other }),
    };
    Ok(SocksConnectRequest { destination })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpProxyRequestLine {
    PlainHttp {
        method: String,
        origin: Origin,
        path_query: String,
    },
    Connect {
        origin: Origin,
    },
}

pub fn parse_http_proxy_request_line(line: &str) -> Result<HttpProxyRequestLine, ProxyParseError> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or(ProxyParseError::Malformed)?;
    let target = parts.next().ok_or(ProxyParseError::Malformed)?;
    let version = parts.next().ok_or(ProxyParseError::Malformed)?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(ProxyParseError::Malformed);
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let origin = parse_connect_target(target).map_err(ProxyParseError::InvalidConnectTarget)?;
        return Ok(HttpProxyRequestLine::Connect { origin });
    }
    let origin =
        crate::origin::parse_http_origin(target).map_err(ProxyParseError::InvalidConnectTarget)?;
    let path_query = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .and_then(|rest| rest.find('/').map(|index| rest[index..].to_string()))
        .unwrap_or_else(|| "/".to_string());
    Ok(HttpProxyRequestLine::PlainHttp {
        method: method.to_ascii_uppercase(),
        origin,
        path_query,
    })
}

pub fn protocol_for_http_proxy_line(line: &HttpProxyRequestLine) -> Protocol {
    match line {
        HttpProxyRequestLine::PlainHttp { .. } => Protocol::Http,
        HttpProxyRequestLine::Connect { .. } => Protocol::HttpsConnect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Scheme;

    #[test]
    fn socks_greeting_requires_no_auth_support() {
        assert_eq!(
            parse_socks5_greeting(&[5, 1, 2]),
            Err(ProxyParseError::NoAcceptableSocksAuth)
        );
        assert_eq!(
            parse_socks5_greeting(&[5, 2, 2, 0]).unwrap(),
            SocksGreeting {
                accepts_no_auth: true
            }
        );
    }

    #[test]
    fn socks_connect_domain_yields_explicit_proxy_attribution() {
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"Example.COM");
        request.extend_from_slice(&443u16.to_be_bytes());
        let parsed = parse_socks5_connect(&request).unwrap();
        let attribution = parsed.destination.hostname_attribution().unwrap();
        assert_eq!(attribution.hostname.as_str(), "example.com");
        assert_eq!(parsed.destination.port(), 443);
    }

    #[test]
    fn socks_udp_associate_is_unsupported() {
        assert_eq!(
            parse_socks5_connect(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 53]),
            Err(ProxyParseError::UnsupportedCommand { command: 3 })
        );
    }

    #[test]
    fn http_proxy_connect_line_is_origin_only() {
        let parsed = parse_http_proxy_request_line("CONNECT Example.com:443 HTTP/1.1").unwrap();
        let HttpProxyRequestLine::Connect { origin } = parsed else {
            panic!("expected CONNECT");
        };
        assert_eq!(origin.scheme, Scheme::Https);
        assert_eq!(origin.host.as_str(), "example.com");
        assert_eq!(origin.port, 443);
    }

    #[test]
    fn http_proxy_absolute_form_preserves_path() {
        let parsed =
            parse_http_proxy_request_line("GET http://Example.com/a?q=1 HTTP/1.1").unwrap();
        let HttpProxyRequestLine::PlainHttp {
            method,
            origin,
            path_query,
        } = parsed
        else {
            panic!("expected HTTP request");
        };
        assert_eq!(method, "GET");
        assert_eq!(origin.host.as_str(), "example.com");
        assert_eq!(origin.port, 80);
        assert_eq!(path_query, "/a?q=1");
    }
}
