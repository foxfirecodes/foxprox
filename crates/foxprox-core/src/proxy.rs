use crate::policy::PolicyRequest;
use crate::types::{
    normalize_hostname, AttributionConfidence, AttributionSource, DenialReason, Frontend,
    HostnameAttribution, NetworkEndpoint, Origin, Protocol,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxyRequestMetadata {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_query: String,
    pub is_connect: bool,
    pub attribution: HostnameAttribution,
}

impl HttpProxyRequestMetadata {
    pub fn into_policy_request(self, sandbox_id: impl Into<String>) -> PolicyRequest {
        let protocol = if self.is_connect {
            Protocol::Https
        } else {
            Protocol::Http
        };
        let mut request = PolicyRequest::new(sandbox_id, Frontend::HttpProxy, protocol)
            .with_destination(NetworkEndpoint {
                ip: None,
                port: Some(self.port),
            })
            .with_attribution(self.attribution)
            .with_origin(Origin::new(self.scheme, self.host, self.port))
            .with_http(self.method, self.path_query);
        request.protocol = protocol;
        request
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksConnectMetadata {
    pub destination_host: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub attribution: Option<HostnameAttribution>,
}

impl SocksConnectMetadata {
    pub fn into_policy_request(self, sandbox_id: impl Into<String>) -> PolicyRequest {
        let mut request = PolicyRequest::new(sandbox_id, Frontend::Socks5Proxy, Protocol::Socks)
            .with_destination(NetworkEndpoint {
                ip: self.destination_ip,
                port: Some(self.destination_port),
            });
        if let Some(attribution) = self.attribution {
            request = request.with_attribution(attribution);
        }
        request
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    NotUtf8,
    MissingRequestLine,
    MalformedRequestLine,
    MissingHost,
    UnsupportedScheme,
    Truncated,
    UnsupportedSocksVersion,
    UnsupportedSocksCommand,
    UnsupportedSocksAddressType,
    EmptySocksDomain,
}

impl ProxyParseError {
    pub fn as_detail(&self) -> &'static str {
        match self {
            Self::NotUtf8 => "not_utf8",
            Self::MissingRequestLine => "missing_request_line",
            Self::MalformedRequestLine => "malformed_request_line",
            Self::MissingHost => "missing_host",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::Truncated => "truncated",
            Self::UnsupportedSocksVersion => "unsupported_socks_version",
            Self::UnsupportedSocksCommand => "unsupported_socks_command",
            Self::UnsupportedSocksAddressType => "unsupported_socks_address_type",
            Self::EmptySocksDomain => "empty_socks_domain",
        }
    }
}

pub fn malformed_proxy_request(
    sandbox_id: impl Into<String>,
    frontend: Frontend,
    error: ProxyParseError,
) -> PolicyRequest {
    PolicyRequest::unsupported(sandbox_id, frontend, DenialReason::ProxyMalformed)
        .with_detail("proxy_parse_error", error.as_detail())
}

pub fn parse_http_proxy_request(bytes: &[u8]) -> Result<HttpProxyRequestMetadata, ProxyParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProxyParseError::NotUtf8)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(ProxyParseError::MissingRequestLine)?;
    if request_line.trim().is_empty() {
        return Err(ProxyParseError::MissingRequestLine);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(ProxyParseError::MalformedRequestLine)?
        .to_ascii_uppercase();
    let target = parts.next().ok_or(ProxyParseError::MalformedRequestLine)?;
    let version = parts.next().ok_or(ProxyParseError::MalformedRequestLine)?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(ProxyParseError::MalformedRequestLine);
    }

    if method == "CONNECT" {
        let (host, port) = split_host_port(target, 443).ok_or(ProxyParseError::MissingHost)?;
        return Ok(HttpProxyRequestMetadata {
            method,
            scheme: "https".to_string(),
            host: host.clone(),
            port,
            path_query: target.to_string(),
            is_connect: true,
            attribution: HostnameAttribution::new(
                host,
                AttributionSource::ExplicitProxyHost,
                AttributionConfidence::High,
            ),
        });
    }

    let host_header = lines.find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        })
    });

    let parsed = parse_http_target(target, host_header.as_deref())?;
    Ok(HttpProxyRequestMetadata {
        method,
        scheme: "http".to_string(),
        host: parsed.host.clone(),
        port: parsed.port,
        path_query: parsed.path_query,
        is_connect: false,
        attribution: HostnameAttribution::new(
            parsed.host,
            AttributionSource::ExplicitProxyHost,
            AttributionConfidence::High,
        ),
    })
}

struct ParsedHttpTarget {
    host: String,
    port: u16,
    path_query: String,
}

fn parse_http_target(
    target: &str,
    host_header: Option<&str>,
) -> Result<ParsedHttpTarget, ProxyParseError> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority, 80).ok_or(ProxyParseError::MissingHost)?;
        return Ok(ParsedHttpTarget {
            host,
            port,
            path_query: format!("/{path}"),
        });
    }
    if target.contains("://") {
        return Err(ProxyParseError::UnsupportedScheme);
    }
    let host_header = host_header.ok_or(ProxyParseError::MissingHost)?;
    let (host, port) = split_host_port(host_header, 80).ok_or(ProxyParseError::MissingHost)?;
    Ok(ParsedHttpTarget {
        host,
        port,
        path_query: target.to_string(),
    })
}

fn split_host_port(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(stripped) = value.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']')?;
        let port = rest
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        let host = normalize_hostname(host);
        return (!host.is_empty()).then_some((host, port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            let host = normalize_hostname(host);
            return (!host.is_empty()).then_some((host, port));
        }
    }
    let host = normalize_hostname(value);
    (!host.is_empty()).then_some((host, default_port))
}

pub fn parse_socks5_connect_request(bytes: &[u8]) -> Result<SocksConnectMetadata, ProxyParseError> {
    if bytes.len() < 7 {
        return Err(ProxyParseError::Truncated);
    }
    if bytes[0] != 0x05 {
        return Err(ProxyParseError::UnsupportedSocksVersion);
    }
    if bytes[1] != 0x01 {
        return Err(ProxyParseError::UnsupportedSocksCommand);
    }
    let atyp = bytes[3];
    let mut cursor = 4usize;
    let (destination_host, destination_ip) = match atyp {
        0x01 => {
            let addr = take(bytes, &mut cursor, 4)?;
            (
                None,
                Some(IpAddr::V4(Ipv4Addr::new(
                    addr[0], addr[1], addr[2], addr[3],
                ))),
            )
        }
        0x03 => {
            let len = *take(bytes, &mut cursor, 1)?
                .first()
                .ok_or(ProxyParseError::Truncated)? as usize;
            if len == 0 {
                return Err(ProxyParseError::EmptySocksDomain);
            }
            let domain = take(bytes, &mut cursor, len)?;
            let domain = std::str::from_utf8(domain).map_err(|_| ProxyParseError::NotUtf8)?;
            (Some(normalize_hostname(domain)), None)
        }
        0x04 => {
            let addr = take(bytes, &mut cursor, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(addr);
            (None, Some(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        _ => return Err(ProxyParseError::UnsupportedSocksAddressType),
    };
    let port = take(bytes, &mut cursor, 2)?;
    let destination_port = u16::from_be_bytes([port[0], port[1]]);
    let attribution = destination_host.as_ref().map(|host| {
        HostnameAttribution::new(
            host.clone(),
            AttributionSource::SocksDestination,
            AttributionConfidence::High,
        )
    });
    Ok(SocksConnectMetadata {
        destination_host,
        destination_ip,
        destination_port,
        attribution,
    })
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ProxyParseError> {
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(ProxyParseError::Truncated);
    }
    let start = *cursor;
    *cursor += len;
    Ok(&bytes[start..start + len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::BrokerCore;
    use crate::policy::{PolicyConfig, PolicyEngine, PolicyRule};
    use crate::types::{AuditKind, Decision};
    use pretty_assertions::assert_eq;

    #[test]
    fn http_proxy_absolute_form_emits_origin_aware_policy_request() {
        let meta = parse_http_proxy_request(
            b"GET http://Example.COM:8080/api/v1?q=1 HTTP/1.1\r\nHost: ignored.test\r\n\r\n",
        )
        .unwrap();
        assert_eq!(meta.method, "GET");
        assert_eq!(meta.host, "example.com");
        assert_eq!(meta.port, 8080);
        assert_eq!(meta.path_query, "/api/v1?q=1");

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-proxy-api")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_path_prefix("/api/"),
        );
        let mut broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let decision = broker.evaluate(&meta.into_policy_request("s1"));
        assert_eq!(decision.decision, Decision::Allow);
        let record = broker.audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpRequestDecision);
        assert_eq!(record.frontend, Some(Frontend::HttpProxy));
        assert_eq!(record.protocol, Some(Protocol::Http));
        assert_eq!(record.hostname.as_deref(), Some("example.com"));
        assert_eq!(
            record.hostname_attribution.as_ref().unwrap().source,
            AttributionSource::ExplicitProxyHost
        );
        assert_eq!(record.origin.as_ref().unwrap().port, 8080);
        assert_eq!(record.details["http_method"], "GET");
        assert_eq!(record.details["http_path"], "/api/v1?q=1");
    }

    #[test]
    fn http_connect_emits_https_connect_decision() {
        let meta = parse_http_proxy_request(b"CONNECT Example.COM:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-connect")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Https)
                .hostname("example.com")
                .destination_port(443),
        );
        let mut broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let decision = broker.evaluate(&meta.into_policy_request("s1"));
        assert_eq!(decision.decision, Decision::Allow);
        let record = broker.audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpsConnectDecision);
        assert_eq!(record.protocol, Some(Protocol::Https));
        assert_eq!(record.destination.as_ref().unwrap().port, Some(443));
        assert_eq!(record.details["http_method"], "CONNECT");
        assert_eq!(record.details["http_path"], "Example.COM:443");
    }

    #[test]
    fn socks5_domain_connect_emits_socks_decision_with_attribution() {
        let request = [
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ];
        let meta = parse_socks5_connect_request(&request).unwrap();
        assert_eq!(meta.destination_host.as_deref(), Some("example.com"));
        assert_eq!(meta.destination_port, 443);

        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks-example")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let mut broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let decision = broker.evaluate(&meta.into_policy_request("s1"));
        assert_eq!(decision.decision, Decision::Allow);
        let record = broker.audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::SocksConnectDecision);
        assert_eq!(record.frontend, Some(Frontend::Socks5Proxy));
        assert_eq!(record.protocol, Some(Protocol::Socks));
        assert_eq!(record.hostname.as_deref(), Some("example.com"));
        assert_eq!(
            record.hostname_attribution.as_ref().unwrap().source,
            AttributionSource::SocksDestination
        );
    }

    #[test]
    fn socks5_ip_connect_keeps_endpoint_visible() {
        let request = [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 42, 0x00, 0x50];
        let meta = parse_socks5_connect_request(&request).unwrap();
        assert_eq!(meta.destination_ip, Some("203.0.113.42".parse().unwrap()));
        assert_eq!(meta.destination_port, 80);
        let policy_request = meta.into_policy_request("s1");
        assert_eq!(
            policy_request.destination.ip,
            Some("203.0.113.42".parse().unwrap())
        );
        assert_eq!(policy_request.destination.port, Some(80));
    }

    #[test]
    fn malformed_proxy_request_fails_closed_with_structured_detail() {
        let error = parse_http_proxy_request(b"GET /missing-host HTTP/1.1\r\n\r\n").unwrap_err();
        let mut broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let decision = broker.evaluate(&malformed_proxy_request("s1", Frontend::HttpProxy, error));
        assert_eq!(decision.decision, Decision::FailClosed);
        let record = broker.audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UnsupportedDenied);
        assert_eq!(record.frontend, Some(Frontend::HttpProxy));
        assert_eq!(record.reason, Some(DenialReason::ProxyMalformed));
        assert_eq!(record.details["proxy_parse_error"], "missing_host");
    }
}
