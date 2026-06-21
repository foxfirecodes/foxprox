//! Transparent inspection and attribution helpers for foxprox.
//!
//! This crate enriches normalized TUN events with metadata discovered by other
//! broker subsystems. It does not own raw packet parsing or policy decisions.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use foxprox_core::{
    AttributionConfidence, AttributionSource, Endpoint, FrontendKind, HostnameAttribution,
    HttpRequest, HttpsConnect, NormalizedEvent, SandboxId, SniDnsMismatch, SocksConnect,
    TlsClientHello,
};

/// Expiring DNS answer cache used for medium-confidence transparent flow
/// attribution.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DnsAttributionCache {
    entries: Vec<DnsAttributionEntry>,
}

impl DnsAttributionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DNS answer mapping one hostname to one or more IP addresses.
    pub fn record_answer(
        &mut self,
        hostname: impl Into<String> + Clone,
        addresses: impl IntoIterator<Item = IpAddr>,
        observed_at: SystemTime,
        ttl: Duration,
    ) {
        let expires_at = observed_at
            .checked_add(ttl)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for address in addresses {
            self.entries.push(DnsAttributionEntry {
                address,
                attribution: HostnameAttribution::new(
                    hostname.clone(),
                    AttributionSource::DnsCache,
                    AttributionConfidence::Medium,
                ),
                expires_at,
            });
        }
    }

    /// Enrich TCP/UDP flow attempts with DNS hostname attribution when the
    /// destination IP has a non-expired DNS answer. Existing attribution is not
    /// overwritten because HTTP Host, TLS SNI, and explicit proxy metadata have
    /// higher confidence.
    pub fn enrich_event(&self, event: NormalizedEvent, now: SystemTime) -> NormalizedEvent {
        match event {
            NormalizedEvent::TcpConnectAttempt(mut tcp) => {
                if tcp.attribution.is_none() {
                    tcp.attribution = self.lookup(tcp.destination.ip, now);
                }
                NormalizedEvent::TcpConnectAttempt(tcp)
            }
            NormalizedEvent::UdpFlowAttempt(mut udp) => {
                if udp.attribution.is_none() {
                    udp.attribution = self.lookup(udp.destination.ip, now);
                }
                NormalizedEvent::UdpFlowAttempt(udp)
            }
            other => other,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn lookup(&self, address: IpAddr, now: SystemTime) -> Option<HostnameAttribution> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.address == address && now <= entry.expires_at)
            .map(|entry| entry.attribution.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsAttributionEntry {
    address: IpAddr,
    attribution: HostnameAttribution,
    expires_at: SystemTime,
}

/// Plaintext HTTP request parsing errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpInspectError {
    NotUtf8,
    MissingRequestLine,
    MalformedRequestLine,
    MissingHostHeader,
    InvalidHostPort,
    UnsupportedMethod,
}

impl std::fmt::Display for HttpInspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("http-request-not-utf8"),
            Self::MissingRequestLine => f.write_str("http-request-line-missing"),
            Self::MalformedRequestLine => f.write_str("http-request-line-malformed"),
            Self::MissingHostHeader => f.write_str("http-host-header-missing"),
            Self::InvalidHostPort => f.write_str("http-host-port-invalid"),
            Self::UnsupportedMethod => f.write_str("http-method-unsupported"),
        }
    }
}

impl std::error::Error for HttpInspectError {}

/// Parse one plaintext HTTP request head into a normalized policy event.
pub fn parse_plaintext_http_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: Option<Endpoint>,
    destination: Option<Endpoint>,
    bytes: &[u8],
) -> Result<NormalizedEvent, HttpInspectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpInspectError::NotUtf8)?;
    let mut lines = text.lines();
    let request_line = lines.next().ok_or(HttpInspectError::MissingRequestLine)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?
        .to_ascii_uppercase();
    let path_query = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?
        .to_owned();
    let version = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?;
    if !version.starts_with("HTTP/") || request_parts.next().is_some() {
        return Err(HttpInspectError::MalformedRequestLine);
    }

    let host_header = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .ok_or(HttpInspectError::MissingHostHeader)?;
    let (host, explicit_port) = split_host_port(host_header)?;
    let port = explicit_port
        .or_else(|| destination.and_then(|endpoint| endpoint.port))
        .unwrap_or(80);

    Ok(NormalizedEvent::HttpRequest(HttpRequest {
        sandbox_id,
        frontend,
        source,
        destination,
        method,
        scheme: "http".to_owned(),
        host,
        port,
        path_query,
    }))
}

/// Parse one HTTP proxy CONNECT request into a normalized HTTPS CONNECT event.
pub fn parse_https_connect_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: Option<Endpoint>,
    bytes: &[u8],
) -> Result<NormalizedEvent, HttpInspectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpInspectError::NotUtf8)?;
    let request_line = text
        .lines()
        .next()
        .ok_or(HttpInspectError::MissingRequestLine)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(HttpInspectError::UnsupportedMethod);
    }
    let authority = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?;
    let version = request_parts
        .next()
        .ok_or(HttpInspectError::MalformedRequestLine)?;
    if !version.starts_with("HTTP/") || request_parts.next().is_some() {
        return Err(HttpInspectError::MalformedRequestLine);
    }
    let (host, port) = split_host_port(authority)?;

    Ok(NormalizedEvent::HttpsConnect(HttpsConnect {
        sandbox_id,
        frontend,
        source,
        destination: None,
        host,
        port: port.unwrap_or(443),
    }))
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>), HttpInspectError> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err(HttpInspectError::MissingHostHeader);
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let port = port
                .parse::<u16>()
                .map_err(|_| HttpInspectError::InvalidHostPort)?;
            return Ok((host.to_ascii_lowercase(), Some(port)));
        }
    }
    Ok((value.to_ascii_lowercase(), None))
}

/// TLS ClientHello parsing errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsInspectError {
    TooShort,
    NotTlsHandshake,
    NotClientHello,
    Truncated,
    InvalidLength,
}

impl std::fmt::Display for TlsInspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => f.write_str("tls-client-hello-too-short"),
            Self::NotTlsHandshake => f.write_str("tls-record-not-handshake"),
            Self::NotClientHello => f.write_str("tls-handshake-not-client-hello"),
            Self::Truncated => f.write_str("tls-client-hello-truncated"),
            Self::InvalidLength => f.write_str("tls-client-hello-invalid-length"),
        }
    }
}

impl std::error::Error for TlsInspectError {}

/// Parse a TLS ClientHello and emit SNI metadata when present.
pub fn parse_tls_client_hello(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    source: Option<Endpoint>,
    destination: Endpoint,
    dns_attribution: Option<HostnameAttribution>,
    bytes: &[u8],
) -> Result<NormalizedEvent, TlsInspectError> {
    let sni = parse_tls_sni(bytes)?;
    let mismatch = match (&sni, &dns_attribution) {
        (Some(sni), Some(dns)) if normalize_host_for_compare(sni) == dns.hostname => {
            SniDnsMismatch::Match
        }
        (Some(_), Some(_)) => SniDnsMismatch::Mismatch,
        (None, Some(_)) => SniDnsMismatch::MissingSni,
        (Some(_), None) => SniDnsMismatch::NotChecked,
        (None, None) => SniDnsMismatch::MissingSni,
    };

    Ok(NormalizedEvent::TlsClientHello(TlsClientHello {
        sandbox_id,
        frontend,
        source,
        destination,
        sni,
        dns_attribution,
        mismatch,
    }))
}

fn parse_tls_sni(bytes: &[u8]) -> Result<Option<String>, TlsInspectError> {
    if bytes.len() < 9 {
        return Err(TlsInspectError::TooShort);
    }
    if bytes[0] != 22 {
        return Err(TlsInspectError::NotTlsHandshake);
    }
    let record_length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if bytes.len() < 5 + record_length {
        return Err(TlsInspectError::Truncated);
    }
    let record = &bytes[5..5 + record_length];
    if record[0] != 1 {
        return Err(TlsInspectError::NotClientHello);
    }
    let handshake_length =
        (usize::from(record[1]) << 16) | (usize::from(record[2]) << 8) | usize::from(record[3]);
    if record.len() < 4 + handshake_length || handshake_length < 38 {
        return Err(TlsInspectError::InvalidLength);
    }
    let body = &record[4..4 + handshake_length];
    let mut offset = 34; // legacy_version + random

    let session_id_len = *body.get(offset).ok_or(TlsInspectError::Truncated)? as usize;
    offset += 1 + session_id_len;
    if offset + 2 > body.len() {
        return Err(TlsInspectError::Truncated);
    }
    let cipher_suites_len = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2 + cipher_suites_len;
    if offset >= body.len() {
        return Err(TlsInspectError::Truncated);
    }
    let compression_methods_len = usize::from(body[offset]);
    offset += 1 + compression_methods_len;
    if offset == body.len() {
        return Ok(None);
    }
    if offset + 2 > body.len() {
        return Err(TlsInspectError::Truncated);
    }
    let extensions_len = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    if offset + extensions_len > body.len() {
        return Err(TlsInspectError::Truncated);
    }
    let extensions_end = offset + extensions_len;

    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        offset += 4;
        if offset + extension_len > extensions_end {
            return Err(TlsInspectError::Truncated);
        }
        if extension_type == 0 {
            return parse_sni_extension(&body[offset..offset + extension_len]);
        }
        offset += extension_len;
    }

    Ok(None)
}

fn parse_sni_extension(extension: &[u8]) -> Result<Option<String>, TlsInspectError> {
    if extension.len() < 2 {
        return Err(TlsInspectError::Truncated);
    }
    let list_len = usize::from(u16::from_be_bytes([extension[0], extension[1]]));
    if 2 + list_len > extension.len() {
        return Err(TlsInspectError::Truncated);
    }
    let mut offset = 2;
    let end = 2 + list_len;
    while offset + 3 <= end {
        let name_type = extension[offset];
        let name_len = usize::from(u16::from_be_bytes([
            extension[offset + 1],
            extension[offset + 2],
        ]));
        offset += 3;
        if offset + name_len > end {
            return Err(TlsInspectError::Truncated);
        }
        if name_type == 0 {
            let hostname = std::str::from_utf8(&extension[offset..offset + name_len])
                .map_err(|_| TlsInspectError::InvalidLength)?;
            return Ok(Some(normalize_host_for_compare(hostname)));
        }
        offset += name_len;
    }
    Ok(None)
}

fn normalize_host_for_compare(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// SOCKS5 request parsing errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksInspectError {
    TooShort,
    UnsupportedVersion { version: u8 },
    UnsupportedCommand { command: u8 },
    InvalidReserved { reserved: u8 },
    UnsupportedAddressType { atyp: u8 },
    DomainNameTruncated,
    AddressTruncated,
}

impl std::fmt::Display for SocksInspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => f.write_str("socks5-request-too-short"),
            Self::UnsupportedVersion { version } => {
                write!(f, "socks5-version-unsupported: {version}")
            }
            Self::UnsupportedCommand { command } => {
                write!(f, "socks5-command-unsupported: {command}")
            }
            Self::InvalidReserved { reserved } => write!(f, "socks5-rsv-invalid: {reserved}"),
            Self::UnsupportedAddressType { atyp } => {
                write!(f, "socks5-atyp-unsupported: {atyp}")
            }
            Self::DomainNameTruncated => f.write_str("socks5-domain-name-truncated"),
            Self::AddressTruncated => f.write_str("socks5-address-truncated"),
        }
    }
}

impl std::error::Error for SocksInspectError {}

/// Parse a SOCKS5 request message after method negotiation.
pub fn parse_socks5_connect_request(
    sandbox_id: SandboxId,
    frontend: FrontendKind,
    bytes: &[u8],
) -> Result<NormalizedEvent, SocksInspectError> {
    if bytes.len() < 7 {
        return Err(SocksInspectError::TooShort);
    }
    if bytes[0] != 5 {
        return Err(SocksInspectError::UnsupportedVersion { version: bytes[0] });
    }
    if bytes[1] != 1 {
        return Err(SocksInspectError::UnsupportedCommand { command: bytes[1] });
    }
    if bytes[2] != 0 {
        return Err(SocksInspectError::InvalidReserved { reserved: bytes[2] });
    }

    let atyp = bytes[3];
    let mut offset = 4;
    let (host, destination_ip) = match atyp {
        1 => {
            if bytes.len() < offset + 4 + 2 {
                return Err(SocksInspectError::AddressTruncated);
            }
            let ip = Ipv4Addr::new(
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            );
            offset += 4;
            (ip.to_string(), Some(IpAddr::V4(ip)))
        }
        3 => {
            let length = usize::from(bytes[offset]);
            offset += 1;
            if bytes.len() < offset + length + 2 {
                return Err(SocksInspectError::DomainNameTruncated);
            }
            let host = std::str::from_utf8(&bytes[offset..offset + length])
                .map_err(|_| SocksInspectError::DomainNameTruncated)?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            offset += length;
            (host, None)
        }
        4 => {
            if bytes.len() < offset + 16 + 2 {
                return Err(SocksInspectError::AddressTruncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            let ip = Ipv6Addr::from(octets);
            offset += 16;
            (ip.to_string(), Some(IpAddr::V6(ip)))
        }
        _ => return Err(SocksInspectError::UnsupportedAddressType { atyp }),
    };

    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    Ok(NormalizedEvent::SocksConnect(SocksConnect {
        sandbox_id,
        frontend,
        host,
        destination_ip,
        port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        AuditDecision, Endpoint, FrontendKind, HostnamePattern, PolicyConfig, PolicyDecision,
        PolicyEngine, PolicyRule, Protocol, RuleAction, SandboxId,
    };
    use foxprox_packet::{parse_ipv4_packet, PacketContext};
    use std::net::Ipv4Addr;

    fn context() -> PacketContext {
        PacketContext::new(SandboxId::new("inspect-test").unwrap(), FrontendKind::Tun)
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_length = 20 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn tcp_syn_payload(source_port: u16, destination_port: u16) -> [u8; 20] {
        let mut payload = [0_u8; 20];
        payload[0..2].copy_from_slice(&source_port.to_be_bytes());
        payload[2..4].copy_from_slice(&destination_port.to_be_bytes());
        payload[12] = 5 << 4;
        payload[13] = 0x02;
        payload
    }

    fn domain_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-https", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Tcp)
            .with_destination_port(443)
            .with_hostname(HostnamePattern::new(".example.com").unwrap());
        PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
    }

    fn tcp_connect_event() -> NormalizedEvent {
        let packet = ipv4_packet(
            6,
            [10, 0, 0, 2],
            [93, 184, 216, 34],
            &tcp_syn_payload(49152, 443),
        );
        parse_ipv4_packet(&context(), &packet).unwrap()
    }

    fn tls_client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0); // session id length
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods length
        body.push(0); // null compression

        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let name = name.as_bytes();
            let mut sni = Vec::new();
            let list_len = 3 + name.len();
            sni.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni.push(0);
            sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni.extend_from_slice(name);
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        let len = body.len();
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn dns_cache_enriches_tcp_flow_for_domain_policy_and_audit() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let event = tcp_connect_event();
        let engine = domain_policy();
        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );

        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "WWW.EXAMPLE.COM.",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(60),
        );
        let enriched = cache.enrich_event(event, now + Duration::from_secs(1));
        let evaluation = engine.evaluate(&enriched);

        assert_eq!(enriched.hostname(), Some("www.example.com"));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example-https".to_owned())
            }
        );
        assert_eq!(evaluation.audit.decision, AuditDecision::Allowed);
        assert_eq!(
            evaluation.audit.hostname.as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            evaluation.audit.hostname_confidence,
            Some(AttributionConfidence::Medium)
        );
    }

    #[test]
    fn expired_dns_answer_does_not_enrich_flow() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "www.example.com",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(5),
        );

        let enriched = cache.enrich_event(tcp_connect_event(), now + Duration::from_secs(6));

        assert_eq!(enriched.hostname(), None);
    }

    #[test]
    fn dns_cache_does_not_overwrite_existing_high_confidence_attribution() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        cache.record_answer(
            "dns.example.com",
            [Ipv4Addr::new(93, 184, 216, 34).into()],
            now,
            Duration::from_secs(60),
        );
        let mut event = tcp_connect_event();
        match &mut event {
            NormalizedEvent::TcpConnectAttempt(tcp) => {
                tcp.attribution = Some(HostnameAttribution::new(
                    "sni.example.com",
                    AttributionSource::TlsSni,
                    AttributionConfidence::High,
                ));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let enriched = cache.enrich_event(event, now + Duration::from_secs(1));

        assert_eq!(enriched.hostname(), Some("sni.example.com"));
        assert_eq!(
            enriched.attribution_confidence(),
            Some(AttributionConfidence::High)
        );
    }

    #[test]
    fn plaintext_http_request_parses_to_policy_event_and_audit() {
        let event = parse_plaintext_http_request(
            SandboxId::new("http-test").unwrap(),
            FrontendKind::Tun,
            Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            Some(Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 80)),
            b"GET /allowed/item?debug=1 HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\n",
        )
        .unwrap();
        let rule = PolicyRule::new("allow-http", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Http)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_destination_port(80)
            .with_http_method("GET")
            .with_http_path_prefix("/allowed");
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });

        let evaluation = engine.evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Http);
        assert_eq!(event.hostname(), Some("example.com"));
        assert_eq!(event.http_method(), Some("GET"));
        assert_eq!(event.http_path_query(), Some("/allowed/item?debug=1"));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-http".to_owned())
            }
        );
        assert_eq!(evaluation.audit.http_method.as_deref(), Some("GET"));
        assert_eq!(
            evaluation.audit.http_path_query.as_deref(),
            Some("/allowed/item?debug=1")
        );
    }

    #[test]
    fn plaintext_http_method_or_path_mismatch_denies() {
        let rule = PolicyRule::new("allow-get-public", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Http)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_http_method("GET")
            .with_http_path_prefix("/public");
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        });
        let event = parse_plaintext_http_request(
            SandboxId::new("http-test").unwrap(),
            FrontendKind::Tun,
            None,
            Some(Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 80)),
            b"POST /private HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            engine.evaluate(&event).decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn plaintext_http_requires_host_header() {
        let error = parse_plaintext_http_request(
            SandboxId::new("http-test").unwrap(),
            FrontendKind::Tun,
            None,
            None,
            b"GET / HTTP/1.1\r\n\r\n",
        )
        .unwrap_err();

        assert_eq!(error, HttpInspectError::MissingHostHeader);
    }

    #[test]
    fn socks5_domain_connect_parses_to_policy_event() {
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"Example.COM");
        request.extend_from_slice(&443_u16.to_be_bytes());
        let event = parse_socks5_connect_request(
            SandboxId::new("socks-test").unwrap(),
            FrontendKind::Socks5,
            &request,
        )
        .unwrap();
        let rule = PolicyRule::new("allow-socks", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Socks)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_destination_port(443);
        let evaluation = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
        .evaluate(&event);

        assert_eq!(event.protocol(), Protocol::Socks);
        assert_eq!(event.hostname(), Some("example.com"));
        assert_eq!(event.destination_port(), Some(443));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-socks".to_owned())
            }
        );
    }

    #[test]
    fn socks5_ipv4_connect_exposes_destination_ip_for_audit() {
        let request = [5, 1, 0, 1, 203, 0, 113, 10, 0, 80];
        let event = parse_socks5_connect_request(
            SandboxId::new("socks-test").unwrap(),
            FrontendKind::Socks5,
            &request,
        )
        .unwrap();
        let evaluation = PolicyEngine::new(PolicyConfig {
            default_policy: foxprox_core::DefaultPolicy::Allow,
            ..PolicyConfig::default()
        })
        .evaluate(&event);

        assert_eq!(event.hostname(), Some("203.0.113.10"));
        assert_eq!(
            event.destination(),
            Some(Endpoint::tcp(Ipv4Addr::new(203, 0, 113, 10).into(), 80))
        );
        assert_eq!(evaluation.audit.frontend, FrontendKind::Socks5);
        assert_eq!(evaluation.audit.destination, event.destination());
    }

    #[test]
    fn socks5_rejects_udp_associate_command() {
        let error = parse_socks5_connect_request(
            SandboxId::new("socks-test").unwrap(),
            FrontendKind::Socks5,
            &[5, 3, 0, 1, 127, 0, 0, 1, 0, 53],
        )
        .unwrap_err();

        assert_eq!(error, SocksInspectError::UnsupportedCommand { command: 3 });
    }

    #[test]
    fn https_connect_request_parses_to_host_port_policy_event() {
        let event = parse_https_connect_request(
            SandboxId::new("connect-test").unwrap(),
            FrontendKind::HttpProxy,
            Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            b"CONNECT Example.COM:443 HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n",
        )
        .unwrap();
        let rule = PolicyRule::new("allow-connect", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::HttpsConnect)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_destination_port(443);
        let evaluation = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
        .evaluate(&event);

        assert_eq!(event.protocol(), Protocol::HttpsConnect);
        assert_eq!(event.hostname(), Some("example.com"));
        assert_eq!(event.destination_port(), Some(443));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-connect".to_owned())
            }
        );
        assert_eq!(evaluation.audit.kind, foxprox_core::AuditKind::HttpsConnect);
    }

    #[test]
    fn https_connect_request_defaults_to_port_443_and_denies_wrong_path() {
        let event = parse_https_connect_request(
            SandboxId::new("connect-test").unwrap(),
            FrontendKind::HttpProxy,
            None,
            b"CONNECT example.com HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        let rule = PolicyRule::new("allow-other-port", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::HttpsConnect)
            .with_hostname(HostnamePattern::new("example.com").unwrap())
            .with_destination_port(8443);

        assert_eq!(event.destination_port(), Some(443));
        assert_eq!(
            PolicyEngine::new(PolicyConfig {
                rules: vec![rule],
                ..PolicyConfig::default()
            })
            .evaluate(&event)
            .decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Drop,
                reason: "default-deny".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn https_connect_rejects_non_connect_method() {
        let error = parse_https_connect_request(
            SandboxId::new("connect-test").unwrap(),
            FrontendKind::HttpProxy,
            None,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap_err();

        assert_eq!(error, HttpInspectError::UnsupportedMethod);
    }

    #[test]
    fn tls_client_hello_sni_allows_domain_policy_and_audit() {
        let event = parse_tls_client_hello(
            SandboxId::new("tls-test").unwrap(),
            FrontendKind::Tun,
            Some(Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)),
            Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            None,
            &tls_client_hello(Some("WWW.EXAMPLE.COM")),
        )
        .unwrap();
        let rule = PolicyRule::new("allow-tls-example", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::TlsClientHello)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_destination_port(443);
        let evaluation = PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
        .evaluate(&event);

        assert_eq!(event.hostname(), Some("www.example.com"));
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-tls-example".to_owned())
            }
        );
        assert_eq!(
            evaluation.audit.hostname.as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn tls_client_hello_dns_sni_mismatch_is_denied_before_allow_rule() {
        let dns = HostnameAttribution::new(
            "good.example.com",
            AttributionSource::DnsCache,
            AttributionConfidence::Medium,
        );
        let event = parse_tls_client_hello(
            SandboxId::new("tls-test").unwrap(),
            FrontendKind::Tun,
            None,
            Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            Some(dns),
            &tls_client_hello(Some("evil.example.com")),
        )
        .unwrap();
        let allow_all_tls = PolicyRule::new("allow-tls", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::TlsClientHello);

        assert_eq!(
            PolicyEngine::new(PolicyConfig {
                rules: vec![allow_all_tls],
                ..PolicyConfig::default()
            })
            .evaluate(&event)
            .decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Reset,
                reason: "tls-sni-dns-mismatch".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn tls_client_hello_missing_sni_is_denied() {
        let event = parse_tls_client_hello(
            SandboxId::new("tls-test").unwrap(),
            FrontendKind::Tun,
            None,
            Endpoint::tcp(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            None,
            &tls_client_hello(None),
        )
        .unwrap();

        assert_eq!(event.hostname(), None);
        assert_eq!(
            PolicyEngine::new(PolicyConfig {
                default_policy: foxprox_core::DefaultPolicy::Allow,
                ..PolicyConfig::default()
            })
            .evaluate(&event)
            .decision,
            PolicyDecision::Deny {
                behavior: foxprox_core::DenialBehavior::Reset,
                reason: "tls-sni-missing".to_owned(),
                rule_id: None,
            }
        );
    }

    #[test]
    fn newest_dns_answer_wins_when_addresses_are_reused() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut cache = DnsAttributionCache::new();
        let shared_ip = Ipv4Addr::new(93, 184, 216, 34);
        cache.record_answer(
            "old.example.com",
            [shared_ip.into()],
            now,
            Duration::from_secs(60),
        );
        cache.record_answer(
            "new.example.com",
            [shared_ip.into()],
            now + Duration::from_secs(1),
            Duration::from_secs(60),
        );

        let enriched = cache.enrich_event(tcp_connect_event(), now + Duration::from_secs(2));

        assert_eq!(cache.len(), 2);
        assert_eq!(enriched.hostname(), Some("new.example.com"));
        assert_eq!(
            enriched.destination(),
            Some(Endpoint::tcp(shared_ip.into(), 443))
        );
    }
}
