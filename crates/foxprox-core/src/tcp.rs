use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::flow::{DnsCache, FlowKey};
use crate::inspect::{
    parse_plaintext_http_request, parse_tls_client_hello_sni, TlsClientHelloError,
};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{
    AuditKind, ByteCounts, Decision, DenialReason, Frontend, NetworkEndpoint, Origin, Protocol,
};
use serde::{Deserialize, Serialize};

pub trait TcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpEgressError {
    ConnectFailed,
    BridgeFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpForwardResult {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub opened_egress: bool,
    pub byte_counts: ByteCounts,
}

#[derive(Clone, Debug)]
pub struct TcpForwarder<E> {
    sandbox_id: String,
    broker: BrokerCore,
    egress: E,
}

impl<E: TcpEgress> TcpForwarder<E> {
    pub fn new(sandbox_id: impl Into<String>, broker: BrokerCore, egress: E) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            egress,
        }
    }

    pub fn connect_and_bridge(
        &mut self,
        key: FlowKey,
        from_sandbox: &[u8],
        opened_at_ms: u64,
        closed_at_ms: u64,
    ) -> Result<TcpForwardResult, TcpEgressError> {
        let request = self.request_for_key(&key, from_sandbox, None, opened_at_ms);
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false, ByteCounts::ZERO));
        }

        let to_sandbox = match self
            .egress
            .connect_and_exchange(key.destination(), from_sandbox)
        {
            Ok(to_sandbox) => to_sandbox,
            Err(error) => {
                let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Tcp)
                    .with_source(key.source())
                    .with_destination(key.destination())
                    .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                    .with_detail("error", tcp_egress_error_detail(&error));
                let _ = self.broker.append_audit_for(&request, audit);
                return Err(error);
            }
        };
        let byte_counts = ByteCounts {
            from_sandbox: from_sandbox.len() as u64,
            to_sandbox: to_sandbox.len() as u64,
        };
        let close_audit = AuditRecord::new_at(
            AuditKind::TcpFlowClosed,
            self.sandbox_id.clone(),
            closed_at_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Tcp)
        .with_source(key.source())
        .with_destination(key.destination())
        .with_byte_counts(byte_counts.clone())
        .with_duration_ms(closed_at_ms.saturating_sub(opened_at_ms));
        if let Err(decision) = self.broker.append_audit_for(&request, close_audit) {
            return Ok(result_from_decision(decision, true, byte_counts));
        }

        Ok(TcpForwardResult {
            decision: Decision::Allow,
            reason: None,
            opened_egress: true,
            byte_counts,
        })
    }

    pub fn connect_and_bridge_with_dns_cache(
        &mut self,
        key: FlowKey,
        from_sandbox: &[u8],
        opened_at_ms: u64,
        closed_at_ms: u64,
        dns_cache: &DnsCache,
    ) -> Result<TcpForwardResult, TcpEgressError> {
        let request = self.request_for_key(&key, from_sandbox, Some(dns_cache), opened_at_ms);
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false, ByteCounts::ZERO));
        }
        let to_sandbox = match self
            .egress
            .connect_and_exchange(key.destination(), from_sandbox)
        {
            Ok(to_sandbox) => to_sandbox,
            Err(error) => {
                let audit = AuditRecord::new(AuditKind::BrokerError, self.sandbox_id.clone())
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Tcp)
                    .with_source(key.source())
                    .with_destination(key.destination())
                    .with_decision(Decision::FailClosed, Some(DenialReason::ResourceLimit))
                    .with_detail("error", tcp_egress_error_detail(&error));
                let _ = self.broker.append_audit_for(&request, audit);
                return Err(error);
            }
        };
        let byte_counts = ByteCounts {
            from_sandbox: from_sandbox.len() as u64,
            to_sandbox: to_sandbox.len() as u64,
        };
        let close_audit = AuditRecord::new_at(
            AuditKind::TcpFlowClosed,
            self.sandbox_id.clone(),
            closed_at_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Tcp)
        .with_source(key.source())
        .with_destination(key.destination())
        .with_byte_counts(byte_counts.clone())
        .with_duration_ms(closed_at_ms.saturating_sub(opened_at_ms));
        if let Err(decision) = self.broker.append_audit_for(&request, close_audit) {
            return Ok(result_from_decision(decision, true, byte_counts));
        }
        Ok(TcpForwardResult {
            decision: Decision::Allow,
            reason: None,
            opened_egress: true,
            byte_counts,
        })
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (BrokerCore, E) {
        (self.broker, self.egress)
    }

    fn request_for_key(
        &self,
        key: &FlowKey,
        from_sandbox: &[u8],
        dns_cache: Option<&DnsCache>,
        now_ms: u64,
    ) -> PolicyRequest {
        let mut request = PolicyRequest::tcp_connect(
            self.sandbox_id.clone(),
            Frontend::Tun,
            key.source(),
            key.destination(),
        );
        request.protocol = Protocol::Tcp;
        match key.destination_port {
            80 => {
                if let Ok(http) = parse_plaintext_http_request(from_sandbox) {
                    request = request
                        .with_attribution(http.attribution)
                        .with_origin(Origin::new("http", http.host, http.port))
                        .with_http(http.method, http.path_query);
                }
            }
            443 => match parse_tls_client_hello_sni(from_sandbox) {
                Ok(attribution) => {
                    let sni_hostname = attribution.hostname.clone();
                    request = request
                        .with_attribution(attribution)
                        .with_tls_sni(sni_hostname.clone());
                    if let Some(dns_hostname) = dns_cache
                        .and_then(|cache| cache.attribution_for(key.destination_ip, now_ms))
                        .map(|attribution| attribution.hostname)
                    {
                        request = request.with_dns_correlated_hostname(dns_hostname.clone());
                        request.sni_dns_mismatch = dns_hostname != sni_hostname;
                    }
                }
                Err(error) => {
                    request.hidden_sni = true;
                    request =
                        request.with_detail("tls_client_hello_error", tls_error_detail(&error));
                }
            },
            _ => {}
        }
        request
    }
}

fn tls_error_detail(error: &TlsClientHelloError) -> &'static str {
    match error {
        TlsClientHelloError::NotTlsHandshake => "not_tls_handshake",
        TlsClientHelloError::NotClientHello => "not_client_hello",
        TlsClientHelloError::Truncated => "truncated",
        TlsClientHelloError::MissingSni => "missing_sni",
        TlsClientHelloError::Malformed => "malformed",
    }
}

fn tcp_egress_error_detail(error: &TcpEgressError) -> &'static str {
    match error {
        TcpEgressError::ConnectFailed => "tcp_egress_connect_failed",
        TcpEgressError::BridgeFailed => "tcp_egress_bridge_failed",
    }
}

fn result_from_decision(
    decision: PolicyDecision,
    opened_egress: bool,
    byte_counts: ByteCounts,
) -> TcpForwardResult {
    TcpForwardResult {
        decision: decision.decision,
        reason: decision.reason,
        opened_egress,
        byte_counts,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryTcpEgress {
    scripted_reply: Vec<u8>,
    opened: Vec<NetworkEndpoint>,
    sent_from_sandbox: Vec<Vec<u8>>,
}

impl InMemoryTcpEgress {
    pub fn with_scripted_reply(reply: impl Into<Vec<u8>>) -> Self {
        Self {
            scripted_reply: reply.into(),
            opened: Vec::new(),
            sent_from_sandbox: Vec::new(),
        }
    }

    pub fn opened(&self) -> &[NetworkEndpoint] {
        &self.opened
    }

    pub fn sent_from_sandbox(&self) -> &[Vec<u8>] {
        &self.sent_from_sandbox
    }
}

impl TcpEgress for InMemoryTcpEgress {
    fn connect_and_exchange(
        &mut self,
        destination: NetworkEndpoint,
        from_sandbox: &[u8],
    ) -> Result<Vec<u8>, TcpEgressError> {
        self.opened.push(destination);
        self.sent_from_sandbox.push(from_sandbox.to_vec());
        Ok(self.scripted_reply.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Cidr, PolicyConfig, PolicyEngine, PolicyRule};
    use pretty_assertions::assert_eq;

    #[test]
    fn allowed_tcp_connect_opens_egress_bridges_bytes_and_logs_close() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-web")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(80),
        );
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"GET / HTTP/1.1\r\n\r\n", 1_000, 1_250)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.opened_egress);
        assert_eq!(result.byte_counts.from_sandbox, 18);
        assert_eq!(result.byte_counts.to_sandbox, 19);
        assert_eq!(forwarder.egress().opened().len(), 1);
        assert_eq!(forwarder.egress().sent_from_sandbox().len(), 1);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[0].decision, Some(Decision::Allow));
        assert_eq!(records[1].kind, AuditKind::TcpFlowClosed);
        assert_eq!(records[1].duration_ms, Some(250));
        assert_eq!(records[1].byte_counts.as_ref().unwrap().from_sandbox, 18);
        assert_eq!(records[1].byte_counts.as_ref().unwrap().to_sandbox, 19);
    }

    #[test]
    fn transparent_http_bytes_gate_egress_with_origin_policy() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-transparent-http")
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_method("GET")
                .http_path_prefix("/ok"),
        );
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(
                key,
                b"GET /ok HTTP/1.1\r\nHost: Example.COM\r\n\r\n",
                1_000,
                1_010,
            )
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.opened_egress);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::TransparentHttpDecision);
        assert_eq!(records[0].details["http_method"], "GET");
        assert_eq!(records[0].details["http_path"], "/ok");
        assert_eq!(records[0].hostname.as_deref(), Some("example.com"));
    }

    #[test]
    fn transparent_http_policy_denial_prevents_egress() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-get")
                .protocol(Protocol::Http)
                .hostname("example.com")
                .http_method("GET"),
        );
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );

        let result = forwarder
            .connect_and_bridge(
                key,
                b"POST /ok HTTP/1.1\r\nHost: Example.COM\r\n\r\n",
                1_000,
                1_010,
            )
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert!(!result.opened_egress);
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::TransparentHttpDecision);
        assert_eq!(record.details["http_method"], "POST");
    }

    #[test]
    fn tls_sni_dns_mismatch_from_stream_bytes_denies_before_egress() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let mut dns_cache = DnsCache::default();
        dns_cache.observe(
            "s1",
            "example.com",
            "A",
            vec!["203.0.113.42".parse().unwrap()],
            1_000,
            60_000,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );

        let result = forwarder
            .connect_and_bridge_with_dns_cache(
                key,
                &test_client_hello("evil.test"),
                2_000,
                2_010,
                &dns_cache,
            )
            .unwrap();
        assert_eq!(result.decision, Decision::DenyReset);
        assert_eq!(result.reason, Some(DenialReason::SniDnsMismatch));
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::SniDnsMismatchDenied);
        assert_eq!(record.hostname.as_deref(), Some("evil.test"));
    }

    #[test]
    fn hidden_sni_explicit_ip_port_allow_opens_egress() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-hidden-sni-ip")
                .protocol(Protocol::Tcp)
                .destination_cidr(Cidr::new("203.0.113.0".parse().unwrap(), 24))
                .destination_port(443),
        );
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"ok".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(key, &test_client_hello_without_sni(), 2_000, 2_010)
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.opened_egress);
        assert_eq!(forwarder.egress().opened().len(), 1);
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::TcpConnectDecision);
        assert_eq!(record.rule_id.as_deref(), Some("allow-hidden-sni-ip"));
        assert_eq!(record.details["tls_client_hello_error"], "missing_sni");
    }

    #[test]
    fn malformed_tls_client_hello_is_hidden_sni_denied_with_detail() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );
        let truncated = &test_client_hello("example.com")[..8];

        let result = forwarder
            .connect_and_bridge(key, truncated, 2_000, 2_010)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyReset);
        assert_eq!(result.reason, Some(DenialReason::HiddenSni));
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HiddenSniDenied);
        assert_eq!(record.details["tls_client_hello_error"], "truncated");
    }

    #[test]
    fn tls_client_hello_missing_sni_is_hidden_sni_denied() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            443,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );

        let result = forwarder
            .connect_and_bridge(key, &test_client_hello_without_sni(), 2_000, 2_010)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyReset);
        assert_eq!(result.reason, Some(DenialReason::HiddenSni));
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HiddenSniDenied);
    }

    #[test]
    fn denied_tcp_connect_does_not_open_egress() {
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(Vec::new()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"GET / HTTP/1.1\r\n\r\n", 1_000, 1_250)
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DefaultDeny));
        assert!(!result.opened_egress);
        assert!(forwarder.egress().opened().is_empty());
        let record = forwarder.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::TcpConnectDecision);
        assert_eq!(record.reason, Some(DenialReason::DefaultDeny));
    }

    #[derive(Clone, Debug)]
    struct FailingTcpEgress(TcpEgressError);

    impl TcpEgress for FailingTcpEgress {
        fn connect_and_exchange(
            &mut self,
            _destination: NetworkEndpoint,
            _from_sandbox: &[u8],
        ) -> Result<Vec<u8>, TcpEgressError> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn tcp_egress_error_is_audited_after_allow() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            FailingTcpEgress(TcpEgressError::ConnectFailed),
        );

        let error = forwarder
            .connect_and_bridge(key, b"hi", 1_000, 1_001)
            .unwrap_err();
        assert_eq!(error, TcpEgressError::ConnectFailed);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::TcpConnectDecision);
        assert_eq!(records[1].kind, AuditKind::BrokerError);
        assert_eq!(records[1].details["error"], "tcp_egress_connect_failed");
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
        test_client_hello_with_extensions(&extensions)
    }

    fn test_client_hello_without_sni() -> Vec<u8> {
        test_client_hello_with_extensions(&[])
    }

    fn test_client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(extensions);

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

    #[test]
    fn close_audit_backpressure_is_visible() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let key = FlowKey::tcp(
            "10.0.2.15".parse().unwrap(),
            40000,
            "203.0.113.42".parse().unwrap(),
            80,
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 1);
        let mut forwarder = TcpForwarder::new(
            "s1",
            broker,
            InMemoryTcpEgress::with_scripted_reply(b"ok".to_vec()),
        );

        let result = forwarder
            .connect_and_bridge(key, b"hi", 1_000, 1_001)
            .unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::AuditBackpressure));
        assert!(result.opened_egress);
        assert_eq!(result.byte_counts.from_sandbox, 2);
        assert_eq!(result.byte_counts.to_sandbox, 2);
        let records: Vec<_> = forwarder.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
    }
}
