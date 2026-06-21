use crate::broker::BrokerCore;
use crate::policy::PolicyDecision;
use crate::proxy::{
    malformed_proxy_request, parse_http_proxy_request, parse_socks5_connect_request,
    HttpProxyRequestMetadata, SocksConnectMetadata,
};
use crate::types::{Decision, DenialReason, Frontend};
use serde::{Deserialize, Serialize};

pub trait ExplicitProxyEgress {
    fn forward_http(
        &mut self,
        request: &HttpProxyRequestMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError>;

    fn connect_socks(
        &mut self,
        request: &SocksConnectMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyEgressError {
    SendFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitProxyResult {
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub forwarded: bool,
}

#[derive(Clone, Debug)]
pub struct ExplicitProxyFrontend<E> {
    sandbox_id: String,
    broker: BrokerCore,
    egress: E,
}

impl<E: ExplicitProxyEgress> ExplicitProxyFrontend<E> {
    pub fn new(sandbox_id: impl Into<String>, broker: BrokerCore, egress: E) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            egress,
        }
    }

    pub fn handle_http_proxy_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        let metadata = match parse_http_proxy_request(bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                let request =
                    malformed_proxy_request(self.sandbox_id.clone(), Frontend::HttpProxy, error);
                let decision = self.broker.evaluate(&request);
                return Ok(result_from_decision(decision, false));
            }
        };
        let request = metadata
            .clone()
            .into_policy_request(self.sandbox_id.clone());
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }
        self.egress.forward_http(&metadata, bytes)?;
        Ok(ExplicitProxyResult {
            decision: decision.decision,
            reason: decision.reason,
            forwarded: true,
        })
    }

    pub fn handle_socks5_connect_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<ExplicitProxyResult, ProxyEgressError> {
        let metadata = match parse_socks5_connect_request(bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                let request =
                    malformed_proxy_request(self.sandbox_id.clone(), Frontend::Socks5Proxy, error);
                let decision = self.broker.evaluate(&request);
                return Ok(result_from_decision(decision, false));
            }
        };
        let request = metadata
            .clone()
            .into_policy_request(self.sandbox_id.clone());
        let decision = self.broker.evaluate(&request);
        if decision.decision.is_deny() {
            return Ok(result_from_decision(decision, false));
        }
        self.egress.connect_socks(&metadata, bytes)?;
        Ok(ExplicitProxyResult {
            decision: decision.decision,
            reason: decision.reason,
            forwarded: true,
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
}

fn result_from_decision(decision: PolicyDecision, forwarded: bool) -> ExplicitProxyResult {
    ExplicitProxyResult {
        decision: decision.decision,
        reason: decision.reason,
        forwarded,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryExplicitProxyEgress {
    forwarded_http: Vec<(HttpProxyRequestMetadata, Vec<u8>)>,
    connected_socks: Vec<(SocksConnectMetadata, Vec<u8>)>,
}

impl InMemoryExplicitProxyEgress {
    pub fn forwarded_http(&self) -> &[(HttpProxyRequestMetadata, Vec<u8>)] {
        &self.forwarded_http
    }

    pub fn connected_socks(&self) -> &[(SocksConnectMetadata, Vec<u8>)] {
        &self.connected_socks
    }
}

impl ExplicitProxyEgress for InMemoryExplicitProxyEgress {
    fn forward_http(
        &mut self,
        request: &HttpProxyRequestMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        self.forwarded_http.push((request.clone(), bytes.to_vec()));
        Ok(())
    }

    fn connect_socks(
        &mut self,
        request: &SocksConnectMetadata,
        bytes: &[u8],
    ) -> Result<(), ProxyEgressError> {
        self.connected_socks.push((request.clone(), bytes.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyConfig, PolicyEngine, PolicyRule};
    use crate::types::{AuditKind, Protocol};
    use pretty_assertions::assert_eq;

    #[test]
    fn allowed_http_proxy_request_forwards_after_shared_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-http-proxy")
                .frontend(Frontend::HttpProxy)
                .protocol(Protocol::Http)
                .origin("http", "example.com", 80),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(
                b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(frontend.egress().forwarded_http().len(), 1);
        assert_eq!(frontend.egress().forwarded_http()[0].0.host, "example.com");
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpRequestDecision);
        assert_eq!(record.decision, Some(Decision::Allow));
        assert_eq!(record.rule_id.as_deref(), Some("allow-http-proxy"));
    }

    #[test]
    fn denied_https_connect_does_not_forward() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DefaultDeny));
        assert!(frontend.egress().forwarded_http().is_empty());
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::HttpsConnectDecision);
        assert_eq!(record.reason, Some(DenialReason::DefaultDeny));
    }

    #[test]
    fn malformed_http_proxy_request_fails_closed_without_forwarding() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());

        let result = frontend
            .handle_http_proxy_bytes(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::ProxyMalformed));
        assert!(frontend.egress().forwarded_http().is_empty());
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::UnsupportedDenied);
        assert_eq!(record.frontend, Some(Frontend::HttpProxy));
        assert_eq!(record.details["proxy_parse_error"], "missing_host");
    }

    #[test]
    fn allowed_socks_connect_forwards_after_shared_audit() {
        let mut config = PolicyConfig::default();
        config.rules.push(
            PolicyRule::allow("allow-socks")
                .frontend(Frontend::Socks5Proxy)
                .protocol(Protocol::Socks)
                .hostname("example.com")
                .destination_port(443),
        );
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut frontend =
            ExplicitProxyFrontend::new("s1", broker, InMemoryExplicitProxyEgress::default());
        let request = [
            0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ];

        let result = frontend.handle_socks5_connect_bytes(&request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.forwarded);
        assert_eq!(frontend.egress().connected_socks().len(), 1);
        assert_eq!(
            frontend.egress().connected_socks()[0]
                .0
                .destination_host
                .as_deref(),
            Some("example.com")
        );
        let record = frontend.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::SocksConnectDecision);
        assert_eq!(record.rule_id.as_deref(), Some("allow-socks"));
    }
}
