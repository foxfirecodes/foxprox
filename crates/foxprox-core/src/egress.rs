use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::audit::{AuditRecord, Decision, EventKind, Frontend, Protocol};
use crate::policy::{PolicyEngine, PolicyOutcome, PolicyRequest};

/// Host egress operation requested by an allowed frontend event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressRequest {
    TcpConnect {
        destination: SocketAddr,
    },
    TcpStreamData {
        destination: SocketAddr,
        bytes: Vec<u8>,
    },
    UdpDatagram {
        destination: SocketAddr,
        bytes: Vec<u8>,
    },
    DnsQuery {
        destination: SocketAddr,
        wire_query: Vec<u8>,
    },
    HttpProxy {
        destination: SocketAddr,
        request_head: String,
    },
    SocksTcpConnect {
        destination: SocketAddr,
    },
}

impl EgressRequest {
    pub fn destination(&self) -> SocketAddr {
        match self {
            Self::TcpConnect { destination }
            | Self::TcpStreamData { destination, .. }
            | Self::UdpDatagram { destination, .. }
            | Self::DnsQuery { destination, .. }
            | Self::HttpProxy { destination, .. }
            | Self::SocksTcpConnect { destination } => *destination,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Self::TcpConnect { .. } | Self::TcpStreamData { .. } => Protocol::Tcp,
            Self::UdpDatagram { .. } => Protocol::Udp,
            Self::DnsQuery { .. } => Protocol::Dns,
            Self::HttpProxy { .. } => Protocol::Http,
            Self::SocksTcpConnect { .. } => Protocol::Socks,
        }
    }
}

/// Deterministic egress outcome for the harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressOutcome {
    pub connected: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub message: String,
    /// Optional response payload to send back through a transparent frontend.
    pub response_payload: Vec<u8>,
}

/// Synchronous host egress abstraction. Production crates can wrap async sockets behind a richer adapter.
pub trait EgressBackend {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String>;
}

/// Mock egress backend for local, no-network verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockEgressBackend {
    responses: BTreeMap<SocketAddr, EgressOutcome>,
    pub requests: Vec<EgressRequest>,
}

impl MockEgressBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(mut self, destination: SocketAddr, outcome: EgressOutcome) -> Self {
        self.responses.insert(destination, outcome);
        self
    }
}

impl EgressBackend for MockEgressBackend {
    fn execute(&mut self, request: &EgressRequest) -> Result<EgressOutcome, String> {
        self.requests.push(request.clone());
        self.responses
            .get(&request.destination())
            .cloned()
            .ok_or_else(|| format!("mock egress has no route for {}", request.destination()))
    }
}

/// Policy + egress + audit harness proving that all frontends share the same enforcement boundary.
#[derive(Debug)]
pub struct BrokerHarness<B> {
    pub policy: PolicyEngine,
    pub egress: B,
    pub audit: Vec<AuditRecord>,
}

impl<B: EgressBackend> BrokerHarness<B> {
    pub fn new(policy: PolicyEngine, egress: B) -> Self {
        Self {
            policy,
            egress,
            audit: Vec::new(),
        }
    }

    pub fn handle(
        &mut self,
        frontend: Frontend,
        event_kind: EventKind,
        policy_request: PolicyRequest,
        egress_request: Option<EgressRequest>,
    ) -> PolicyOutcome {
        let outcome = self.policy.evaluate(&policy_request);
        let mut record = AuditRecord::new(
            event_kind,
            &policy_request.sandbox_id,
            outcome.decision,
            &outcome.reason,
        )
        .with_frontend(frontend)
        .with_protocol(policy_request.protocol)
        .with_rule(outcome.rule_id.clone());

        if let (Some(source_ip), Some(source_port)) =
            (policy_request.source_ip, policy_request.source_port)
        {
            if let (Some(destination_ip), Some(destination_port)) = (
                policy_request.destination_ip,
                policy_request.destination_port,
            ) {
                record = record.with_addresses(
                    Some(SocketAddr::new(source_ip, source_port)),
                    Some(SocketAddr::new(destination_ip, destination_port)),
                );
            }
        }
        if let Some(hostname) = policy_request.hostname.clone() {
            record.hostname = Some(hostname);
            record.attribution_confidence = policy_request.attribution_confidence;
        }

        if outcome.decision.is_allow() {
            match egress_request {
                Some(request) => match self.egress.execute(&request) {
                    Ok(egress) => {
                        record = record
                            .with_bytes(egress.bytes_sent, egress.bytes_received)
                            .with_metadata("egress", egress.message);
                    }
                    Err(err) => {
                        record.decision = Decision::FailClosed;
                        record.reason = format!("egress failed closed: {err}");
                    }
                },
                None => {
                    record = record.with_metadata("egress", "not_required");
                }
            }
        }

        self.audit.push(record);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::audit::AttributionConfidence;
    use crate::policy::{PolicyConfig, PolicyRule, RuleAction};

    use super::*;

    #[test]
    fn broker_harness_uses_policy_before_mock_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-example", RuleAction::Allow)
                    .protocol(Protocol::Tcp)
                    .hostname("example.com")
                    .port(443),
            ),
        );
        let egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 7,
                message: "mock connected".to_string(),
                response_payload: Vec::new(),
            },
        );
        let mut harness = BrokerHarness::new(policy, egress);
        let req = PolicyRequest::new("lab", Frontend::Tun, Protocol::Tcp)
            .with_source(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)), 50000)
            .with_destination(destination.ip(), destination.port())
            .with_hostname("example.com", AttributionConfidence::High);
        let outcome = harness.handle(
            Frontend::Tun,
            EventKind::TcpConnectAttempt,
            req,
            Some(EgressRequest::TcpConnect { destination }),
        );
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(harness.egress.requests.len(), 1);
        assert_eq!(harness.audit[0].bytes_out, 7);
    }

    #[test]
    fn denied_request_never_reaches_egress() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443);
        let policy = PolicyEngine::new(PolicyConfig::deny_by_default());
        let mut harness = BrokerHarness::new(policy, MockEgressBackend::new());
        let req = PolicyRequest::new("lab", Frontend::HttpProxy, Protocol::HttpsConnect)
            .with_destination(destination.ip(), destination.port());
        let outcome = harness.handle(
            Frontend::HttpProxy,
            EventKind::HttpsConnect,
            req,
            Some(EgressRequest::TcpConnect { destination }),
        );
        assert_eq!(outcome.decision, Decision::DenyReset);
        assert!(harness.egress.requests.is_empty());
    }
}
