//! Runtime boundary traits for wiring verified core decisions to egress.
//!
//! This crate intentionally contains no Linux, bwrap, TUN, or smoltcp code yet.
//! Those integrations should implement these traits so policy/audit decisions
//! remain mandatory before host egress is attempted.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditSink, Decision, DecisionAction, Endpoint, FrontendKind, NormalizedEvent, Protocol,
    VerificationKernel,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpConnectRequest {
    pub frontend: FrontendKind,
    pub destination: Endpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagramRequest {
    pub frontend: FrontendKind,
    pub destination: Endpoint,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressError {
    ConnectFailed,
    SendFailed,
    UnsupportedProtocol,
}

pub trait HostEgress {
    fn open_tcp(&mut self, request: TcpConnectRequest) -> Result<(), EgressError>;
    fn send_udp(&mut self, request: UdpDatagramRequest) -> Result<(), EgressError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOutcome {
    Denied {
        decision: Decision,
    },
    EgressOpened {
        decision: Decision,
    },
    EgressFailed {
        decision: Decision,
        error: EgressError,
    },
    NotAnEgressEvent {
        decision: Decision,
    },
}

pub struct BrokerRuntime<E, S> {
    egress: E,
    kernel: VerificationKernel<S>,
}

impl<E, S> BrokerRuntime<E, S> {
    pub fn new(egress: E, kernel: VerificationKernel<S>) -> Self {
        Self { egress, kernel }
    }

    pub fn egress(&self) -> &E {
        &self.egress
    }

    pub fn into_parts(self) -> (E, VerificationKernel<S>) {
        (self.egress, self.kernel)
    }
}

impl<E: HostEgress, S: AuditSink> BrokerRuntime<E, S> {
    pub fn handle_event(
        &mut self,
        event: &NormalizedEvent,
        timestamp_millis: u128,
    ) -> RuntimeOutcome {
        let decision = self.kernel.decide_and_audit(event, timestamp_millis);
        if decision.action != DecisionAction::Allow {
            return RuntimeOutcome::Denied { decision };
        }
        match event_to_egress(event) {
            Some(EgressRequest::Tcp(request)) => match self.egress.open_tcp(request) {
                Ok(()) => RuntimeOutcome::EgressOpened { decision },
                Err(error) => RuntimeOutcome::EgressFailed { decision, error },
            },
            Some(EgressRequest::Udp(request)) => match self.egress.send_udp(request) {
                Ok(()) => RuntimeOutcome::EgressOpened { decision },
                Err(error) => RuntimeOutcome::EgressFailed { decision, error },
            },
            None => RuntimeOutcome::NotAnEgressEvent { decision },
        }
    }
}

enum EgressRequest {
    Tcp(TcpConnectRequest),
    Udp(UdpDatagramRequest),
}

fn event_to_egress(event: &NormalizedEvent) -> Option<EgressRequest> {
    match event {
        NormalizedEvent::TcpConnectAttempt {
            frontend,
            destination,
            ..
        } => Some(EgressRequest::Tcp(TcpConnectRequest {
            frontend: *frontend,
            destination: destination.clone(),
        })),
        NormalizedEvent::UdpFlowAttempt {
            frontend,
            destination,
            ..
        } => Some(EgressRequest::Udp(UdpDatagramRequest {
            frontend: *frontend,
            destination: destination.clone(),
            bytes: Vec::new(),
        })),
        NormalizedEvent::HttpsConnect { frontend, port, .. } => {
            Some(EgressRequest::Tcp(TcpConnectRequest {
                frontend: *frontend,
                destination: Endpoint::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    *port,
                ),
            }))
        }
        NormalizedEvent::SocksConnect {
            destination: Some(destination),
            ..
        } => Some(EgressRequest::Tcp(TcpConnectRequest {
            frontend: FrontendKind::Socks5,
            destination: destination.clone(),
        })),
        NormalizedEvent::DnsQuery { .. }
        | NormalizedEvent::HttpRequest { .. }
        | NormalizedEvent::IcmpMessage { .. }
        | NormalizedEvent::UnsupportedNetworkEvent { .. }
        | NormalizedEvent::SocksConnect { .. } => None,
    }
}

pub fn event_protocol(event: &NormalizedEvent) -> Protocol {
    event.to_policy_input().protocol
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        PolicyConfig, PolicyEngine, PolicyRule, RuleSet, SandboxId, SniStatus, VecAuditSink,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Default)]
    struct FakeEgress {
        tcp_attempts: usize,
        udp_attempts: usize,
    }

    impl HostEgress for FakeEgress {
        fn open_tcp(&mut self, _request: TcpConnectRequest) -> Result<(), EgressError> {
            self.tcp_attempts += 1;
            Ok(())
        }

        fn send_udp(&mut self, _request: UdpDatagramRequest) -> Result<(), EgressError> {
            self.udp_attempts += 1;
            Ok(())
        }
    }

    fn tcp_event() -> NormalizedEvent {
        NormalizedEvent::TcpConnectAttempt {
            sandbox_id: SandboxId::new("runtime").unwrap(),
            frontend: FrontendKind::Tun,
            source: None,
            destination: Endpoint::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            hostname: None,
            sni_status: SniStatus::Missing,
            sni_dns_mismatch: false,
        }
    }

    #[test]
    fn denied_events_do_not_reach_host_egress() {
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig::default()),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_event(&tcp_event(), 1);
        assert!(matches!(outcome, RuntimeOutcome::Denied { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 0);
    }

    #[test]
    fn allowed_tcp_event_reaches_host_egress_once() {
        let mut rules = RuleSet::default();
        let mut rule = PolicyRule::allow("allow-tcp");
        rule.protocol = Some(Protocol::Tcp);
        rules.push(rule);
        let kernel = VerificationKernel::new(
            PolicyEngine::new(PolicyConfig {
                rules,
                ..PolicyConfig::default()
            }),
            VecAuditSink::bounded(8),
        );
        let mut runtime = BrokerRuntime::new(FakeEgress::default(), kernel);
        let outcome = runtime.handle_event(&tcp_event(), 1);
        assert!(matches!(outcome, RuntimeOutcome::EgressOpened { .. }));
        assert_eq!(runtime.egress().tcp_attempts, 1);
    }
}
