use std::collections::VecDeque;
use std::net::IpAddr;

use crate::attribution::Hostname;
use crate::policy::{Decision, DenialReason, DenyBehavior};
use crate::types::{Endpoint, Frontend, HostnameConfidence, HostnameSource, Protocol, SandboxId};

/// Structured audit event. Serialization is intentionally left to outer crates;
/// the core owns a stable schema and required fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub kind: AuditEventKind,
    pub frontend: Option<Frontend>,
    pub protocol: Option<Protocol>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub hostname: Option<Hostname>,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
    pub decision: Option<AuditDecision>,
    pub rule_id: Option<String>,
    pub reason: Option<DenialReason>,
    pub byte_count: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPolicyContext {
    pub timestamp_millis: u64,
    pub sandbox_id: SandboxId,
    pub kind: AuditEventKind,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub destination: Option<Endpoint>,
    pub hostname: Option<Hostname>,
    pub hostname_source: HostnameSource,
    pub hostname_confidence: HostnameConfidence,
}

impl AuditEvent {
    pub fn from_policy_decision(context: AuditPolicyContext, decision: &Decision) -> Self {
        let (audit_decision, rule_id, reason) = match decision {
            Decision::Allow { rule_id } => (Some(AuditDecision::Allow), rule_id.clone(), None),
            Decision::Deny {
                behavior,
                reason,
                rule_id,
            } => (
                Some(AuditDecision::Deny {
                    behavior: *behavior,
                }),
                rule_id.clone(),
                Some(*reason),
            ),
            Decision::FailClosed { reason } => {
                (Some(AuditDecision::FailClosed), None, Some(*reason))
            }
        };

        Self {
            timestamp_millis: context.timestamp_millis,
            sandbox_id: context.sandbox_id,
            kind: context.kind,
            frontend: Some(context.frontend),
            protocol: Some(context.protocol),
            source: None,
            destination: context.destination,
            hostname: context.hostname,
            hostname_source: context.hostname_source,
            hostname_confidence: context.hostname_confidence,
            decision: audit_decision,
            rule_id,
            reason,
            byte_count: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuditEventKind {
    NetworkSessionStart,
    BrokerStart,
    TunConfigured,
    ProxyListenerConfigured,
    DnsQuery,
    TcpConnect,
    TcpFlowClosed,
    UdpFlowCreated,
    UdpPacket,
    UdpFlowExpired,
    QuicCandidateFlowCreated,
    IcmpMessage,
    HttpRequest,
    HttpsConnect,
    SocksConnect,
    TlsClientHello,
    UnsupportedNetworkEvent,
    PolicyReload,
    BrokerError,
    NetworkSessionExit,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    Allow,
    Deny { behavior: DenyBehavior },
    FailClosed,
}

/// Fixed-size audit queue. Pushing to a full queue reports backpressure and does
/// not allocate beyond the configured capacity.
#[derive(Clone, Debug)]
pub struct BoundedAuditBuffer {
    capacity: usize,
    queue: VecDeque<AuditEvent>,
}

impl BoundedAuditBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, event: AuditEvent) -> PushOutcome {
        if self.capacity == 0 || self.queue.len() == self.capacity {
            return PushOutcome::Backpressure { event };
        }
        self.queue.push_back(event);
        PushOutcome::Accepted
    }

    pub fn pop(&mut self) -> Option<AuditEvent> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PushOutcome {
    Accepted,
    Backpressure { event: AuditEvent },
}

/// Utility for audit callers that need to record a destination IP without a
/// port, such as unsupported packet events.
pub fn ip_endpoint(ip: IpAddr) -> Endpoint {
    Endpoint::new(ip, None)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::policy::{Decision, DenialReason, DenyBehavior};

    fn event(decision: Decision) -> AuditEvent {
        AuditEvent::from_policy_decision(
            AuditPolicyContext {
                timestamp_millis: 1,
                sandbox_id: SandboxId::new("sandbox-a"),
                kind: AuditEventKind::TcpConnect,
                frontend: Frontend::Tun,
                protocol: Protocol::Tcp,
                destination: Some(Endpoint::tcp(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    443,
                )),
                hostname: None,
                hostname_source: HostnameSource::None,
                hostname_confidence: HostnameConfidence::None,
            },
            &decision,
        )
    }

    #[test]
    fn audit_event_preserves_structured_denial_reason_and_behavior() {
        let audit = event(Decision::Deny {
            behavior: DenyBehavior::Reset,
            reason: DenialReason::DefaultDeny,
            rule_id: Some("default".into()),
        });

        assert_eq!(
            audit.decision,
            Some(AuditDecision::Deny {
                behavior: DenyBehavior::Reset,
            })
        );
        assert_eq!(audit.reason, Some(DenialReason::DefaultDeny));
        assert_eq!(audit.rule_id.as_deref(), Some("default"));
        assert_eq!(audit.protocol, Some(Protocol::Tcp));
        assert_eq!(audit.frontend, Some(Frontend::Tun));
    }

    #[test]
    fn audit_buffer_reports_backpressure_instead_of_growing_unbounded() {
        let mut buffer = BoundedAuditBuffer::new(1);
        assert_eq!(
            buffer.push(event(Decision::Allow { rule_id: None })),
            PushOutcome::Accepted
        );
        let rejected = event(Decision::FailClosed {
            reason: DenialReason::MalformedInput,
        });
        assert_eq!(
            buffer.push(rejected.clone()),
            PushOutcome::Backpressure { event: rejected }
        );
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.capacity(), 1);
    }
}
