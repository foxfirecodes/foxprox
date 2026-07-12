//! Platform-independent host egress request/trait boundary.
//!
//! Concrete host socket types live outside `foxprox-core`. These traits and
//! request objects let frontends, stack adapters, policy, and audit code agree
//! on what is being opened without importing `TcpStream`, `UdpSocket`, Tokio,
//! smoltcp, or Linux-specific APIs into core.

use crate::event::{Attribution, Frontend, Hostname, Protocol, SandboxId, TransportEndpoint};
use crate::flow::FlowTimeoutClass;
use crate::policy::Decision;
use std::fmt;
use std::time::Duration;

/// Common metadata for host egress attempts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressContext {
    /// Sandbox/session identifier.
    pub sandbox_id: SandboxId,
    /// Frontend that requested egress.
    pub frontend: Frontend,
    /// Policy decision associated with this egress attempt.
    ///
    /// Host implementations should fail closed unless this decision is allowed.
    pub decision: Decision,
    /// Hostname attribution associated with the flow/request.
    pub attribution: Attribution,
}

impl EgressContext {
    /// Returns true when the associated policy decision allows host egress.
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }
}

/// TCP host connect request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpEgressRequest {
    /// Common egress context.
    pub context: EgressContext,
    /// Sandbox-side source endpoint when known.
    pub source: Option<TransportEndpoint>,
    /// Host destination endpoint.
    pub destination: TransportEndpoint,
    /// Optional connect timeout.
    pub connect_timeout: Option<Duration>,
}

/// UDP host socket/datagram request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpEgressRequest {
    /// Common egress context.
    pub context: EgressContext,
    /// Sandbox-side source endpoint.
    pub source: TransportEndpoint,
    /// Host destination endpoint.
    pub destination: TransportEndpoint,
    /// UDP timeout class selected for this pseudo-flow.
    pub timeout_class: FlowTimeoutClass,
}

/// DNS upstream query request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsEgressRequest {
    /// Common egress context.
    pub context: EgressContext,
    /// Queried hostname.
    pub hostname: Hostname,
    /// DNS query type such as `A` or `AAAA`.
    pub query_type: String,
    /// Upstream DNS resolver endpoint.
    pub upstream: TransportEndpoint,
}

/// A successful host egress open/forwarding outcome suitable for audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressOutcome {
    /// Protocol opened or forwarded.
    pub protocol: Protocol,
    /// Host destination endpoint.
    pub destination: TransportEndpoint,
    /// Rule id that authorized the egress attempt, when available.
    pub rule_id: Option<String>,
}

/// Structured host egress failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressError {
    /// Error category.
    pub kind: EgressErrorKind,
    /// Human-readable detail for logs/audit.
    pub detail: String,
}

impl EgressError {
    /// Creates a new egress error.
    pub fn new(kind: EgressErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for EgressError {}

/// Host egress failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EgressErrorKind {
    /// Policy denied the attempt before host I/O.
    PolicyDenied,
    /// Host connect failed.
    ConnectFailed,
    /// Host read failed.
    ReadFailed,
    /// Host write failed.
    WriteFailed,
    /// Operation timed out.
    Timeout,
    /// Resource limit was reached.
    ResourceLimit,
    /// Protocol is not supported by this egress implementation.
    Unsupported,
}

/// Platform-specific TCP egress implementation.
pub trait TcpEgress {
    /// Concrete TCP stream type owned by the implementation.
    type Stream;

    /// Opens a host TCP stream for a policy-evaluated request.
    fn connect_tcp(&mut self, request: TcpEgressRequest) -> Result<Self::Stream, EgressError>;
}

/// Platform-specific UDP egress implementation.
pub trait UdpEgress {
    /// Concrete UDP flow/socket handle owned by the implementation.
    type Flow;

    /// Opens or retrieves a host UDP pseudo-flow for a policy-evaluated request.
    fn open_udp(&mut self, request: UdpEgressRequest) -> Result<Self::Flow, EgressError>;
}

/// Platform-specific DNS upstream implementation.
pub trait DnsEgress {
    /// Concrete DNS response type owned by the implementation.
    type Response;

    /// Performs an upstream DNS query for a policy-evaluated request.
    fn query_dns(&mut self, request: DnsEgressRequest) -> Result<Self::Response, EgressError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Decision;
    use std::net::IpAddr;

    fn context() -> EgressContext {
        EgressContext {
            sandbox_id: SandboxId::new("alpha").unwrap(),
            frontend: Frontend::Tun,
            decision: Decision::allow("allow-alpha"),
            attribution: Attribution::ip_only(),
        }
    }

    #[test]
    fn tcp_request_carries_authorization_and_destination() {
        let destination = TransportEndpoint::new(IpAddr::from([93, 184, 216, 34]), 80);
        let request = TcpEgressRequest {
            context: context(),
            source: None,
            destination,
            connect_timeout: Some(Duration::from_secs(5)),
        };
        assert_eq!(request.destination, destination);
        assert_eq!(request.context.frontend, Frontend::Tun);
        assert!(request.context.is_allowed());
    }

    #[test]
    fn egress_error_is_displayable() {
        let error = EgressError::new(EgressErrorKind::Timeout, "connect timed out");
        assert!(error.to_string().contains("connect timed out"));
    }
}
