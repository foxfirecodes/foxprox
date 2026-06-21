//! Structured audit event schema.

use crate::event::{
    Attribution, Frontend, Hostname, HttpMethod, Origin, Protocol, SandboxId, TransportEndpoint,
};
use crate::policy::Decision;
use std::time::{Duration, SystemTime};

/// Type of broker event recorded by audit output.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuditEventKind {
    /// Network session started.
    SessionStarted,
    /// Broker runtime started.
    BrokerStarted,
    /// TUN device configured for a session.
    TunConfigured,
    /// Proxy listener configured for a session.
    ProxyListenerConfigured,
    /// HTTP request was evaluated.
    HttpRequest,
    /// HTTPS CONNECT request was evaluated.
    HttpsConnect,
    /// Transparent plaintext HTTP request was evaluated.
    TransparentHttpRequest,
    /// TLS ClientHello SNI was observed.
    TlsClientHello,
    /// SNI and DNS attribution mismatch was denied.
    SniDnsMismatchDenied,
    /// Hidden-SNI/ECH-like case was denied.
    HiddenSniDenied,
    /// SOCKS CONNECT request was evaluated.
    SocksConnect,
    /// DNS query was evaluated.
    DnsQuery,
    /// TCP connect attempt was evaluated.
    TcpConnect,
    /// TCP flow closed.
    TcpFlowClosed,
    /// UDP flow was created.
    UdpFlowCreated,
    /// UDP packet was denied.
    UdpPacketDenied,
    /// UDP flow expired.
    UdpFlowExpired,
    /// QUIC candidate flow was created.
    QuicCandidateFlowCreated,
    /// ICMP message was evaluated.
    IcmpMessage,
    /// Unsupported packet or request was denied.
    UnsupportedDenied,
    /// Policy was reloaded.
    PolicyReload,
    /// Broker error occurred.
    BrokerError,
    /// Network session exited.
    SessionExited,
}

/// Structured audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Timestamp when the event was produced.
    pub timestamp: SystemTime,
    /// Sandbox/session identifier.
    pub sandbox_id: Option<SandboxId>,
    /// Frontend that produced the event.
    pub frontend: Frontend,
    /// Audit event kind.
    pub kind: AuditEventKind,
    /// Semantic protocol, when applicable.
    pub protocol: Option<Protocol>,
    /// Source transport endpoint, when applicable.
    pub source: Option<TransportEndpoint>,
    /// Destination transport endpoint, when applicable.
    pub destination: Option<TransportEndpoint>,
    /// Hostname associated with the event, when available.
    pub hostname: Option<Hostname>,
    /// Hostname attribution metadata, when available.
    pub attribution: Option<Attribution>,
    /// HTTP origin metadata, when available.
    pub origin: Option<Origin>,
    /// HTTP method metadata, when available.
    pub http_method: Option<HttpMethod>,
    /// HTTP path and query metadata, when available.
    pub path_and_query: Option<String>,
    /// Policy decision, when the event records a policy evaluation.
    pub decision: Option<Decision>,
    /// Bytes read from the sandbox side.
    pub bytes_from_sandbox: u64,
    /// Bytes written back to the sandbox side.
    pub bytes_to_sandbox: u64,
    /// Flow duration, when applicable.
    pub flow_duration: Option<Duration>,
    /// Human-readable detail for errors or setup messages.
    pub detail: Option<String>,
}

impl AuditEvent {
    /// Creates a minimal audit event with the current system timestamp.
    pub fn new(frontend: Frontend, kind: AuditEventKind) -> Self {
        Self {
            timestamp: SystemTime::now(),
            sandbox_id: None,
            frontend,
            kind,
            protocol: None,
            source: None,
            destination: None,
            hostname: None,
            attribution: None,
            origin: None,
            http_method: None,
            path_and_query: None,
            decision: None,
            bytes_from_sandbox: 0,
            bytes_to_sandbox: 0,
            flow_duration: None,
            detail: None,
        }
    }

    /// Returns a copy with sandbox identifier attached.
    pub fn with_sandbox_id(mut self, sandbox_id: SandboxId) -> Self {
        self.sandbox_id = Some(sandbox_id);
        self
    }

    /// Returns a copy with a policy decision attached.
    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Returns a copy with structured HTTP metadata attached.
    pub fn with_http_metadata(
        mut self,
        origin: Origin,
        method: HttpMethod,
        path_and_query: impl Into<String>,
    ) -> Self {
        self.origin = Some(origin);
        self.http_method = Some(method);
        self.path_and_query = Some(path_and_query.into());
        self
    }

    /// Returns a copy with source and destination endpoints attached.
    pub const fn with_endpoints(
        mut self,
        source: Option<TransportEndpoint>,
        destination: Option<TransportEndpoint>,
    ) -> Self {
        self.source = source;
        self.destination = destination;
        self
    }
}

/// Platform-independent audit sink configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub enum AuditSinkConfig {
    /// Emit JSON lines to standard output.
    #[default]
    StdoutJson,
    /// Emit JSON lines to standard error.
    StderrJson,
    /// Emit JSON lines to a file path.
    FileJsonLines {
        /// Filesystem path for the audit log.
        path: String,
    },
    /// Disable audit output. Useful only for tests; production profiles should audit.
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DecisionAction;

    #[test]
    fn audit_event_builder_attaches_decision_and_endpoints() {
        let source = TransportEndpoint::new("10.0.0.2".parse().unwrap(), 40_000);
        let destination = TransportEndpoint::new("93.184.216.34".parse().unwrap(), 80);
        let event = AuditEvent::new(Frontend::Tun, AuditEventKind::TcpConnect)
            .with_endpoints(Some(source), Some(destination))
            .with_decision(crate::policy::Decision::default_deny(
                DecisionAction::DenyReset,
            ));

        assert_eq!(event.source, Some(source));
        assert_eq!(event.destination, Some(destination));
        assert_eq!(
            event.decision.as_ref().map(|decision| decision.action),
            Some(DecisionAction::DenyReset)
        );
    }
}
