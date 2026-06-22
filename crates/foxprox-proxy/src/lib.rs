//! Explicit proxy frontend helpers for foxprox.
//!
//! This crate turns proxy request bytes into normalized policy events, audit
//! evidence, and deterministic frontend response bytes. It does not own host
//! egress sockets; allowed requests are handed off to a future tunnel/egress
//! bridge after this preflight boundary succeeds.

#![forbid(unsafe_code)]

use foxprox_core::{
    AuditDecision, Endpoint, FrontendKind, NormalizedEvent, PolicyEngine, PolicyEvaluation,
    SandboxId, UnsupportedNetworkEvent,
};
use foxprox_inspect::parse_https_connect_request;

/// Result of one HTTP CONNECT preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectPreflight {
    pub evaluation: PolicyEvaluation,
    pub response: HttpProxyResponse,
}

/// Client-visible HTTP proxy response bytes for the preflight decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProxyResponse {
    ConnectionEstablished,
    Forbidden,
}

impl HttpProxyResponse {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::ConnectionEstablished => b"HTTP/1.1 200 Connection Established\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        }
    }
}

/// Minimal HTTP proxy frontend preflight handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProxyPreflight {
    policy: PolicyEngine,
}

impl HttpProxyPreflight {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    /// Parse and evaluate one HTTPS CONNECT request head.
    ///
    /// A successful allow decision produces a 200 response for the future tunnel
    /// bridge. Denied or malformed requests produce a 403 response and audit
    /// evidence; malformed requests are represented as fail-closed unsupported
    /// events so they do not bypass policy/audit.
    pub fn handle_connect_request(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
    ) -> HttpConnectPreflight {
        let event = parse_https_connect_request(
            sandbox_id.clone(),
            FrontendKind::HttpProxy,
            source,
            request_head,
        )
        .unwrap_or_else(|error| malformed_connect_event(sandbox_id, source, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let response = if evaluation.audit.decision == AuditDecision::Allowed {
            HttpProxyResponse::ConnectionEstablished
        } else {
            HttpProxyResponse::Forbidden
        };

        HttpConnectPreflight {
            evaluation,
            response,
        }
    }
}

fn malformed_connect_event(
    sandbox_id: SandboxId,
    source: Option<Endpoint>,
    reason: String,
) -> NormalizedEvent {
    NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
        sandbox_id,
        frontend: FrontendKind::HttpProxy,
        source,
        destination: None,
        reason: format!("malformed-https-connect: {reason}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_audit::audit_record_to_json_line;
    use foxprox_core::{
        AttributionConfidence, HostnamePattern, PolicyConfig, PolicyDecision, PolicyRule, Protocol,
        RuleAction,
    };
    use serde_json::Value;
    use std::net::Ipv4Addr;

    fn sandbox_id() -> SandboxId {
        SandboxId::new("proxy-test").unwrap()
    }

    fn source() -> Endpoint {
        Endpoint::tcp(Ipv4Addr::new(10, 0, 0, 2).into(), 49152)
    }

    fn allow_example_connect_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-connect", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::HttpsConnect)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_minimum_hostname_confidence(AttributionConfidence::High)
            .with_destination_port(443);
        PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
    }

    #[test]
    fn allowed_connect_preflight_emits_audit_and_200_response() {
        let handler = HttpProxyPreflight::new(allow_example_connect_policy());

        let result = handler.handle_connect_request(
            sandbox_id(),
            Some(source()),
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        );

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example-connect".to_owned())
            }
        );
        assert_eq!(result.response, HttpProxyResponse::ConnectionEstablished);
        assert_eq!(
            result.response.as_bytes(),
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );

        let audit: Value =
            serde_json::from_str(&audit_record_to_json_line(&result.evaluation.audit).unwrap())
                .unwrap();
        assert_eq!(audit["kind"], "https_connect");
        assert_eq!(audit["frontend"], "http_proxy");
        assert_eq!(audit["hostname"], "api.example.com");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(audit["rule_id"], "allow-example-connect");
    }

    #[test]
    fn denied_connect_preflight_emits_audit_and_403_response() {
        let handler = HttpProxyPreflight::new(allow_example_connect_policy());

        let result = handler.handle_connect_request(
            sandbox_id(),
            Some(source()),
            b"CONNECT blocked.invalid:443 HTTP/1.1\r\n\r\n",
        );

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(result.response, HttpProxyResponse::Forbidden);
        assert_eq!(
            result.response.as_bytes(),
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn malformed_connect_preflight_fails_closed_and_returns_403() {
        let handler = HttpProxyPreflight::new(allow_example_connect_policy());

        let result = handler.handle_connect_request(
            sandbox_id(),
            Some(source()),
            b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        );

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::FailClosed { .. }
        ));
        assert_eq!(result.evaluation.audit.decision, AuditDecision::FailClosed);
        assert_eq!(result.evaluation.audit.protocol, Protocol::Unsupported);
        assert_eq!(result.response, HttpProxyResponse::Forbidden);
        assert!(result
            .evaluation
            .audit
            .reason
            .as_deref()
            .unwrap()
            .contains("malformed-https-connect"));
    }
}
