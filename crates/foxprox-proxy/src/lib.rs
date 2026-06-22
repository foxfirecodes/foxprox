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
use foxprox_inspect::{
    parse_http_proxy_request, parse_https_connect_request, parse_socks5_connect_request,
};

/// Result of one plaintext HTTP proxy preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestPreflight {
    pub evaluation: PolicyEvaluation,
    pub action: HttpProxyAction,
}

/// Result of one HTTP CONNECT preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectPreflight {
    pub evaluation: PolicyEvaluation,
    pub response: HttpProxyResponse,
}

/// Next frontend action after HTTP proxy preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProxyAction {
    Forward,
    Respond(HttpProxyResponse),
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

/// Result of one SOCKS5 CONNECT preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ConnectPreflight {
    pub evaluation: PolicyEvaluation,
    pub response: Socks5Response,
}

/// Client-visible SOCKS5 response bytes for the preflight decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Socks5Response {
    Succeeded,
    ConnectionNotAllowedByRuleset,
    GeneralFailure,
}

impl Socks5Response {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Succeeded => b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
            Self::ConnectionNotAllowedByRuleset => b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00",
            Self::GeneralFailure => b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00",
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

    /// Parse and evaluate one plaintext HTTP proxy request head.
    ///
    /// A successful allow decision returns [`HttpProxyAction::Forward`] for a
    /// future egress bridge. Denied or malformed requests return a 403 response
    /// and audit evidence; malformed requests are represented as fail-closed
    /// unsupported events so they do not bypass policy/audit.
    pub fn handle_http_request(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
    ) -> HttpRequestPreflight {
        let event = parse_http_proxy_request(
            sandbox_id.clone(),
            FrontendKind::HttpProxy,
            source,
            request_head,
        )
        .unwrap_or_else(|error| malformed_http_event(sandbox_id, source, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let action = if evaluation.audit.decision == AuditDecision::Allowed {
            HttpProxyAction::Forward
        } else {
            HttpProxyAction::Respond(HttpProxyResponse::Forbidden)
        };

        HttpRequestPreflight { evaluation, action }
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

/// Minimal SOCKS5 frontend preflight handler for CONNECT requests after method
/// negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Preflight {
    policy: PolicyEngine,
}

impl Socks5Preflight {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    /// Parse and evaluate one SOCKS5 CONNECT request message.
    ///
    /// Allowed decisions produce a SOCKS5 success reply for a future TCP bridge.
    /// Policy denials produce reply code 0x02, while malformed or unsupported
    /// request messages fail closed and produce general failure code 0x01.
    pub fn handle_connect_request(
        &self,
        sandbox_id: SandboxId,
        request: &[u8],
    ) -> Socks5ConnectPreflight {
        let event = parse_socks5_connect_request(sandbox_id.clone(), FrontendKind::Socks5, request)
            .unwrap_or_else(|error| malformed_socks5_event(sandbox_id, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let response = match evaluation.audit.decision {
            AuditDecision::Allowed => Socks5Response::Succeeded,
            AuditDecision::Denied => Socks5Response::ConnectionNotAllowedByRuleset,
            AuditDecision::FailClosed | AuditDecision::Observed => Socks5Response::GeneralFailure,
        };

        Socks5ConnectPreflight {
            evaluation,
            response,
        }
    }
}

fn malformed_http_event(
    sandbox_id: SandboxId,
    source: Option<Endpoint>,
    reason: String,
) -> NormalizedEvent {
    NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
        sandbox_id,
        frontend: FrontendKind::HttpProxy,
        source,
        destination: None,
        reason: format!("malformed-http-proxy-request: {reason}"),
    })
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

fn malformed_socks5_event(sandbox_id: SandboxId, reason: String) -> NormalizedEvent {
    NormalizedEvent::Unsupported(UnsupportedNetworkEvent {
        sandbox_id,
        frontend: FrontendKind::Socks5,
        source: None,
        destination: None,
        reason: format!("malformed-socks5-connect: {reason}"),
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

    fn allow_example_http_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-http", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Http)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_minimum_hostname_confidence(AttributionConfidence::High)
            .with_destination_port(80)
            .with_http_method("GET")
            .with_http_path_prefix("/public");
        PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
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

    fn allow_example_socks_policy() -> PolicyEngine {
        let rule = PolicyRule::new("allow-example-socks", RuleAction::Allow)
            .unwrap()
            .with_protocol(Protocol::Socks)
            .with_hostname(HostnamePattern::new(".example.com").unwrap())
            .with_minimum_hostname_confidence(AttributionConfidence::High)
            .with_destination_port(443);
        PolicyEngine::new(PolicyConfig {
            rules: vec![rule],
            ..PolicyConfig::default()
        })
    }

    fn socks5_domain_connect(hostname: &str, port: u16) -> Vec<u8> {
        let mut request = vec![5, 1, 0, 3, hostname.len() as u8];
        request.extend_from_slice(hostname.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    fn socks5_udp_associate() -> Vec<u8> {
        let mut request = socks5_domain_connect("api.example.com", 443);
        request[1] = 3;
        request
    }

    #[test]
    fn allowed_http_proxy_preflight_emits_audit_and_forward_action() {
        let handler = HttpProxyPreflight::new(allow_example_http_policy());

        let result = handler.handle_http_request(
            sandbox_id(),
            Some(source()),
            b"GET http://api.example.com/public/index.html?debug=1 HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n",
        );

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example-http".to_owned())
            }
        );
        assert_eq!(result.action, HttpProxyAction::Forward);

        let audit: Value =
            serde_json::from_str(&audit_record_to_json_line(&result.evaluation.audit).unwrap())
                .unwrap();
        assert_eq!(audit["kind"], "http_request");
        assert_eq!(audit["frontend"], "http_proxy");
        assert_eq!(audit["hostname"], "api.example.com");
        assert_eq!(audit["http_method"], "GET");
        assert_eq!(audit["http_scheme"], "http");
        assert_eq!(audit["http_path_query"], "/public/index.html?debug=1");
        assert_eq!(audit["decision"], "allowed");
    }

    #[test]
    fn denied_http_proxy_preflight_returns_403_response_action() {
        let handler = HttpProxyPreflight::new(allow_example_http_policy());

        let result = handler.handle_http_request(
            sandbox_id(),
            Some(source()),
            b"POST http://api.example.com/private HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        );

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(
            result.action,
            HttpProxyAction::Respond(HttpProxyResponse::Forbidden)
        );
    }

    #[test]
    fn malformed_http_proxy_preflight_fails_closed_and_returns_403_response_action() {
        let handler = HttpProxyPreflight::new(allow_example_http_policy());

        let result = handler.handle_http_request(
            sandbox_id(),
            Some(source()),
            b"GET /origin-form HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        );

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::FailClosed { .. }
        ));
        assert_eq!(result.evaluation.audit.protocol, Protocol::Unsupported);
        assert_eq!(
            result.action,
            HttpProxyAction::Respond(HttpProxyResponse::Forbidden)
        );
        assert!(result
            .evaluation
            .audit
            .reason
            .as_deref()
            .unwrap()
            .contains("malformed-http-proxy-request"));
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

    #[test]
    fn allowed_socks5_connect_preflight_emits_audit_and_success_response() {
        let handler = Socks5Preflight::new(allow_example_socks_policy());

        let result = handler
            .handle_connect_request(sandbox_id(), &socks5_domain_connect("api.example.com", 443));

        assert_eq!(
            result.evaluation.decision,
            PolicyDecision::Allow {
                rule_id: Some("allow-example-socks".to_owned())
            }
        );
        assert_eq!(result.response, Socks5Response::Succeeded);
        assert_eq!(
            result.response.as_bytes(),
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        );

        let audit: Value =
            serde_json::from_str(&audit_record_to_json_line(&result.evaluation.audit).unwrap())
                .unwrap();
        assert_eq!(audit["kind"], "socks_connect");
        assert_eq!(audit["frontend"], "socks5");
        assert_eq!(audit["hostname"], "api.example.com");
        assert_eq!(audit["decision"], "allowed");
        assert_eq!(audit["rule_id"], "allow-example-socks");
    }

    #[test]
    fn denied_socks5_connect_preflight_returns_ruleset_denied_response() {
        let handler = Socks5Preflight::new(allow_example_socks_policy());

        let result = handler
            .handle_connect_request(sandbox_id(), &socks5_domain_connect("blocked.invalid", 443));

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(
            result.response,
            Socks5Response::ConnectionNotAllowedByRuleset
        );
        assert_eq!(
            result.response.as_bytes(),
            b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn malformed_socks5_connect_preflight_fails_closed_with_general_failure() {
        let handler = Socks5Preflight::new(allow_example_socks_policy());

        let result = handler.handle_connect_request(sandbox_id(), &socks5_udp_associate());

        assert!(matches!(
            result.evaluation.decision,
            PolicyDecision::FailClosed { .. }
        ));
        assert_eq!(result.evaluation.audit.decision, AuditDecision::FailClosed);
        assert_eq!(result.evaluation.audit.protocol, Protocol::Unsupported);
        assert_eq!(result.response, Socks5Response::GeneralFailure);
        assert_eq!(
            result.response.as_bytes(),
            b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
        );
        assert!(result
            .evaluation
            .audit
            .reason
            .as_deref()
            .unwrap()
            .contains("malformed-socks5-connect"));
    }
}
