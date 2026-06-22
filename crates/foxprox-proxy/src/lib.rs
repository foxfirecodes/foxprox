//! Explicit proxy frontend helpers for foxprox.
//!
//! This crate turns proxy request bytes into normalized policy events, audit
//! evidence, and deterministic frontend response bytes. It does not own host
//! egress sockets; allowed requests are handed off to a future tunnel/egress
//! bridge after this preflight boundary succeeds.

#![forbid(unsafe_code)]

use std::io::Write;

use foxprox_core::{
    AuditDecision, Endpoint, FrontendKind, NormalizedEvent, PolicyEngine, PolicyEvaluation,
    SandboxId, UnsupportedNetworkEvent,
};
use foxprox_egress::{EgressError, TcpEgress, TcpEgressConnection, TcpTarget};
use foxprox_inspect::{
    parse_http_proxy_request, parse_https_connect_request, parse_socks5_connect_request,
};

/// Result of one plaintext HTTP proxy preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestPreflight {
    pub evaluation: PolicyEvaluation,
    pub action: HttpProxyAction,
}

/// Result of attempting to forward an allowed plaintext HTTP proxy request.
#[derive(Debug)]
pub struct HttpRequestForward {
    pub preflight: HttpRequestPreflight,
    pub connection: Option<TcpEgressConnection>,
    pub egress_error: Option<EgressError>,
}

/// Result of one HTTP CONNECT preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectPreflight {
    pub evaluation: PolicyEvaluation,
    pub response: HttpProxyResponse,
}

/// Result of attempting to establish an allowed HTTP CONNECT tunnel via host egress.
#[derive(Debug)]
pub struct HttpConnectTunnel {
    pub preflight: HttpConnectPreflight,
    pub connection: Option<TcpEgressConnection>,
    pub egress_error: Option<EgressError>,
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
    BadGateway,
}

impl HttpProxyResponse {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::ConnectionEstablished => b"HTTP/1.1 200 Connection Established\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
        }
    }
}

/// Result of one SOCKS5 CONNECT preflight evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ConnectPreflight {
    pub evaluation: PolicyEvaluation,
    pub response: Socks5Response,
}

/// Result of attempting to establish an allowed SOCKS5 CONNECT via host egress.
#[derive(Debug)]
pub struct Socks5ConnectTunnel {
    pub preflight: Socks5ConnectPreflight,
    pub connection: Option<TcpEgressConnection>,
    pub egress_error: Option<EgressError>,
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
        let (preflight, _, _) = self.evaluate_http_request(sandbox_id, source, request_head);
        preflight
    }

    /// Parse, authorize, connect host TCP egress, and write one plaintext HTTP
    /// proxy request head in origin-form to the upstream server.
    ///
    /// Policy denial or malformed input does not call egress. If policy allows
    /// but target extraction, connection, or upstream write fails, the returned
    /// preflight action is changed to `502 Bad Gateway` and the error is
    /// retained for diagnostics.
    pub fn forward_http_request<E: TcpEgress>(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
        egress: &E,
    ) -> HttpRequestForward {
        let (mut preflight, target, rewritten_request) =
            self.evaluate_http_request(sandbox_id, source, request_head);
        if preflight.evaluation.audit.decision != AuditDecision::Allowed {
            return HttpRequestForward {
                preflight,
                connection: None,
                egress_error: None,
            };
        }

        let (Some(target), Some(rewritten_request)) = (target, rewritten_request) else {
            preflight.action = HttpProxyAction::Respond(HttpProxyResponse::BadGateway);
            return HttpRequestForward {
                preflight,
                connection: None,
                egress_error: Some(EgressError::InvalidTarget(
                    "missing HTTP proxy target after allow".to_owned(),
                )),
            };
        };

        match egress.connect(&target) {
            Ok(mut connection) => match connection.stream_mut().write_all(&rewritten_request) {
                Ok(()) => HttpRequestForward {
                    preflight,
                    connection: Some(connection),
                    egress_error: None,
                },
                Err(error) => {
                    preflight.action = HttpProxyAction::Respond(HttpProxyResponse::BadGateway);
                    HttpRequestForward {
                        preflight,
                        connection: None,
                        egress_error: Some(EgressError::from(error)),
                    }
                }
            },
            Err(error) => {
                preflight.action = HttpProxyAction::Respond(HttpProxyResponse::BadGateway);
                HttpRequestForward {
                    preflight,
                    connection: None,
                    egress_error: Some(error),
                }
            }
        }
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
        let (preflight, _) = self.evaluate_connect_request(sandbox_id, source, request_head);
        preflight
    }

    /// Parse, authorize, and open host TCP egress for one HTTPS CONNECT request.
    ///
    /// Policy denial or malformed input does not call egress. If policy allows
    /// but the host connect fails, the returned preflight response is changed to
    /// `502 Bad Gateway` and the egress error is retained for diagnostics.
    pub fn establish_connect_tunnel<E: TcpEgress>(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
        egress: &E,
    ) -> HttpConnectTunnel {
        let (mut preflight, target) =
            self.evaluate_connect_request(sandbox_id, source, request_head);
        if preflight.evaluation.audit.decision != AuditDecision::Allowed {
            return HttpConnectTunnel {
                preflight,
                connection: None,
                egress_error: None,
            };
        }

        let Some(target) = target else {
            preflight.response = HttpProxyResponse::BadGateway;
            return HttpConnectTunnel {
                preflight,
                connection: None,
                egress_error: Some(EgressError::InvalidTarget(
                    "missing CONNECT target after allow".to_owned(),
                )),
            };
        };

        match egress.connect(&target) {
            Ok(connection) => HttpConnectTunnel {
                preflight,
                connection: Some(connection),
                egress_error: None,
            },
            Err(error) => {
                preflight.response = HttpProxyResponse::BadGateway;
                HttpConnectTunnel {
                    preflight,
                    connection: None,
                    egress_error: Some(error),
                }
            }
        }
    }

    fn evaluate_http_request(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
    ) -> (HttpRequestPreflight, Option<TcpTarget>, Option<Vec<u8>>) {
        let parsed = parse_http_proxy_request(
            sandbox_id.clone(),
            FrontendKind::HttpProxy,
            source,
            request_head,
        );
        let target = parsed.as_ref().ok().and_then(http_target_from_event);
        let rewritten_request = parsed
            .as_ref()
            .ok()
            .and_then(|event| rewrite_http_request_for_origin(event, request_head));
        let event = parsed
            .unwrap_or_else(|error| malformed_http_event(sandbox_id, source, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let action = if evaluation.audit.decision == AuditDecision::Allowed {
            HttpProxyAction::Forward
        } else {
            HttpProxyAction::Respond(HttpProxyResponse::Forbidden)
        };

        (
            HttpRequestPreflight { evaluation, action },
            target,
            rewritten_request,
        )
    }

    fn evaluate_connect_request(
        &self,
        sandbox_id: SandboxId,
        source: Option<Endpoint>,
        request_head: &[u8],
    ) -> (HttpConnectPreflight, Option<TcpTarget>) {
        let parsed = parse_https_connect_request(
            sandbox_id.clone(),
            FrontendKind::HttpProxy,
            source,
            request_head,
        );
        let target = parsed.as_ref().ok().and_then(connect_target_from_event);
        let event = parsed
            .unwrap_or_else(|error| malformed_connect_event(sandbox_id, source, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let response = if evaluation.audit.decision == AuditDecision::Allowed {
            HttpProxyResponse::ConnectionEstablished
        } else {
            HttpProxyResponse::Forbidden
        };

        (
            HttpConnectPreflight {
                evaluation,
                response,
            },
            target,
        )
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
        let (preflight, _) = self.evaluate_connect_request(sandbox_id, request);
        preflight
    }

    /// Parse, authorize, and open host TCP egress for one SOCKS5 CONNECT request.
    pub fn establish_connect_tunnel<E: TcpEgress>(
        &self,
        sandbox_id: SandboxId,
        request: &[u8],
        egress: &E,
    ) -> Socks5ConnectTunnel {
        let (mut preflight, target) = self.evaluate_connect_request(sandbox_id, request);
        if preflight.evaluation.audit.decision != AuditDecision::Allowed {
            return Socks5ConnectTunnel {
                preflight,
                connection: None,
                egress_error: None,
            };
        }

        let Some(target) = target else {
            preflight.response = Socks5Response::GeneralFailure;
            return Socks5ConnectTunnel {
                preflight,
                connection: None,
                egress_error: Some(EgressError::InvalidTarget(
                    "missing SOCKS5 target after allow".to_owned(),
                )),
            };
        };

        match egress.connect(&target) {
            Ok(connection) => Socks5ConnectTunnel {
                preflight,
                connection: Some(connection),
                egress_error: None,
            },
            Err(error) => {
                preflight.response = Socks5Response::GeneralFailure;
                Socks5ConnectTunnel {
                    preflight,
                    connection: None,
                    egress_error: Some(error),
                }
            }
        }
    }

    fn evaluate_connect_request(
        &self,
        sandbox_id: SandboxId,
        request: &[u8],
    ) -> (Socks5ConnectPreflight, Option<TcpTarget>) {
        let parsed =
            parse_socks5_connect_request(sandbox_id.clone(), FrontendKind::Socks5, request);
        let target = parsed.as_ref().ok().and_then(connect_target_from_event);
        let event =
            parsed.unwrap_or_else(|error| malformed_socks5_event(sandbox_id, error.to_string()));
        let evaluation = self.policy.evaluate(&event);
        let response = match evaluation.audit.decision {
            AuditDecision::Allowed => Socks5Response::Succeeded,
            AuditDecision::Denied => Socks5Response::ConnectionNotAllowedByRuleset,
            AuditDecision::FailClosed | AuditDecision::Observed => Socks5Response::GeneralFailure,
        };

        (
            Socks5ConnectPreflight {
                evaluation,
                response,
            },
            target,
        )
    }
}

fn connect_target_from_event(event: &NormalizedEvent) -> Option<TcpTarget> {
    match event {
        NormalizedEvent::HttpsConnect(connect) => {
            TcpTarget::new_host(&connect.host, connect.port).ok()
        }
        NormalizedEvent::SocksConnect(connect) => match connect.destination_ip {
            Some(ip) => TcpTarget::new_ip(ip, connect.port).ok(),
            None => TcpTarget::new_host(&connect.host, connect.port).ok(),
        },
        _ => None,
    }
}

fn http_target_from_event(event: &NormalizedEvent) -> Option<TcpTarget> {
    match event {
        NormalizedEvent::HttpRequest(request) => match request.destination {
            Some(destination) => TcpTarget::new_ip(destination.ip, request.port).ok(),
            None => TcpTarget::new_host(&request.host, request.port).ok(),
        },
        _ => None,
    }
}

fn rewrite_http_request_for_origin(
    event: &NormalizedEvent,
    request_head: &[u8],
) -> Option<Vec<u8>> {
    let NormalizedEvent::HttpRequest(request) = event else {
        return None;
    };
    let text = std::str::from_utf8(request_head).ok()?;
    let line_end = text.find("\r\n").or_else(|| text.find('\n'))?;
    let request_line = &text[..line_end];
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let _absolute_uri = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let rest = &request_head[line_end..];
    let mut rewritten = Vec::with_capacity(request_head.len());
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.extend_from_slice(b" ");
    rewritten.extend_from_slice(request.path_query.as_bytes());
    rewritten.extend_from_slice(b" ");
    rewritten.extend_from_slice(version.as_bytes());
    rewritten.extend_from_slice(rest);
    Some(rewritten)
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
        AttributionConfidence, DefaultPolicy, HostnamePattern, PolicyConfig, PolicyDecision,
        PolicyRule, Protocol, RuleAction,
    };
    use foxprox_egress::HostTcpEgress;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;
    use std::time::Duration;

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

    fn socks5_ipv4_connect(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&port.to_be_bytes());
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
    fn allowed_http_proxy_forward_opens_host_egress_and_rewrites_origin_form() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .unwrap();
            request
        });
        let handler = HttpProxyPreflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_secs(1)).unwrap();
        let request = format!(
            "GET http://127.0.0.1:{}/public/index.html?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port(),
            addr.port()
        );

        let mut forwarded =
            handler.forward_http_request(sandbox_id(), Some(source()), request.as_bytes(), &egress);

        assert_eq!(forwarded.preflight.action, HttpProxyAction::Forward);
        assert_eq!(forwarded.egress_error, None);
        let connection = forwarded
            .connection
            .as_mut()
            .expect("egress connection exists");
        let mut response = Vec::new();
        connection.stream_mut().read_to_end(&mut response).unwrap();
        let upstream_request = server.join().unwrap();
        let upstream_request = String::from_utf8(upstream_request).unwrap();
        assert!(upstream_request.starts_with("GET /public/index.html?x=1 HTTP/1.1\r\n"));
        assert!(!upstream_request.contains("GET http://127.0.0.1"));
        assert!(String::from_utf8(response).unwrap().contains("pong"));
    }

    #[test]
    fn denied_http_proxy_forward_does_not_call_egress() {
        struct PanicEgress;
        impl TcpEgress for PanicEgress {
            fn connect(&self, _target: &TcpTarget) -> Result<TcpEgressConnection, EgressError> {
                panic!("egress must not be called for denied HTTP proxy request")
            }
        }

        let handler = HttpProxyPreflight::new(allow_example_http_policy());
        let forwarded = handler.forward_http_request(
            sandbox_id(),
            Some(source()),
            b"POST http://api.example.com/private HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            &PanicEgress,
        );

        assert_eq!(
            forwarded.preflight.action,
            HttpProxyAction::Respond(HttpProxyResponse::Forbidden)
        );
        assert!(forwarded.connection.is_none());
        assert_eq!(forwarded.egress_error, None);
    }

    #[test]
    fn allowed_http_proxy_forward_returns_bad_gateway_when_egress_connect_fails() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let handler = HttpProxyPreflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_millis(100)).unwrap();
        let request = format!(
            "GET http://127.0.0.1:{}/public HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port(),
            addr.port()
        );

        let forwarded =
            handler.forward_http_request(sandbox_id(), Some(source()), request.as_bytes(), &egress);

        assert_eq!(
            forwarded.preflight.action,
            HttpProxyAction::Respond(HttpProxyResponse::BadGateway)
        );
        assert!(forwarded.connection.is_none());
        assert!(matches!(
            forwarded.egress_error,
            Some(EgressError::Connect { .. })
        ));
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
    fn allowed_connect_tunnel_opens_host_egress_and_bridges_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"pong").unwrap();
            request
        });
        let handler = HttpProxyPreflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_secs(1)).unwrap();
        let request = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", addr.port());

        let mut tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            Some(source()),
            request.as_bytes(),
            &egress,
        );

        assert_eq!(
            tunnel.preflight.response,
            HttpProxyResponse::ConnectionEstablished
        );
        assert_eq!(tunnel.egress_error, None);
        let connection = tunnel
            .connection
            .as_mut()
            .expect("egress connection exists");
        connection.stream_mut().write_all(b"ping").unwrap();
        let mut response = [0_u8; 4];
        connection.stream_mut().read_exact(&mut response).unwrap();
        let server_request = server.join().unwrap();
        assert_eq!(&server_request, b"ping");
        assert_eq!(&response, b"pong");
    }

    #[test]
    fn denied_connect_tunnel_does_not_call_egress() {
        struct PanicEgress;
        impl TcpEgress for PanicEgress {
            fn connect(&self, _target: &TcpTarget) -> Result<TcpEgressConnection, EgressError> {
                panic!("egress must not be called for denied preflight")
            }
        }

        let handler = HttpProxyPreflight::new(allow_example_connect_policy());
        let tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            Some(source()),
            b"CONNECT blocked.invalid:443 HTTP/1.1\r\n\r\n",
            &PanicEgress,
        );

        assert_eq!(tunnel.preflight.response, HttpProxyResponse::Forbidden);
        assert!(tunnel.connection.is_none());
        assert_eq!(tunnel.egress_error, None);
    }

    #[test]
    fn allowed_connect_tunnel_returns_bad_gateway_when_egress_connect_fails() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let handler = HttpProxyPreflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_millis(100)).unwrap();
        let request = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", addr.port());

        let tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            Some(source()),
            request.as_bytes(),
            &egress,
        );

        assert_eq!(tunnel.preflight.response, HttpProxyResponse::BadGateway);
        assert_eq!(
            tunnel.preflight.response.as_bytes(),
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(tunnel.connection.is_none());
        assert!(matches!(
            tunnel.egress_error,
            Some(EgressError::Connect { .. })
        ));
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

    #[test]
    fn allowed_socks5_tunnel_opens_host_egress_and_bridges_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"pong").unwrap();
            request
        });
        let handler = Socks5Preflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_secs(1)).unwrap();

        let mut tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            &socks5_ipv4_connect(Ipv4Addr::LOCALHOST, addr.port()),
            &egress,
        );

        assert_eq!(tunnel.preflight.response, Socks5Response::Succeeded);
        assert_eq!(tunnel.egress_error, None);
        let connection = tunnel
            .connection
            .as_mut()
            .expect("egress connection exists");
        connection.stream_mut().write_all(b"ping").unwrap();
        let mut response = [0_u8; 4];
        connection.stream_mut().read_exact(&mut response).unwrap();
        let server_request = server.join().unwrap();
        assert_eq!(&server_request, b"ping");
        assert_eq!(&response, b"pong");
    }

    #[test]
    fn denied_socks5_tunnel_does_not_call_egress() {
        struct PanicEgress;
        impl TcpEgress for PanicEgress {
            fn connect(&self, _target: &TcpTarget) -> Result<TcpEgressConnection, EgressError> {
                panic!("egress must not be called for denied SOCKS5 preflight")
            }
        }

        let handler = Socks5Preflight::new(allow_example_socks_policy());
        let tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            &socks5_domain_connect("blocked.invalid", 443),
            &PanicEgress,
        );

        assert_eq!(
            tunnel.preflight.response,
            Socks5Response::ConnectionNotAllowedByRuleset
        );
        assert!(tunnel.connection.is_none());
        assert_eq!(tunnel.egress_error, None);
    }

    #[test]
    fn allowed_socks5_tunnel_returns_general_failure_when_egress_connect_fails() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let handler = Socks5Preflight::new(PolicyEngine::new(PolicyConfig {
            default_policy: DefaultPolicy::Allow,
            ..PolicyConfig::default()
        }));
        let egress = HostTcpEgress::new(Duration::from_millis(100)).unwrap();

        let tunnel = handler.establish_connect_tunnel(
            sandbox_id(),
            &socks5_ipv4_connect(Ipv4Addr::LOCALHOST, addr.port()),
            &egress,
        );

        assert_eq!(tunnel.preflight.response, Socks5Response::GeneralFailure);
        assert!(tunnel.connection.is_none());
        assert!(matches!(
            tunnel.egress_error,
            Some(EgressError::Connect { .. })
        ));
    }
}
