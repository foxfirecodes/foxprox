use crate::attribution::Hostname;
use crate::policy::{Decision, PolicyRequest};
use crate::types::{Endpoint, Frontend, Protocol, SandboxId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPermit {
    pub sandbox_id: SandboxId,
    pub frontend: Frontend,
    pub protocol: Protocol,
    pub destination: EgressDestination,
    pub rule_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressDestination {
    Ip(Endpoint),
    Host { hostname: Hostname, port: u16 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EgressPermitError {
    NotAllowed,
    MissingDestination,
    MissingPort,
    UnsupportedProtocol,
}

impl EgressPermit {
    pub fn from_policy_decision(
        request: &PolicyRequest,
        decision: &Decision,
    ) -> Result<Self, EgressPermitError> {
        let rule_id = match decision {
            Decision::Allow { rule_id } => rule_id.clone(),
            Decision::Deny { .. } | Decision::FailClosed { .. } => {
                return Err(EgressPermitError::NotAllowed);
            }
        };

        if matches!(request.protocol, Protocol::Unsupported(_)) {
            return Err(EgressPermitError::UnsupportedProtocol);
        }

        let destination = match request.destination {
            Some(endpoint) => EgressDestination::Ip(endpoint),
            None => {
                let hostname = request
                    .attribution
                    .hostname
                    .clone()
                    .ok_or(EgressPermitError::MissingDestination)?;
                let port = request
                    .requested_port
                    .ok_or(EgressPermitError::MissingPort)?;
                EgressDestination::Host { hostname, port }
            }
        };

        Ok(Self {
            sandbox_id: request.sandbox_id.clone(),
            frontend: request.frontend,
            protocol: request.protocol,
            destination,
            rule_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::attribution::{HostAttribution, Hostname};
    use crate::policy::{DenialReason, DenyBehavior};

    use super::*;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    #[test]
    fn allowed_ip_policy_decisions_create_egress_permits() {
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(ip([203, 0, 113, 10]), 443));
        let decision = Decision::Allow {
            rule_id: Some("allow-ip".into()),
        };

        let permit = EgressPermit::from_policy_decision(&request, &decision).unwrap();
        assert_eq!(permit.frontend, Frontend::Tun);
        assert_eq!(permit.protocol, Protocol::Tcp);
        assert_eq!(
            permit.destination,
            EgressDestination::Ip(Endpoint::tcp(ip([203, 0, 113, 10]), 443))
        );
        assert_eq!(permit.rule_id.as_deref(), Some("allow-ip"));
    }

    #[test]
    fn allowed_explicit_host_policy_decisions_create_authority_permits() {
        let hostname = Hostname::parse("secure.example.com").unwrap();
        let mut request = PolicyRequest::new(Protocol::HttpsConnect)
            .with_attribution(HostAttribution::explicit_proxy(hostname.clone()))
            .with_requested_port(443);
        request.frontend = Frontend::HttpProxy;
        let decision = Decision::Allow {
            rule_id: Some("allow-connect".into()),
        };

        let permit = EgressPermit::from_policy_decision(&request, &decision).unwrap();
        assert_eq!(permit.frontend, Frontend::HttpProxy);
        assert_eq!(permit.protocol, Protocol::HttpsConnect);
        assert_eq!(
            permit.destination,
            EgressDestination::Host {
                hostname,
                port: 443
            }
        );
        assert_eq!(permit.rule_id.as_deref(), Some("allow-connect"));
    }

    #[test]
    fn denied_or_fail_closed_decisions_cannot_create_egress_permits() {
        let request = PolicyRequest::new(Protocol::Tcp)
            .with_destination(Endpoint::tcp(ip([203, 0, 113, 10]), 443));
        assert_eq!(
            EgressPermit::from_policy_decision(
                &request,
                &Decision::Deny {
                    behavior: DenyBehavior::Drop,
                    reason: DenialReason::DefaultDeny,
                    rule_id: None,
                },
            ),
            Err(EgressPermitError::NotAllowed)
        );
        assert_eq!(
            EgressPermit::from_policy_decision(
                &request,
                &Decision::FailClosed {
                    reason: DenialReason::MalformedInput,
                },
            ),
            Err(EgressPermitError::NotAllowed)
        );
    }

    #[test]
    fn egress_permits_require_normalized_destination_metadata() {
        let request = PolicyRequest::new(Protocol::HttpsConnect).with_attribution(
            HostAttribution::explicit_proxy(Hostname::parse("secure.example.com").unwrap()),
        );
        assert_eq!(
            EgressPermit::from_policy_decision(&request, &Decision::Allow { rule_id: None }),
            Err(EgressPermitError::MissingPort)
        );

        let request = PolicyRequest::new(Protocol::Tcp);
        assert_eq!(
            EgressPermit::from_policy_decision(&request, &Decision::Allow { rule_id: None }),
            Err(EgressPermitError::MissingDestination)
        );
    }

    #[test]
    fn unsupported_protocols_cannot_create_egress_permits_even_if_allowed() {
        let request = PolicyRequest::new(Protocol::Unsupported(99))
            .with_destination(Endpoint::new(ip([203, 0, 113, 10]), None));
        assert_eq!(
            EgressPermit::from_policy_decision(&request, &Decision::Allow { rule_id: None }),
            Err(EgressPermitError::UnsupportedProtocol)
        );
    }
}
