//! Reusable broker orchestration around core runtimes and packet devices.
//!
//! This crate deliberately starts with a synchronous, one-packet-at-a-time broker loop so the
//! harness can verify lifecycle decisions before production async integration adds pollers/tasks.

use std::net::{Ipv4Addr, SocketAddr};

use foxprox_core::audit::{
    AuditRecord, BoundedAuditBuffer, Decision, EventKind, Frontend, Protocol,
};
use foxprox_core::egress::EgressBackend;
use foxprox_core::policy::PolicyEngine;
use foxprox_core::runtime::{
    flush_audit_to_buffer, route_transparent_ipv4_packet, TransparentDnsRuntime,
    TransparentIcmpRuntime, TransparentPacketRoute, TransparentTcpRuntime, TransparentUdpRuntime,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerStep {
    pub packets_to_device: Vec<Vec<u8>>,
}

impl BrokerStep {
    fn none() -> Self {
        Self {
            packets_to_device: Vec::new(),
        }
    }

    fn maybe(packet: Option<Vec<u8>>) -> Self {
        Self {
            packets_to_device: packet.into_iter().collect(),
        }
    }
}

#[derive(Debug)]
pub struct TransparentBroker<U, T> {
    pub broker_dns: SocketAddr,
    pub dns: TransparentDnsRuntime,
    pub udp: TransparentUdpRuntime<U>,
    pub tcp: TransparentTcpRuntime<T>,
    pub icmp: TransparentIcmpRuntime,
    pub audit: Vec<AuditRecord>,
}

impl<U: EgressBackend, T: EgressBackend> TransparentBroker<U, T> {
    pub fn new(
        broker_dns: SocketAddr,
        dns_answers: impl IntoIterator<Item = (String, Ipv4Addr)>,
        udp_policy: PolicyEngine,
        udp_egress: U,
        tcp_policy: PolicyEngine,
        tcp_egress: T,
        icmp_policy: PolicyEngine,
    ) -> Self {
        Self {
            broker_dns,
            dns: TransparentDnsRuntime::new(dns_answers),
            udp: TransparentUdpRuntime::new(udp_policy, udp_egress),
            tcp: TransparentTcpRuntime::new(tcp_policy, tcp_egress),
            icmp: TransparentIcmpRuntime::new(icmp_policy),
            audit: Vec::new(),
        }
    }

    pub fn set_tick(&mut self, tick: u64) {
        self.dns.now_tick = tick;
        self.udp.now_tick = tick;
        self.tcp.now_tick = tick;
    }

    pub fn handle_ipv4_packet(
        &mut self,
        sandbox_id: impl Into<String>,
        packet: &[u8],
    ) -> Result<BrokerStep, String> {
        let sandbox_id = sandbox_id.into();
        let step = match route_transparent_ipv4_packet(packet, self.broker_dns) {
            Ok(TransparentPacketRoute::BrokerDns) => {
                let reply = self.dns.handle_ipv4_packet(&sandbox_id, packet)?;
                self.sync_dns_cache();
                BrokerStep::maybe(reply)
            }
            Ok(TransparentPacketRoute::Udp) => {
                BrokerStep::maybe(self.udp.handle_ipv4_packet(&sandbox_id, packet)?)
            }
            Ok(TransparentPacketRoute::Tcp) => {
                self.tcp.handle_ipv4_packet(&sandbox_id, packet)?;
                BrokerStep::none()
            }
            Ok(TransparentPacketRoute::Icmp) => {
                BrokerStep::maybe(self.icmp.handle_ipv4_packet(&sandbox_id, packet)?)
            }
            Ok(TransparentPacketRoute::Unsupported(protocol)) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UnsupportedNetworkEvent,
                        sandbox_id,
                        Decision::FailClosed,
                        "transparent broker dispatcher rejected unsupported packet protocol",
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(protocol),
                );
                BrokerStep::none()
            }
            Err(err) => {
                self.audit.push(
                    AuditRecord::new(
                        EventKind::UnsupportedNetworkEvent,
                        sandbox_id,
                        Decision::FailClosed,
                        format!("transparent broker dispatcher failed closed: {err}"),
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Unsupported),
                );
                BrokerStep::none()
            }
        };
        self.drain_runtime_audit();
        Ok(step)
    }

    pub fn flush_audit_to(&mut self, sink: &mut BoundedAuditBuffer) -> Result<usize, String> {
        flush_audit_to_buffer(&mut self.audit, sink)
    }

    fn sync_dns_cache(&mut self) {
        self.udp.dns_cache = self.dns.dns_cache.clone();
        self.tcp.dns_cache = self.dns.dns_cache.clone();
    }

    fn drain_runtime_audit(&mut self) {
        self.audit.append(&mut self.dns.audit);
        self.audit.append(&mut self.udp.audit);
        self.audit.append(&mut self.tcp.audit);
        self.audit.append(&mut self.icmp.audit);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use foxprox_core::audit::Decision;
    use foxprox_core::egress::{EgressOutcome, MockEgressBackend};
    use foxprox_core::packet::{checksum, parse_ipv4, parse_udp};
    use foxprox_core::policy::{PolicyConfig, PolicyRule, RuleAction};

    use super::*;

    #[test]
    fn broker_dispatches_udp_to_egress_and_returns_device_packet() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5354);
        let udp_policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-udp", RuleAction::Allow)
                    .protocol(Protocol::Udp)
                    .port(5354),
            ),
        );
        let udp_egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 12,
                message: "mock UDP forwarded".to_string(),
                response_payload: b"egress:probe".to_vec(),
            },
        );
        let mut broker = TransparentBroker::new(
            "10.0.2.1:53".parse().unwrap(),
            [],
            udp_policy,
            udp_egress,
            PolicyEngine::new(PolicyConfig::deny_by_default()),
            MockEgressBackend::new(),
            PolicyEngine::new(PolicyConfig::deny_by_default()),
        );

        let step = broker
            .handle_ipv4_packet(
                "lab",
                &udp_packet(destination.ip(), destination.port(), b"probe"),
            )
            .unwrap();

        assert_eq!(step.packets_to_device.len(), 1);
        let parsed = parse_ipv4(&step.packets_to_device[0]).unwrap();
        let udp = parse_udp(parsed.payload).unwrap();
        assert_eq!(udp.payload, b"egress:probe");
        assert_eq!(broker.audit.last().unwrap().decision, Decision::Allow);
    }

    #[test]
    fn broker_dns_answer_attributes_later_udp_flow() {
        let answer_ip = Ipv4Addr::new(203, 0, 113, 77);
        let destination = SocketAddr::new(IpAddr::V4(answer_ip), 5354);
        let udp_policy = PolicyEngine::new(
            PolicyConfig::deny_by_default().with_rule(
                PolicyRule::new("allow-attributed", RuleAction::Allow)
                    .protocol(Protocol::Udp)
                    .domain_suffix("example")
                    .port(5354)
                    .require_hostname_attribution(),
            ),
        );
        let udp_egress = MockEgressBackend::new().with_response(
            destination,
            EgressOutcome {
                connected: true,
                bytes_sent: 5,
                bytes_received: 2,
                message: "mock UDP forwarded".to_string(),
                response_payload: b"ok".to_vec(),
            },
        );
        let mut broker = TransparentBroker::new(
            "10.0.2.1:53".parse().unwrap(),
            [("lab.example".to_string(), answer_ip)],
            udp_policy,
            udp_egress,
            PolicyEngine::new(PolicyConfig::deny_by_default()),
            MockEgressBackend::new(),
            PolicyEngine::new(PolicyConfig::deny_by_default()),
        );
        broker.set_tick(2);

        let dns_step = broker
            .handle_ipv4_packet(
                "lab",
                &udp_packet(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
                    53,
                    &dns_a_query("lab.example"),
                ),
            )
            .unwrap();
        assert_eq!(dns_step.packets_to_device.len(), 1);

        let udp_step = broker
            .handle_ipv4_packet(
                "lab",
                &udp_packet(destination.ip(), destination.port(), b"probe"),
            )
            .unwrap();
        assert_eq!(udp_step.packets_to_device.len(), 1);
        let audit = broker.audit.last().unwrap();
        assert_eq!(audit.decision, Decision::Allow);
        assert_eq!(audit.hostname.as_deref(), Some("lab.example"));
    }

    fn udp_packet(destination: IpAddr, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let source = Ipv4Addr::new(10, 0, 2, 2);
        let destination = match destination {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("test destination must be IPv4"),
        };
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        packet[20..22].copy_from_slice(&49152_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn dns_a_query(hostname: &str) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234_u16.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in hostname.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }
}
