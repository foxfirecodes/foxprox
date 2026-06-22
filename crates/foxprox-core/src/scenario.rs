use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::audit::{
    AttributionConfidence, AttributionSource, AuditRecord, Decision, EventKind, Frontend, Protocol,
};
use crate::dns::{DnsCache, DnsQuery, QueryType};
use crate::flow::{FlowKey, UdpFlowTable, UdpTimeouts};
use crate::origin::{
    classify_quic_candidate, parse_connect_target, parse_http_request, parse_socks5_connect_request,
};
use crate::packet::{
    checksum, parse_icmp_echo_request, parse_ipv4, parse_tcp, parse_udp, synthesize_icmp_echo_reply,
};
use crate::policy::{PolicyConfig, PolicyEngine, PolicyRequest, PolicyRule, RuleAction};
use crate::smoltcp_gate::feed_tcp_syn_to_smoltcp_listener;

/// Named deterministic harness scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioName {
    All,
    Policy,
    Dns,
    Proxy,
    Packets,
    Flows,
    Stack,
}

impl ScenarioName {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "all" => Ok(Self::All),
            "policy" => Ok(Self::Policy),
            "dns" => Ok(Self::Dns),
            "proxy" => Ok(Self::Proxy),
            "packets" => Ok(Self::Packets),
            "flows" => Ok(Self::Flows),
            "stack" => Ok(Self::Stack),
            other => Err(format!("unknown scenario '{other}'")),
        }
    }

    pub fn list() -> &'static [&'static str] {
        &["all", "policy", "dns", "proxy", "packets", "flows", "stack"]
    }
}

/// Run one or more deterministic lab scenarios and return structured audit records.
pub fn run_scenario(name: ScenarioName) -> Vec<AuditRecord> {
    match name {
        ScenarioName::All => {
            let mut records = Vec::new();
            for child in [
                ScenarioName::Policy,
                ScenarioName::Dns,
                ScenarioName::Proxy,
                ScenarioName::Packets,
                ScenarioName::Flows,
                ScenarioName::Stack,
            ] {
                records.extend(run_scenario(child));
            }
            records
        }
        ScenarioName::Policy => scenario_policy(),
        ScenarioName::Dns => scenario_dns(),
        ScenarioName::Proxy => scenario_proxy(),
        ScenarioName::Packets => scenario_packets(),
        ScenarioName::Flows => scenario_flows(),
        ScenarioName::Stack => scenario_stack(),
    }
}

fn scenario_policy() -> Vec<AuditRecord> {
    let engine = PolicyEngine::new(
        PolicyConfig::deny_by_default()
            .broker_dns(ip("10.0.2.1"))
            .allow_quic(true)
            .with_rule(
                PolicyRule::new("allow-example-https", RuleAction::Allow)
                    .protocol(Protocol::Tcp)
                    .domain_suffix("example.com")
                    .port(443)
                    .require_hostname_attribution(),
            )
            .with_rule(
                PolicyRule::new("deny-admin-http", RuleAction::DenyReset)
                    .protocol(Protocol::Http)
                    .hostname("example.com")
                    .http_path_prefix("/admin"),
            ),
    );
    let allowed = PolicyRequest::new("lab", Frontend::Tun, Protocol::Tcp)
        .with_destination(ip("93.184.216.34"), 443)
        .with_hostname("www.example.com", AttributionConfidence::Medium);
    let mut direct_dns =
        PolicyRequest::new("lab", Frontend::Tun, Protocol::Dns).with_destination(ip("1.1.1.1"), 53);
    direct_dns.is_direct_dns = true;
    let mut unsupported = PolicyRequest::new("lab", Frontend::Tun, Protocol::Unsupported);
    unsupported.is_unsupported = true;

    vec![
        record_policy(
            EventKind::TcpConnectAttempt,
            Protocol::Tcp,
            &engine,
            &allowed,
            Some(sock("10.0.2.2:50000")),
            Some(sock("93.184.216.34:443")),
        ),
        record_policy(
            EventKind::DnsQuery,
            Protocol::Dns,
            &engine,
            &direct_dns,
            Some(sock("10.0.2.2:50123")),
            Some(sock("1.1.1.1:53")),
        ),
        record_policy(
            EventKind::UnsupportedNetworkEvent,
            Protocol::Unsupported,
            &engine,
            &unsupported,
            None,
            None,
        ),
    ]
}

fn scenario_dns() -> Vec<AuditRecord> {
    let mut cache = DnsCache::new();
    let query = DnsQuery::new("Example.COM", QueryType::A).expect("fixture hostname valid");
    let answer = ip("93.184.216.34");
    cache
        .observe_response(&query.hostname, [answer], 1, 30)
        .expect("fixture response valid");
    let attr = cache
        .attribution_for(answer, 2)
        .expect("attribution present");
    vec![
        AuditRecord::new(
            EventKind::DnsQuery,
            "lab",
            Decision::Allow,
            "broker DNS query observed",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Dns)
        .with_addresses(Some(sock("10.0.2.2:53000")), Some(sock("10.0.2.1:53")))
        .with_hostname(
            Some(query.hostname),
            AttributionSource::DnsCache,
            AttributionConfidence::Medium,
        )
        .with_metadata("query_type", query.query_type.as_str()),
        AuditRecord::new(
            EventKind::TcpConnectAttempt,
            "lab",
            Decision::Allow,
            "DNS cache attribution available",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Tcp)
        .with_addresses(
            Some(sock("10.0.2.2:50001")),
            Some(SocketAddr::new(answer, 443)),
        )
        .with_hostname(Some(attr.hostname), attr.source, attr.confidence),
    ]
}

fn scenario_proxy() -> Vec<AuditRecord> {
    let http = parse_http_request(b"GET /public HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("fixture HTTP valid");
    let connect = parse_connect_target("example.com:443").expect("fixture CONNECT valid");
    let mut socks = vec![0x05, 0x01, 0x00, 0x03, 11];
    socks.extend_from_slice(b"example.com");
    socks.extend_from_slice(&443u16.to_be_bytes());
    let socks = parse_socks5_connect_request(&socks).expect("fixture SOCKS valid");
    vec![
        AuditRecord::new(
            EventKind::HttpRequest,
            "lab",
            Decision::Allow,
            "HTTP proxy request parsed",
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::Http)
        .with_addresses(None, Some(sock("93.184.216.34:80")))
        .with_hostname(
            Some(http.host),
            AttributionSource::ExplicitProxy,
            AttributionConfidence::High,
        )
        .with_metadata("method", http.method)
        .with_metadata("path", http.path),
        AuditRecord::new(
            EventKind::HttpsConnect,
            "lab",
            Decision::Allow,
            "HTTPS CONNECT parsed",
        )
        .with_frontend(Frontend::HttpProxy)
        .with_protocol(Protocol::HttpsConnect)
        .with_hostname(
            Some(connect.host),
            AttributionSource::ExplicitProxy,
            AttributionConfidence::High,
        )
        .with_metadata("port", connect.port.to_string()),
        AuditRecord::new(
            EventKind::SocksConnect,
            "lab",
            Decision::Allow,
            "SOCKS5 TCP CONNECT parsed",
        )
        .with_frontend(Frontend::Socks5)
        .with_protocol(Protocol::Socks)
        .with_hostname(
            Some(socks.destination_host),
            AttributionSource::ExplicitProxy,
            AttributionConfidence::High,
        )
        .with_metadata("port", socks.destination_port.to_string()),
    ]
}

fn scenario_packets() -> Vec<AuditRecord> {
    let icmp_request = icmp_echo_request_packet();
    let reply = synthesize_icmp_echo_reply(&icmp_request).expect("fixture ICMP reply");
    let parsed_reply = parse_ipv4(&reply).expect("reply IPv4 valid");
    parse_icmp_echo_request(parsed_reply.payload).expect_err("reply is not request");

    let quic_payload = [0xc3, 0, 0, 0, 1];
    let quic = classify_quic_candidate(443, &quic_payload);

    let malformed = {
        let mut pkt = ipv4_packet(17, &[0u8; 8]);
        pkt[6] = 0x20;
        pkt[10] = 0;
        pkt[11] = 0;
        let sum = crate::packet::checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        parse_ipv4(&pkt).unwrap_err()
    };

    vec![
        AuditRecord::new(
            EventKind::IcmpMessage,
            "lab",
            Decision::Allow,
            "synthetic ICMP echo reply generated",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Icmp)
        .with_addresses(Some(sock("10.0.2.1:0")), Some(sock("10.0.2.2:0")))
        .with_bytes(icmp_request.len() as u64, reply.len() as u64),
        AuditRecord::new(
            EventKind::QuicCandidateFlow,
            "lab",
            Decision::Allow,
            "UDP/443 long-header payload classified as QUIC candidate",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Quic)
        .with_metadata("quic_candidate", quic.to_string()),
        AuditRecord::new(
            EventKind::UnsupportedNetworkEvent,
            "lab",
            Decision::FailClosed,
            malformed,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Unsupported),
    ]
}

fn scenario_flows() -> Vec<AuditRecord> {
    let mut table = UdpFlowTable::new(UdpTimeouts::default());
    let key = FlowKey::new(
        ip("10.0.2.2"),
        50000,
        ip("93.184.216.34"),
        443,
        Protocol::Udp,
    );
    let created =
        table.observe_from_sandbox(key.clone(), crate::flow::UdpClass::QuicCandidate, 1, 1200);
    table
        .observe_from_host(&key, 2, 800)
        .expect("host reply maps to pseudo-flow");
    let expired = table.expire(200);
    vec![
        AuditRecord::new(
            EventKind::UdpFlowCreated,
            "lab",
            Decision::Allow,
            "UDP pseudo-flow observed",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Udp)
        .with_addresses(
            Some(sock("10.0.2.2:50000")),
            Some(sock("93.184.216.34:443")),
        )
        .with_metadata("created", created.to_string())
        .with_metadata("class", "quic_candidate"),
        AuditRecord::new(
            EventKind::UdpFlowExpired,
            "lab",
            Decision::Allow,
            "UDP pseudo-flow expired deterministically",
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(Protocol::Udp)
        .with_metadata("expired_count", expired.len().to_string()),
    ]
}

fn scenario_stack() -> Vec<AuditRecord> {
    let listen_ip = Ipv4Addr::new(203, 0, 113, 20);
    let source_ip = Ipv4Addr::new(10, 0, 2, 2);
    let syn = tcp_syn_packet(source_ip, listen_ip, 49152, 8080);
    let result = feed_tcp_syn_to_smoltcp_listener(syn, listen_ip, 8080)
        .expect("smoltcp TCP gate fixture should poll successfully");
    let emitted_syn_ack = result.emitted_packets.iter().any(|packet| {
        let Ok(ipv4) = parse_ipv4(packet) else {
            return false;
        };
        let Ok(tcp) = parse_tcp(ipv4.payload) else {
            return false;
        };
        ipv4.source == listen_ip
            && ipv4.destination == source_ip
            && tcp.source_port == 8080
            && tcp.destination_port == 49152
            && tcp.syn
            && tcp.ack
    });

    vec![AuditRecord::new(
        EventKind::TcpConnectAttempt,
        "lab",
        if emitted_syn_ack {
            Decision::Allow
        } else {
            Decision::FailClosed
        },
        if emitted_syn_ack {
            "smoltcp consumed a TUN-shaped TCP SYN and emitted a SYN-ACK"
        } else {
            "smoltcp did not emit the expected SYN-ACK"
        },
    )
    .with_frontend(Frontend::Tun)
    .with_protocol(Protocol::Tcp)
    .with_addresses(
        Some(sock("10.0.2.2:49152")),
        Some(sock("203.0.113.20:8080")),
    )
    .with_metadata(
        "socket_active_after_poll",
        result.socket_active_after_poll.to_string(),
    )
    .with_metadata("emitted_packets", result.emitted_packets.len().to_string())]
}

fn record_policy(
    kind: EventKind,
    protocol: Protocol,
    engine: &PolicyEngine,
    request: &PolicyRequest,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> AuditRecord {
    let outcome = engine.evaluate(request);
    AuditRecord::new(kind, &request.sandbox_id, outcome.decision, outcome.reason)
        .with_frontend(request.frontend)
        .with_protocol(protocol)
        .with_addresses(source, destination)
        .with_hostname(
            request.hostname.clone(),
            if request.hostname.is_some() {
                AttributionSource::DnsCache
            } else {
                AttributionSource::None
            },
            request.attribution_confidence,
        )
        .with_rule(outcome.rule_id)
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("fixture IP valid")
}

fn sock(value: &str) -> SocketAddr {
    value.parse().expect("fixture socket valid")
}

fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[10, 0, 2, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 2, 1]);
    packet[20..].copy_from_slice(payload);
    let sum = crate::packet::checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn tcp_syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let total_len = 40;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&64240_u16.to_be_bytes());
    let tcp_sum = tcp_checksum_ipv4(source, destination, tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
    packet
}

fn tcp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    checksum(&pseudo)
}

fn icmp_echo_request_packet() -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
    let sum = crate::packet::checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4_packet(1, &icmp)
}

#[allow(dead_code)]
fn _parse_fixture_packet_for_coverage(bytes: &[u8]) -> Result<(), String> {
    let ipv4 = parse_ipv4(bytes)?;
    match ipv4.protocol_number {
        6 => {
            let _ = parse_tcp(ipv4.payload)?;
        }
        17 => {
            let _ = parse_udp(ipv4.payload)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_scenario_emits_core_alpha_audit_events() {
        let records = run_scenario(ScenarioName::All);
        let events = records
            .iter()
            .map(|record| record.kind.as_str())
            .collect::<Vec<_>>();
        assert!(events.contains(&"tcp_connect_attempt"));
        assert!(events.contains(&"dns_query"));
        assert!(events.contains(&"http_request"));
        assert!(events.contains(&"https_connect"));
        assert!(events.contains(&"socks_connect"));
        assert!(events.contains(&"icmp_message"));
        assert!(events.contains(&"quic_candidate_flow"));
        assert!(events.contains(&"udp_flow_created"));
        assert!(events.contains(&"unsupported_network_event"));
    }

    #[test]
    fn scenario_json_lines_are_structured() {
        let records = run_scenario(ScenarioName::Policy);
        let lines = records
            .into_iter()
            .map(|record| record.to_json_line())
            .collect::<Vec<_>>();
        assert!(lines
            .iter()
            .any(|line| line.contains("\"decision\":\"allow\"")));
        assert!(lines
            .iter()
            .any(|line| line.contains("direct external DNS denied")));
    }

    #[test]
    fn cidr_is_available_for_harness_policy_rules() {
        let cidr = "93.184.216.0/24".parse::<crate::policy::Cidr>().unwrap();
        assert!(cidr.contains(ip("93.184.216.34")));
    }
}
