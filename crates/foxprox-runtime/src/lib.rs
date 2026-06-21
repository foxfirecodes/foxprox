//! Runtime boundary traits for wiring verified core decisions to egress.
//!
//! This crate intentionally contains no Linux, bwrap, TUN, or smoltcp code yet.
//! Those integrations should implement these traits so policy/audit decisions
//! remain mandatory before host egress is attempted.

#![forbid(unsafe_code)]

use foxprox_core::{
    classify_udp, parse_dns_query, parse_ip_packet, synthesize_icmpv4_echo_reply,
    synthesize_udpv4_response, AuditSink, Decision, DecisionAction, DnsCache, DnsParseError,
    Endpoint, FlowKey, FlowTable, FrontendKind, HostnameAttribution, NormalizedEvent, PacketError,
    ParsedIpPacket, Protocol, QuicStatus, SandboxId, StaticDnsResolver, UdpFlow, Udpv4Packet,
    UnsupportedIpv4Protocol, VerificationKernel,
};
use std::io::{self, Read, Write};
use std::net::IpAddr;

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
        | NormalizedEvent::DnsPacketAttempt { .. }
        | NormalizedEvent::HttpRequest { .. }
        | NormalizedEvent::IcmpMessage { .. }
        | NormalizedEvent::MalformedNetworkEvent { .. }
        | NormalizedEvent::UnsupportedNetworkEvent { .. }
        | NormalizedEvent::SocksConnect { .. } => None,
    }
}

pub fn event_protocol(event: &NormalizedEvent) -> Protocol {
    event.to_policy_input().protocol
}

pub struct TunIcmpProofSession<T> {
    device: T,
    buffer: Vec<u8>,
}

impl<T> TunIcmpProofSession<T> {
    pub fn new(device: T, mtu: usize) -> Self {
        Self {
            device,
            buffer: vec![0; mtu],
        }
    }

    pub fn into_inner(self) -> T {
        self.device
    }
}

impl<T: Read + Write> TunIcmpProofSession<T> {
    pub fn run_once(&mut self) -> io::Result<TunPacketOutcome> {
        let bytes_read = self.device.read(&mut self.buffer)?;
        let packet = &self.buffer[..bytes_read];
        match tun_packet_reply(packet) {
            Ok(Some(reply)) => {
                self.device.write_all(&reply)?;
                Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
            }
            Ok(None) => unsupported_or_malformed_outcome(packet),
            Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunPacketOutcome {
    EchoReplyWritten {
        bytes: usize,
    },
    DroppedMalformed {
        error: PacketError,
    },
    DroppedMalformedDns,
    DroppedUnsupportedIpv4 {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    },
    UdpObserved {
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        payload_len: usize,
    },
    DnsResponseWritten {
        bytes: usize,
        cached: bool,
    },
}

pub fn handle_one_tun_packet<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match tun_packet_reply(packet) {
        Ok(Some(reply)) => {
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(None) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

pub fn handle_one_tun_packet_with_dns<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    resolver: &StaticDnsResolver,
    cache: &mut DnsCache,
    broker_dns: &[IpAddr],
    now_millis: u128,
) -> io::Result<TunPacketOutcome> {
    let bytes_read = reader.read(buffer)?;
    let packet = &buffer[..bytes_read];
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Udpv4Packet(udp)) => {
            let destination = IpAddr::V4(udp.destination);
            if udp.destination_port == 53 && broker_dns.contains(&destination) {
                return match handle_broker_dns_udp_packet(&udp, resolver, cache, now_millis) {
                    Ok(response) => {
                        writer.write_all(&response.packet)?;
                        Ok(TunPacketOutcome::DnsResponseWritten {
                            bytes: response.packet.len(),
                            cached: response.cached,
                        })
                    }
                    Err(_) => Ok(TunPacketOutcome::DroppedMalformedDns),
                };
            }
            unsupported_or_malformed_outcome(packet)
        }
        Ok(ParsedIpPacket::Icmpv4EchoRequest(request)) => {
            let reply = synthesize_icmpv4_echo_reply(&request);
            writer.write_all(&reply)?;
            Ok(TunPacketOutcome::EchoReplyWritten { bytes: reply.len() })
        }
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(_)) => unsupported_or_malformed_outcome(packet),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

fn unsupported_or_malformed_outcome(packet: &[u8]) -> io::Result<TunPacketOutcome> {
    match parse_ip_packet(packet) {
        Ok(ParsedIpPacket::Udpv4Packet(Udpv4Packet {
            source,
            destination,
            source_port,
            destination_port,
            payload,
        })) => Ok(TunPacketOutcome::UdpObserved {
            source: IpAddr::V4(source),
            destination: IpAddr::V4(destination),
            source_port,
            destination_port,
            payload_len: payload.len(),
        }),
        Ok(ParsedIpPacket::UnsupportedIpv4Protocol(UnsupportedIpv4Protocol {
            source,
            destination,
            protocol,
            ..
        })) => Ok(TunPacketOutcome::DroppedUnsupportedIpv4 {
            source: IpAddr::V4(source),
            destination: IpAddr::V4(destination),
            protocol,
        }),
        Ok(ParsedIpPacket::Icmpv4EchoRequest(_)) => unreachable!("echo requests produce replies"),
        Err(error) => Ok(TunPacketOutcome::DroppedMalformed { error }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerDnsUdpResponse {
    pub packet: Vec<u8>,
    pub cached: bool,
}

pub fn handle_broker_dns_udp_packet(
    packet: &Udpv4Packet<'_>,
    resolver: &StaticDnsResolver,
    cache: &mut DnsCache,
    now_millis: u128,
) -> Result<BrokerDnsUdpResponse, DnsParseError> {
    let dns_response = resolver.resolve_query_packet(packet.payload, now_millis)?;
    let cached = if let Some(observation) = dns_response.observation {
        cache.record(observation);
        true
    } else {
        false
    };
    Ok(BrokerDnsUdpResponse {
        packet: synthesize_udpv4_response(packet, &dns_response.packet),
        cached,
    })
}

pub fn record_udpv4_flow(
    table: &mut FlowTable,
    packet: &Udpv4Packet<'_>,
    broker_dns: &[IpAddr],
    now_millis: u128,
) -> UdpFlow {
    let source = Endpoint::new(IpAddr::V4(packet.source), packet.source_port);
    let destination = Endpoint::new(IpAddr::V4(packet.destination), packet.destination_port);
    let class = classify_udp(&destination, broker_dns);
    let key = FlowKey::new(Protocol::Udp, source, destination);
    table
        .upsert_udp(key, class, now_millis, (8 + packet.payload.len()) as u64)
        .clone()
}

pub fn udpv4_packet_to_event(sandbox_id: SandboxId, packet: &Udpv4Packet<'_>) -> NormalizedEvent {
    udpv4_packet_to_event_with_broker_dns(sandbox_id, packet, &[])
}

pub fn udpv4_packet_to_event_with_broker_dns(
    sandbox_id: SandboxId,
    packet: &Udpv4Packet<'_>,
    broker_dns: &[IpAddr],
) -> NormalizedEvent {
    let source = Endpoint::new(IpAddr::V4(packet.source), packet.source_port);
    let destination = Endpoint::new(IpAddr::V4(packet.destination), packet.destination_port);
    if destination.is_dns_port() {
        if broker_dns.contains(&destination.ip) {
            return match parse_dns_query(packet.payload) {
                Ok(question) => NormalizedEvent::DnsQuery {
                    sandbox_id,
                    frontend: FrontendKind::Tun,
                    source,
                    destination,
                    query: HostnameAttribution::broker_dns(question.hostname),
                },
                Err(_) => NormalizedEvent::MalformedNetworkEvent {
                    sandbox_id,
                    frontend: FrontendKind::Tun,
                    protocol: Protocol::Dns,
                },
            };
        }
        return NormalizedEvent::DnsPacketAttempt {
            sandbox_id,
            frontend: FrontendKind::Tun,
            source,
            destination,
        };
    }
    NormalizedEvent::UdpFlowAttempt {
        sandbox_id,
        frontend: FrontendKind::Tun,
        source,
        destination: destination.clone(),
        hostname: None,
        quic_status: if destination.is_quic_port() {
            QuicStatus::Candidate
        } else {
            QuicStatus::NotQuic
        },
    }
}

fn tun_packet_reply(packet: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    match parse_ip_packet(packet)? {
        ParsedIpPacket::Icmpv4EchoRequest(request) => {
            Ok(Some(synthesize_icmpv4_echo_reply(&request)))
        }
        ParsedIpPacket::Udpv4Packet(_) | ParsedIpPacket::UnsupportedIpv4Protocol(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxprox_core::{
        DecisionAction, DecisionReason, Hostname, PolicyConfig, PolicyEngine, PolicyRule, RuleSet,
        SniStatus, UdpClass, UdpTimeouts, VecAuditSink,
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

    struct FakeTunIo {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for FakeTunIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for FakeTunIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
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
    fn tun_icmp_proof_session_runs_one_packet_against_device_io() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let fake = FakeTunIo {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };
        let mut session = TunIcmpProofSession::new(fake, 1500);

        let outcome = session.run_once().unwrap();
        let fake = session.into_inner();

        assert_eq!(outcome, TunPacketOutcome::EchoReplyWritten { bytes: 28 });
        assert_eq!(fake.output[20], 0);
        assert_eq!(checksum(&fake.output[..20]), 0);
        assert_eq!(checksum(&fake.output[20..]), 0);
    }

    #[test]
    fn tun_echo_packet_writes_synthetic_reply() {
        let request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7, b'o', b'k']);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(outcome, TunPacketOutcome::EchoReplyWritten { bytes: 30 });
        assert_eq!(writer[9], 1);
        assert_eq!(&writer[12..16], &[10, 66, 0, 1]);
        assert_eq!(&writer[16..20], &[10, 66, 0, 2]);
        assert_eq!(writer[20], 0);
        assert_eq!(&writer[24..28], &[0x12, 0x34, 0, 7]);
        assert_eq!(&writer[28..], b"ok");
        assert_eq!(checksum(&writer[..20]), 0);
        assert_eq!(checksum(&writer[20..]), 0);
    }

    #[test]
    fn tun_packet_with_broker_dns_query_writes_dns_response() {
        let dns_payload = dns_query_payload();
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&((8 + dns_payload.len()) as u16).to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(&dns_payload);
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );
        let mut cache = DnsCache::new();

        let outcome = handle_one_tun_packet_with_dns(
            &mut reader,
            &mut writer,
            &mut buffer,
            &resolver,
            &mut cache,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        )
        .unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::DnsResponseWritten {
                bytes: writer.len(),
                cached: true,
            }
        );
        let ParsedIpPacket::Udpv4Packet(response_udp) = parse_ip_packet(&writer).unwrap() else {
            panic!("expected UDP response");
        };
        assert_eq!(response_udp.source_port, 53);
        assert_eq!(response_udp.destination_port, 53000);
        assert!(cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 101)
            .is_some());
    }

    #[test]
    fn tun_packet_with_malformed_broker_dns_query_drops_without_writeback() {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&11u16.to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(&[0, 1, 2]);
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();

        let outcome = handle_one_tun_packet_with_dns(
            &mut reader,
            &mut writer,
            &mut buffer,
            &resolver,
            &mut cache,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        )
        .unwrap();

        assert_eq!(outcome, TunPacketOutcome::DroppedMalformedDns);
        assert!(writer.is_empty());
        assert!(cache.observations().is_empty());
    }

    #[test]
    fn broker_dns_udp_handler_writes_response_and_caches_observation() {
        let dns_payload = dns_query_payload();
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &dns_payload,
        };
        let mut resolver = StaticDnsResolver::new(30);
        resolver.insert(
            Hostname::normalize("example.com").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );
        let mut cache = DnsCache::new();

        let response = handle_broker_dns_udp_packet(&packet, &resolver, &mut cache, 100).unwrap();

        assert!(response.cached);
        let ParsedIpPacket::Udpv4Packet(response_udp) = parse_ip_packet(&response.packet).unwrap()
        else {
            panic!("expected UDP response packet");
        };
        assert_eq!(response_udp.source, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(response_udp.destination, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(response_udp.source_port, 53);
        assert_eq!(response_udp.destination_port, 53000);
        assert!(cache
            .lookup_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 101)
            .is_some());
    }

    #[test]
    fn broker_dns_udp_handler_rejects_malformed_query_without_cache() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &[0, 1, 2],
        };
        let resolver = StaticDnsResolver::new(30);
        let mut cache = DnsCache::new();

        assert!(handle_broker_dns_udp_packet(&packet, &resolver, &mut cache, 100).is_err());
        assert!(cache.observations().is_empty());
    }

    #[test]
    fn udp_flow_recording_classifies_and_counts_datagrams() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: b"dns?",
        };
        let mut table = FlowTable::new();

        let flow = record_udpv4_flow(
            &mut table,
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            100,
        );
        assert_eq!(flow.class, UdpClass::BrokerDns);
        assert_eq!(flow.bytes_from_sandbox, 12);

        let flow = record_udpv4_flow(
            &mut table,
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            110,
        );
        assert_eq!(flow.bytes_from_sandbox, 24);
        assert_eq!(flow.last_seen_millis, 110);
    }

    #[test]
    fn udp_flow_recording_applies_quic_timeout_class() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let mut table = FlowTable::new();
        let flow = record_udpv4_flow(&mut table, &packet, &[], 0);
        assert_eq!(flow.class, UdpClass::QuicCandidate);

        assert!(table
            .expire_udp(121_000, &UdpTimeouts::default())
            .is_empty());
        assert_eq!(table.expire_udp(181_000, &UdpTimeouts::default()).len(), 1);
    }

    #[test]
    fn broker_dns_udp_packet_parses_query_for_audit_policy_event() {
        let dns_payload = dns_query_payload();
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &dns_payload,
        };
        let event = udpv4_packet_to_event_with_broker_dns(
            SandboxId::new("udp-policy").unwrap(),
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        );

        let NormalizedEvent::DnsQuery { query, .. } = event else {
            panic!("expected parsed DNS query event");
        };
        assert_eq!(query.hostname.as_str(), "example.com");
    }

    #[test]
    fn malformed_broker_dns_udp_packet_fails_closed_as_malformed() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(10, 66, 0, 1),
            source_port: 53000,
            destination_port: 53,
            payload: &[0, 1, 2],
        };
        let event = udpv4_packet_to_event_with_broker_dns(
            SandboxId::new("udp-policy").unwrap(),
            &packet,
            &[IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        );

        let decision =
            PolicyEngine::new(PolicyConfig::default()).evaluate(&event.to_policy_input());
        assert_eq!(decision.action, DecisionAction::FailClosed);
        assert_eq!(decision.reason, DecisionReason::MalformedInput);
    }

    #[test]
    fn udp_dns_packet_event_triggers_direct_dns_policy_denial() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(8, 8, 8, 8),
            source_port: 53000,
            destination_port: 53,
            payload: b"dns?",
        };
        let event = udpv4_packet_to_event(SandboxId::new("udp-policy").unwrap(), &packet);
        assert!(matches!(event, NormalizedEvent::DnsPacketAttempt { .. }));

        let decision = PolicyEngine::new(PolicyConfig {
            broker_dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
            ..PolicyConfig::default()
        })
        .evaluate(&event.to_policy_input());

        assert_eq!(decision.action, DecisionAction::RequireBrokerDns);
        assert_eq!(decision.reason, DecisionReason::DirectDnsBypass);
    }

    #[test]
    fn udp_443_packet_event_is_quic_candidate() {
        let packet = Udpv4Packet {
            source: Ipv4Addr::new(10, 66, 0, 2),
            destination: Ipv4Addr::new(93, 184, 216, 34),
            source_port: 53000,
            destination_port: 443,
            payload: b"quic?",
        };
        let event = udpv4_packet_to_event(SandboxId::new("udp-policy").unwrap(), &packet);
        let NormalizedEvent::UdpFlowAttempt { quic_status, .. } = event else {
            panic!("expected UDP flow event");
        };
        assert_eq!(quic_status, QuicStatus::Candidate);
    }

    #[test]
    fn tun_udp_packet_is_observed_without_writeback_until_forwarder_exists() {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&53000u16.to_be_bytes());
        udp_payload.extend_from_slice(&53u16.to_be_bytes());
        udp_payload.extend_from_slice(&12u16.to_be_bytes());
        udp_payload.extend_from_slice(&0u16.to_be_bytes());
        udp_payload.extend_from_slice(b"dns?");
        let request = build_ipv4_packet(17, &udp_payload);
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::UdpObserved {
                source: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                source_port: 53000,
                destination_port: 53,
                payload_len: 4,
            }
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn tun_unsupported_protocol_is_dropped_without_writeback() {
        let request = build_ipv4_packet(6, b"tcp-ish");
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert_eq!(
            outcome,
            TunPacketOutcome::DroppedUnsupportedIpv4 {
                source: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
                protocol: 6,
            }
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn tun_malformed_packet_is_dropped_without_writeback() {
        let mut request = build_ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 7]);
        request[10] = 0xff;
        let mut reader = std::io::Cursor::new(request);
        let mut writer = Vec::new();
        let mut buffer = [0u8; 1500];

        let outcome = handle_one_tun_packet(&mut reader, &mut writer, &mut buffer).unwrap();

        assert!(matches!(
            outcome,
            TunPacketOutcome::DroppedMalformed {
                error: PacketError::InvalidChecksum
            }
        ));
        assert!(writer.is_empty());
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

    fn dns_query_payload() -> Vec<u8> {
        let mut packet = vec![0x12, 0x34];
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn build_ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 66, 0, 1]);
        packet[20..].copy_from_slice(payload);
        if protocol == 1 {
            let icmp_checksum = checksum(&packet[20..]);
            packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        }
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if let Some(&remaining) = chunks.remainder().first() {
            sum += (remaining as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
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
