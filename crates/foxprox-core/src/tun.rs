use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::packet::{synthesize_icmpv4_echo_reply, IpParseError, ParsedIpPacket};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::types::{AuditKind, Decision, DenialReason, Frontend, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub trait PacketDevice {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceIoError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceIoError {
    ReadFailed,
    WriteFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunPacketHarnessResult {
    pub parsed: Option<ParsedIpPacket>,
    pub decision: Decision,
    pub reason: Option<DenialReason>,
    pub wrote_packet: bool,
}

#[derive(Clone, Debug)]
pub struct TunPacketHarness<D> {
    sandbox_id: String,
    broker: BrokerCore,
    device: D,
}

impl<D: PacketDevice> TunPacketHarness<D> {
    pub fn new(sandbox_id: impl Into<String>, broker: BrokerCore, device: D) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            broker,
            device,
        }
    }

    pub fn process_next_packet(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<TunPacketHarnessResult>, DeviceIoError> {
        let Some(packet) = self.device.read_packet()? else {
            return Ok(None);
        };
        Ok(Some(self.process_packet(&packet, now_ms)?))
    }

    pub fn process_packet(
        &mut self,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<TunPacketHarnessResult, DeviceIoError> {
        let parsed = match ParsedIpPacket::parse(packet) {
            Ok(parsed) => parsed,
            Err(error) => return Ok(self.record_parse_failure(error, now_ms)),
        };

        let request = request_for_packet(&self.sandbox_id, &parsed);
        let observed = AuditRecord::new_at(
            AuditKind::PacketObserved,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_protocol(parsed.protocol)
        .with_source(parsed.source_endpoint())
        .with_destination(parsed.destination_endpoint())
        .with_detail("direction", "from_sandbox")
        .with_detail("ip_version", parsed.ip_version.to_string())
        .with_detail("packet_len", packet.len().to_string())
        .with_detail("payload_len", parsed.payload_len.to_string());
        if let Err(decision) = self.broker.append_audit_for(&request, observed) {
            return Ok(result_from_decision(Some(parsed), decision, false));
        }

        if parsed.ip_version == 4
            && parsed.protocol == Protocol::Icmp
            && parsed.icmp_type == Some(8)
        {
            let reply = match synthesize_icmpv4_echo_reply(packet) {
                Ok(reply) => reply,
                Err(error) => return Ok(self.record_parse_failure(error, now_ms)),
            };
            let reply_parsed = match ParsedIpPacket::parse_ipv4(&reply) {
                Ok(reply_parsed) => reply_parsed,
                Err(error) => return Ok(self.record_parse_failure(error, now_ms)),
            };
            let reply_request = request_for_packet(&self.sandbox_id, &reply_parsed);
            let write_audit = AuditRecord::new_at(
                AuditKind::PacketObserved,
                self.sandbox_id.clone(),
                now_ms as u128,
            )
            .with_frontend(Frontend::Tun)
            .with_protocol(Protocol::Icmp)
            .with_source(reply_parsed.source_endpoint())
            .with_destination(reply_parsed.destination_endpoint())
            .with_detail("direction", "to_sandbox")
            .with_detail("ip_version", reply_parsed.ip_version.to_string())
            .with_detail("packet_len", reply.len().to_string())
            .with_detail("write_back", "icmp_echo_reply");
            if let Err(decision) = self.broker.append_audit_for(&reply_request, write_audit) {
                return Ok(result_from_decision(Some(parsed), decision, false));
            }
            self.device.write_packet(&reply)?;
            return Ok(TunPacketHarnessResult {
                parsed: Some(parsed),
                decision: Decision::Allow,
                reason: None,
                wrote_packet: true,
            });
        }

        Ok(TunPacketHarnessResult {
            parsed: Some(parsed),
            decision: Decision::Allow,
            reason: None,
            wrote_packet: false,
        })
    }

    pub fn broker(&self) -> &BrokerCore {
        &self.broker
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn into_parts(self) -> (BrokerCore, D) {
        (self.broker, self.device)
    }

    fn record_parse_failure(&mut self, error: IpParseError, now_ms: u64) -> TunPacketHarnessResult {
        let request = PolicyRequest::unsupported(
            self.sandbox_id.clone(),
            Frontend::Tun,
            error.denial_reason(),
        );
        let audit = error
            .audit_record(self.sandbox_id.clone())
            .with_timestamp_ms(now_ms as u128);
        let decision = match self.broker.append_audit_for(&request, audit) {
            Ok(_) => PolicyDecision {
                decision: Decision::FailClosed,
                reason: Some(error.denial_reason()),
                rule_id: None,
                audit_kind: AuditKind::PacketMalformedDenied,
            },
            Err(decision) => decision,
        };
        result_from_decision(None, decision, false)
    }
}

fn request_for_packet(sandbox_id: &str, parsed: &ParsedIpPacket) -> PolicyRequest {
    let mut request = PolicyRequest::new(sandbox_id, Frontend::Tun, parsed.protocol)
        .with_destination(parsed.destination_endpoint());
    request.source = parsed.source_endpoint();
    request.icmp_type = parsed.icmp_type;
    request.icmp_code = parsed.icmp_code;
    request
}

fn result_from_decision(
    parsed: Option<ParsedIpPacket>,
    decision: PolicyDecision,
    wrote_packet: bool,
) -> TunPacketHarnessResult {
    TunPacketHarnessResult {
        parsed,
        decision: decision.decision,
        reason: decision.reason,
        wrote_packet,
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryPacketDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl InMemoryPacketDevice {
    pub fn with_inbound(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            inbound: packets.into_iter().collect(),
            outbound: Vec::new(),
        }
    }

    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    pub fn outbound(&self) -> &[Vec<u8>] {
        &self.outbound
    }
}

impl PacketDevice for InMemoryPacketDevice {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
        Ok(self.inbound.pop_front())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceIoError> {
        self.outbound.push(packet.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::checksum;
    use crate::policy::{PolicyConfig, PolicyEngine};
    use pretty_assertions::assert_eq;
    use std::net::IpAddr;

    #[test]
    fn valid_ipv4_udp_packet_emits_structured_packet_observed_audit() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x00, 0x35, 0, 8, 0, 0]);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.wrote_packet);
        let record = harness.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::PacketObserved);
        assert_eq!(record.frontend, Some(Frontend::Tun));
        assert_eq!(record.protocol, Some(Protocol::Udp));
        assert_eq!(record.source.as_ref().unwrap().port, Some(0x1234));
        assert_eq!(record.destination.as_ref().unwrap().port, Some(53));
        assert_eq!(record.details["direction"], "from_sandbox");
        assert_eq!(record.details["ip_version"], "4");
        assert_eq!(record.details["packet_len"], "28");
        assert_eq!(record.details["payload_len"], "8");
    }

    #[test]
    fn valid_ipv6_udp_packet_emits_ip_version_six_audit() {
        let packet = ipv6_packet(17, &[0x12, 0x34, 0x00, 0x35, 0, 8, 0, 0]);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_500).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let record = harness.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::PacketObserved);
        assert_eq!(record.protocol, Some(Protocol::Udp));
        assert_eq!(record.details["ip_version"], "6");
        assert_eq!(record.destination.as_ref().unwrap().port, Some(53));
    }

    #[test]
    fn malformed_packet_fails_closed_without_write() {
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([vec![0; 11]]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(2_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::MalformedPacket));
        assert!(!result.wrote_packet);
        assert!(harness.device().outbound().is_empty());
        let record = harness.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::PacketMalformedDenied);
        assert_eq!(record.reason, Some(DenialReason::MalformedPacket));
        assert_eq!(record.details["parse_error"], "unsupported_ip_version");
    }

    #[test]
    fn icmp_echo_request_writes_reply_after_write_back_audit() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i'];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(3_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.wrote_packet);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[1].details["direction"], "to_sandbox");
        assert_eq!(records[1].details["write_back"], "icmp_echo_reply");
        let reply = &harness.device().outbound()[0];
        let parsed = ParsedIpPacket::parse_ipv4(reply).unwrap();
        assert_eq!(parsed.source, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.destination, "10.0.2.15".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.icmp_type, Some(0));
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(checksum(&reply[20..]), 0);
    }

    #[test]
    fn write_back_audit_backpressure_prevents_unobserved_reply() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 1);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(4_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::FailClosed);
        assert_eq!(result.reason, Some(DenialReason::AuditBackpressure));
        assert!(harness.device().outbound().is_empty());
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::AuditBackpressure);
    }

    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn ipv4_packet(protocol: u8, flags_fragment: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 2, 15]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet[20..].copy_from_slice(payload);
        let csum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&csum.to_be_bytes());
        packet
    }
}
