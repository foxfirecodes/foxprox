use crate::audit::AuditRecord;
use crate::broker::BrokerCore;
use crate::packet::{synthesize_icmpv4_echo_reply, IpParseError, ParsedIpPacket};
use crate::policy::{PolicyDecision, PolicyRequest};
use crate::runtime::{RuntimeComponent, RuntimeTaskOutcome, RuntimeTaskStatus};
use crate::types::{AuditKind, Decision, DenialReason, Frontend, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub trait PacketDevice {
    /// Return one packet, `Ok(None)` when no packet is currently ready, or a
    /// fail-closed device error. Runtime adapters must make this operation
    /// nonblocking or time-bounded so cancellation can be observed between
    /// reads by `process_packet_loop_until`.
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), DeviceIoError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunPacketLoopReport {
    pub processed_packets: usize,
    pub error: Option<DeviceIoError>,
    pub task_outcome: RuntimeTaskOutcome,
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
        let packet = match self.device.read_packet() {
            Ok(Some(packet)) => packet,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.record_device_read_failure(now_ms);
                return Err(error);
            }
        };
        Ok(Some(self.process_packet(&packet, now_ms)?))
    }

    pub fn process_packet_loop(&mut self, now_ms: u64, max_packets: usize) -> TunPacketLoopReport {
        self.process_packet_loop_until(now_ms, max_packets, || false)
    }

    pub fn process_packet_loop_until(
        &mut self,
        now_ms: u64,
        max_packets: usize,
        mut should_cancel: impl FnMut() -> bool,
    ) -> TunPacketLoopReport {
        let mut processed_packets = 0usize;
        while processed_packets < max_packets {
            if should_cancel() {
                return TunPacketLoopReport {
                    processed_packets,
                    error: None,
                    task_outcome: tun_task_outcome(RuntimeTaskStatus::Cancelled),
                };
            }
            match self.process_next_packet(now_ms) {
                Ok(Some(_)) => processed_packets += 1,
                Ok(None) => {
                    return TunPacketLoopReport {
                        processed_packets,
                        error: None,
                        task_outcome: tun_task_outcome(RuntimeTaskStatus::Completed),
                    };
                }
                Err(error) => {
                    return TunPacketLoopReport {
                        processed_packets,
                        error: Some(error),
                        task_outcome: tun_task_outcome(RuntimeTaskStatus::Failed),
                    };
                }
            }
        }
        TunPacketLoopReport {
            processed_packets,
            error: None,
            task_outcome: tun_task_outcome(RuntimeTaskStatus::TimedOut),
        }
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

        let policy_decision = self.broker.evaluate(&request);
        if policy_decision.decision.is_deny() {
            return Ok(result_from_decision(Some(parsed), policy_decision, false));
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
            .with_detail("write_back", "icmp_echo_reply")
            .with_detail("write_phase", "attempt");
            if let Err(decision) = self.broker.append_audit_for(&reply_request, write_audit) {
                return Ok(result_from_decision(Some(parsed), decision, false));
            }
            match self.device.write_packet(&reply) {
                Ok(()) => {
                    return Ok(TunPacketHarnessResult {
                        parsed: Some(parsed),
                        decision: Decision::Allow,
                        reason: None,
                        wrote_packet: true,
                    });
                }
                Err(error) => {
                    let error_audit = AuditRecord::new_at(
                        AuditKind::BrokerError,
                        self.sandbox_id.clone(),
                        now_ms as u128,
                    )
                    .with_frontend(Frontend::Tun)
                    .with_protocol(Protocol::Icmp)
                    .with_source(reply_parsed.source_endpoint())
                    .with_destination(reply_parsed.destination_endpoint())
                    .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                    .with_detail("direction", "to_sandbox")
                    .with_detail("write_back", "icmp_echo_reply")
                    .with_detail("device_io_error", "write_failed");
                    let _ = self.broker.append_audit_for(&reply_request, error_audit);
                    return Err(error);
                }
            }
        }

        Ok(TunPacketHarnessResult {
            parsed: Some(parsed),
            decision: policy_decision.decision,
            reason: policy_decision.reason,
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

    fn record_device_read_failure(&mut self, now_ms: u64) {
        let request = PolicyRequest::unsupported(
            self.sandbox_id.clone(),
            Frontend::Tun,
            DenialReason::SetupFailed,
        );
        let audit = AuditRecord::new_at(
            AuditKind::BrokerError,
            self.sandbox_id.clone(),
            now_ms as u128,
        )
        .with_frontend(Frontend::Tun)
        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
        .with_detail("direction", "from_sandbox")
        .with_detail("device_io_error", "read_failed");
        let _ = self.broker.append_audit_for(&request, audit);
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

fn tun_task_outcome(status: RuntimeTaskStatus) -> RuntimeTaskOutcome {
    RuntimeTaskOutcome::new(RuntimeComponent::TunDevice, "tun_packet_loop", status)
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
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
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
        assert_eq!(record.destination.as_ref().unwrap().port, Some(12345));
        assert_eq!(record.details["direction"], "from_sandbox");
        assert_eq!(record.details["ip_version"], "4");
        assert_eq!(record.details["packet_len"], "28");
        assert_eq!(record.details["payload_len"], "8");
    }

    #[test]
    fn valid_ipv6_udp_packet_emits_ip_version_six_audit() {
        let packet = ipv6_packet(17, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_500).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let record = harness.broker().audit().records().next().unwrap();
        assert_eq!(record.kind, AuditKind::PacketObserved);
        assert_eq!(record.protocol, Some(Protocol::Udp));
        assert_eq!(record.details["ip_version"], "6");
        assert_eq!(record.destination.as_ref().unwrap().port, Some(12345));
    }

    #[test]
    fn default_denied_tun_packet_is_observed_then_denied_without_write() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(1_750).unwrap().unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::DefaultDeny));
        assert!(!result.wrote_packet);
        assert!(harness.device().outbound().is_empty());
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[1].kind, AuditKind::UdpPacketDecision);
        assert_eq!(records[1].reason, Some(DenialReason::DefaultDeny));
    }

    #[derive(Clone, Debug)]
    struct FailingReadDevice;

    impl PacketDevice for FailingReadDevice {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
            Err(DeviceIoError::ReadFailed)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), DeviceIoError> {
            Ok(())
        }
    }

    #[test]
    fn tun_read_failure_is_audited_fail_closed() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, FailingReadDevice);

        assert_eq!(
            harness.process_next_packet(1_000).unwrap_err(),
            DeviceIoError::ReadFailed
        );
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].frontend, Some(Frontend::Tun));
        assert_eq!(records[0].decision, Some(Decision::FailClosed));
        assert_eq!(records[0].reason, Some(DenialReason::SetupFailed));
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[0].details["device_io_error"], "read_failed");
    }

    #[test]
    fn tun_packet_loop_reports_read_failure_task_outcome() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let mut harness = TunPacketHarness::new("s1", broker, FailingReadDevice);

        let report = harness.process_packet_loop(1_000, 8);

        assert_eq!(report.processed_packets, 0);
        assert_eq!(report.error, Some(DeviceIoError::ReadFailed));
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Failed);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[0].kind, AuditKind::BrokerError);
        assert_eq!(records[0].details["device_io_error"], "read_failed");
    }

    #[test]
    fn tun_packet_loop_reports_idle_completion() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let report = harness.process_packet_loop(1_000, 8);

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Completed);
    }

    #[test]
    fn tun_packet_loop_reports_cancellation_before_idle_read() {
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = InMemoryPacketDevice::default();
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let report = harness.process_packet_loop_until(1_000, 8, || true);

        assert_eq!(report.processed_packets, 0);
        assert_eq!(report.error, None);
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Cancelled);
        assert!(harness.broker().audit().records().next().is_none());
    }

    #[test]
    fn tun_packet_loop_reports_external_cancellation() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = InMemoryPacketDevice::with_inbound([packet.clone(), packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);
        let mut checks = 0usize;

        let report = harness.process_packet_loop_until(1_000, 8, || {
            checks += 1;
            checks > 1
        });

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Cancelled);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, AuditKind::PacketObserved);
        assert_eq!(records[1].kind, AuditKind::UdpPacketDecision);
    }

    #[test]
    fn tun_packet_loop_reports_budget_timeout() {
        let packet = ipv4_packet(17, 0, &[0x12, 0x34, 0x30, 0x39, 0, 8, 0, 0]);
        let config = PolicyConfig {
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = InMemoryPacketDevice::with_inbound([packet.clone(), packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let report = harness.process_packet_loop(1_000, 1);

        assert_eq!(report.processed_packets, 1);
        assert_eq!(report.error, None);
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::TimedOut);
    }

    #[test]
    fn tun_packet_loop_reports_write_failure_task_outcome() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = FailingWritePacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let report = harness.process_packet_loop(3_250, 8);

        assert_eq!(report.processed_packets, 0);
        assert_eq!(report.error, Some(DeviceIoError::WriteFailed));
        assert_eq!(report.task_outcome.component, RuntimeComponent::TunDevice);
        assert_eq!(report.task_outcome.task_name, "tun_packet_loop");
        assert_eq!(report.task_outcome.status, RuntimeTaskStatus::Failed);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[3].kind, AuditKind::BrokerError);
        assert_eq!(records[3].details["device_io_error"], "write_failed");
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
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(3_000).unwrap().unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.wrote_packet);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].details["direction"], "from_sandbox");
        assert_eq!(records[1].kind, AuditKind::IcmpDecision);
        assert_eq!(records[1].decision, Some(Decision::Allow));
        assert_eq!(records[2].details["direction"], "to_sandbox");
        assert_eq!(records[2].details["write_back"], "icmp_echo_reply");
        let reply = &harness.device().outbound()[0];
        let parsed = ParsedIpPacket::parse_ipv4(reply).unwrap();
        assert_eq!(parsed.source, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.destination, "10.0.2.15".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.icmp_type, Some(0));
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(checksum(&reply[20..]), 0);
    }

    #[test]
    fn icmp_echo_write_failure_is_audited_without_success_claim() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let config = PolicyConfig {
            allow_ping: true,
            default_decision: Decision::Allow,
            ..PolicyConfig::default()
        };
        let broker = BrokerCore::new(PolicyEngine::new(config), 8);
        let device = FailingWritePacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let error = harness.process_next_packet(3_250).unwrap_err();
        assert_eq!(error, DeviceIoError::WriteFailed);
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records.len(), 4);
        assert_eq!(records[2].kind, AuditKind::PacketObserved);
        assert_eq!(records[2].details["direction"], "to_sandbox");
        assert_eq!(records[2].details["write_phase"], "attempt");
        assert_eq!(records[3].kind, AuditKind::BrokerError);
        assert_eq!(records[3].decision, Some(Decision::FailClosed));
        assert_eq!(records[3].details["device_io_error"], "write_failed");
        assert!(harness.device().outbound().is_empty());
    }

    #[test]
    fn icmp_echo_request_is_denied_when_ping_is_not_allowed() {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let icmp_checksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let packet = ipv4_packet(1, 0, &icmp);
        let broker = BrokerCore::new(PolicyEngine::new(PolicyConfig::default()), 4);
        let device = InMemoryPacketDevice::with_inbound([packet]);
        let mut harness = TunPacketHarness::new("s1", broker, device);

        let result = harness.process_next_packet(3_500).unwrap().unwrap();
        assert_eq!(result.decision, Decision::DenyDrop);
        assert_eq!(result.reason, Some(DenialReason::IcmpUnsupported));
        assert!(!result.wrote_packet);
        assert!(harness.device().outbound().is_empty());
        let records: Vec<_> = harness.broker().audit().records().collect();
        assert_eq!(records[1].kind, AuditKind::IcmpDecision);
        assert_eq!(records[1].reason, Some(DenialReason::IcmpUnsupported));
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

    #[derive(Clone, Debug, Default)]
    struct FailingWritePacketDevice {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
    }

    impl FailingWritePacketDevice {
        fn with_inbound(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                inbound: packets.into_iter().collect(),
                outbound: Vec::new(),
            }
        }

        fn outbound(&self) -> &[Vec<u8>] {
            &self.outbound
        }
    }

    impl PacketDevice for FailingWritePacketDevice {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, DeviceIoError> {
            Ok(self.inbound.pop_front())
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), DeviceIoError> {
            Err(DeviceIoError::WriteFailed)
        }
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
