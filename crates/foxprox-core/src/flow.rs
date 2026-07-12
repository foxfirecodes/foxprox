//! Flow keys and timeout classes used by the broker flow manager.

use crate::event::Attribution;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Transport protocol for flow keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FlowProtocol {
    /// TCP flow.
    Tcp,
    /// UDP pseudo-flow.
    Udp,
}

/// Stable key for transparent TCP and UDP flow tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FlowKey {
    /// Sandbox-side source address.
    pub source_ip: IpAddr,
    /// Sandbox-side source port.
    pub source_port: u16,
    /// Destination address.
    pub destination_ip: IpAddr,
    /// Destination port.
    pub destination_port: u16,
    /// Transport protocol.
    pub protocol: FlowProtocol,
}

impl FlowKey {
    /// Creates a TCP flow key.
    pub const fn tcp(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Self {
        Self {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol: FlowProtocol::Tcp,
        }
    }

    /// Creates a UDP pseudo-flow key.
    pub const fn udp(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Self {
        Self {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol: FlowProtocol::Udp,
        }
    }
}

/// Timeout bucket for UDP pseudo-flow cleanup and policy decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FlowTimeoutClass {
    /// Broker-controlled DNS traffic.
    Dns,
    /// Generic UDP traffic.
    GenericUdp,
    /// QUIC candidate traffic, usually UDP/443.
    Quic,
    /// NTP-like one-shot traffic.
    OneShot,
}

impl FlowTimeoutClass {
    /// Recommended default timeout for the class.
    pub const fn default_duration(self) -> Duration {
        match self {
            Self::Dns => Duration::from_secs(10),
            Self::GenericUdp => Duration::from_secs(60),
            Self::Quic => Duration::from_secs(180),
            Self::OneShot => Duration::from_secs(5),
        }
    }
}

/// Runtime metadata for a UDP pseudo-flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowRecord {
    /// Stable UDP flow key.
    pub key: FlowKey,
    /// Timeout class selected for this pseudo-flow.
    pub timeout_class: FlowTimeoutClass,
    /// Hostname attribution available when the flow was created or updated.
    pub attribution: Attribution,
    /// Time the pseudo-flow was first observed.
    pub created_at: SystemTime,
    /// Time the pseudo-flow last saw traffic in either direction.
    pub last_activity: SystemTime,
    /// Bytes sent from sandbox to host.
    pub bytes_from_sandbox: u64,
    /// Bytes sent from host to sandbox.
    pub bytes_to_sandbox: u64,
}

impl UdpFlowRecord {
    /// Creates a new UDP pseudo-flow record.
    pub fn new(
        key: FlowKey,
        timeout_class: FlowTimeoutClass,
        attribution: Attribution,
        now: SystemTime,
    ) -> Self {
        Self {
            key,
            timeout_class,
            attribution,
            created_at: now,
            last_activity: now,
            bytes_from_sandbox: 0,
            bytes_to_sandbox: 0,
        }
    }

    /// Records sandbox-to-host bytes and refreshes activity time.
    pub fn record_sandbox_bytes(&mut self, bytes: usize, now: SystemTime) {
        self.bytes_from_sandbox = self.bytes_from_sandbox.saturating_add(bytes as u64);
        self.last_activity = now;
    }

    /// Records host-to-sandbox bytes and refreshes activity time.
    pub fn record_host_bytes(&mut self, bytes: usize, now: SystemTime) {
        self.bytes_to_sandbox = self.bytes_to_sandbox.saturating_add(bytes as u64);
        self.last_activity = now;
    }

    /// Returns true when this pseudo-flow has exceeded its timeout.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.last_activity) {
            Ok(elapsed) => elapsed >= self.timeout_class.default_duration(),
            Err(_) => false,
        }
    }
}

/// Small UDP pseudo-flow table with deterministic expiry behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UdpFlowTable {
    flows: HashMap<FlowKey, UdpFlowRecord>,
}

impl UdpFlowTable {
    /// Inserts a new pseudo-flow or updates an existing one with sandbox bytes.
    pub fn record_sandbox_datagram(
        &mut self,
        key: FlowKey,
        timeout_class: FlowTimeoutClass,
        attribution: Attribution,
        bytes: usize,
        now: SystemTime,
    ) -> &mut UdpFlowRecord {
        let record = self
            .flows
            .entry(key)
            .or_insert_with(|| UdpFlowRecord::new(key, timeout_class, attribution.clone(), now));
        record.timeout_class = timeout_class;
        record.attribution = attribution;
        record.record_sandbox_bytes(bytes, now);
        record
    }

    /// Records host-to-sandbox bytes for an existing pseudo-flow.
    pub fn record_host_datagram(
        &mut self,
        key: &FlowKey,
        bytes: usize,
        now: SystemTime,
    ) -> Option<&mut UdpFlowRecord> {
        let record = self.flows.get_mut(key)?;
        record.record_host_bytes(bytes, now);
        Some(record)
    }

    /// Looks up a pseudo-flow by key.
    pub fn get(&self, key: &FlowKey) -> Option<&UdpFlowRecord> {
        self.flows.get(key)
    }

    /// Returns expired pseudo-flow records without removing them.
    pub fn expired(&self, now: SystemTime) -> Vec<UdpFlowRecord> {
        self.flows
            .values()
            .filter(|record| record.is_expired(now))
            .cloned()
            .collect()
    }

    /// Removes one pseudo-flow by key.
    pub fn remove(&mut self, key: &FlowKey) -> Option<UdpFlowRecord> {
        self.flows.remove(key)
    }

    /// Removes expired pseudo-flows and returns the expired records.
    pub fn expire(&mut self, now: SystemTime) -> Vec<UdpFlowRecord> {
        let expired = self.expired(now);
        for record in &expired {
            self.flows.remove(&record.key);
        }
        expired
    }

    /// Returns the number of active pseudo-flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns true when no pseudo-flows are active.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_keys_distinguish_transport_protocols() {
        let source = "10.0.0.2".parse().unwrap();
        let destination = "93.184.216.34".parse().unwrap();
        assert_ne!(
            FlowKey::tcp(source, 40_000, destination, 443),
            FlowKey::udp(source, 40_000, destination, 443)
        );
    }

    #[test]
    fn udp_timeout_defaults_match_architecture_ranges() {
        assert_eq!(
            FlowTimeoutClass::Dns.default_duration(),
            Duration::from_secs(10)
        );
        assert_eq!(
            FlowTimeoutClass::GenericUdp.default_duration(),
            Duration::from_secs(60)
        );
        assert_eq!(
            FlowTimeoutClass::Quic.default_duration(),
            Duration::from_secs(180)
        );
    }

    #[test]
    fn udp_flow_table_tracks_bytes_and_expires() {
        let source = "10.0.0.2".parse().unwrap();
        let destination = "93.184.216.34".parse().unwrap();
        let key = FlowKey::udp(source, 40_000, destination, 443);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut table = UdpFlowTable::default();

        let record = table.record_sandbox_datagram(
            key,
            FlowTimeoutClass::Quic,
            Attribution::ip_only(),
            1200,
            now,
        );
        assert_eq!(record.bytes_from_sandbox, 1200);
        table
            .record_host_datagram(&key, 900, now + Duration::from_secs(1))
            .unwrap();

        let record = table.get(&key).unwrap();
        assert_eq!(record.bytes_to_sandbox, 900);
        assert!(table
            .expire(now + FlowTimeoutClass::Quic.default_duration())
            .is_empty());
        let expired = table.expire(now + Duration::from_secs(181));
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }
}
