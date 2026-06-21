use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::audit::Protocol;

/// Stable flow key for TCP or UDP traffic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    pub fn new(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
        }
    }
}

/// UDP classification used for default idle timeout and audit semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpClass {
    Dns,
    QuicCandidate,
    NtpLike,
    Generic,
}

impl UdpClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::QuicCandidate => "quic_candidate",
            Self::NtpLike => "ntp_like",
            Self::Generic => "generic",
        }
    }
}

/// Configurable UDP timeouts represented in deterministic harness ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTimeouts {
    pub dns: u64,
    pub generic: u64,
    pub quic: u64,
    pub ntp_like: u64,
}

impl Default for UdpTimeouts {
    fn default() -> Self {
        Self {
            dns: 10,
            generic: 60,
            quic: 180,
            ntp_like: 5,
        }
    }
}

impl UdpTimeouts {
    pub fn timeout_for(&self, class: UdpClass) -> u64 {
        match class {
            UdpClass::Dns => self.dns,
            UdpClass::Generic => self.generic,
            UdpClass::QuicCandidate => self.quic,
            UdpClass::NtpLike => self.ntp_like,
        }
    }
}

/// Active UDP pseudo-flow tracked by the harness flow manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFlow {
    pub key: FlowKey,
    pub class: UdpClass,
    pub created_at_tick: u64,
    pub last_seen_tick: u64,
    pub expires_at_tick: u64,
    pub bytes_from_sandbox: u64,
    pub bytes_from_host: u64,
}

/// Deterministic UDP pseudo-flow manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFlowTable {
    timeouts: UdpTimeouts,
    flows: BTreeMap<FlowKey, UdpFlow>,
}

impl UdpFlowTable {
    pub fn new(timeouts: UdpTimeouts) -> Self {
        Self {
            timeouts,
            flows: BTreeMap::new(),
        }
    }

    pub fn observe_from_sandbox(
        &mut self,
        key: FlowKey,
        class: UdpClass,
        now_tick: u64,
        byte_count: u64,
    ) -> bool {
        let timeout = self.timeouts.timeout_for(class);
        let created = !self.flows.contains_key(&key);
        let flow = self.flows.entry(key.clone()).or_insert_with(|| UdpFlow {
            key,
            class,
            created_at_tick: now_tick,
            last_seen_tick: now_tick,
            expires_at_tick: now_tick.saturating_add(timeout),
            bytes_from_sandbox: 0,
            bytes_from_host: 0,
        });
        flow.class = class;
        flow.last_seen_tick = now_tick;
        flow.expires_at_tick = now_tick.saturating_add(timeout);
        flow.bytes_from_sandbox = flow.bytes_from_sandbox.saturating_add(byte_count);
        created
    }

    pub fn observe_from_host(
        &mut self,
        key: &FlowKey,
        now_tick: u64,
        byte_count: u64,
    ) -> Result<(), String> {
        let flow = self
            .flows
            .get_mut(key)
            .ok_or_else(|| "host reply has no UDP pseudo-flow".to_string())?;
        let timeout = self.timeouts.timeout_for(flow.class);
        flow.last_seen_tick = now_tick;
        flow.expires_at_tick = now_tick.saturating_add(timeout);
        flow.bytes_from_host = flow.bytes_from_host.saturating_add(byte_count);
        Ok(())
    }

    pub fn expire(&mut self, now_tick: u64) -> Vec<UdpFlow> {
        let expired_keys = self
            .flows
            .iter()
            .filter_map(|(key, flow)| (flow.expires_at_tick < now_tick).then_some(key.clone()))
            .collect::<Vec<_>>();
        expired_keys
            .into_iter()
            .filter_map(|key| self.flows.remove(&key))
            .collect()
    }

    pub fn get(&self, key: &FlowKey) -> Option<&UdpFlow> {
        self.flows.get(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key() -> FlowKey {
        FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Udp,
        )
    }

    #[test]
    fn udp_flow_uses_class_timeout_and_byte_counts() {
        let mut table = UdpFlowTable::new(UdpTimeouts::default());
        assert!(table.observe_from_sandbox(key(), UdpClass::QuicCandidate, 1, 1200));
        assert!(!table.observe_from_sandbox(key(), UdpClass::QuicCandidate, 2, 10));
        let flow = table.get(&key()).unwrap();
        assert_eq!(flow.bytes_from_sandbox, 1210);
        assert_eq!(flow.expires_at_tick, 182);
        assert!(table.expire(181).is_empty());
        assert_eq!(table.expire(183).len(), 1);
    }

    #[test]
    fn host_reply_without_mapping_fails_closed_for_callers() {
        let mut table = UdpFlowTable::new(UdpTimeouts::default());
        assert!(table.observe_from_host(&key(), 1, 4).is_err());
    }
}
