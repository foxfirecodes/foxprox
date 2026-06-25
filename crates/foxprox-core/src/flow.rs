use crate::types::{Endpoint, FlowKey, Protocol};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UdpClass {
    BrokerDns,
    DirectDnsBypass,
    QuicCandidate,
    MulticastOrBroadcast,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpTimeouts {
    pub dns: Duration,
    pub generic: Duration,
    pub quic: Duration,
    pub one_shot: Duration,
}

impl Default for UdpTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(10),
            generic: Duration::from_secs(60),
            quic: Duration::from_secs(180),
            one_shot: Duration::from_secs(5),
        }
    }
}

impl UdpTimeouts {
    pub fn timeout_for(&self, class: UdpClass) -> Duration {
        match class {
            UdpClass::BrokerDns | UdpClass::DirectDnsBypass => self.dns,
            UdpClass::QuicCandidate => self.quic,
            UdpClass::MulticastOrBroadcast => self.one_shot,
            UdpClass::Generic => self.generic,
        }
    }
}

pub fn classify_udp(destination: &Endpoint, broker_dns: &[std::net::IpAddr]) -> UdpClass {
    if destination.is_multicast_or_broadcast() {
        return UdpClass::MulticastOrBroadcast;
    }
    if destination.is_dns_port() {
        if broker_dns.contains(&destination.ip) {
            UdpClass::BrokerDns
        } else {
            UdpClass::DirectDnsBypass
        }
    } else if destination.is_quic_port() {
        UdpClass::QuicCandidate
    } else {
        UdpClass::Generic
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFlow {
    pub key: FlowKey,
    pub class: UdpClass,
    pub created_at_millis: u128,
    pub last_seen_millis: u128,
    pub bytes_from_sandbox: u64,
    pub bytes_to_sandbox: u64,
}

impl UdpFlow {
    pub fn new(key: FlowKey, class: UdpClass, now_millis: u128) -> Self {
        debug_assert_eq!(key.protocol, Protocol::Udp);
        Self {
            key,
            class,
            created_at_millis: now_millis,
            last_seen_millis: now_millis,
            bytes_from_sandbox: 0,
            bytes_to_sandbox: 0,
        }
    }

    pub fn record_sandbox_datagram(&mut self, now_millis: u128, bytes: u64) {
        self.last_seen_millis = now_millis;
        self.bytes_from_sandbox = self.bytes_from_sandbox.saturating_add(bytes);
    }

    pub fn record_host_datagram(&mut self, now_millis: u128, bytes: u64) {
        self.last_seen_millis = now_millis;
        self.bytes_to_sandbox = self.bytes_to_sandbox.saturating_add(bytes);
    }

    pub fn expired_at(&self, now_millis: u128, timeouts: &UdpTimeouts) -> bool {
        let timeout = timeouts.timeout_for(self.class).as_millis();
        now_millis.saturating_sub(self.last_seen_millis) > timeout
    }
}

#[derive(Clone, Debug, Default)]
pub struct FlowTable {
    udp: HashMap<FlowKey, UdpFlow>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_udp(
        &mut self,
        key: FlowKey,
        class: UdpClass,
        now_millis: u128,
        bytes: u64,
    ) -> &UdpFlow {
        self.udp
            .entry(key.clone())
            .and_modify(|flow| flow.record_sandbox_datagram(now_millis, bytes))
            .or_insert_with(|| {
                let mut flow = UdpFlow::new(key, class, now_millis);
                flow.record_sandbox_datagram(now_millis, bytes);
                flow
            })
    }

    pub fn expire_udp(&mut self, now_millis: u128, timeouts: &UdpTimeouts) -> Vec<UdpFlow> {
        let expired_keys: Vec<_> = self
            .udp
            .iter()
            .filter(|(_, flow)| flow.expired_at(now_millis, timeouts))
            .map(|(key, _)| key.clone())
            .collect();
        expired_keys
            .into_iter()
            .filter_map(|key| self.udp.remove(&key))
            .collect()
    }

    pub fn record_udp_host_datagram(
        &mut self,
        key: &FlowKey,
        now_millis: u128,
        bytes: u64,
    ) -> Option<&UdpFlow> {
        self.udp.get_mut(key).map(|flow| {
            flow.record_host_datagram(now_millis, bytes);
            flow as &UdpFlow
        })
    }

    pub fn udp_flows(&self) -> &HashMap<FlowKey, UdpFlow> {
        &self.udp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn classifies_direct_dns_bypass() {
        let broker_dns = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let destination = Endpoint::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        assert_eq!(
            classify_udp(&destination, &broker_dns),
            UdpClass::DirectDnsBypass
        );
    }

    #[test]
    fn quic_flows_use_longer_expiry() {
        let src = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000);
        let dst = Endpoint::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 443);
        let key = FlowKey::new(Protocol::Udp, src, dst);
        let flow = UdpFlow::new(key, UdpClass::QuicCandidate, 0);
        let timeouts = UdpTimeouts::default();
        assert!(!flow.expired_at(120_000, &timeouts));
        assert!(flow.expired_at(181_000, &timeouts));
    }
}
