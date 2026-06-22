use std::collections::VecDeque;

use crate::types::{Endpoint, Protocol};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpFlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
}

impl TcpFlowKey {
    pub fn new(source: Endpoint, destination: Endpoint) -> Self {
        Self {
            source,
            destination,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpFlowEntry {
    pub key: TcpFlowKey,
    pub created_at_millis: u64,
    pub last_seen_millis: u64,
    pub expires_at_millis: u64,
    pub bytes_from_sandbox: u64,
    pub bytes_from_host: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpFlowObserveStatus {
    Created,
    Updated,
    RejectedNoCapacity,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcpFlowObserveOutcome {
    pub status: TcpFlowObserveStatus,
    pub evicted: usize,
    pub expired: usize,
}

#[derive(Clone, Debug)]
pub struct TcpFlowTable {
    max_flows: usize,
    idle_timeout_millis: u64,
    flows: VecDeque<TcpFlowEntry>,
}

impl TcpFlowTable {
    pub fn new(max_flows: usize, idle_timeout_millis: u64) -> Self {
        Self {
            max_flows,
            idle_timeout_millis,
            flows: VecDeque::with_capacity(max_flows),
        }
    }

    pub fn observe_from_sandbox(
        &mut self,
        key: TcpFlowKey,
        byte_count: u64,
        now_millis: u64,
    ) -> TcpFlowObserveOutcome {
        self.observe(key, byte_count, 0, now_millis)
    }

    pub fn observe_from_host(
        &mut self,
        key: TcpFlowKey,
        byte_count: u64,
        now_millis: u64,
    ) -> TcpFlowObserveOutcome {
        self.observe(key, 0, byte_count, now_millis)
    }

    fn observe(
        &mut self,
        key: TcpFlowKey,
        sandbox_bytes: u64,
        host_bytes: u64,
        now_millis: u64,
    ) -> TcpFlowObserveOutcome {
        let expired = self.expire(now_millis);
        if let Some(entry) = self.flows.iter_mut().find(|entry| entry.key == key) {
            entry.last_seen_millis = now_millis;
            entry.expires_at_millis = now_millis.saturating_add(self.idle_timeout_millis);
            entry.bytes_from_sandbox = entry.bytes_from_sandbox.saturating_add(sandbox_bytes);
            entry.bytes_from_host = entry.bytes_from_host.saturating_add(host_bytes);
            return TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::Updated,
                evicted: 0,
                expired,
            };
        }

        if self.max_flows == 0 || self.idle_timeout_millis == 0 {
            return TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::RejectedNoCapacity,
                evicted: 0,
                expired,
            };
        }

        let mut evicted = 0;
        while self.flows.len() >= self.max_flows {
            self.flows.pop_front();
            evicted += 1;
        }

        self.flows.push_back(TcpFlowEntry {
            key,
            created_at_millis: now_millis,
            last_seen_millis: now_millis,
            expires_at_millis: now_millis.saturating_add(self.idle_timeout_millis),
            bytes_from_sandbox: sandbox_bytes,
            bytes_from_host: host_bytes,
        });

        TcpFlowObserveOutcome {
            status: TcpFlowObserveStatus::Created,
            evicted,
            expired,
        }
    }

    pub fn close(&mut self, key: TcpFlowKey) -> Option<TcpFlowEntry> {
        let index = self.flows.iter().position(|entry| entry.key == key)?;
        self.flows.remove(index)
    }

    pub fn expire(&mut self, now_millis: u64) -> usize {
        self.expire_collect(now_millis).len()
    }

    pub fn expire_collect(&mut self, now_millis: u64) -> Vec<TcpFlowEntry> {
        let mut retained = VecDeque::with_capacity(self.max_flows);
        let mut expired = Vec::new();

        while let Some(entry) = self.flows.pop_front() {
            if entry.expires_at_millis <= now_millis {
                expired.push(entry);
            } else {
                retained.push_back(entry);
            }
        }

        self.flows = retained;
        expired
    }

    pub fn get(&self, key: TcpFlowKey) -> Option<&TcpFlowEntry> {
        self.flows.iter().find(|entry| entry.key == key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_flows
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct UdpFlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
}

impl UdpFlowKey {
    pub fn new(source: Endpoint, destination: Endpoint) -> Self {
        Self {
            source,
            destination,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UdpFlowClass {
    Dns,
    QuicCandidate,
    NtpLike,
    Generic,
}

impl UdpFlowClass {
    pub fn classify(protocol: Protocol, destination: Endpoint) -> Self {
        match protocol {
            Protocol::Dns => Self::Dns,
            Protocol::QuicCandidate => Self::QuicCandidate,
            Protocol::Udp if destination.port == Some(123) => Self::NtpLike,
            _ => Self::Generic,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowTimeouts {
    pub dns_millis: u64,
    pub generic_millis: u64,
    pub quic_millis: u64,
    pub ntp_like_millis: u64,
}

impl UdpFlowTimeouts {
    pub fn timeout_for(self, class: UdpFlowClass) -> u64 {
        match class {
            UdpFlowClass::Dns => self.dns_millis,
            UdpFlowClass::QuicCandidate => self.quic_millis,
            UdpFlowClass::NtpLike => self.ntp_like_millis,
            UdpFlowClass::Generic => self.generic_millis,
        }
    }
}

impl Default for UdpFlowTimeouts {
    fn default() -> Self {
        Self {
            dns_millis: 10_000,
            generic_millis: 60_000,
            quic_millis: 180_000,
            ntp_like_millis: 5_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowEntry {
    pub key: UdpFlowKey,
    pub class: UdpFlowClass,
    pub created_at_millis: u64,
    pub last_seen_millis: u64,
    pub expires_at_millis: u64,
    pub bytes_from_sandbox: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UdpFlowObserveStatus {
    Created,
    Updated,
    RejectedNoCapacity,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UdpFlowObserveOutcome {
    pub status: UdpFlowObserveStatus,
    pub evicted: usize,
    pub expired: usize,
}

#[derive(Clone, Debug)]
pub struct UdpFlowTable {
    max_flows: usize,
    timeouts: UdpFlowTimeouts,
    flows: VecDeque<UdpFlowEntry>,
}

impl UdpFlowTable {
    pub fn new(max_flows: usize, timeouts: UdpFlowTimeouts) -> Self {
        Self {
            max_flows,
            timeouts,
            flows: VecDeque::with_capacity(max_flows),
        }
    }

    pub fn observe_from_sandbox(
        &mut self,
        key: UdpFlowKey,
        protocol: Protocol,
        byte_count: u64,
        now_millis: u64,
    ) -> UdpFlowObserveOutcome {
        let expired = self.expire(now_millis);
        if let Some(entry) = self.flows.iter_mut().find(|entry| entry.key == key) {
            entry.class = UdpFlowClass::classify(protocol, key.destination);
            entry.last_seen_millis = now_millis;
            entry.bytes_from_sandbox = entry.bytes_from_sandbox.saturating_add(byte_count);
            entry.expires_at_millis =
                now_millis.saturating_add(self.timeouts.timeout_for(entry.class));
            return UdpFlowObserveOutcome {
                status: UdpFlowObserveStatus::Updated,
                evicted: 0,
                expired,
            };
        }

        if self.max_flows == 0 {
            return UdpFlowObserveOutcome {
                status: UdpFlowObserveStatus::RejectedNoCapacity,
                evicted: 0,
                expired,
            };
        }

        let mut evicted = 0;
        while self.flows.len() >= self.max_flows {
            self.flows.pop_front();
            evicted += 1;
        }

        let class = UdpFlowClass::classify(protocol, key.destination);
        self.flows.push_back(UdpFlowEntry {
            key,
            class,
            created_at_millis: now_millis,
            last_seen_millis: now_millis,
            expires_at_millis: now_millis.saturating_add(self.timeouts.timeout_for(class)),
            bytes_from_sandbox: byte_count,
        });

        UdpFlowObserveOutcome {
            status: UdpFlowObserveStatus::Created,
            evicted,
            expired,
        }
    }

    pub fn expire(&mut self, now_millis: u64) -> usize {
        self.expire_collect(now_millis).len()
    }

    pub fn expire_collect(&mut self, now_millis: u64) -> Vec<UdpFlowEntry> {
        let mut retained = VecDeque::with_capacity(self.max_flows);
        let mut expired = Vec::new();

        while let Some(entry) = self.flows.pop_front() {
            if entry.expires_at_millis <= now_millis {
                expired.push(entry);
            } else {
                retained.push_back(entry);
            }
        }

        self.flows = retained;
        expired
    }

    pub fn get(&self, key: UdpFlowKey) -> Option<&UdpFlowEntry> {
        self.flows.iter().find(|entry| entry.key == key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_flows
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn endpoint(octets: [u8; 4], port: u16) -> Endpoint {
        Endpoint::udp(IpAddr::V4(Ipv4Addr::from(octets)), port)
    }

    fn key(source_port: u16, destination: Endpoint) -> UdpFlowKey {
        UdpFlowKey::new(endpoint([10, 0, 0, 2], source_port), destination)
    }

    fn tcp_endpoint(octets: [u8; 4], port: u16) -> Endpoint {
        Endpoint::tcp(IpAddr::V4(Ipv4Addr::from(octets)), port)
    }

    fn tcp_key(source_port: u16, destination_port: u16) -> TcpFlowKey {
        TcpFlowKey::new(
            tcp_endpoint([10, 0, 0, 2], source_port),
            tcp_endpoint([203, 0, 113, 10], destination_port),
        )
    }

    #[test]
    fn tcp_flow_table_tracks_lifecycle_and_saturating_counters() {
        let flow = tcp_key(40000, 443);
        let mut table = TcpFlowTable::new(4, 30);

        assert_eq!(
            table.observe_from_sandbox(flow, 10, 1),
            TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::Created,
                evicted: 0,
                expired: 0,
            }
        );
        assert_eq!(
            table.observe_from_host(flow, 20, 5),
            TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::Updated,
                evicted: 0,
                expired: 0,
            }
        );
        table.observe_from_sandbox(flow, u64::MAX, 6);

        let entry = table.get(flow).unwrap();
        assert_eq!(entry.created_at_millis, 1);
        assert_eq!(entry.last_seen_millis, 6);
        assert_eq!(entry.expires_at_millis, 36);
        assert_eq!(entry.bytes_from_sandbox, u64::MAX);
        assert_eq!(entry.bytes_from_host, 20);

        let closed = table.close(flow).unwrap();
        assert_eq!(closed.key, flow);
        assert!(table.is_empty());
    }

    #[test]
    fn tcp_flow_table_bounds_capacity_and_expiration() {
        let mut table = TcpFlowTable::new(2, 10);
        let first = tcp_key(40000, 80);
        let second = tcp_key(40001, 80);
        let third = tcp_key(40002, 80);

        table.observe_from_sandbox(first, 1, 0);
        table.observe_from_sandbox(second, 1, 1);
        assert_eq!(
            table.observe_from_sandbox(third, 1, 2),
            TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::Created,
                evicted: 1,
                expired: 0,
            }
        );
        assert!(table.get(first).is_none());
        assert!(table.get(second).is_some());
        assert!(table.get(third).is_some());

        let expired = table.expire_collect(11);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, second);
        assert!(table.get(third).is_some());
    }

    #[test]
    fn tcp_flow_table_rejects_zero_capacity_or_zero_timeout() {
        let flow = tcp_key(40000, 443);
        assert_eq!(
            TcpFlowTable::new(0, 30).observe_from_sandbox(flow, 1, 0),
            TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::RejectedNoCapacity,
                evicted: 0,
                expired: 0,
            }
        );
        assert_eq!(
            TcpFlowTable::new(4, 0).observe_from_sandbox(flow, 1, 0),
            TcpFlowObserveOutcome {
                status: TcpFlowObserveStatus::RejectedNoCapacity,
                evicted: 0,
                expired: 0,
            }
        );
    }

    #[test]
    fn classifies_udp_flows_with_explicit_timeouts() {
        let timeouts = UdpFlowTimeouts {
            dns_millis: 5,
            generic_millis: 30,
            quic_millis: 120,
            ntp_like_millis: 3,
        };
        let mut table = UdpFlowTable::new(8, timeouts);

        let dns = key(40000, endpoint([10, 0, 2, 3], 53));
        let generic = key(40001, endpoint([203, 0, 113, 10], 9999));
        let quic = key(40002, endpoint([203, 0, 113, 20], 443));
        let ntp = key(40003, endpoint([129, 6, 15, 28], 123));

        assert_eq!(
            table
                .observe_from_sandbox(dns, Protocol::Dns, 20, 10)
                .status,
            UdpFlowObserveStatus::Created
        );
        table.observe_from_sandbox(generic, Protocol::Udp, 30, 10);
        table.observe_from_sandbox(quic, Protocol::QuicCandidate, 40, 10);
        table.observe_from_sandbox(ntp, Protocol::Udp, 50, 10);

        assert_eq!(table.get(dns).unwrap().class, UdpFlowClass::Dns);
        assert_eq!(table.get(dns).unwrap().expires_at_millis, 15);
        assert_eq!(table.get(generic).unwrap().expires_at_millis, 40);
        assert_eq!(table.get(quic).unwrap().expires_at_millis, 130);
        assert_eq!(table.get(ntp).unwrap().expires_at_millis, 13);
    }

    #[test]
    fn updates_existing_flow_with_saturating_byte_counter() {
        let mut table = UdpFlowTable::new(8, UdpFlowTimeouts::default());
        let flow = key(40000, endpoint([203, 0, 113, 10], 443));
        table.observe_from_sandbox(flow, Protocol::QuicCandidate, u64::MAX, 1);
        let outcome = table.observe_from_sandbox(flow, Protocol::QuicCandidate, 1, 2);

        assert_eq!(outcome.status, UdpFlowObserveStatus::Updated);
        let entry = table.get(flow).unwrap();
        assert_eq!(entry.created_at_millis, 1);
        assert_eq!(entry.last_seen_millis, 2);
        assert_eq!(entry.bytes_from_sandbox, u64::MAX);
        assert_eq!(entry.expires_at_millis, 180_002);
    }

    #[test]
    fn expires_flows_when_timeout_elapses() {
        let mut table = UdpFlowTable::new(
            8,
            UdpFlowTimeouts {
                dns_millis: 5,
                generic_millis: 30,
                quic_millis: 120,
                ntp_like_millis: 3,
            },
        );
        let dns = key(40000, endpoint([10, 0, 2, 3], 53));
        let quic = key(40001, endpoint([203, 0, 113, 20], 443));
        table.observe_from_sandbox(dns, Protocol::Dns, 20, 10);
        table.observe_from_sandbox(quic, Protocol::QuicCandidate, 40, 10);

        assert_eq!(table.expire(14), 0);
        assert_eq!(table.expire(15), 1);
        assert!(table.get(dns).is_none());
        assert!(table.get(quic).is_some());
    }

    #[test]
    fn expire_collect_returns_auditable_expired_entries() {
        let mut table = UdpFlowTable::new(
            8,
            UdpFlowTimeouts {
                dns_millis: 5,
                generic_millis: 30,
                quic_millis: 120,
                ntp_like_millis: 3,
            },
        );
        let dns = key(40000, endpoint([10, 0, 2, 3], 53));
        let quic = key(40001, endpoint([203, 0, 113, 20], 443));
        table.observe_from_sandbox(dns, Protocol::Dns, 20, 10);
        table.observe_from_sandbox(quic, Protocol::QuicCandidate, 40, 10);

        let expired = table.expire_collect(15);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, dns);
        assert_eq!(expired[0].class, UdpFlowClass::Dns);
        assert_eq!(expired[0].bytes_from_sandbox, 20);
        assert!(table.get(dns).is_none());
        assert!(table.get(quic).is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn evicts_oldest_flow_at_capacity_and_reports_zero_capacity() {
        let mut table = UdpFlowTable::new(1, UdpFlowTimeouts::default());
        let first = key(40000, endpoint([203, 0, 113, 10], 1000));
        let second = key(40001, endpoint([203, 0, 113, 11], 1001));
        table.observe_from_sandbox(first, Protocol::Udp, 1, 0);
        let outcome = table.observe_from_sandbox(second, Protocol::Udp, 1, 1);

        assert_eq!(outcome.evicted, 1);
        assert_eq!(outcome.status, UdpFlowObserveStatus::Created);
        assert!(table.get(first).is_none());
        assert!(table.get(second).is_some());

        let mut none = UdpFlowTable::new(0, UdpFlowTimeouts::default());
        let outcome = none.observe_from_sandbox(first, Protocol::Udp, 1, 0);
        assert_eq!(outcome.status, UdpFlowObserveStatus::RejectedNoCapacity);
        assert!(none.is_empty());
    }

    #[test]
    fn expires_before_accepting_new_flow() {
        let mut table = UdpFlowTable::new(
            1,
            UdpFlowTimeouts {
                dns_millis: 5,
                generic_millis: 30,
                quic_millis: 120,
                ntp_like_millis: 3,
            },
        );
        let first = key(40000, endpoint([10, 0, 2, 3], 53));
        let second = key(40001, endpoint([203, 0, 113, 10], 1000));
        table.observe_from_sandbox(first, Protocol::Dns, 1, 0);
        let outcome = table.observe_from_sandbox(second, Protocol::Udp, 1, 5);

        assert_eq!(outcome.expired, 1);
        assert_eq!(outcome.evicted, 0);
        assert!(table.get(second).is_some());
    }
}
