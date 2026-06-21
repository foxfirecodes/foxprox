//! Flow keys and timeout classes used by the broker flow manager.

use std::net::IpAddr;
use std::time::Duration;

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
}
