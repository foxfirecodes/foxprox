//! smoltcp adapter boundary for foxprox.
//!
//! This crate is allowed to depend on smoltcp. Core policy/audit crates must
//! continue to see only foxprox normalized runtime types.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpIpConfig {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmoltcpAdapterError {
    InvalidPrefixLen,
    AddressRejected,
    InvalidTcpPort,
    InvalidTcpBufferSize,
    TcpListenRejected,
}

pub struct SmoltcpIpLoopback {
    iface: Interface,
    device: Loopback,
    sockets: SocketSet<'static>,
    config: SmoltcpIpConfig,
}

impl SmoltcpIpLoopback {
    pub fn new(config: SmoltcpIpConfig, now_millis: i64) -> Result<Self, SmoltcpAdapterError> {
        if config.prefix_len > 32 {
            return Err(SmoltcpAdapterError::InvalidPrefixLen);
        }
        let mut device = Loopback::new(Medium::Ip);
        let iface_config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(now_millis));
        let cidr = IpCidr::new(ipv4_to_smoltcp(config.address), config.prefix_len);
        let mut accepted = false;
        iface.update_ip_addrs(|addresses| {
            accepted = addresses.push(cidr).is_ok();
        });
        if !accepted {
            return Err(SmoltcpAdapterError::AddressRejected);
        }
        Ok(Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            config,
        })
    }

    pub fn config(&self) -> &SmoltcpIpConfig {
        &self.config
    }

    pub fn listen_tcp(
        &mut self,
        port: u16,
        rx_bytes: usize,
        tx_bytes: usize,
    ) -> Result<(), SmoltcpAdapterError> {
        if port == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpPort);
        }
        if rx_bytes == 0 || tx_bytes == 0 {
            return Err(SmoltcpAdapterError::InvalidTcpBufferSize);
        }
        let rx_buffer = tcp::SocketBuffer::new(vec![0; rx_bytes]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; tx_bytes]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(port)
            .map_err(|_| SmoltcpAdapterError::TcpListenRejected)
    }

    pub fn poll_once(&mut self, now_millis: i64) {
        let _ = self.iface.poll(
            Instant::from_millis(now_millis),
            &mut self.device,
            &mut self.sockets,
        );
    }
}

fn ipv4_to_smoltcp(address: Ipv4Addr) -> IpAddress {
    let octets = address.octets();
    IpAddress::v4(octets[0], octets[1], octets[2], octets[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_loopback_interface_accepts_configured_ipv4_address() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        adapter.poll_once(1);

        assert_eq!(adapter.config().address, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(adapter.config().prefix_len, 24);
    }

    #[test]
    fn tcp_listener_socket_is_allocated_with_explicit_buffers() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        adapter.listen_tcp(8080, 1024, 1024).unwrap();
        adapter.poll_once(1);
    }

    #[test]
    fn tcp_listener_rejects_invalid_port_and_buffers() {
        let mut adapter = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 24,
            },
            0,
        )
        .unwrap();

        assert!(matches!(
            adapter.listen_tcp(0, 1024, 1024),
            Err(SmoltcpAdapterError::InvalidTcpPort)
        ));
        assert!(matches!(
            adapter.listen_tcp(8080, 0, 1024),
            Err(SmoltcpAdapterError::InvalidTcpBufferSize)
        ));
        assert!(matches!(
            adapter.listen_tcp(8080, 1024, 0),
            Err(SmoltcpAdapterError::InvalidTcpBufferSize)
        ));
    }

    #[test]
    fn ip_loopback_rejects_invalid_ipv4_prefix_before_interface_build() {
        let result = SmoltcpIpLoopback::new(
            SmoltcpIpConfig {
                address: Ipv4Addr::new(10, 66, 0, 1),
                prefix_len: 33,
            },
            0,
        );

        assert!(matches!(result, Err(SmoltcpAdapterError::InvalidPrefixLen)));
    }
}
