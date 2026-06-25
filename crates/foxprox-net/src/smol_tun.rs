use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};

use foxprox_device::TunDevice;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

#[derive(Debug)]
pub enum SmolTunError {
    Fcntl(io::Error),
}

impl PartialEq for SmolTunError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Fcntl(_), Self::Fcntl(_)))
    }
}

impl Eq for SmolTunError {}

pub struct SmolTunDevice {
    file: File,
    mtu: usize,
}

impl SmolTunDevice {
    pub fn new(device: TunDevice, mtu: usize) -> Result<Self, SmolTunError> {
        let file = device.into_file();
        set_nonblocking(file.as_raw_fd())?;
        Ok(Self { file, mtu })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Device for SmolTunDevice {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = vec![0_u8; self.mtu];
        match self.file.read(&mut buffer) {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some((
                    TunRxToken { buffer },
                    TunTxToken {
                        fd: self.file.as_raw_fd(),
                    },
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            fd: self.file.as_raw_fd(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps
    }
}

pub struct TunRxToken {
    buffer: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TunTxToken {
    fd: RawFd,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0_u8; len];
        let result = f(&mut buffer);
        write_all_fd(self.fd, &buffer);
        result
    }
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `fd` is owned by `SmolTunDevice` and remains open while the
        // token is alive; `bytes.as_ptr()` is valid for `bytes.len()` bytes for
        // the duration of this syscall.
        let rc = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if rc <= 0 {
            return;
        }
        bytes = &bytes[rc as usize..];
    }
}

pub fn set_nonblocking(fd: RawFd) -> Result<(), SmolTunError> {
    // SAFETY: F_GETFL only reads kernel flags for an open fd and does not touch
    // Rust-managed memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(SmolTunError::Fcntl(io::Error::last_os_error()));
    }
    // SAFETY: F_SETFL mutates kernel descriptor flags only; `fd` remains owned
    // by its File/TunDevice and the bit-or preserves existing flags.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(SmolTunError::Fcntl(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use foxprox_device::{
        configure_tun_interface, create_tun, IpCommandRunner, TunConfig, TunSetup,
    };
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

    use super::*;

    #[test]
    #[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
    fn smoltcp_accepts_tcp_from_real_tun() {
        let tun = create_tun(&TunConfig::new("fp0").unwrap()).unwrap();
        let setup = TunSetup::new("fp0", "10.0.0.1/24", "0.0.0.0/0", 1300).unwrap();
        configure_tun_interface(&setup, &mut IpCommandRunner).unwrap();

        let mut device = SmolTunDevice::new(tun, 1300).unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1234_5678;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });

        let rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
        let mut tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp_socket.listen(8080).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(tcp_socket);

        let mut curl = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "http://10.0.0.2:8080/",
            ])
            .spawn()
            .unwrap();

        let started = StdInstant::now();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nfoxok\n";
        let mut served = false;
        while started.elapsed() < StdDuration::from_secs(3) {
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
            if socket.can_recv() {
                let _ = socket.recv(|data| (data.len(), data.len())).unwrap();
            }
            if socket.may_send() && !served && socket.send_slice(response).is_ok() {
                socket.close();
                served = true;
            }
            if served && socket.state() == tcp::State::Closed {
                break;
            }
            std::thread::sleep(StdDuration::from_millis(5));
        }

        let status = curl.wait().unwrap();
        assert!(
            served,
            "smoltcp should receive the HTTP request and send a response"
        );
        assert!(status.success(), "curl should receive the smoltcp response");
    }
}
