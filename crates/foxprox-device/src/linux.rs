use std::ffi::CStr;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;

const DEFAULT_TUN_PATH: &str = "/dev/net/tun";
const IFNAMSIZ: usize = libc::IFNAMSIZ;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Configuration for creating one Linux TUN device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunCreateConfig {
    pub device_path: PathBuf,
    pub name: String,
    pub packet_information: bool,
}

impl TunCreateConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            device_path: PathBuf::from(DEFAULT_TUN_PATH),
            name: name.into(),
            packet_information: false,
        }
    }

    pub fn with_device_path(mut self, device_path: impl Into<PathBuf>) -> Self {
        self.device_path = device_path.into();
        self
    }

    pub fn with_packet_information(mut self, packet_information: bool) -> Self {
        self.packet_information = packet_information;
        self
    }
}

/// Created TUN device and owned fd.
#[derive(Debug)]
pub struct TunDevice {
    pub name: String,
    pub fd: OwnedFd,
}

/// Packet IO wrapper around a TUN-like fd received by the broker.
#[derive(Debug)]
pub struct TunPacketIo {
    fd: File,
    max_packet_len: usize,
}

impl TunPacketIo {
    pub fn from_owned_fd(fd: OwnedFd, max_packet_len: usize) -> Result<Self, TunIoError> {
        if max_packet_len == 0 {
            return Err(TunIoError::InvalidMaxPacketLen);
        }
        Ok(Self {
            fd: File::from(fd),
            max_packet_len,
        })
    }

    pub fn read_packet(&mut self) -> Result<Vec<u8>, TunIoError> {
        let mut packet = vec![0_u8; self.max_packet_len];
        let length = self
            .fd
            .read(&mut packet)
            .map_err(|error| TunIoError::Read {
                error: error.to_string(),
            })?;
        packet.truncate(length);
        Ok(packet)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunIoError> {
        if packet.len() > self.max_packet_len {
            return Err(TunIoError::PacketTooLarge {
                max_packet_len: self.max_packet_len,
                actual: packet.len(),
            });
        }
        self.fd
            .write_all(packet)
            .map_err(|error| TunIoError::Write {
                error: error.to_string(),
            })
    }

    pub fn into_inner(self) -> File {
        self.fd
    }
}

/// TUN packet IO errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunIoError {
    InvalidMaxPacketLen,
    PacketTooLarge {
        max_packet_len: usize,
        actual: usize,
    },
    Read {
        error: String,
    },
    Write {
        error: String,
    },
}

impl fmt::Display for TunIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaxPacketLen => f.write_str("tun-io-invalid-max-packet-len"),
            Self::PacketTooLarge {
                max_packet_len,
                actual,
            } => write!(
                f,
                "tun-io-packet-too-large: max_packet_len={max_packet_len} actual={actual}"
            ),
            Self::Read { error } => write!(f, "tun-io-read-error: {error}"),
            Self::Write { error } => write!(f, "tun-io-write-error: {error}"),
        }
    }
}

impl std::error::Error for TunIoError {}

/// TUN setup errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunCreateError {
    InvalidName(String),
    Open { path: PathBuf, error: String },
    Ioctl { name: String, error: String },
    KernelReturnedInvalidName,
}

impl fmt::Display for TunCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(reason) => write!(f, "tun-invalid-name: {reason}"),
            Self::Open { path, error } => write!(f, "tun-open-failed: {}: {error}", path.display()),
            Self::Ioctl { name, error } => write!(f, "tun-ioctl-tunsetiff-failed: {name}: {error}"),
            Self::KernelReturnedInvalidName => f.write_str("tun-kernel-returned-invalid-name"),
        }
    }
}

impl std::error::Error for TunCreateError {}

/// Open `/dev/net/tun` and create a TUN interface with `TUNSETIFF`.
pub fn create_tun(config: &TunCreateConfig) -> Result<TunDevice, TunCreateError> {
    validate_interface_name(&config.name)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.device_path)
        .map_err(|error| TunCreateError::Open {
            path: config.device_path.clone(),
            error: error.to_string(),
        })?;

    let mut request = IfReq::for_tun(&config.name, config.packet_information)?;
    let raw_fd = file.into_raw_fd();
    let result = tunsetiff(raw_fd, &mut request);
    if let Err(error) = result {
        let fd = raw_fd_to_owned(raw_fd);
        drop(fd);
        return Err(TunCreateError::Ioctl {
            name: config.name.clone(),
            error: error.to_string(),
        });
    }

    Ok(TunDevice {
        name: request.interface_name()?,
        fd: raw_fd_to_owned(raw_fd),
    })
}

fn validate_interface_name(name: &str) -> Result<(), TunCreateError> {
    if name.is_empty() {
        return Err(TunCreateError::InvalidName(
            "interface name must not be empty".to_owned(),
        ));
    }
    if name.as_bytes().contains(&0) {
        return Err(TunCreateError::InvalidName(
            "interface name must not contain NUL".to_owned(),
        ));
    }
    if name.len() >= IFNAMSIZ {
        return Err(TunCreateError::InvalidName(format!(
            "interface name must be shorter than {IFNAMSIZ} bytes"
        )));
    }
    Ok(())
}

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
}

impl IfReq {
    fn for_tun(name: &str, packet_information: bool) -> Result<Self, TunCreateError> {
        let mut request = Self {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN,
        };
        if !packet_information {
            request.flags |= IFF_NO_PI;
        }
        for (index, byte) in name.bytes().enumerate() {
            request.name[index] = byte as libc::c_char;
        }
        Ok(request)
    }

    fn interface_name(&self) -> Result<String, TunCreateError> {
        let cstr = CStr::from_bytes_until_nul(c_char_slice_as_u8(&self.name))
            .map_err(|_| TunCreateError::KernelReturnedInvalidName)?;
        cstr.to_str()
            .map(str::to_owned)
            .map_err(|_| TunCreateError::KernelReturnedInvalidName)
    }
}

fn c_char_slice_as_u8(value: &[libc::c_char]) -> &[u8] {
    let byte_len = mem::size_of_val(value);
    let ptr = value.as_ptr().cast::<u8>();
    // SAFETY: `libc::c_char` has size 1, and this creates an immutable byte
    // view over the exact same initialized fixed-size interface-name buffer.
    unsafe { std::slice::from_raw_parts(ptr, byte_len) }
}

fn tunsetiff(fd: libc::c_int, request: &mut IfReq) -> Result<(), std::io::Error> {
    let rc = unsafe_tunsetiff(fd, request);
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unsafe_tunsetiff(fd: libc::c_int, request: &mut IfReq) -> libc::c_int {
    // SAFETY: `fd` is an open `/dev/net/tun` descriptor owned by this process,
    // and `request` points to a valid writable `ifreq`-compatible buffer for
    // the duration of the ioctl call.
    unsafe { libc::ioctl(fd, TUNSETIFF, request) }
}

fn raw_fd_to_owned(fd: libc::c_int) -> OwnedFd {
    // SAFETY: `fd` came from `File::into_raw_fd`, transferring ownership away
    // from `File`; this wraps it exactly once so it closes on drop.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_config_rejects_invalid_interface_names_before_open() {
        assert!(matches!(
            create_tun(&TunCreateConfig::new("")),
            Err(TunCreateError::InvalidName(_))
        ));
        assert!(matches!(
            create_tun(&TunCreateConfig::new("0123456789abcdef")),
            Err(TunCreateError::InvalidName(_))
        ));
        assert!(matches!(
            create_tun(&TunCreateConfig::new("bad\0name")),
            Err(TunCreateError::InvalidName(_))
        ));
    }

    #[test]
    fn tun_packet_io_reads_and_writes_over_owned_fd_boundary() {
        use std::io::{Read, Write};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (mut peer, broker_side) = UnixStream::pair().unwrap();
        let owned: OwnedFd = broker_side.into();
        let mut io = TunPacketIo::from_owned_fd(owned, 64).unwrap();

        peer.write_all(b"inbound-packet").unwrap();
        let packet = io.read_packet().unwrap();
        assert_eq!(&packet, b"inbound-packet");

        io.write_packet(b"outbound-packet").unwrap();
        let mut response = [0_u8; 15];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"outbound-packet");
        assert_eq!(
            io.write_packet(&[0_u8; 65]).unwrap_err(),
            TunIoError::PacketTooLarge {
                max_packet_len: 64,
                actual: 65,
            }
        );
    }

    #[test]
    fn tun_create_reports_open_failure_for_missing_device_path() {
        let config = TunCreateConfig::new("fpxmissing0")
            .with_device_path(std::path::Path::new("/tmp/foxprox-missing-tun-device"));

        let error = create_tun(&config).expect_err("missing TUN path fails early");

        assert!(matches!(error, TunCreateError::Open { .. }));
        assert!(error.to_string().contains("tun-open-failed"));
    }

    #[test]
    fn live_tun_create_attempt_succeeds_or_reports_ioctl_failure() {
        let config = TunCreateConfig::new(format!("fpx{}", std::process::id() % 10_000));

        match create_tun(&config) {
            Ok(device) => {
                assert!(device.name.starts_with("fpx"));
                drop(device);
            }
            Err(TunCreateError::Ioctl { error, .. }) => {
                assert!(
                    error.contains("Operation not permitted")
                        || error.contains("Permission denied")
                        || error.contains("Device or resource busy")
                        || error.contains("File exists")
                        || error.contains("No such device")
                );
            }
            Err(TunCreateError::Open { error, .. }) => {
                assert!(
                    error.contains("No such file") || error.contains("Permission denied"),
                    "unexpected open error: {error}"
                );
            }
            Err(other) => panic!("unexpected TUN create error: {other}"),
        }
    }
}
