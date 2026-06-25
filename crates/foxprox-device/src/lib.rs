//! Device IO boundary for TUN-like IP packet frontends.
//!
//! This crate owns read/write mechanics for opaque IP packets. Policy and audit
//! crates must not depend on these types, Linux file descriptors, or TUN setup
//! details.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

/// Default alpha MTU used by the TUN setup plan.
pub const DEFAULT_ALPHA_MTU: usize = 1500;

/// Opaque IP packet bytes read from or written to a device frontend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePacket {
    bytes: Vec<u8>,
}

impl DevicePacket {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DeviceError> {
        if bytes.is_empty() {
            return Err(DeviceError::EmptyPacket);
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Device IO contract used by runtime loops. Implementations may wrap a TUN fd,
/// a mock, or another packet source, but only opaque packet bytes cross here.
pub trait PacketDevice {
    fn read_packet(&mut self) -> Result<DevicePacket, DeviceError>;
    fn write_packet(&mut self, packet: &DevicePacket) -> Result<(), DeviceError>;
}

/// Optional-read packet device contract for nonblocking runtime loops. A return
/// value of `Ok(None)` means no packet is currently ready, not policy denial or
/// malformed packet data.
pub trait TryPacketDevice: PacketDevice {
    fn try_read_packet(&mut self) -> Result<Option<DevicePacket>, DeviceError>;
}

/// Generic blocking packet device over a `Read + Write` stream.
///
/// A production TUN fd can be wrapped as a file-like object behind this contract;
/// tests can use in-memory cursors without Linux-specific setup.
#[derive(Debug)]
pub struct BlockingPacketDevice<Io> {
    io: Io,
    max_packet_bytes: usize,
}

impl<Io> BlockingPacketDevice<Io> {
    pub fn new(io: Io, max_packet_bytes: usize) -> Result<Self, DeviceError> {
        if max_packet_bytes == 0 {
            return Err(DeviceError::InvalidMaxPacketBytes);
        }
        Ok(Self {
            io,
            max_packet_bytes,
        })
    }

    pub fn alpha_default(io: Io) -> Self {
        Self {
            io,
            max_packet_bytes: DEFAULT_ALPHA_MTU,
        }
    }

    pub fn max_packet_bytes(&self) -> usize {
        self.max_packet_bytes
    }

    pub fn into_inner(self) -> Io {
        self.io
    }
}

impl<Io: Read + Write> PacketDevice for BlockingPacketDevice<Io> {
    fn read_packet(&mut self) -> Result<DevicePacket, DeviceError> {
        let mut buffer = vec![0_u8; self.max_packet_bytes];
        let len = self.io.read(&mut buffer).map_err(|error| {
            if error.kind() == ErrorKind::WouldBlock {
                DeviceError::WouldBlock
            } else {
                DeviceError::Io(error.to_string())
            }
        })?;
        if len == 0 {
            return Err(DeviceError::EmptyRead);
        }
        buffer.truncate(len);
        DevicePacket::new(buffer)
    }

    fn write_packet(&mut self, packet: &DevicePacket) -> Result<(), DeviceError> {
        if packet.bytes().len() > self.max_packet_bytes {
            return Err(DeviceError::PacketTooLarge {
                len: packet.bytes().len(),
                max: self.max_packet_bytes,
            });
        }
        self.io
            .write_all(packet.bytes())
            .map_err(|error| DeviceError::Io(error.to_string()))
    }
}

/// TUN-facing device wrapper for an already-opened TUN endpoint.
///
/// This type deliberately accepts a file-like object instead of creating a TUN
/// device or taking ownership from a raw file descriptor. Setup helpers and
/// integration backends can decide how the TUN fd is created/handed off; runtime
/// code only receives an opaque packet device.
#[derive(Debug)]
pub struct PreopenedTunDevice<Io> {
    inner: BlockingPacketDevice<Io>,
}

impl<Io> PreopenedTunDevice<Io> {
    pub fn from_io(io: Io, max_packet_bytes: usize) -> Result<Self, DeviceError> {
        Ok(Self {
            inner: BlockingPacketDevice::new(io, max_packet_bytes)?,
        })
    }

    pub fn alpha_default(io: Io) -> Self {
        Self {
            inner: BlockingPacketDevice::alpha_default(io),
        }
    }

    pub fn max_packet_bytes(&self) -> usize {
        self.inner.max_packet_bytes()
    }

    pub fn into_inner(self) -> Io {
        self.inner.into_inner()
    }
}

impl PreopenedTunDevice<File> {
    /// Wrap an already-opened TUN file handle.
    pub fn from_file(file: File, max_packet_bytes: usize) -> Result<Self, DeviceError> {
        Self::from_io(file, max_packet_bytes)
    }

    /// Adopt an inherited/preopened Unix file descriptor as the broker TUN
    /// device endpoint.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open file descriptor for a TUN-like packet device
    /// or equivalent test endpoint. Ownership is transferred to the returned
    /// `PreopenedTunDevice`; callers must not close or use `fd` after this call.
    #[cfg(unix)]
    pub unsafe fn from_raw_fd(fd: RawFd, max_packet_bytes: usize) -> Result<Self, DeviceError> {
        let file = unsafe { File::from_raw_fd(fd) };
        Self::from_file(file, max_packet_bytes)
    }
}

impl<Io: Read + Write> TryPacketDevice for BlockingPacketDevice<Io> {
    fn try_read_packet(&mut self) -> Result<Option<DevicePacket>, DeviceError> {
        match self.read_packet() {
            Ok(packet) => Ok(Some(packet)),
            Err(DeviceError::WouldBlock) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl<Io: Read + Write> PacketDevice for PreopenedTunDevice<Io> {
    fn read_packet(&mut self) -> Result<DevicePacket, DeviceError> {
        self.inner.read_packet()
    }

    fn write_packet(&mut self, packet: &DevicePacket) -> Result<(), DeviceError> {
        self.inner.write_packet(packet)
    }
}

impl<Io: Read + Write> TryPacketDevice for PreopenedTunDevice<Io> {
    fn try_read_packet(&mut self) -> Result<Option<DevicePacket>, DeviceError> {
        self.inner.try_read_packet()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DeviceError {
    EmptyPacket,
    EmptyRead,
    WouldBlock,
    InvalidMaxPacketBytes,
    PacketTooLarge { len: usize, max: usize },
    Io(String),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPacket => f.write_str("device packet must not be empty"),
            Self::EmptyRead => f.write_str("device read returned no bytes"),
            Self::WouldBlock => f.write_str("device read would block"),
            Self::InvalidMaxPacketBytes => {
                f.write_str("max packet bytes must be greater than zero")
            }
            Self::PacketTooLarge { len, max } => {
                write!(f, "device packet length {len} exceeds max {max}")
            }
            Self::Io(error) => write!(f, "device io error: {error}"),
        }
    }
}

impl std::error::Error for DeviceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[cfg(unix)]
    use std::os::fd::IntoRawFd;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[test]
    fn blocking_device_reads_opaque_packet_bytes() {
        let cursor = Cursor::new(vec![0x45, 0, 0, 20]);
        let mut device = BlockingPacketDevice::new(cursor, DEFAULT_ALPHA_MTU).unwrap();

        let packet = device.read_packet().unwrap();

        assert_eq!(packet.bytes(), &[0x45, 0, 0, 20]);
    }

    #[test]
    fn blocking_device_writes_opaque_packet_bytes() {
        let cursor = Cursor::new(Vec::new());
        let mut device = BlockingPacketDevice::new(cursor, 4).unwrap();
        let packet = DevicePacket::new(vec![1, 2, 3, 4]).unwrap();

        device.write_packet(&packet).unwrap();
        let cursor = device.into_inner();

        assert_eq!(cursor.into_inner(), vec![1, 2, 3, 4]);
    }

    #[cfg(unix)]
    #[test]
    fn preopened_tun_can_adopt_inherited_raw_fd() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let raw_fd = reader.into_raw_fd();
        let mut device = unsafe { PreopenedTunDevice::from_raw_fd(raw_fd, 1500) }.unwrap();

        writer.write_all(&[0x45, 0, 0, 20]).unwrap();
        let packet = device.read_packet().unwrap();

        assert_eq!(packet.bytes(), &[0x45, 0, 0, 20]);
    }

    #[test]
    fn preopened_tun_wrapper_preserves_opaque_packet_contract() {
        let cursor = Cursor::new(vec![0x45, 0, 0, 20]);
        let mut device = PreopenedTunDevice::from_io(cursor, DEFAULT_ALPHA_MTU).unwrap();

        let packet = device.read_packet().unwrap();
        device.write_packet(&packet).unwrap();
        let cursor = device.into_inner();

        assert_eq!(packet.bytes(), &[0x45, 0, 0, 20]);
        assert_eq!(cursor.into_inner(), vec![0x45, 0, 0, 20, 0x45, 0, 0, 20]);
    }

    #[test]
    fn try_packet_device_reports_not_ready_without_exposing_io_kind() {
        let mut device = BlockingPacketDevice::new(WouldBlockIo, DEFAULT_ALPHA_MTU).unwrap();

        assert_eq!(device.try_read_packet().unwrap(), None);
    }

    #[test]
    fn preopened_tun_rejects_invalid_packet_limit() {
        let cursor = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            PreopenedTunDevice::from_io(cursor, 0).unwrap_err(),
            DeviceError::InvalidMaxPacketBytes
        );
    }

    #[test]
    fn device_rejects_empty_and_oversized_packets() {
        assert_eq!(DevicePacket::new(Vec::new()), Err(DeviceError::EmptyPacket));
        assert_eq!(
            BlockingPacketDevice::new(Cursor::new(Vec::<u8>::new()), 0).unwrap_err(),
            DeviceError::InvalidMaxPacketBytes
        );

        let cursor = Cursor::new(Vec::new());
        let mut device = BlockingPacketDevice::new(cursor, 2).unwrap();
        let packet = DevicePacket::new(vec![1, 2, 3]).unwrap();
        assert_eq!(
            device.write_packet(&packet),
            Err(DeviceError::PacketTooLarge { len: 3, max: 2 })
        );
    }

    struct WouldBlockIo;

    impl Read for WouldBlockIo {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(ErrorKind::WouldBlock))
        }
    }

    impl Write for WouldBlockIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
