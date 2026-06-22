//! Linux network device frontend primitives for foxprox.
//!
//! This crate owns Linux-specific TUN/TAP setup details. Broker core and policy
//! code must not depend on these ioctl-facing types.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{create_tun, TunCreateConfig, TunCreateError, TunDevice, TunIoError, TunPacketIo};

#[cfg(not(target_os = "linux"))]
compile_error!("foxprox-device currently supports Linux only");
