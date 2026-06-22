//! Core, platform-independent types and deterministic harness helpers for foxprox.
//!
//! The production broker will have Linux/TUN/smoltcp integration crates around
//! this crate. This crate deliberately keeps policy, audit, parsing, attribution,
//! and mock-flow behavior free of OS-specific code so the harness can prove the
//! semantics without requiring network namespace privileges.

#![forbid(unsafe_code)]

pub mod audit;
pub mod dns;
pub mod egress;
pub mod flow;
pub mod integration;
pub mod origin;
pub mod packet;
pub mod policy;
pub mod runtime;
pub mod scenario;
pub mod smoltcp_gate;

/// Stable crate marker used by scaffold tests and downstream workspace checks.
pub const CRATE_NAME: &str = "foxprox-core";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_crate_marker() {
        assert_eq!(CRATE_NAME, "foxprox-core");
    }
}
