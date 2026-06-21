//! Core, platform-independent types for foxprox.
//!
//! This crate is intentionally minimal for now. It is the home for broker
//! concepts that must not depend on Linux, TUN, bwrap, smoltcp, or any concrete
//! frontend/backend implementation.

#![forbid(unsafe_code)]

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
