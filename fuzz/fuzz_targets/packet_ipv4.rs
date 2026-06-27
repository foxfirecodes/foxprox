#![no_main]

use foxprox_core::{FrontendKind, SandboxId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let sandbox_id = SandboxId::new("fuzz").expect("static sandbox id is valid");
    let inspection = foxprox_packet::inspect_ipv4_packet(sandbox_id, FrontendKind::Tun, bytes);
    if let Some(packet) = inspection.synthetic_reply {
        let _ = packet.bytes();
    }
});
