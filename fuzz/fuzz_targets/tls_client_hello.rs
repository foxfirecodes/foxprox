#![no_main]

use foxprox_core::{FrontendKind, SandboxId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let sandbox_id = SandboxId::new("fuzz").expect("static sandbox id is valid");
    let _ = foxprox_inspect::inspect_tls_client_hello(
        sandbox_id,
        FrontendKind::Tun,
        "203.0.113.10:443"
            .parse()
            .expect("static destination address is valid"),
        None,
        bytes,
    );
    let _ = foxprox_inspect::parse_tls_client_hello_sni(bytes);
});
