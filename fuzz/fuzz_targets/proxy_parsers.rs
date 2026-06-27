#![no_main]

use foxprox_core::{FrontendKind, ParserLimits, SandboxId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let sandbox_id = SandboxId::new("fuzz").expect("static sandbox id is valid");
    let limits = ParserLimits::default();
    let _ = foxprox_frontends::parse_http_request_with_limits(
        sandbox_id.clone(),
        FrontendKind::HttpProxy,
        bytes,
        limits,
    );
    let _ = foxprox_frontends::select_socks5_no_auth_method_with_limits(bytes, limits);
    let _ = foxprox_frontends::parse_socks5_connect_with_limits(sandbox_id, bytes, limits);
});
