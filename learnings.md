# Learning Ledger


## 2026-06-21 — Contract-first alpha foundation

- Domain and CIDR policy needed to live in `foxprox-core` as narrow normalized matchers; otherwise `foxprox-policy` would have been tempted to import parser/config helper crates and widen its dependency surface.
- Direct external DNS bypass and unsupported events need hard policy pre-checks before default allow rules; this preserves fail-closed behavior even when a profile later opts into broad allow-by-default forwarding.
- Explicit proxy hostnames and transparent DNS/SNI attribution share a common hostname/confidence model, but explicit proxy destinations should remain high-confidence normalized events rather than frontend-specific request structs.
