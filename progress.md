# Progress Ledger

## 2026-06-21 — Boundary objective: alpha contract foundation

- Boundary under work: normalized event, policy, audit, egress, frontend, network-adapter, and integration-backend contracts for the alpha broker.
- Allowed dependency direction: `foxprox-core` has no project crate dependencies; `foxprox-policy`, `foxprox-audit`, `foxprox-egress`, `foxprox-frontends`, and `foxprox-integrations` depend only on `foxprox-core`; orchestration/network code may depend on all contract crates; no policy/audit crate may import frontend, Linux, bwrap, smoltcp, or parser-specific types.
- Dependency-risk assessment: the highest drift risk is accidentally letting TUN/proxy/parser details define policy data models, so first work defines narrow normalized event and decision contracts plus mock-driven tests before any Linux/TUN implementation.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: pending.
- Changed files: pending.
- Commit hash after commit: pending.
- Remaining boundary risks: real TUN fd setup, userspace TCP stack integration, and production proxy forwarding still need to be implemented behind these contracts.

### Results

- Defined `foxprox-core` normalized contracts for sandbox IDs, hostnames, CIDR matching, frontend/protocol enums, hostname attribution source/confidence, normalized events, exhaustive policy decisions, typed runtime config, and rule matchers.
- Added contract crates:
  - `foxprox-policy`: deterministic policy over normalized events only.
  - `foxprox-audit`: stable structured audit record schema plus bounded audit sink/backpressure.
  - `foxprox-egress`: shared host egress trait and mock backend used by transparent and proxy paths.
  - `foxprox-frontends`: frontend/event-producer contract plus minimal HTTP CONNECT/HTTP/SOCKS normalization and unsupported TUN packet wrapping.
  - `foxprox-net`: stack-adapter boundary, DNS attribution cache, UDP classification/timeouts, flow table, and policy→audit→egress orchestration.
  - `foxprox-integrations`: backend-neutral network setup plans plus bwrap-compatible setup-helper plan.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 27 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - Dependency-direction check with `cargo tree -p foxprox-policy`, `foxprox-audit`, `foxprox-egress`, `foxprox-frontends`, `foxprox-integrations`, and `foxprox-net` — policy/audit/egress/frontends/integrations depend only on `foxprox-core`; `foxprox-net` depends on policy/audit/egress/core.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-audit/Cargo.toml`
  - `crates/foxprox-audit/src/lib.rs`
  - `crates/foxprox-egress/Cargo.toml`
  - `crates/foxprox-egress/src/lib.rs`
  - `crates/foxprox-frontends/Cargo.toml`
  - `crates/foxprox-frontends/src/lib.rs`
  - `crates/foxprox-integrations/Cargo.toml`
  - `crates/foxprox-integrations/src/lib.rs`
  - `crates/foxprox-net/Cargo.toml`
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-policy/Cargo.toml`
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Commit hash after commit: 8318811.
- Remaining boundary risks: production TUN setup/fd handoff, smoltcp adapter, real host socket egress, DNS resolver implementation, TLS/QUIC metadata parsing, and end-to-end namespace validation still need implementation behind the contracts.

## 2026-06-21 — Boundary objective: packet write-back proof behind adapter

- Boundary under work: IPv4/ICMP packet parsing and synthetic ICMP echo reply generation for the alpha write-back proof.
- Allowed dependency direction: packet parsing/synthesis may depend on `foxprox-core` normalized event types; `foxprox-core`, `foxprox-policy`, and `foxprox-audit` must not depend on packet parser structs or raw packet buffers.
- Dependency-risk assessment: packet parsing is a high-risk boundary because raw IP/ICMP details can leak into policy. The parser must return normalized `IcmpMessage` or `UnsupportedNetworkEvent` plus opaque outbound packet bytes only.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-packet`.
- Observed results: pending.
- Changed files: pending.
- Commit hash after commit: pending.
- Remaining boundary risks: IPv6, fragmentation, TCP/UDP stack integration, and real TUN fd IO are still outside this packet proof.

### Results

- Added `foxprox-packet` as the raw packet boundary for alpha write-back proof work.
- Implemented IPv4 validation, unsupported-fragmentation and unsupported-protocol normalization, ICMP event normalization, and synthetic ICMP echo reply generation with IPv4/ICMP checksum recomputation.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 30 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet crate depends only on `foxprox-core`.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-packet/Cargo.toml`
  - `crates/foxprox-packet/src/lib.rs`
  - `progress.md`
- Commit hash after commit: 9bcbd63.
- Remaining boundary risks: IPv6, TCP/UDP parsing, smoltcp handoff, production TUN writes, and ICMP policy response behavior remain to be implemented behind adapter contracts.
