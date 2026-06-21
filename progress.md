# Progress Ledger

## 2026-06-21T16:41:33Z
- Current objective: start verification-kernel session and implement the smallest verified alpha-scope slice from `docs/implementation-approach-verification-kernel.md`.
- Git status summary: clean worktree before ledger creation.
- Intended slice: establish append-only ledgers, inspect source docs, then build platform-independent core verification kernel before any Linux/TUN integration.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` after the first coherent change.
- Files expected to change: `progress.md`, `learnings.md`, core Rust sources.
- Remaining risks: full alpha includes Linux namespace/TUN/proxy integration that must be built outward only after core behavior is typed and tested.
- Exact next step: implement the smallest deterministic broker-core types for normalized events, decisions, audit records, and fail-closed policy evaluation.

## 2026-06-21T16:47:30Z
- Current objective: complete first coherent verification-kernel slice for platform-independent broker core behavior.
- Files changed: `crates/foxprox-core/src/lib.rs`, `types.rs`, `policy.rs`, `audit.rs`, `dns.rs`, `flow.rs`, `origin.rs`, `inspect.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed because new files needed rustfmt; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on test vector initialization; fixed)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 17 unit tests passed. The tests cover default deny, direct DNS bypass denial, malformed fail-closed precedence, domain attribution rules, CIDR matching, audit backpressure, DNS cache expiry, UDP/QUIC classification, HTTP request metadata extraction, CONNECT/HTTP origin parsing, and TLS ClientHello SNI extraction.
- Commit hash when committed: pending.
- Remaining risks: this slice intentionally does not yet create TUN devices, bridge TCP/UDP, run bwrap setup, expose proxy listeners, fuzz parsers, or provide a CLI/config loader.
- Exact next step: commit this verified core slice, then add executable configuration loading and proxy/frontend normalized request handling tests around the same policy engine.

## 2026-06-21T16:51:50Z
- Current objective: add deterministic packet-facing proof for the packet write-back milestone without introducing Linux/TUN dependencies.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/packet.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in new packet tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 20 unit tests passed. New tests prove IPv4 ICMP echo requests parse deterministically, synthetic echo replies reverse source/destination and preserve id/sequence/payload with valid checksums, malformed checksums are rejected, and fragmentation fails closed.
- Commit hash when committed: previous verified core slice committed as `7762592`; packet proof commit pending.
- Remaining risks: packet parsing currently covers only the minimal IPv4/ICMP proof path; TCP/UDP parsing, IPv6, fuzzing, and real TUN write-back are not implemented yet.
- Exact next step: commit packet proof, then add normalized proxy frontend parsers for HTTP CONNECT/SOCKS and config validation around the shared policy engine.

## 2026-06-21T16:55:20Z
- Current objective: add explicit proxy request parsing to feed the same normalized policy/audit kernel.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/frontend.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified rustfmt changes in the new frontend parser; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 25 unit tests passed. New tests prove SOCKS5 no-auth negotiation is explicit, unsupported SOCKS UDP ASSOCIATE is rejected, SOCKS domain destinations produce high-confidence explicit-proxy attribution, HTTP proxy CONNECT is origin-only, and HTTP absolute-form requests preserve plaintext paths for policy.
- Commit hash when committed: previous packet proof committed as `67e6bf2`; proxy parser commit pending.
- Remaining risks: this is parser/kernel behavior only; no listener sockets, proxy forwarding loops, host egress sockets, or malformed-request fuzzing yet.
- Exact next step: commit parser slice, then add config validation and deny-by-default examples that connect parsed proxy/TUN metadata to policy decisions.

## 2026-06-21T16:58:10Z
- Current objective: add explicit policy configuration validation so invalid defaults and ambiguous domain rules fail before runtime.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/config.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 29 unit tests passed. New tests prove duplicate rule IDs, global `RequireBrokerDns` defaults, and domain rules without explicit attribution confidence are rejected, while a valid domain rule with broker DNS passes.
- Commit hash when committed: previous proxy parser slice committed as `ed06d5f`; config validation commit pending.
- Remaining risks: no file-format parser exists yet; callers must construct `PolicyConfig` in memory until a serde-free or serde-backed loader is selected.
- Exact next step: commit config validation, then add end-to-end normalized decision scenarios that combine DNS/TLS/HTTP/SOCKS metadata with policy decisions and audit records.

## 2026-06-21T17:02:05Z
- Current objective: add normalized event conversion so transparent and explicit frontends share one policy/audit path.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/event.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new event module; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 32 unit tests passed. New scenario tests prove transparent HTTP Host/path metadata, TLS SNI/DNS mismatch, and SOCKS explicit-host metadata all evaluate through the same policy engine and fail closed before allow rules where required.
- Commit hash when committed: previous config validation slice committed as `02adb85`; normalized event commit pending.
- Remaining risks: normalized events are in-memory only; packet adapters, proxy listener loops, audit sinks beyond bounded memory, and host egress runtime are still pending.
- Exact next step: commit normalized event slice, then add egress/frontend abstraction types and a minimal CLI/config-facing crate boundary for future runtime wiring.

## 2026-06-21T17:04:35Z
- Current objective: enforce the verification-kernel invariant that every policy decision is appended to bounded audit history or fails closed.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/kernel.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new kernel module; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 34 unit tests passed. New tests prove decisions are recorded in audit events and audit backpressure turns an otherwise allowed decision into fail-closed `AuditBackpressure`.
- Commit hash when committed: previous normalized event slice committed as `99add43`; verification kernel commit pending.
- Remaining risks: only in-memory audit sink exists; durable append-only audit sinks, runtime forwarding, and process lifecycle events are not yet implemented.
- Exact next step: commit kernel slice, then scaffold the runtime crate boundaries for device/integration/egress code without leaking those types into core policy.

## 2026-06-21T17:07:10Z
- Current objective: scaffold runtime egress boundary so host sockets cannot be opened before verified policy/audit decisions.
- Files changed: `Cargo.toml`, `crates/foxprox-runtime/Cargo.toml`, `crates/foxprox-runtime/src/lib.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new runtime crate; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 34 core unit tests and 2 runtime unit tests passed. Runtime tests prove denied events do not call host egress and allowed TCP events call egress exactly once after the verification kernel decision/audit path.
- Commit hash when committed: previous audit kernel slice committed as `dc88fa8`; runtime boundary commit pending.
- Remaining risks: host egress trait is not yet backed by real TCP/UDP sockets; there is no smoltcp adapter, device frontend, bwrap setup helper, or network namespace integration.
- Exact next step: commit runtime boundary, then add device/setup backend abstractions and fail-early setup planning types for TUN/bwrap integration.
