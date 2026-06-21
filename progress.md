# Progress Ledger

## 2026-06-21 Session Start — normalized event → policy → audit slice

- Slice attempted: establish the first platform-independent vertical boundary where normalized network events are evaluated by policy and converted into structured audit records.
- Why next: the repository currently only has a core crate marker, and this slice crosses core-to-policy-to-audit without requiring speculative Linux/TUN scaffolding.
- Verification plan: add focused Rust unit tests for allow/deny/fail-closed outcomes, direct DNS bypass denial, and structured audit output; run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — normalized event → policy → audit

- Slice attempted: platform-independent normalized network events evaluated by a deterministic policy engine and converted into structured audit records.
- Why next: this crossed the documented core-to-policy-to-audit boundary while avoiding speculative Linux/TUN/bwrap scaffolding before packet forwarding evidence exists.
- What changed: added typed sandbox IDs, endpoints, frontend/protocol enums, normalized event variants, hostname attribution, minimal CIDR/port/hostname policy rules, explicit allow/deny/fail-closed decisions, DNS bypass denial, TLS SNI mismatch denial, and structured `AuditRecord` generation in `crates/foxprox-core/src/lib.rs`.
- Verification:
  - `cargo fmt --check` initially failed before formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 9 unit tests and 0 doc tests.
  - `cargo fmt --check` passed after formatting.
  - Focused checks passed: `cargo test -p foxprox-core direct_external_dns_bypass_is_denied_before_default_allow` and `cargo test -p foxprox-core unsupported_event_fails_closed_and_is_audited`.
- What failed or surprised the agent: `cargo test ... -- --exact` matched zero tests because the filter did not include full test paths; reran focused tests without `--exact` and both passed.
- What remains unproven: no packet parser, TUN frontend, bwrap setup helper, smoltcp adapter, DNS server, egress backend, runtime audit sink, or forwarding proof yet.
- Commit: this commit.

## 2026-06-21 Session Continue — IPv4 parser → normalized event → policy/audit slice

- Slice attempted: add the smallest packet-core proof that parses IPv4 TCP/UDP/ICMP bytes into normalized events and then verifies those events through the existing policy/audit boundary.
- Why next: parser-to-normalized-event is the next unresolved integration risk that can be proven without Linux privileges or speculative TUN setup.
- Verification plan: add a platform-independent `foxprox-packet` crate with focused fixture tests for TCP SYN, UDP DNS/QUIC classification, ICMP, malformed packets, unsupported protocols, and fragmentation fail-closed; run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — IPv4 parser → normalized event → policy/audit

- Slice attempted: platform-independent IPv4 packet parsing that normalizes TCP SYN, UDP, ICMP, unsupported protocols, malformed packets, and fragments into policy-consumable outcomes.
- Why next: this proves the parser-to-normalized-event boundary and reuses the already verified policy/audit boundary without requiring a TUN fd or host networking privileges.
- What changed: added `crates/foxprox-packet`, workspace membership, and tests for TCP connect events, UDP DNS direct-bypass denial through policy/audit, UDP/443 QUIC candidate classification, ICMP normalization, unsupported protocol fail-closed evaluation, malformed packet fail-closed conversion, and IPv4 fragmentation rejection.
- Verification:
  - `cargo fmt --check` initially failed before formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 9 `foxprox-core` tests, 7 `foxprox-packet` tests, and 0 doc tests.
  - `cargo fmt --check` passed after formatting.
  - Focused checks passed: `cargo test -p foxprox-packet parses_ipv4_tcp_syn_into_connect_attempt`, `cargo test -p foxprox-packet malformed_packet_can_be_converted_to_fail_closed_event`, and `cargo test -p foxprox-packet parses_udp_dns_packet_and_policy_denies_direct_external_dns`.
- What failed or surprised the agent: no packet parsing dependency was needed for the minimal IPv4 evidence; checksum validation remains intentionally unproven.
- What remains unproven: IPv6 parsing, checksum validation, TCP stream state, UDP forwarding, DNS payload parsing, ICMP reply synthesis, TUN read/write, runtime audit sinks, and host egress are still absent.
- Commit: this commit.
