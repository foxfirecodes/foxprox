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

## 2026-06-21 — Boundary objective: transparent inspection contracts

- Boundary under work: TLS ClientHello SNI extraction, hidden-SNI/ECH detection, SNI/DNS mismatch normalization, and QUIC candidate payload classification.
- Allowed dependency direction: inspection code may depend on `foxprox-core`; policy consumes only normalized `TlsClientHello`, `UdpFlowAttempt`, or `UnsupportedNetworkEvent` data and must not import parser types.
- Dependency-risk assessment: TLS/QUIC metadata parsing can easily widen into a full protocol stack or leak parser internals, so this boundary extracts only alpha policy metadata and fails closed for malformed or hidden-SNI/ECH inputs.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-inspect`.
- Observed results: pending.
- Changed files: pending.
- Commit hash after commit: pending.
- Remaining boundary risks: production-grade TLS/QUIC parser hardening and fuzzing are still required.

### Results

- Added `foxprox-inspect` as the transparent metadata boundary.
- Implemented narrow TLS ClientHello SNI extraction, ECH extension fail-closed normalization, SNI/DNS mismatch normalization, and QUIC candidate payload heuristic.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 34 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-inspect` — inspect crate depends only on `foxprox-core`.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-inspect/Cargo.toml`
  - `crates/foxprox-inspect/src/lib.rs`
  - `progress.md`
- Commit hash after commit: 867407d.
- Remaining boundary risks: fuzzing malformed TLS inputs, production QUIC metadata extraction, and transparent stream reassembly remain to be implemented.

## 2026-06-21 — Boundary objective: DNS normalization foundation

- Boundary under work: DNS wire query parsing, direct-external DNS bypass detection metadata, and fail-closed DNS refusal response synthesis.
- Allowed dependency direction: DNS wire parsing remains in a DNS subsystem crate depending only on `foxprox-core`; policy consumes normalized `DnsQuery` events and audit records normalized data.
- Dependency-risk assessment: DNS is both policy input and bypass vector, so parser output must be minimal and typed while malformed DNS fails closed.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-dns`.
- Observed results: pending.
- Changed files: pending.
- Commit hash after commit: pending.
- Remaining boundary risks: upstream DNS forwarding, response address caching from real answers, TCP DNS, DoH/DoT detection, and async serving remain to be implemented.

### Results

- Added `foxprox-dns` as the DNS wire normalization boundary.
- Implemented DNS query parsing for the first question, typed query classification, broker-vs-external DNS destination marking, malformed DNS unsupported-event normalization, and REFUSED response synthesis for denied DNS.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 38 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-dns` — DNS crate depends only on `foxprox-core`.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-dns/Cargo.toml`
  - `crates/foxprox-dns/src/lib.rs`
  - `progress.md`
- Commit hash after commit: 3ca2ed2.
- Remaining boundary risks: upstream DNS forwarding, answer parsing/caching from real upstream responses, async DNS service IO, TCP DNS, and DoH/DoT detection remain.

## 2026-06-21 — Boundary objective: widen HTTP origin contract safely

- Boundary under work: HTTP normalized request destination type.
- Allowed dependency direction: frontend parsing may produce a normalized hostname-or-IP destination; policy/audit consume that normalized type without raw parser structs.
- Dependency-risk assessment: the initial HTTP contract was too narrow because Host/absolute-URI authorities can be IP literals; forcing hostnames would make IP/port policy paths inconsistent across TCP, HTTP proxy, and SOCKS.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 38 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-audit/src/lib.rs`
  - `crates/foxprox-frontends/src/lib.rs`
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Commit hash after commit: f05915d.
- Remaining boundary risks: HTTP path/method matching is still not represented in rule matchers and should be added before relying on path-aware policy.

## 2026-06-21 — Boundary objective: HTTP method/path policy contract

- Boundary under work: normalized plaintext HTTP method/path rule matching.
- Allowed dependency direction: HTTP parser/frontends emit normalized `HttpRequest`; policy matches typed method and path-prefix contracts without importing parser/request types.
- Dependency-risk assessment: origin-aware HTTP policy is alpha scope, but adding it directly to frontend parsing would bypass the shared policy engine. The rule contract must stay in core and policy-only.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: pending.
- Changed files: pending.
- Commit hash after commit: pending.
- Remaining boundary risks: richer HTTP header matching and explicit proxy forwarding are still outside this rule matcher.

### Results

- Added `HttpMethodMatcher` and `HttpPathMatcher` to the core rule contract.
- Updated `foxprox-policy` to enforce method and exact/prefix path matchers only against normalized `HttpRequest` events.
- Added a policy test proving GET `/api/` is allowed while POST to the same path is denied under the same rule set.
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 39 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
- Commit hash after commit: 0ccd827.
- Remaining boundary risks: header-based policy and real transparent stream reassembly are still pending.

## 2026-06-21 — Boundary objective: DNS response attribution contract

- Boundary under work: DNS response answer normalization and DNS-to-flow attribution cache ingestion.
- Allowed dependency direction: DNS wire parsing remains in `foxprox-dns` depending only on `foxprox-core`; `foxprox-net` may consume normalized DNS address records for attribution; policy/audit must not consume DNS parser structs or raw response packets.
- Dependency-risk assessment: DNS answers are policy-sensitive attribution input, so only hostname/IP/TTL records should cross the DNS boundary and malformed responses must remain parser-local errors instead of partial policy events.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-dns`/`cargo tree -p foxprox-net`.
- Observed results: initial `cargo test --workspace` failed on an ambiguous test parse type; after specifying `IpAddr`, all verification passed.
- Changed files:
  - `Cargo.lock`
  - `crates/foxprox-dns/src/lib.rs`
  - `crates/foxprox-net/Cargo.toml`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 42 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-dns` — DNS crate depends only on `foxprox-core`.
  - `cargo tree -p foxprox-net` — network crate consumes DNS normalized records plus core/policy/audit/egress.
- Commit hash after commit: 0e9c816.
- Remaining boundary risks: upstream DNS IO, DNS response synthesis for allowed queries, TCP DNS, CNAME-to-address attribution, and DoH/DoT detection remain.

## 2026-06-21 — Boundary objective: typed config validation contract

- Boundary under work: user-facing alpha policy config validation into normalized `RuntimeConfig`.
- Allowed dependency direction: `foxprox-config` may depend only on `foxprox-core`; policy consumes validated runtime contracts only and must not parse raw config strings or config-file shapes.
- Dependency-risk assessment: config is a drift risk because stringly typed protocol, destination, decision, and timeout values could leak into policy; validation should normalize them before policy construction.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-config`.
- Observed results: initial verification found an unused import and ambiguous test IP parse; after narrowing the import and specifying `IpAddr`, all verification passed.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-config/Cargo.toml`
  - `crates/foxprox-config/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 44 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-config` — config crate depends only on `foxprox-core`.
- Commit hash after commit: pending.
- Remaining boundary risks: file format deserialization, CLI config paths, config reload audit, and schema compatibility tests remain.
