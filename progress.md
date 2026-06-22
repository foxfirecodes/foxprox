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
- Commit hash after commit: 6ed5a43.
- Remaining boundary risks: file format deserialization, CLI config paths, config reload audit, and schema compatibility tests remain.

## 2026-06-21 — Boundary objective: shared HTTP egress contract

- Boundary under work: explicit/plaintext HTTP request forwarding contract through the shared host egress layer.
- Allowed dependency direction: `foxprox-egress` receives normalized `HttpRequest` events from `foxprox-core`; frontends parse HTTP but do not forward directly; policy/audit do not import egress implementations.
- Dependency-risk assessment: HTTP proxy support can become a policy bypass if allowed `HttpRequest` events are treated as no-op or frontend-local forwarding, so the egress trait must include normalized HTTP forwarding.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: initial clippy found the expanded dispatch return type too complex; factoring it into `DispatchOutcome` resolved the boundary API without allowing clippy exceptions. All verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 45 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: d1b9a42.
- Remaining boundary risks: production HTTP request IO, response streaming/backpressure, CONNECT byte bridging, and transparent stream reassembly remain.

## 2026-06-21 — Boundary objective: hidden-SNI TLS policy fail-closed

- Boundary under work: transparent TLS ClientHello policy handling when SNI/hostname attribution is unavailable.
- Allowed dependency direction: `foxprox-policy` consumes only normalized `TlsClientHello` metadata from `foxprox-core`; TLS parser/ECH details remain in `foxprox-inspect` or unsupported normalized events.
- Dependency-risk assessment: default-allow policies could accidentally permit hidden-SNI/ECH-like HTTPS flows unless policy has a pre-default fail-closed guard with an explicit IP/port rule escape hatch.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: TLS ClientHello events without SNI now bypass default-allow and are denied unless an explicit IP/port rule matches; all verification passed.
- Changed files:
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 46 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: a1ee0ce.
- Remaining boundary risks: production stream reassembly, ECH detection hardening, and richer TLS parser fuzzing remain.

## 2026-06-21 — Boundary objective: ICMP default policy contract

- Boundary under work: normalized ICMP policy defaults for essential errors, ping, and unusual ICMP denial.
- Allowed dependency direction: packet code emits normalized `IcmpMessage`; policy decides using only type/code metadata and does not import raw packet buffers.
- Dependency-risk assessment: ICMP defaults were ambiguous under default allow/deny; essential errors should not require broad allow rules, while unusual ICMP and ping must remain explicit/default-safe.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: essential IPv4/IPv6 ICMP errors are allowed before default-deny, ping is allowed only when `allow_ping` is true, and unusual ICMP is denied before default-allow. All verification passed.
- Changed files:
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 47 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: f17ddb8.
- Remaining boundary risks: ICMPv6 packet normalization, synthesized unreachable responses for denied UDP, and path-MTU integration remain.

## 2026-06-21 — Boundary objective: flow lifecycle audit contract

- Boundary under work: normalized audit records for TCP/UDP flow close and expiry lifecycle events.
- Allowed dependency direction: `foxprox-audit` defines lifecycle record constructors from normalized core fields only; `foxprox-net` may translate flow state into audit records, but audit must not depend on network adapter structs.
- Dependency-risk assessment: flow lifecycle logging can drift toward stack-specific flow objects; this boundary keeps audit records schema-stable with protocol/source/destination/byte-count/duration fields.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: initial clippy rejected a many-argument audit constructor, so the lifecycle input was narrowed into `FlowClosedAudit`; all verification passed.
- Changed files:
  - `crates/foxprox-audit/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 49 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 71dac67.
- Remaining boundary risks: production TCP close hooks, UDP expiry scheduler, and stream byte accounting integration remain.

## 2026-06-21 — Boundary objective: policy timeout override contract

- Boundary under work: normalized allow-decision timeout overrides for rule-matched flows.
- Allowed dependency direction: timeout override is a `foxprox-core` policy contract and `foxprox-config` validates user seconds into typed durations; flow code consumes `AllowDecision` without config strings.
- Dependency-risk assessment: UDP/QUIC timeout policy can become hard-coded in flow code unless rule-specific overrides are normalized at policy decision time.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: allow rules can now carry typed timeout overrides; config validates nonzero seconds and policy returns the override in `AllowDecision`. All verification passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-config/src/lib.rs`
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 50 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: b39a70c.
- Remaining boundary risks: per-flow storage of timeout override and production expiry scheduling remain.

## 2026-06-21 — Boundary objective: per-flow idle timeout enforcement

- Boundary under work: flow manager storage and expiry using normalized per-flow timeout decisions.
- Allowed dependency direction: `foxprox-net` may read `AllowDecision.timeout_override` from core policy decisions; it must not parse config or hard-code frontend-specific timeout rules into policy.
- Dependency-risk assessment: configurable UDP/QUIC timeouts are ineffective unless the flow table stores timeout decisions per flow and expires each flow independently.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: `FlowState` now stores a per-flow idle timeout, flow table expiry can evaluate each flow independently, and timeout overrides fall back to default classification timeouts when absent. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 51 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 1e67f79.
- Remaining boundary risks: production timers, egress handle cleanup, and lifecycle audit emission from the scheduler remain.

## 2026-06-21 — Boundary objective: CNAME-aware DNS attribution contract

- Boundary under work: DNS response normalization for CNAME-to-address alias chains.
- Allowed dependency direction: CNAME wire parsing remains in `foxprox-dns`; `foxprox-net` continues to consume only normalized hostname/IP/TTL address records.
- Dependency-risk assessment: hostnames often resolve through aliases, and ignoring CNAME chains can silently drop domain attribution even though DNS observed a valid hostname-to-IP relationship.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: DNS response parsing now follows CNAME answers to add alias hostname/IP/TTL attribution records while still exporting only normalized address records. All verification passed.
- Changed files:
  - `crates/foxprox-dns/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 52 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 9ae7f71.
- Remaining boundary risks: multi-response cache merging, negative DNS caching, and DNSSEC/authority metadata remain.

## 2026-06-21 — Boundary objective: HTTP origin scheme matcher contract

- Boundary under work: normalized HTTP scheme matching for origin-aware plaintext/proxy HTTP policy.
- Allowed dependency direction: frontends emit `HttpRequest.scheme`; `foxprox-policy` matches typed core rule fields; no parser structs or raw request text enter policy.
- Dependency-risk assessment: origin policy is incomplete if rules can match host/port/path but not scheme, especially for explicit proxy absolute-form HTTP requests.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added typed `HttpSchemeMatcher` to core rules, config validation, and policy matching; HTTP origin rules can now distinguish `http` from `https` normalized requests. All verification passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-config/src/lib.rs`
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 52 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 0a735c3.
- Remaining boundary risks: header matching, production proxy forwarding, and transparent HTTP stream reassembly remain.

## 2026-06-21 — Boundary objective: HTTP audit metadata contract

- Boundary under work: structured audit fields for normalized HTTP method, scheme, and path/query metadata.
- Allowed dependency direction: `foxprox-audit` reads only `foxprox-core::HttpRequest` normalized fields; it must not parse raw HTTP bytes or depend on frontend parser structs.
- Dependency-risk assessment: origin/path-aware policy is hard to review if audit records collapse HTTP requests to only host/port, so visible method/scheme/path must be schema fields.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: audit schema now includes HTTP method, scheme, and path/query fields populated from normalized `HttpRequest`; all verification passed.
- Changed files:
  - `crates/foxprox-audit/src/lib.rs`
  - `progress.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 53 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 7790475.
- Remaining boundary risks: selected header audit policy, production request/response byte counts, and sensitive header redaction remain.

## 2026-06-21 — Boundary objective: IPv4 TCP/UDP packet normalization

- Boundary under work: IPv4 packet boundary normalization for TCP connect attempts, UDP flow attempts, and denied-flow ICMP unreachable synthesis.
- Allowed dependency direction: `foxprox-packet` may depend only on `foxprox-core`; policy/audit must continue to consume normalized events, never raw packet headers or parser structs.
- Dependency-risk assessment: broadening packet parsing could leak TCP/UDP header details into policy or duplicate UDP classification semantics. The parser should emit only existing normalized contracts, and shared UDP classification should live in core to avoid drift between packet and network-adapter paths.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-packet`.
- Observed results: all verification passed. A first `cargo check --workspace` produced an unused-import warning while moving UDP classification; the follow-up check after adding the compatibility wrapper passed cleanly.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-packet/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 58 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet crate depends only on `foxprox-core`.
- Commit hash after commit: 7affa80.
- Remaining boundary risks: IPv6 TCP/UDP normalization, production stack-adapter TCP segment handling, real TUN fd IO, UDP forwarding sockets, and policy-driven ICMP-unreachable write-back integration remain.

## 2026-06-21 — Boundary objective: identifiable encrypted-DNS policy guard

- Boundary under work: default fail-closed policy for identifiable direct encrypted DNS, starting with DNS-over-TLS TCP/853 candidates.
- Allowed dependency direction: `foxprox-policy` consumes normalized destination IP/port and runtime broker DNS addresses from `foxprox-core`; it must not inspect raw TLS, DNS, TCP, or frontend parser objects.
- Dependency-risk assessment: default-allow TCP policy can accidentally permit DoT bypass before richer TLS/DoH metadata exists, so the policy needs a normalized pre-default guard with an explicit rule escape hatch.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-policy/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 60 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 7de4f01.
- Remaining boundary risks: DoH identification by hostname/IP intelligence, DNS-over-QUIC classification, and production TLS metadata wiring remain.

## 2026-06-21 — Boundary objective: flow resource limit contract

- Boundary under work: normalized runtime resource limit for maximum tracked flows and flow-table enforcement.
- Allowed dependency direction: config validation normalizes resource limits into `foxprox-core`; `foxprox-net` enforces typed limits without parsing config strings or importing policy/frontends.
- Dependency-risk assessment: unbounded flow state violates alpha robustness and can become a cross-layer shortcut if limits live only in launcher code. The limit should be a core runtime contract and enforced at the flow table boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-config/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 61 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: e73124b.
- Remaining boundary risks: per-backend socket/file-descriptor limits, per-sandbox byte/flow-rate accounting, production timer cleanup, and memory budgeting for stream buffers remain.

## 2026-06-21 — Boundary objective: proxy authority normalization robustness

- Boundary under work: HTTP/CONNECT authority parsing for bracketed IPv6 destinations.
- Allowed dependency direction: frontend parser code emits normalized `DestinationHost` values from `foxprox-core`; policy and egress continue to consume normalized host/IP plus port only.
- Dependency-risk assessment: explicit proxy parsing is a bypass-sensitive boundary. IPv6 authority parsing should be fixed in the frontend without introducing parser crate types or ad-hoc string destinations into policy.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: initial `cargo test --workspace` failed because the new IPv6 assertion had an ambiguous `parse()` type; after specifying `IpAddr`, all verification passed.
- Changed files:
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 62 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: ea0f3c7.
- Remaining boundary risks: production proxy listener IO, response/CONNECT stream bridging, request-size limits, and stricter malformed authority coverage remain.

## 2026-06-21 — Boundary objective: proxy parser size limit

- Boundary under work: fail-closed HTTP proxy request-size limit before UTF-8/request-line parsing.
- Allowed dependency direction: frontend parser enforces a local byte limit and emits normalized `UnsupportedNetworkEvent`; policy sees only `ParserLimitExceeded`, not raw request buffers.
- Dependency-risk assessment: unbounded proxy parser input violates robustness and could pressure memory before audit/policy. The limit should be enforced at the frontend boundary without adding policy-level raw parser state.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 63 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: d4219dc.
- Remaining boundary risks: configurable parser limits, streaming read limits in production listener IO, SOCKS negotiation size/timeout handling, and fuzzing proxy parser inputs remain.

## 2026-06-21 — Boundary objective: SOCKS5 handshake helpers

- Boundary under work: SOCKS5 no-auth method negotiation and CONNECT reply byte synthesis in the frontend crate.
- Allowed dependency direction: SOCKS wire handshake details remain frontend-local; after CONNECT parsing, policy/egress receive only normalized `SocksConnect` events.
- Dependency-risk assessment: SOCKS support is incomplete without handshake response helpers, but adding them must not push SOCKS wire enums into core policy contracts.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 64 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 7e22cf3.
- Remaining boundary risks: production SOCKS listener state machine, handshake/read timeouts, CONNECT stream bridging, and policy-to-reply-code mapping remain.

## 2026-06-21 — Boundary objective: TLS mismatch audit schema

- Boundary under work: structured audit field for transparent TLS SNI/DNS mismatch state.
- Allowed dependency direction: audit consumes only normalized `TlsClientHello.mismatch` state from `foxprox-core`; TLS parser details remain in `foxprox-inspect`.
- Dependency-risk assessment: policy can deny SNI/DNS mismatch, but without a stable audit field reviewers must infer the cause from reason strings. The audit schema should expose the normalized mismatch enum without raw TLS inputs.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-audit/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 65 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 0998dc8.
- Remaining boundary risks: audit serialization compatibility, hidden-SNI/ECH audit detail, and production TLS stream reassembly remain.

## 2026-06-21 — Boundary objective: policy-driven packet denial synthesis

- Boundary under work: packet-boundary helper that turns normalized `Deny(IcmpUnreachable)` decisions into opaque IPv4 ICMP unreachable bytes.
- Allowed dependency direction: `foxprox-packet` depends only on `foxprox-core`; policy chooses denial action but never imports packet synthesis or raw IP types.
- Dependency-risk assessment: denial write-back can tempt policy or net orchestration to learn packet headers. Mapping the decision to bytes inside the packet crate preserves the boundary while making ICMP-unreachable denial behavior testable.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-packet`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 66 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet crate depends only on `foxprox-core`.
- Commit hash after commit: a057b35.
- Remaining boundary risks: net/device orchestration must call this helper with the original packet, IPv6 ICMP unreachable synthesis is not implemented, and TCP reset denial synthesis remains behind the future stack adapter.

## 2026-06-21 — Boundary objective: standard-library host egress backend

- Boundary under work: production-oriented host egress implementation for TCP, UDP, CONNECT/SOCKS destinations, and basic plaintext HTTP dispatch behind the shared `HostEgress` trait.
- Allowed dependency direction: `foxprox-egress` consumes only normalized core events and standard-library sockets; frontends and policy must not own host socket opening.
- Dependency-risk assessment: explicit proxy and transparent paths can bypass shared enforcement if production socket opening is implemented in frontends. A std-backed egress type keeps host networking centralized while leaving async/backpressure refinements for later.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: all verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 67 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: f5e11b6.
- Remaining boundary risks: async egress, stream backpressure, HTTP response parsing/streaming, connection timeouts, DNS upstream selection, and integration with TUN/proxy listener event loops remain.

## 2026-06-21 — Boundary objective: IPv4 packet policy orchestration

- Boundary under work: TUN-facing IPv4 packet orchestration that connects packet normalization, policy/audit, shared egress, and policy-driven packet write-back.
- Allowed dependency direction: `foxprox-net` may orchestrate `foxprox-packet`, policy, audit, and egress; `foxprox-policy` and `foxprox-audit` must still consume only normalized events and must not import packet/raw-buffer types.
- Dependency-risk assessment: packet write-back can leak raw packet details upward if policy or audit learn packet headers. The orchestrator should keep original bytes local, ask policy only about normalized events, and return opaque outbound packets.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency checks for `foxprox-policy`, `foxprox-audit`, and `foxprox-net`.
- Observed results: initial `cargo clippy --all-targets --all-features -- -D warnings` found an 8-argument packet handler API; factoring the packet/session labels into `InboundIpv4Packet` kept the public boundary narrower and clippy-clean. All verification passed afterward.
- Changed files:
  - `Cargo.lock`
  - `crates/foxprox-net/Cargo.toml`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 69 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed after the API narrowing noted above.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
  - `cargo tree -p foxprox-net` — net orchestrates core/audit/dns/egress/packet/policy; packet remains behind the net orchestration boundary.
- Commit hash after commit: ba162f1.
- Remaining boundary risks: real TUN fd IO, userspace stack handoff for non-proof TCP segments, TCP reset denial synthesis, and production device event loops remain.

## 2026-06-21 — Boundary objective: configurable HTTP parser limit contract

- Boundary under work: normalized runtime/config contract for HTTP parser request-head size limits and frontend enforcement.
- Allowed dependency direction: config validates user-facing parser limits into `foxprox-core`; `foxprox-frontends` enforces typed limits locally and emits normalized unsupported events; policy/audit must not see raw request buffers or parser state.
- Dependency-risk assessment: keeping parser limits as frontend constants makes production listener robustness hard to configure and can encourage ad-hoc per-frontend knobs. The limit should be typed in runtime config while malformed/oversized inputs stay normalized.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `ParserLimits` to the normalized runtime config, config validation for nonzero HTTP request-head limits, and `parse_http_request_with_limits` enforcement before UTF-8/request parsing. All verification passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-config/src/lib.rs`
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 70 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-config` — config depends only on `foxprox-core`.
  - `cargo tree -p foxprox-frontends` — frontends depend only on `foxprox-core`.
- Commit hash after commit: 4db40c8.
- Remaining boundary risks: streaming listener read limits, SOCKS handshake limits/timeouts, and fuzzing proxy parser inputs remain.

## 2026-06-21 — Boundary objective: configurable SOCKS parser limit contract

- Boundary under work: normalized runtime/config contract for SOCKS5 greeting and CONNECT request size limits plus frontend fail-closed enforcement.
- Allowed dependency direction: `foxprox-core` owns typed parser limits, `foxprox-config` validates them, and `foxprox-frontends` enforces them before SOCKS wire parsing; policy/audit still consume only normalized `SocksConnect` or unsupported events.
- Dependency-risk assessment: SOCKS listener robustness should not rely on unbounded byte slices or frontend-local magic numbers. Size failures need a distinct normalized parser-limit reason without leaking SOCKS wire details to policy.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: extended `ParserLimits` and config validation with a SOCKS5 message byte limit; SOCKS greeting and CONNECT helpers enforce the typed limit before wire parsing and normalize oversized CONNECT requests as parser-limit unsupported events. All verification passed.
- Changed files:
  - `crates/foxprox-core/src/lib.rs`
  - `crates/foxprox-config/src/lib.rs`
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 71 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 6fd580d.
- Remaining boundary risks: production SOCKS listener read timeouts, CONNECT stream bridging, and policy-to-reply-code mapping remain.

## 2026-06-21 — Boundary objective: SOCKS policy reply mapping

- Boundary under work: frontend-local SOCKS5 reply-code mapping from normalized policy decisions.
- Allowed dependency direction: `foxprox-frontends` may depend on `foxprox-core` policy decision enums to choose SOCKS wire replies; policy must not import SOCKS reply codes or frontend wire details.
- Dependency-risk assessment: without a mapping helper, production SOCKS listener code may duplicate or leak SOCKS reply codes into policy/egress paths. Keep wire response selection in the frontend crate and make policy decisions remain protocol-neutral.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `socks5_reply_for_policy_decision` in `foxprox-frontends`, mapping normalized allow/deny/require-DNS/fail-closed decisions to frontend-local SOCKS5 reply codes without policy importing SOCKS wire details. All verification passed.
- Changed files:
  - `crates/foxprox-frontends/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 72 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-frontends` — frontends depend only on `foxprox-core`.
- Commit hash after commit: 5addd51.
- Remaining boundary risks: egress-error-to-reply mapping, production SOCKS listener state machine, read timeouts, and CONNECT stream bridging remain.

## 2026-06-21 — Boundary objective: audit JSON line serialization contract

- Boundary under work: stable structured audit record emission as JSON lines from normalized audit schema fields.
- Allowed dependency direction: `foxprox-audit` serializes its own normalized `AuditRecord`; it must not parse frontend/raw packet data or depend on policy/frontends/egress crates.
- Dependency-risk assessment: audit output is a first-class alpha feature, and leaving records only as Rust structs delays log compatibility testing. Serialization should stay schema-driven and avoid ad-hoc frontend-specific fields.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-audit`.
- Observed results: added `AuditRecord::to_json_line` with stable schema field emission, JSON escaping, explicit enum label mapping, byte-count objects, and snapshot coverage for HTTP audit output. All verification passed.
- Changed files:
  - `crates/foxprox-audit/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 73 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: d2f2d8e.
- Remaining boundary risks: file/stdout sinks, async audit backpressure integration, and schema versioning remain.
