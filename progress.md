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

## 2026-06-21 — Boundary objective: JSON line audit sink

- Boundary under work: concrete audit sink that emits stable JSON lines through a bounded writer boundary.
- Allowed dependency direction: `foxprox-audit` may own serialization and writer sinks over normalized `AuditRecord`; broker/network code should depend on the `AuditSink` trait and not format audit records itself.
- Dependency-risk assessment: without a concrete sink, production/runtime code may add ad-hoc log formatting outside the audit crate. Keep IO errors typed in audit and retain normalized schema ownership.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `JsonLineAuditSink<W: Write>` that writes `AuditRecord::to_json_line()` output and returns typed audit IO errors. Added tests proving one-line JSON output through the sink. All verification passed.
- Changed files:
  - `crates/foxprox-audit/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 74 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Commit hash after commit: 615aec7.
- Remaining boundary risks: async/nonblocking audit backpressure and log rotation remain.

## 2026-06-21 — Boundary objective: TUN device IO contract

- Boundary under work: concrete read/write IO boundary for opaque IP packets from a TUN-like device without leaking file descriptors or raw packet buffers to policy/audit.
- Allowed dependency direction: `foxprox-device` owns device IO and exports opaque packet bytes; core/policy/audit must not depend on device, Linux fd, or TUN implementation types.
- Dependency-risk assessment: production TUN loops need a narrow IO contract before adding Linux-specific creation/setup. Keep the first implementation generic over `Read + Write` so tests can prove behavior without unsafe or kernel dependencies.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks for `foxprox-device` plus policy/audit.
- Observed results: added `foxprox-device` with opaque `DevicePacket`, `PacketDevice`, and generic blocking `Read + Write` IO wrapper. Tests cover read, write, empty packet, invalid max size, and oversized writes without introducing policy/audit dependencies on device or fd types. All verification passed.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-device/Cargo.toml`
  - `crates/foxprox-device/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 77 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-device` — device has no project crate dependencies.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 757c2b6.
- Remaining boundary risks: Linux TUN creation/ioctl, fd handoff, async readiness, and namespace setup remain.

## 2026-06-21 — Boundary objective: one-step device packet runtime

- Boundary under work: runtime orchestration that reads one opaque IPv4 packet from a device, applies normalized packet policy/audit/egress handling, and writes opaque outbound packets back to the device.
- Allowed dependency direction: `foxprox-runtime` may depend on device, core, net, policy, audit, and egress; policy/audit/core must not depend on runtime or device types.
- Dependency-risk assessment: device loops can become a dumping ground for raw packet and policy shortcuts. Keep the loop as orchestration over existing contracts and require outbound write-back to pass through opaque device packets.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks for runtime plus policy/audit.
- Observed results: added `foxprox-runtime` with `process_one_ipv4_device_packet`, wiring `PacketDevice` reads into `foxprox-net` packet handling and writing opaque outbound packets back to the device. Mock test proves an allowed ICMP echo request is audited and written back through the device. All verification passed.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-runtime/Cargo.toml`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 78 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime depends on device/core/net/policy/audit/egress with packet as a dev-dependency only for checksum fixtures.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 61ef71c.
- Remaining boundary risks: continuous async event loop, real TUN fd readiness, smoltcp TCP stream integration, and Linux setup remain.

## 2026-06-22 — Boundary objective: pre-opened TUN device wrapper

- Boundary under work: Linux-runtime-adjacent pre-opened TUN wrapper that accepts an already-opened file-like object without owning TUN creation, ioctl, namespace, or raw-fd handoff decisions.
- Allowed dependency direction: `foxprox-device` owns the TUN-facing IO wrapper and exports only opaque `DevicePacket`/`PacketDevice`; policy, audit, core, and net contracts must not import Linux fd or TUN implementation types.
- Dependency-risk assessment: accepting a pre-opened TUN endpoint is the safest unblocked path because it proves the runtime/device boundary while avoiding privileged setup and raw fd ownership. The wrapper must not introduce unsafe raw-fd constructors or policy-visible device metadata.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-device`/policy/audit checks.
- Observed results: added `PreopenedTunDevice<Io>` in `foxprox-device`, including `from_io`, `from_file`, `PacketDevice` delegation, and tests proving opaque read/write behavior plus invalid limit rejection. The wrapper accepts already-opened file-like TUN endpoints without unsafe raw-fd constructors or setup/ioctl behavior. All verification passed.
- Changed files:
  - `crates/foxprox-device/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 80 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-device` — device has no project crate dependencies.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: fa6cee9.
- Remaining boundary risks: raw fd ownership conventions, Linux TUN ioctl creation/configuration, bwrap fd handoff, async readiness, and namespace setup remain.

## 2026-06-22 — Boundary objective: runtime uses pre-opened TUN contract

- Boundary under work: runtime/device orchestration proof using the semantic pre-opened TUN wrapper rather than the lower-level generic blocking device directly.
- Allowed dependency direction: `foxprox-runtime` may consume `foxprox-device::PreopenedTunDevice` through the `PacketDevice` trait; policy/audit/core remain independent of runtime/device types.
- Dependency-risk assessment: adding a wrapper is insufficient unless runtime tests prove the TUN-facing type can pass through the existing packet policy and write-back path. Keep this as verification-only wiring without Linux fd or ioctl behavior.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-runtime`.
- Observed results: updated the one-step runtime test to use `PreopenedTunDevice` as the `PacketDevice`, proving the semantic pre-opened TUN wrapper can drive normalized packet handling, audit, and write-back. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 80 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime consumes device/net/policy/audit/egress contracts; policy/audit remain independent.
- Commit hash after commit: 491a086.
- Remaining boundary risks: actual pre-opened `File` integration in a launcher, raw fd handoff, async readiness, and Linux setup remain.

## 2026-06-22 — Boundary objective: DNS allowed address response synthesis

- Boundary under work: DNS subsystem response synthesis for allowed A/AAAA queries from normalized address data.
- Allowed dependency direction: `foxprox-dns` owns DNS wire response construction and depends only on `foxprox-core`; policy/audit/net consume normalized DNS events/records and must not build DNS wire packets directly.
- Dependency-risk assessment: DNS broker support needs allowed responses as well as refusal responses, but DNS packet details should remain contained in the DNS boundary. The response builder should accept IP address data and original query bytes, not policy/frontends/parser structs.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo tree -p foxprox-dns`.
- Observed results: added `build_address_response` to synthesize successful A/AAAA DNS responses from original query bytes plus caller-supplied IP addresses, filtering answers by query type and returning valid no-answer responses for unsupported types. Initial test compile failed on ambiguous IP parse; specifying `IpAddr` fixed it. All verification passed.
- Changed files:
  - `crates/foxprox-dns/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 82 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-dns` — DNS depends only on `foxprox-core`.
- Commit hash after commit: 6beadd8.
- Remaining boundary risks: UDP socket serving, upstream DNS wire forwarding, TCP DNS, negative caching, and DNSSEC/authority metadata remain.

## 2026-06-22 — Boundary objective: DNS packet broker orchestration

- Boundary under work: DNS packet handling that parses a UDP DNS query, applies shared policy/audit, resolves allowed queries through shared egress, and returns DNS wire responses from the DNS boundary.
- Allowed dependency direction: `foxprox-net` may orchestrate DNS/policy/audit/egress; `foxprox-dns` owns wire parsing/synthesis; policy/audit must not import DNS wire structs or egress types.
- Dependency-risk assessment: DNS serving can bypass shared policy if implemented as a standalone resolver path. Keep query decisions audited through normalized events and use shared egress for allowed resolution.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks for `foxprox-net`, `foxprox-policy`, and `foxprox-audit`.
- Observed results: added `handle_dns_packet` in `foxprox-net`, plus `DnsPacketRequest`/`DnsPacketOutcome`, to parse DNS wire queries, audit policy decisions, resolve allowed queries through shared `HostEgress`, synthesize address responses through `foxprox-dns`, and return refused responses for denied/direct-external DNS. Extended `MockEgress` with configurable DNS results. All verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 84 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-net` — net orchestrates DNS/policy/audit/egress behind normalized boundaries.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 651a917.
- Remaining boundary risks: real UDP DNS socket loop, upstream wire forwarding, response caching integration, TCP DNS, and negative caching remain.

## 2026-06-22 — Boundary objective: smoltcp adapter dependency proof

- Boundary under work: userspace network stack adapter proof using `smoltcp` behind the existing `StackAdapter` contract.
- Allowed dependency direction: a stack-specific adapter crate may depend on `smoltcp`, `foxprox-core`, and `foxprox-net`; policy, audit, frontend, device, DNS, and egress crates must not import or expose smoltcp types.
- Dependency-risk assessment: smoltcp is the highest-leverage alpha unknown because it shapes TCP/UDP packet ingress, outbound packet write-back, and eventual flow lifecycle. The first proof should keep smoltcp types private and only return normalized/opaque adapter outputs.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks for the smoltcp adapter plus policy/audit.
- Observed results: added `foxprox-smoltcp` using `smoltcp` 0.12.0 behind `foxprox-net::StackAdapter`. Implemented a private queued IP-medium smoltcp `Device`, public stack-neutral `SmoltcpAdapterConfig`, and `SmoltcpStackAdapter` that ingests opaque IP packets and emits opaque outbound packets. Test proves smoltcp processes an ICMP echo request and emits a valid echo reply without exposing smoltcp types. Initial clippy found a useless conversion in the IP address setup; removing it made all verification pass.
- Changed files:
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/foxprox-smoltcp/Cargo.toml`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 87 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed after the IP conversion fix noted above.
  - `cargo tree -p foxprox-smoltcp` — smoltcp is isolated in the adapter crate; dev-only packet dependency is used for checksum fixtures.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 2dbb247.
- Remaining boundary risks: TCP stream event extraction, host socket bridging, async polling, and real TUN integration remain.

## 2026-06-22 — Boundary objective: smoltcp TCP connect event extraction

- Boundary under work: TCP connection intent extraction from smoltcp sockets into normalized `TcpConnectAttempt` events.
- Allowed dependency direction: `foxprox-smoltcp` may use private smoltcp socket handles and emit `foxprox-core` normalized events through `foxprox-net::StackAdapter`; policy/audit/frontends/device must not import smoltcp types.
- Dependency-risk assessment: TCP forwarding alpha depends on turning sandbox SYN traffic into policy-visible connect attempts. The event must include only normalized socket metadata and avoid leaking smoltcp socket state or packet headers across the adapter boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks.
- Observed results: extended `foxprox-smoltcp` config with normalized sandbox/frontend labels and TCP listener ports, enabled smoltcp `any_ip`, tracked private listener socket handles, and emitted normalized `TcpConnectAttempt` events when a listened socket receives a SYN. Test proves a TCP SYN produces a normalized connect attempt and an opaque SYN-ACK packet without exposing smoltcp types. All verification passed.
- Changed files:
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 88 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in the adapter crate.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: b00cd15.
- Remaining boundary risks: accepting bridged stream bytes, host socket bridging, TCP close/error lifecycle, and real TUN polling remain.

## 2026-06-22 — Boundary objective: stack adapter runtime loop

- Boundary under work: runtime orchestration from opaque device packets into a `StackAdapter`, normalized policy/audit/egress handling for emitted events, and opaque outbound packet write-back.
- Allowed dependency direction: `foxprox-runtime` may depend on device/net/policy/audit/egress traits and contracts; it must not depend on smoltcp or packet parser internals. Stack-specific crates plug in through `StackAdapter`.
- Dependency-risk assessment: after proving smoltcp can emit normalized TCP events, runtime needs a generic adapter loop so stack-specific code does not start owning policy or device writes. Flow-close handling remains a separate lifecycle boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks for runtime/smoltcp/policy/audit.
- Observed results: added `process_one_stack_device_packet` in `foxprox-runtime`, which reads an opaque device packet, feeds it to any `StackAdapter`, routes emitted normalized policy events through shared policy/audit/egress handling, and writes opaque adapter outbound packets back to the device. Added a mock stack-adapter runtime test proving event policy/eager egress/audit plus write-back. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 89 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime depends on generic stack/device/policy/audit/egress contracts and not smoltcp.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in its adapter crate.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 5786b24.
- Remaining boundary risks: flow-close lifecycle handling from adapters, continuous polling, host stream bridging, and real TUN readiness remain.

## 2026-06-22 — Boundary objective: smoltcp adapter runtime integration proof

- Boundary under work: end-to-end proof that the smoltcp adapter plugs into the generic runtime stack loop without runtime depending on smoltcp.
- Allowed dependency direction: `foxprox-smoltcp` may use runtime/device/audit/egress/policy crates in tests to prove integration; production runtime must not import smoltcp, and policy/audit must remain smoltcp-independent.
- Dependency-risk assessment: separate adapter and runtime proofs can still miss wiring drift. A dev-only integration test should prove smoltcp TCP connect events travel through runtime policy/audit/egress and outbound SYN-ACK packets return to the device.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree checks.
- Observed results: added a dev-only integration test in `foxprox-smoltcp` that plugs `SmoltcpStackAdapter` into `foxprox-runtime::process_one_stack_device_packet` with a pre-opened device, policy rule, mock egress, and audit sink. The test proves a SYN is read from the device, converted to a normalized TCP connect attempt, allowed/audited/egressed, and produces an opaque SYN-ACK write-back. All verification passed.
- Changed files:
  - `crates/foxprox-smoltcp/Cargo.toml`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 90 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime has no smoltcp dependency.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in the adapter crate; runtime/device/audit/egress/policy are dev-dependencies for integration proof.
  - `cargo tree -p foxprox-policy` — policy depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: c704e38.
- Remaining boundary risks: TCP byte-stream bridging, continuous polling, flow-close lifecycle, and real TUN readiness remain.

## 2026-06-22 — Boundary objective: stack flow-close audit contract

- Boundary under work: normalized stack-adapter flow close events and runtime audit handling.
- Allowed dependency direction: stack adapters emit normalized flow lifecycle fields through `foxprox-net::StackEvent`; `foxprox-runtime` records them through `foxprox-audit`; audit must not depend on adapter internals or smoltcp socket state.
- Dependency-risk assessment: the stack runtime loop previously counted flow-close events without audit because the event was too narrow. Lifecycle events need enough normalized data for stable audit records without passing stack-specific flow objects.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: widened `StackEvent::FlowClosed` to carry `StackFlowClosed` normalized lifecycle fields and updated the runtime stack loop to convert those fields into `AuditRecord::flow_closed`. Added a mock stack-adapter test proving flow-close audit recording without adapter-specific state. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 91 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-net` — net exposes normalized stack lifecycle contract.
  - `cargo tree -p foxprox-runtime` — runtime records lifecycle audit through audit contract.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 8d27e4d.
- Remaining boundary risks: actual smoltcp close detection, TCP byte counts, stream bridging, and continuous polling remain.

## 2026-06-22 — Boundary objective: smoltcp TCP stream data events

- Boundary under work: userspace TCP stream data extraction from smoltcp sockets into stack-neutral adapter events.
- Allowed dependency direction: smoltcp socket buffering and TCP state remain private to `foxprox-smoltcp`; `foxprox-net` exposes only normalized source/destination/frontend/sandbox metadata plus payload bytes as a stack event; policy/audit remain independent.
- Dependency-risk assessment: TCP forwarding needs byte events after connect policy, but exposing smoltcp sockets or raw TCP headers would couple future forwarding and inspection to the selected stack. Keep data as a normalized runtime/adapter event and leave egress bridging for the next boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `StackTcpData` to the stack event contract and taught `foxprox-smoltcp` to drain received TCP socket bytes into stack-neutral data events after connect. Added a SYN/SYN-ACK/ACK+payload fixture proving smoltcp emits `hello` as normalized TCP data without exposing socket or TCP header types. Runtime counts TCP data events for now; bridging is left to the next boundary. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 92 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in the adapter crate.
  - `cargo tree -p foxprox-net` — net exposes only normalized stack event contracts.
  - `cargo tree -p foxprox-audit` — audit depends only on `foxprox-core`.
- Commit hash after commit: 33a5dee.
- Remaining boundary risks: egress stream writes, backpressure, server-to-sandbox data, close lifecycle from real sockets, and continuous polling remain.

## 2026-06-22 — Boundary objective: host TCP stream IO contract

- Boundary under work: shared host TCP stream read/write contract for future transparent and proxy byte bridging.
- Allowed dependency direction: `foxprox-egress` owns host stream IO traits/implementations; frontends and stack adapters must not write host sockets directly, and policy/audit must not depend on stream types.
- Dependency-risk assessment: smoltcp can now emit TCP payload bytes, but without a shared egress stream contract runtime code would be tempted to downcast or handle std sockets directly. Define the narrow stream IO API before wiring bridge state.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `HostTcpStream` as the shared egress-owned stream IO trait, bounded `HostEgress::TcpStream` by it, implemented the trait for `std::net::TcpStream` and `MockTcpStream`, and added a contract test proving bridge code can write/read through the normalized egress handle without frontend or stack socket types. All verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 93 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-egress` — egress depends only on `foxprox-core`.
  - `cargo tree -p foxprox-runtime` — runtime reaches stream handles through shared egress trait.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: f495281.
- Remaining boundary risks: runtime connection-handle storage, backpressure, server-to-sandbox packet injection, and async stream IO remain.

## 2026-06-22 — Boundary objective: runtime TCP bridge table

- Boundary under work: runtime-owned TCP bridge state that connects policy-approved stack TCP flows to shared host egress streams.
- Allowed dependency direction: runtime may retain opaque `HostTcpStream` handles returned by `foxprox-egress`; policy/audit continue to consume only normalized events; smoltcp socket types and std socket details must not leak across the stack/egress boundaries.
- Dependency-risk assessment: TCP forwarding is the main alpha proof gap. Without a bridge table, stack payload events are counted but not connected to host egress, inviting ad-hoc socket handling in runtime or stack code. The bridge key should be normalized sandbox/frontend/source/destination data and writes should use only `HostTcpStream`.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/egress/audit/smoltcp.
- Observed results: added `StackTcpBridgeTable` and normalized `StackTcpFlowKey` in runtime, exposed a net-layer `handle_normalized_event_with_egress` result so runtime can retain the exact host stream opened by shared egress, and wired `StackTcpData` writes through `HostTcpStream`. Added tests proving allowed stack TCP connects store a bridge and write payload bytes, while denied connects store no bridge and drop payload data without egress writes. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 95 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime depends on shared egress/net contracts, not smoltcp.
  - `cargo tree -p foxprox-egress` — egress depends only on `foxprox-core`.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in adapter crate.
- Commit hash after commit: bfa7515.
- Remaining boundary risks: host-to-sandbox packet injection, partial-write/backpressure semantics, async stream readiness, and bridge cleanup on real close remain.

## 2026-06-22 — Boundary objective: host-to-sandbox TCP write-back contract

- Boundary under work: runtime path for reading host egress TCP bytes and injecting them back into the stack adapter as opaque outbound packets for the device.
- Allowed dependency direction: runtime reads only `HostTcpStream` handles from its bridge table and calls a stack-neutral adapter write method; smoltcp packetization remains inside `foxprox-smoltcp`; policy/audit remain normalized-event only.
- Dependency-risk assessment: sandbox-to-host writes are now proven, but alpha TCP forwarding also needs return bytes. The fragile boundary is preventing runtime from learning smoltcp socket APIs or raw TCP packet synthesis; adapter-owned `StackTcpWrite` should express only normalized flow key plus payload bytes.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/net/smoltcp/audit.
- Observed results: added `StackTcpWrite` and a default stack-adapter TCP write-back method, implemented runtime `flush_tcp_bridge_reads_to_stack_device` to read bridged `HostTcpStream` bytes, enqueue them into the adapter, and write resulting opaque packets to the device. Implemented smoltcp write-back by sending bytes through private TCP sockets and polling outbound packets. Added runtime and smoltcp tests proving host bytes become adapter writes and smoltcp emits an opaque packet containing return payload. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 97 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime depends on contracts, not smoltcp.
  - `cargo tree -p foxprox-net` — stack write-back contract stays normalized.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in adapter crate.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: d101d39.
- Remaining boundary risks: partial-write/backpressure policy, async readiness, FIN/RST lifecycle, and real continuous loop scheduling remain.

## 2026-06-22 — Boundary objective: TCP bridge partial-write backpressure

- Boundary under work: prevent sandbox-to-host TCP payload loss when a host stream accepts only a partial write.
- Allowed dependency direction: runtime bridge state may buffer normalized payload bytes for `HostTcpStream` handles; egress implementations keep owning actual socket IO; policy/audit remain unaware of buffers and stream backpressure internals.
- Dependency-risk assessment: `HostTcpStream::write_from_sandbox` returns a byte count, so partial writes are part of the contract. Dropping unwritten bytes would silently corrupt forwarded streams. Runtime should retain unwritten bytes in bridge-owned pending state before later async readiness work.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: refactored runtime bridge entries to own a `HostTcpStream` plus a pending sandbox-to-host byte queue. `StackTcpBridgeTable::write_from_sandbox` now stores unwritten suffix bytes on short writes, exposes pending byte counts, and can flush queued bytes later through the same egress stream contract. Added a test proving `hello` written to a two-byte stream is retained and flushed as `he`/`ll`/`o` without data loss. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 98 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — backpressure state stays in runtime bridge.
  - `cargo tree -p foxprox-egress` — egress remains core-only and socket-IO focused.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 7afc89c.
- Remaining boundary risks: real async wakeups, maximum pending-buffer limits, connection teardown on repeated zero writes, and fair scheduling remain.

## 2026-06-22 — Boundary objective: bounded TCP bridge buffering

- Boundary under work: explicit resource limits for runtime TCP bridge pending buffers.
- Allowed dependency direction: runtime owns bridge memory accounting and rejects excess normalized payload buffering; policy/audit remain independent of stream backpressure internals; egress streams only perform IO.
- Dependency-risk assessment: retaining partial writes fixed data loss but introduced a possible unbounded memory queue. The bridge contract needs a bounded pending-byte limit before continuous forwarding loops are safe.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: added `StackTcpBridgeLimits` with a default 1 MiB pending sandbox-to-host cap, table construction with explicit limits, pending-byte inspection, and enforcement that rejects additional queued bytes before exceeding the cap. Added a test proving pending bytes remain unchanged and an egress stream error is returned when a second payload would exceed a three-byte cap. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 99 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — bounded bridge memory remains runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 9f8c4d2.
- Remaining boundary risks: per-sandbox/global limits, async wakeups, and teardown policy for exceeded limits remain.

## 2026-06-22 — Boundary objective: TCP bridge cleanup on normalized flow close

- Boundary under work: remove runtime TCP bridge state when a stack adapter emits a normalized flow-close event.
- Allowed dependency direction: flow lifecycle remains normalized (`StackFlowClosed`/`FlowKey`); runtime may use it to drop host stream handles; audit records normalized close data; smoltcp-specific close state stays adapter-local.
- Dependency-risk assessment: bridge tables now retain host streams and pending buffers. Without cleanup, closed stack flows leak egress handles and memory. Runtime should react to the normalized close contract rather than adapter-specific socket state.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`.
- Observed results: runtime now derives a normalized `StackTcpFlowKey` from TCP `StackFlowClosed` events, records the flow-close audit record, and removes any matching bridge entry. Extended the flow-close runtime test to pre-seed a bridge and prove the close event removes it while preserving normalized audit behavior. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 99 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — cleanup is runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 4bda7b1.
- Remaining boundary risks: detecting real smoltcp close events, teardown/audit reasons, and half-close semantics remain.

## 2026-06-22 — Boundary objective: nonblocking host TCP stream behavior

- Boundary under work: make standard host TCP stream handles safe for runtime bridge polling without blocking the broker loop.
- Allowed dependency direction: `foxprox-egress` owns std socket mode and `WouldBlock` handling behind `HostTcpStream`; runtime continues to use only the trait; policy/audit stay independent of socket IO.
- Dependency-risk assessment: runtime now has a bridge flush step that calls `read_to_sandbox`. If std streams remain blocking, a continuous loop can hang on one idle connection. The egress contract should normalize non-ready reads/writes as zero progress instead of leaking OS errors or blocking semantics upward.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for egress/runtime/audit.
- Observed results: updated `StdHostEgress` TCP connect/CONNECT/SOCKS stream paths to configure returned bridge streams as nonblocking, and normalized `WouldBlock` in the `HostTcpStream for TcpStream` implementation to zero progress for reads/writes. Added a localhost contract test proving an idle standard stream read returns an empty buffer instead of blocking or erroring. All verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 100 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-egress` — std socket behavior remains behind egress.
  - `cargo tree -p foxprox-runtime` — runtime still uses only `HostTcpStream`.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 79a4fb8.
- Remaining boundary risks: async connect timeouts, readiness registration, write fairness, and handling repeated zero-progress streams remain.

## 2026-06-22 — Boundary objective: smoltcp normalized flow-close detection

- Boundary under work: emit normalized stack flow-close events from smoltcp TCP socket lifecycle without exposing smoltcp state.
- Allowed dependency direction: smoltcp socket states and endpoints stay in `foxprox-smoltcp`; emitted close data uses `StackFlowClosed`, `FlowKey`, and normalized byte counts; runtime/audit consume only the stack-neutral lifecycle event.
- Dependency-risk assessment: runtime can clean bridges when it receives normalized close events, but smoltcp was not yet producing real close events. Adding adapter-local state for flow keys and byte counts proves cleanup/audit can be driven by actual stack lifecycle.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for smoltcp/runtime/audit.
- Observed results: extended smoltcp listener state with normalized flow keys, byte counters, connection start time, and close emission state. `collect_tcp_events` now emits `StackEvent::FlowClosed(StackFlowClosed)` when an observed TCP socket is no longer active, with normalized byte counts and duration, while smoltcp state remains private. Added a RST-based test proving a real smoltcp close emits a normalized close event with 5 sandbox-to-host and 6 host-to-sandbox bytes. All verification passed.
- Changed files:
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 101 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in adapter crate.
  - `cargo tree -p foxprox-runtime` — runtime consumes normalized close events.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 47cc2db.
- Remaining boundary risks: FIN half-close nuance, timeout-driven closes, and richer close reasons remain.

## 2026-06-22 — Boundary objective: minimal UDP payload forwarding proof

- Boundary under work: one-datagram UDP forwarding through the shared egress contract after normalized packet policy allows the flow.
- Allowed dependency direction: packet parsing may expose opaque UDP payload bytes to net orchestration only; policy/audit continue to receive only `UdpFlowAttempt`; egress owns host UDP socket send/receive behavior behind a trait.
- Dependency-risk assessment: UDP policy events already open host UDP flows, but payload bytes were not forwarded. A minimal send proof closes the alpha UDP gap while preserving the packet/policy boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for packet/net/egress/audit.
- Observed results: added opaque UDP payload extraction to `PacketInspection`, introduced `HostUdpFlow` for shared UDP send/receive behavior, implemented it for `UdpSocket` and mocks with nonblocking `WouldBlock` normalization, and taught `handle_ipv4_packet` to send allowed UDP payloads through the opened egress UDP handle. Added a net test proving an allowed UDP packet sends four payload bytes through shared egress while policy/audit see only the normalized event. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-egress/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 102 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-net` — orchestration owns packet-to-egress forwarding.
  - `cargo tree -p foxprox-egress` — UDP IO remains behind egress.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 0f23f9b.
- Remaining boundary risks: UDP response packet synthesis, UDP flow table handle retention, ICMP errors, and backpressure/rate limits remain.

## 2026-06-22 — Boundary objective: runtime UDP flow bridge retention

- Boundary under work: retain shared egress UDP flow handles after allowed packet forwarding so later host replies can be routed back to the sandbox.
- Allowed dependency direction: net orchestration may return an egress-owned UDP handle to runtime; runtime stores it by normalized sandbox/frontend/source/destination key; policy/audit continue to consume only `UdpFlowAttempt`; packet payload bytes stay opaque to policy/audit.
- Dependency-risk assessment: minimal UDP send forwarding currently opens a host UDP handle and drops it, preventing response routing and idle lifecycle management. The smallest next contract is returning the opened handle after payload send without exposing socket types outside egress/runtime generics.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for net/runtime/egress/audit.
- Observed results: added `PacketBrokerResult` and `handle_ipv4_packet_with_egress` so net orchestration can preserve opened egress handles after packet policy handling. Runtime now has normalized `UdpFlowKey`, `UdpBridgeTable`, and `process_one_ipv4_device_packet_with_udp_bridges` that sends the initial allowed UDP payload through shared egress and retains the resulting `HostUdpFlow` handle. Added a runtime test proving an allowed UDP packet writes `ping` and stores one normalized UDP bridge. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 103 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-net` — packet-to-egress handle preservation stays in orchestration.
  - `cargo tree -p foxprox-runtime` — UDP bridge retention is runtime-owned.
  - `cargo tree -p foxprox-egress` — UDP socket IO remains behind egress.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 8afeb78.
- Remaining boundary risks: UDP response packet synthesis, idle expiry, per-flow limits, ICMP errors, and rate limiting remain.

## 2026-06-22 — Boundary objective: UDP response write-back proof

- Boundary under work: route host UDP reply bytes from retained egress handles back to the sandbox as opaque IPv4 UDP packets.
- Allowed dependency direction: runtime reads only `HostUdpFlow` handles and asks `foxprox-packet` to synthesize packet bytes; packet crate owns IPv4/UDP wire formatting; policy/audit remain normalized-event only.
- Dependency-risk assessment: UDP egress handles are now retained, but without response synthesis UDP forwarding is one-way. Adding a narrow packet synthesis helper keeps raw IPv4/UDP details out of runtime and preserves future TAP compatibility.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for packet/runtime/audit.
- Observed results: added `foxprox_packet::synthesize_udp_ipv4_response` to build opaque IPv4 UDP reply packets from normalized original flow endpoints and host reply bytes, and added runtime `flush_udp_bridge_reads_to_device` to read retained `HostUdpFlow` handles, synthesize replies, and write them to the device. Added packet and runtime tests proving endpoint/port swapping and host `pong` response write-back. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-runtime/Cargo.toml`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 105 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-runtime` — runtime depends on packet for packet synthesis, not raw formatting.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 75f68e5.
- Remaining boundary risks: UDP idle expiry, IPv6 UDP responses, UDP checksums, ICMP errors, and rate limiting remain.

## 2026-06-22 — Boundary objective: UDP bridge idle expiry

- Boundary under work: runtime expiry of retained UDP pseudo-flow handles using normalized classification timeouts.
- Allowed dependency direction: runtime owns host UDP handle lifetime and uses typed `UdpTimeouts`; policy/audit remain independent; egress handles are dropped through the bridge table without exposing socket internals.
- Dependency-risk assessment: UDP bridge retention enables replies but can leak host sockets without idle expiry. Expiry should be based on normalized flow metadata and runtime time, not packet parser or OS socket details.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: extended runtime `UdpBridgeTable` entries with last-activity and idle-timeout metadata, added `expire_idle`, and inserted retained UDP handles with timeouts derived from normalized UDP classification plus typed `UdpTimeouts`. Updated UDP response flushing to refresh activity timestamps. Added a runtime test proving a bridge survives before its timeout and is removed exactly at expiry. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 106 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — UDP expiry remains runtime-owned and typed.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 8a68a00.
- Remaining boundary risks: per-sandbox/global UDP limits, ICMP error handling, IPv6, and rate limiting remain.

## 2026-06-22 — Boundary objective: bounded UDP bridge count

- Boundary under work: explicit runtime resource limit for retained UDP pseudo-flow handles.
- Allowed dependency direction: runtime enforces bridge-count limits over normalized flow keys; egress handles remain opaque; policy/audit remain independent of resource accounting internals.
- Dependency-risk assessment: UDP idle expiry bounds time but not burst cardinality. Before a continuous loop, the retained UDP bridge table needs a hard max-flow cap to prevent unbounded host socket retention.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: added `UdpBridgeLimits` with a default max-flow cap, `UdpBridgeTable::with_limits`, and checked insertion that rejects new flows when the table is full while allowing replacement of existing keys. Runtime UDP bridge retention now uses the checked insertion path. Added a test proving a one-flow table rejects a second distinct UDP flow without changing the retained count. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 107 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — UDP flow limits are runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 6c16a08.
- Remaining boundary risks: per-sandbox flow limits, rate limiting, ICMP error handling, and IPv6 remain.

## 2026-06-22 — Boundary objective: UDP response checksum hardening

- Boundary under work: IPv4 UDP response synthesis correctness inside the packet boundary.
- Allowed dependency direction: UDP pseudo-header/checksum calculation stays in `foxprox-packet`; runtime receives opaque packet bytes only; policy/audit remain normalized-event only.
- Dependency-risk assessment: the minimal UDP response proof used an IPv4-legal zero UDP checksum, but real forwarding should emit checksummed UDP responses when possible. Hardening this in packet code improves correctness without changing runtime or policy contracts.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency tree for packet.
- Observed results: replaced zero-checksum UDP response synthesis with IPv4 pseudo-header UDP checksum calculation inside `foxprox-packet`, including the all-zero checksum to `0xffff` normalization. Updated the response synthesis test to assert a nonzero UDP checksum while preserving endpoint swapping and payload assertions. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 107 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — checksum logic remains packet/core-only.
- Commit hash after commit: cf1b824.
- Remaining boundary risks: IPv6 UDP responses, ICMP errors, and rate limiting remain.

## 2026-06-22 — Boundary objective: bridge maintenance tick contract

- Boundary under work: one bounded runtime maintenance tick that flushes retained TCP/UDP bridge state without parsing packets or invoking policy.
- Allowed dependency direction: runtime coordinates `HostTcpStream`, `HostUdpFlow`, stack adapter write-back, and device writes through existing contracts; packet formatting stays in packet/adapter crates; policy/audit remain outside bridge maintenance.
- Dependency-risk assessment: forwarding pieces are now implemented as separate functions. A small maintenance tick proves how a future loop can flush pending TCP writes, TCP host reads, UDP host reads, and UDP expiry without hardwiring smoltcp or std sockets into orchestration.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: added `BridgeMaintenanceStep`, `BridgeMaintenanceOutcome`, and `process_bridge_maintenance_tick` in runtime. The tick flushes pending sandbox-to-host TCP bytes, host-to-sandbox TCP reads through the stack adapter, host UDP reply reads through packet synthesis/device write-back, and UDP idle expiry without invoking policy or exposing socket/stack internals. Added a runtime test proving one maintenance tick flushes both TCP and UDP paths and reports combined outbound packet writes. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 108 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — maintenance orchestration stays in runtime over contracts.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 0279186.
- Remaining boundary risks: blocking device read integration, readiness registration, async scheduling, and fair per-flow budgets remain.

## 2026-06-22 — Boundary objective: nonblocking device readiness contract

- Boundary under work: packet device readiness for future runtime loops that should not block maintenance on an idle TUN/device read.
- Allowed dependency direction: `foxprox-device` owns IO readiness normalization (`WouldBlock`); runtime can ask for an optional opaque `DevicePacket`; policy/audit still never see device or IO errors directly.
- Dependency-risk assessment: bridge maintenance can now run independently, but the packet-ingest APIs still call blocking reads. A small readiness contract lets future loops skip packet ingestion when no device packet is ready without leaking OS error kinds into runtime logic.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for device/runtime/audit.
- Observed results: added `TryPacketDevice` in `foxprox-device`, normalized `std::io::ErrorKind::WouldBlock` into `Ok(None)` for optional packet reads, and implemented it for `BlockingPacketDevice`/`PreopenedTunDevice`. Runtime now has `process_one_ipv4_device_packet_if_ready`, which returns `None` without policy/audit/egress side effects when no packet is ready. Added device and runtime tests for would-block behavior. All verification passed.
- Changed files:
  - `crates/foxprox-device/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 110 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-device` — device remains dependency-free.
  - `cargo tree -p foxprox-runtime` — runtime consumes device readiness through the device contract.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 8a7cce0.
- Remaining boundary risks: full async readiness registration, blocking production fd configuration, and fair loop scheduling remain.

## 2026-06-22 — Boundary objective: nonblocking stack device packet step

- Boundary under work: optional-read stack packet ingestion for the smoltcp/TUN path.
- Allowed dependency direction: runtime consumes `TryPacketDevice` and `StackAdapter` contracts only; stack-specific smoltcp behavior remains in adapter crate; policy/audit still see only normalized stack events.
- Dependency-risk assessment: IPv4 one-step processing now has a nonblocking readiness path, but stack/TCP forwarding still blocks on device reads. Adding a stack optional-read step lets future loops run bridge maintenance when no TUN packet is ready.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/device/smoltcp/audit.
- Observed results: factored stack packet processing so both blocking and optional-read entry points use the same stack-event policy/audit/egress handling. Added `process_one_stack_device_packet_if_ready`, using `TryPacketDevice` to return `Ok(None)` when no TUN packet is ready, and added a runtime test proving no adapter/policy/audit/bridge side effects occur on would-block. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 111 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — optional stack step consumes device/stack contracts only.
  - `cargo tree -p foxprox-device` — readiness stays in device crate.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated behind adapter.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 79feaf2.
- Remaining boundary risks: full loop scheduling, readiness registration, and fairness budgets remain.

## 2026-06-22 — Boundary objective: stack runtime tick orchestration

- Boundary under work: one nonblocking stack runtime tick that optionally ingests a TUN packet and always runs bridge maintenance.
- Allowed dependency direction: runtime coordinates `TryPacketDevice`, `StackAdapter`, policy/audit/egress, TCP bridges, and UDP bridges through existing contracts; no smoltcp or std socket types leak into policy/audit.
- Dependency-risk assessment: optional packet steps and bridge maintenance exist separately. A tick-level orchestration contract proves an idle device no longer starves forwarding maintenance, while still keeping scheduling/fairness policy outside lower-level crates.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/device/smoltcp/audit.
- Observed results: added `StackRuntimeTickStep` and `process_stack_runtime_tick`, which optionally ingests one stack device packet via `TryPacketDevice` and then always runs `process_bridge_maintenance_tick`. Added `StackRuntimeTickOutcome` with separate packet and maintenance results. Added a runtime test proving an idle device still flushes TCP host bytes through the adapter and writes outbound packets. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 112 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — tick coordinates only existing runtime boundary crates.
  - `cargo tree -p foxprox-device` — device remains readiness boundary.
  - `cargo tree -p foxprox-smoltcp` — smoltcp remains isolated in adapter crate.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 8fbe8e6.
- Remaining boundary risks: production event loop, readiness registration, per-flow fairness, and signal/shutdown handling remain.

## 2026-06-22 — Boundary objective: bounded bridge maintenance budgets

- Boundary under work: per-tick bridge maintenance budgets for TCP and UDP flows.
- Allowed dependency direction: runtime owns scheduling/budget decisions while egress streams, packet synthesis, stack adapters, and audit remain behind their existing contracts.
- Dependency-risk assessment: maintenance can now run when the device is idle, but unlimited flow iteration per tick risks starving packet ingress or other sandboxes. Bounded flow counts are a scheduler-facing contract for future fairness without changing policy/audit/egress types.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/device/audit.
- Observed results: added `BridgeMaintenanceBudget` with default TCP/UDP flow-count caps, wired it through `BridgeMaintenanceStep` and `StackRuntimeTickStep`, and added bounded read helpers for TCP and UDP bridge maintenance. Existing unbounded helpers remain as convenience wrappers. Added a runtime test proving a tick with a 1/1 budget reads only one TCP stream and one UDP flow while preserving existing per-flow byte caps. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 113 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — fairness/budgeting remains runtime-owned.
  - `cargo tree -p foxprox-device` — device contract unchanged.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 0aaf715.
- Remaining boundary risks: true round-robin readiness cursors, per-sandbox fairness, and rate accounting remain.

## 2026-06-22 — Boundary objective: per-sandbox bridge retention limits

- Boundary under work: per-sandbox TCP/UDP bridge retention caps in runtime-owned bridge tables.
- Allowed dependency direction: runtime enforces retained-flow resource limits using normalized sandbox ids; egress handles and policy/audit contracts remain unchanged.
- Dependency-risk assessment: global bridge caps exist for UDP and pending-byte caps exist for TCP, but a single sandbox can still occupy all retained bridge slots. Per-sandbox caps reduce blast radius without leaking scheduler state into egress/policy/audit.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: added default global and per-sandbox retained bridge caps for TCP and UDP. `UdpBridgeTable` now rejects inserts that exceed either global or per-sandbox flow caps. `StackTcpBridgeTable` now has global/per-sandbox stream caps plus a fallible `try_insert`; stack policy/egress handling uses the fallible path so retention-limit failures return runtime errors rather than panicking. Added tests for TCP and UDP per-sandbox limits. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 115 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — per-sandbox caps remain runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 39f1b54.
- Remaining boundary risks: rate-limit accounting and cross-sandbox weighted fairness remain.

## 2026-06-22 — Boundary objective: IPv6 UDP reply synthesis

- Boundary under work: host UDP reply write-back for IPv6 flows.
- Allowed dependency direction: `foxprox-packet` owns IPv6/UDP wire synthesis; runtime selects synthesis based on normalized `SocketAddr` flow keys and still writes opaque packets only.
- Dependency-risk assessment: UDP bridge write-back currently synthesizes IPv4 only, so IPv6 UDP replies cannot be returned without leaking packet-format logic into runtime. Adding packet-owned IPv6 synthesis preserves the boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/packet/audit.
- Observed results: added `foxprox_packet::synthesize_udp_ipv6_response` with IPv6 header construction, endpoint swapping, payload length, UDP ports, and IPv6 UDP checksum. Runtime UDP bridge write-back now selects IPv4 or IPv6 synthesis from normalized flow-key socket address families and still writes opaque outbound packets. Added packet and runtime tests for IPv6 UDP host replies. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 117 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime selects packet crate synthesis through existing dependency.
  - `cargo tree -p foxprox-packet` — packet crate remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 3e291f4.
- Remaining boundary risks: IPv6 packet classification/input path and ICMPv6 errors remain.

## 2026-06-22 — Boundary objective: UDP host-failure ICMP write-back

- Boundary under work: ICMP error write-back for IPv4 UDP bridge host-side failures.
- Allowed dependency direction: packet crate owns ICMP/IPv4 wire synthesis; runtime detects egress-flow failure through `HostUdpFlow`, removes the retained bridge, and writes opaque ICMP packets without exposing socket errors to policy/audit.
- Dependency-risk assessment: UDP bridge read errors currently bubble as runtime errors and leave no sandbox-visible network failure. A packet-owned ICMP unreachable helper lets runtime report host-side failure while preserving normalized boundaries.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/packet/audit.
- Observed results: added `synthesize_udp_ipv4_unreachable_from_flow` in `foxprox-packet`, which builds the quoted minimal IPv4/UDP packet and delegates ICMP response construction to packet-owned code. Runtime UDP bridge reads now remove failed IPv4 flows, synthesize ICMP port-unreachable packets, and write opaque packets to the device instead of bubbling the egress error to policy/audit. Added packet and runtime tests. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 119 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime uses packet crate for ICMP bytes.
  - `cargo tree -p foxprox-packet` — packet crate remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 0443a31.
- Remaining boundary risks: TCP reset/error signaling and ICMPv6 errors remain.

## 2026-06-22 — Boundary objective: Linux TUN setup helper command plan

- Boundary under work: privileged setup-helper contract for concrete Linux TUN commands.
- Allowed dependency direction: `foxprox-integrations` owns Linux helper command details; runtime/device/net/policy/audit still receive only preopened devices and normalized events.
- Dependency-risk assessment: bwrap planning already names `foxproxsetup`, but the helper-side TUN setup steps are not represented. A command-plan contract makes the privileged helper boundary testable without moving ioctl/iproute details into broker core.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for integrations/device/audit.
- Observed results: added data-only `TunSetupCommand`, `TunSetupCommandPlan`, and `LinuxIpTunSetup::plan_commands` in `foxprox-integrations`. The plan produces concrete Linux `ip tuntap add`, `ip addr add ... peer ...`, and `ip link set ... mtu ... up` commands while keeping privileged details outside runtime/device/net/policy/audit. Added validation for mismatched TUN address families and tests for the generated command plan. All verification passed.
- Changed files:
  - `crates/foxprox-integrations/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 121 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-integrations` — integrations remains core-only.
  - `cargo tree -p foxprox-device` — device remains independent/preopened boundary.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 52cde96.
- Remaining boundary risks: executing these commands, fd handoff, and OS-specific error mapping remain.

## 2026-06-22 — Boundary objective: transparent TCP payload inspection before forwarding

- Boundary under work: transparent HTTP/TLS first-payload policy gates for stack TCP forwarding.
- Allowed dependency direction: `foxprox-inspect` emits normalized HTTP/TLS/unsupported events from stream bytes; runtime asks `foxprox-net` to apply policy/audit without opening a second egress path; existing egress TCP bridge remains the only host forwarding handle.
- Dependency-risk assessment: direct TUN HTTP/HTTPS policy is incomplete if TCP payload bytes are bridged after only an IP/port connect decision. The risk is accidentally proxying transparent bytes through the HTTP egress path, so this boundary needs an explicit policy/audit-only event handler.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/inspect/net/audit.
- Observed results: added `handle_normalized_event_without_egress` in `foxprox-net` so inline transparent observations can be policy/audited without opening a second egress path. Added plaintext transparent HTTP inspection in `foxprox-inspect`. Runtime now marks the first TCP bridge payload, emits normalized transparent HTTP or TLS inspection events for ports 80/443, records policy/audit, and drops/removes the bridge on inspection denial before forwarding bytes. Added tests proving allowed transparent HTTP is audited then forwarded and denied transparent HTTP is not forwarded. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-inspect/src/lib.rs`
  - `crates/foxprox-runtime/Cargo.toml`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 124 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime depends on inspect/net contracts, not parser internals.
  - `cargo tree -p foxprox-inspect` — inspect remains core-only.
  - `cargo tree -p foxprox-net` — net owns policy/audit orchestration.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: ac2d86f.
- Remaining boundary risks: full stream reassembly and deferred host connect before HTTP/TLS allow remain.

## 2026-06-22 — Boundary objective: DNS attribution enrichment contract

- Boundary under work: DNS-to-flow correlation for transparent TCP/UDP events.
- Allowed dependency direction: `foxprox-net` owns flow/event enrichment using normalized DNS cache entries; packet parsers and policy still exchange only normalized events with typed hostname attribution.
- Dependency-risk assessment: DNS cache shape exists, but flow events can remain IP-only unless attribution is applied at the net boundary. The enrichment contract must avoid letting DNS parser records or cache internals leak into policy.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for net/dns/policy/audit.
- Observed results: added `apply_dns_attribution` in `foxprox-net`, which enriches normalized TCP and UDP events with medium-confidence hostname attribution from `DnsAttributionCache` when no higher-confidence hostname is already present. Added a test proving transparent TCP and QUIC-candidate UDP events receive DNS-correlated hostnames without exposing DNS wire/parser data. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 125 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-net` — net owns DNS attribution orchestration.
  - `cargo tree -p foxprox-dns` — DNS remains core-only.
  - `cargo tree -p foxprox-policy` — policy remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: cc1b91f.
- Remaining boundary risks: wiring the cache into long-running stack runtime state remains.

## 2026-06-22 — Boundary objective: stack runtime DNS attribution wiring

- Boundary under work: long-running stack runtime policy events enriched from DNS cache before policy/audit decisions.
- Allowed dependency direction: runtime may pass `foxprox-net::DnsAttributionCache` into stack orchestration; stack adapters still emit normalized events, and policy/audit see only enriched normalized event fields.
- Dependency-risk assessment: a net-layer enrichment helper exists but stack traffic still bypasses it unless runtime applies it before policy. The risk is domain rules silently failing for transparent stack TCP despite broker DNS observations.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/net/audit.
- Observed results: added `StackDnsAttribution` to runtime stack packet/tick steps and applied `foxprox_net::apply_dns_attribution` to stack adapter policy events before policy/audit/egress handling. Added a runtime test proving a DNS-correlated hostname can satisfy a transparent TCP domain rule and appears in audit without exposing cache internals to policy. Updated smoltcp runtime integration call sites. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `crates/foxprox-smoltcp/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 126 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime coordinates net attribution and inspect contracts.
  - `cargo tree -p foxprox-net` — net owns DNS attribution cache/enrichment.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 81bcbd1.
- Remaining boundary risks: updating cache from live DNS packets in the stack runtime loop remains.

## 2026-06-22 — Boundary objective: broker DNS service for IPv4 TUN packets

- Boundary under work: route broker-addressed UDP/53 packets through the DNS subsystem, synthesize UDP responses, and update DNS attribution cache.
- Allowed dependency direction: `foxprox-net` may combine packet inspection, DNS subsystem, egress, and packet synthesis; policy/audit still consume normalized `DnsQuery` events only, and runtime receives opaque outbound packets.
- Dependency-risk assessment: `handle_dns_packet` exists but raw IPv4 UDP packets can still follow generic UDP forwarding unless the net boundary recognizes broker DNS destinations and returns a DNS response packet. This is required for transparent DNS reachability and attribution.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for net/dns/packet/audit.
- Observed results: added `Ipv4DnsServiceRequest`, `DnsCacheUpdate`, and `handle_ipv4_dns_service_packet` in `foxprox-net`. Broker-addressed IPv4 UDP/53 packets now route through `handle_dns_packet`, resolve via shared egress, synthesize opaque IPv4 UDP DNS responses through `foxprox-packet`, and return normalized DNS address records for attribution cache updates. Non-broker DNS packets fall through to generic handling. Added a test proving response packet endpoint reversal and cache records. All verification passed.
- Changed files:
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 127 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-net` — net orchestrates DNS/packet/egress boundaries.
  - `cargo tree -p foxprox-dns` — DNS remains core-only.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: e7b538e.
- Remaining boundary risks: TCP DNS and live runtime DNS service scheduling remain.

## 2026-06-22 — Boundary objective: runtime DNS service and attribution cache update

- Boundary under work: runtime packet step that services broker DNS packets before generic UDP forwarding and updates DNS attribution cache.
- Allowed dependency direction: runtime coordinates net DNS-service outcomes, device writes, UDP bridges, and DNS cache updates; DNS parsing and packet synthesis remain in net/dns/packet crates; policy/audit see normalized DNS events only.
- Dependency-risk assessment: net can intercept broker DNS packets, but a device runtime must invoke it before generic UDP bridge retention or DNS traffic will be forwarded as ordinary UDP and attribution will not feed later stack policy.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/net/dns/audit.
- Observed results: added `DevicePacketStepWithDnsAndUdp` and `process_one_ipv4_device_packet_with_dns_and_udp_bridges` in runtime. The step reads one packet, services broker-addressed DNS through `foxprox-net`, writes opaque DNS response packets to the device, updates `DnsAttributionCache` with returned address records, and falls back to generic UDP bridge retention for non-DNS packets. Added a runtime test proving broker DNS produces no UDP bridge, writes a DNS response, audits once, and updates attribution. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 128 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime coordinates net/dns/audit contracts.
  - `cargo tree -p foxprox-net` — net owns DNS packet interception.
  - `cargo tree -p foxprox-dns` — DNS remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 21455f6.
- Remaining boundary risks: TCP DNS and async DNS serving remain.

## 2026-06-22 — Boundary objective: setup-helper route DNS and proxy plan

- Boundary under work: complete data-only Linux setup-helper plan for TUN route, DNS resolver config, and proxy environment handoff.
- Allowed dependency direction: `foxprox-integrations` owns Linux setup-helper commands and file writes; broker runtime/device/policy/audit remain independent of bwrap/Linux setup details.
- Dependency-risk assessment: TUN create/address/link commands are not enough for alpha validation; without route and DNS/proxy plan fields, setup-helper responsibilities remain implicit and likely to leak into callers.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for integrations/audit.
- Observed results: extended `TunSetupCommandPlan` with setup-helper file writes and proxy environment. `LinuxIpTunSetup::plan_commands` now includes default route setup and `/etc/resolv.conf` contents pointing at broker DNS, in addition to TUN create/address/link commands. Tests now prove route, resolver, and proxy handoff are represented in the data-only integration boundary. All verification passed.
- Changed files:
  - `crates/foxprox-integrations/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 128 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-integrations` — integrations remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: e0bc5fc.
- Remaining boundary risks: command execution, fd handoff, and privilege drop enforcement remain.

## 2026-06-22 — Boundary objective: setup-helper command execution contract

- Boundary under work: executable setup-helper boundary for data-only TUN setup plans.
- Allowed dependency direction: `foxprox-integrations` owns command/file execution for setup helpers; broker core/runtime/device remain preopened-device consumers and never invoke Linux setup commands directly.
- Dependency-risk assessment: command plans prove shape but not execution order or error translation. A narrow executor trait lets the trusted helper run plans while tests verify ordering without privileged operations.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for integrations/audit.
- Observed results: added `TunSetupExecutor`, `execute_tun_setup_plan`, and `StdTunSetupExecutor` in `foxprox-integrations`. The executor applies planned resolver file writes before setup commands and translates command/file failures into integration errors. Added a mock executor test proving deterministic ordering and error translation without privileged operations. All verification passed.
- Changed files:
  - `crates/foxprox-integrations/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 129 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-integrations` — execution boundary remains integrations/core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: aff7c8e.
- Remaining boundary risks: fd handoff and privilege drop enforcement remain.

## 2026-06-22 — Boundary objective: inherited TUN fd device handoff

- Boundary under work: device-side constructor for trusted setup helpers handing an already-opened TUN fd to broker runtime.
- Allowed dependency direction: `foxprox-device` may own raw fd adoption into `PreopenedTunDevice`; runtime still consumes `PacketDevice`/`TryPacketDevice`, and policy/audit never see fd types.
- Dependency-risk assessment: setup/helper planning can create/configure TUN, but runtime still needs a narrow handoff point for an inherited/preopened fd. The unsafe ownership adoption must be isolated and documented at the device boundary.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for device/runtime/audit.
- Observed results: added a documented unsafe Unix `PreopenedTunDevice<File>::from_raw_fd` constructor that adopts ownership of an inherited/preopened fd into the device boundary. Added a UnixStream-based test proving an inherited raw fd becomes an opaque packet device without exposing fd types to runtime/policy/audit. All verification passed.
- Changed files:
  - `crates/foxprox-device/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 130 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-device` — device remains dependency-free.
  - `cargo tree -p foxprox-runtime` — runtime still consumes only device traits.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: a569705.
- Remaining boundary risks: SCM_RIGHTS control-socket passing and privilege drop enforcement remain.

## 2026-06-22 — Boundary objective: setup-helper privilege-drop lifecycle

- Boundary under work: explicit setup-helper lifecycle ordering from TUN setup to privilege drop to target exec.
- Allowed dependency direction: `foxprox-integrations` owns setup-helper lifecycle contracts; broker runtime and policy/audit never handle capabilities, bwrap, or target exec details.
- Dependency-risk assessment: setup command execution and fd adoption exist, but alpha requires setup-only privileges to be dropped before target exec. Encoding the lifecycle prevents callers from accidentally execing the target before the privileged setup phase is complete.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for integrations/audit.
- Observed results: added `TargetCommand`, `SetupHelperLifecycleExecutor`, and `run_setup_helper_lifecycle` in `foxprox-integrations`. The lifecycle applies the TUN setup plan, calls a privilege-drop hook, then execs the target. Added a mock lifecycle test proving setup commands happen before privilege drop and target exec happens after privilege drop. All verification passed.
- Changed files:
  - `crates/foxprox-integrations/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 131 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-integrations` — lifecycle remains integrations/core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: ec95775.
- Remaining boundary risks: OS-specific capability drop implementation and SCM_RIGHTS fd passing remain.

## 2026-06-22 — Boundary objective: malformed-input fuzz corpus tests

- Boundary under work: fuzz-style malformed input coverage for packet, proxy, and TLS parser boundaries.
- Allowed dependency direction: fuzz corpus tests stay inside parser/packet crates and assert normalized fail-closed outputs; policy/audit do not receive parser internals or panics.
- Dependency-risk assessment: alpha robustness requires malformed packet/proxy/TLS handling. Without corpus-style tests, parser edge cases can regress into panics or non-normalized errors.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for packet/frontends/inspect/audit.
- Observed results: added malformed corpus tests in `foxprox-packet`, `foxprox-frontends`, and `foxprox-inspect`. The tests feed malformed IPv4, HTTP proxy, SOCKS5, and TLS ClientHello inputs through public boundary functions and assert normalized fail-closed/unsupported outcomes without panics. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-frontends/src/lib.rs`
  - `crates/foxprox-inspect/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 134 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-frontends` — frontends remains core-only.
  - `cargo tree -p foxprox-inspect` — inspect remains core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 5992719.
- Remaining boundary risks: coverage-guided fuzz harnesses remain future work.

## 2026-06-22 — Boundary objective: IPv6 packet input and ICMPv6 error synthesis

- Boundary under work: IPv6 packet normalization/write-back for TUN packet paths.
- Allowed dependency direction: `foxprox-packet` owns IPv6 header parsing and ICMPv6/UDP wire synthesis; `foxprox-net` may orchestrate packet/policy/audit/egress; runtime/device still handle opaque IP packets only. Policy/audit consume normalized events and decisions only.
- Dependency-risk assessment: IPv6 UDP replies existed but inbound IPv6 classification was still missing. Adding IPv6 by copying header details into runtime/policy would break the raw-packet boundary, so packet-owned parsing plus net-owned orchestration is required.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for packet/net/runtime/audit.
- Observed results: added packet-owned IPv6 classification for TCP SYN, UDP payloads, and ICMPv6 messages; IPv6 ICMP echo write-back; IPv6 ICMP unreachable synthesis for policy denials and UDP host failures; IPv6 packet and broker-DNS orchestration in `foxprox-net`; and runtime IPv6 UDP bridge retention. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 143 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-net` — net orchestrates packet/DNS/policy/audit/egress boundaries.
  - `cargo tree -p foxprox-runtime` — runtime depends on packet only for opaque synthesis helpers and keeps policy/audit normalized.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 23d5e4c.
- Remaining boundary risks: IPv6 extension headers/NDP and full production IPv6 stack behavior remain future work.

## 2026-06-22 — Boundary objective: round-robin bridge readiness cursors

- Boundary under work: scheduler-facing fairness for retained TCP/UDP bridge maintenance.
- Allowed dependency direction: fairness cursors live in `foxprox-runtime` bridge tables; egress handles remain opaque, packet synthesis stays in packet/net boundaries, and policy/audit are not scheduler-aware.
- Dependency-risk assessment: maintenance budgets currently cap work per tick, but repeatedly taking the first map entries can starve later flows. Round-robin cursors must be runtime-owned so readiness scheduling does not leak into egress, stack adapter, or policy contracts.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: added runtime-owned round-robin read cursors to TCP and UDP bridge tables. Bounded TCP/UDP maintenance now selects a rotated set of retained flows instead of repeatedly taking the first map entries. Added tests proving single-flow budgets visit all retained TCP and UDP flows over successive ticks. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 145 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — fairness remains runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 8c7bf27.
- Remaining boundary risks: cross-sandbox weighted fairness and byte-rate accounting remain.

## 2026-06-22 — Boundary objective: Unix fd handoff channel

- Boundary under work: setup-helper TUN fd transfer from sandbox helper to host broker.
- Allowed dependency direction: `foxprox-integrations` owns Unix/SCM_RIGHTS handoff mechanics; `foxprox-device` only adopts an already-received raw fd; runtime/policy/audit never see Unix socket control messages or fd-passing details.
- Dependency-risk assessment: raw fd adoption exists but without a real handoff channel the bwrap-compatible alpha setup path is incomplete. SCM_RIGHTS must stay in integrations so backend details do not leak into device/runtime contracts.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for integrations/device/audit.
- Observed results: added Unix `send_tun_fd`/`recv_tun_fd` SCM_RIGHTS helpers in `foxprox-integrations` using safe `nix` socket control-message APIs. Added an integration test that passes a preopened fd over a Unix datagram pair, proving setup helper fd transfer without exposing SCM_RIGHTS details to device/runtime/policy/audit. All verification passed.
- Changed files:
  - `Cargo.lock`
  - `crates/foxprox-integrations/Cargo.toml`
  - `crates/foxprox-integrations/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 146 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-integrations` — Unix fd handoff dependencies are isolated to integrations.
  - `cargo tree -p foxprox-device` — device remains dependency-free.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 9ab4ea3.
- Remaining boundary risks: opening the real TUN fd with ioctl and end-to-end namespace smoke tests remain.

## 2026-06-22 — Boundary objective: Linux TUN open/ioctl device boundary

- Boundary under work: actual Linux `/dev/net/tun` fd creation for the packet device layer.
- Allowed dependency direction: `foxprox-device` owns Linux TUN fd opening and ioctl configuration; integrations own namespace/helper execution and fd handoff; runtime consumes only `PacketDevice`/`TryPacketDevice`; policy/audit remain fd-free.
- Dependency-risk assessment: setup plans and fd handoff are in place, but alpha TUN setup still needs a concrete device-owned open/configure function. The required unsafe ioctl must be tiny and isolated in the device crate.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for device/runtime/audit.
- Observed results: added Linux-only `PreopenedTunDevice<File>::open_linux_tun`, which opens `/dev/net/tun`, configures `IFF_TUN | IFF_NO_PI` with `TUNSETIFF`, and returns the safe packet-device wrapper. Added pre-ioctl validation for invalid TUN names. All verification passed.
- Changed files:
  - `Cargo.lock`
  - `crates/foxprox-device/Cargo.toml`
  - `crates/foxprox-device/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 147 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-device` — Linux ioctl dependency is isolated to device.
  - `cargo tree -p foxprox-runtime` — runtime still consumes device traits.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 300fc45.
- Remaining boundary risks: privileged end-to-end namespace smoke tests remain.

## 2026-06-22 — Boundary objective: TCP reset denial synthesis

- Boundary under work: packet-owned TCP reset write-back for deny/reset policy decisions.
- Allowed dependency direction: `foxprox-packet` owns TCP/IP reset packet formatting and checksums; `foxprox-net` only maps normalized policy decisions to opaque outbound packets; policy/audit never handle raw TCP headers.
- Dependency-risk assessment: policy has a deny/reset action, but packet denial synthesis only handled ICMP unreachable. Implementing reset outside the packet crate would leak TCP wire details into orchestration/runtime.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for packet/net/audit.
- Observed results: added packet-owned IPv4 and IPv6 TCP RST+ACK synthesis for deny/reset decisions, including endpoint swapping, SYN acknowledgement, and TCP/IP checksums. `foxprox-net` now returns opaque reset packets for denied TCP SYN packet paths. All verification passed.
- Changed files:
  - `crates/foxprox-packet/src/lib.rs`
  - `crates/foxprox-net/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 150 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-packet` — packet remains core-only.
  - `cargo tree -p foxprox-net` — net orchestrates reset bytes without exposing TCP headers to policy/audit.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: d789581.
- Remaining boundary risks: stack-adapter-native reset signaling for established smoltcp flows remains.

## 2026-06-22 — Boundary objective: per-sandbox maintenance fairness budget

- Boundary under work: cross-sandbox fairness for bridge maintenance scheduling.
- Allowed dependency direction: per-sandbox scheduling budgets stay in `foxprox-runtime`; egress, stack adapter, packet, policy, and audit contracts remain unchanged.
- Dependency-risk assessment: round-robin cursors avoid fixed-flow starvation but a single sandbox can still consume an entire tick budget. Per-sandbox maintenance caps keep cross-sandbox fairness explicit without moving scheduler state into policy or egress.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: extended `BridgeMaintenanceBudget` with per-sandbox TCP/UDP caps and routed maintenance ticks through fairness-aware read selection. Added tests proving a tick budget reads from multiple sandboxes instead of allowing one sandbox with multiple flows to consume all selected TCP/UDP slots. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 152 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — fairness remains runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 44f4c6e.
- Remaining boundary risks: byte-rate limit windows remain.

## 2026-06-22 — Boundary objective: per-sandbox byte-rate accounting

- Boundary under work: per-sandbox byte budgets during bridge maintenance.
- Allowed dependency direction: byte-rate accounting is runtime scheduler state; egress streams remain opaque and policy/audit consume only normalized events/audit records.
- Dependency-risk assessment: flow-count fairness prevents slot starvation but does not bound bytes read for one sandbox in a tick. Byte caps should be enforced in runtime before data is enqueued to stack/device write-back.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/audit.
- Observed results: extended `BridgeMaintenanceBudget` with per-sandbox TCP/UDP byte caps and enforced those caps before reading from retained host streams/flows. Added tests proving TCP and UDP reads are truncated to the per-sandbox byte budget before stack/device write-back. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 154 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — byte-rate accounting remains runtime-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: d842c3a.
- Remaining boundary risks: wall-clock token-bucket refill policy remains future scheduler work.

## 2026-06-22 — Boundary objective: production runtime loop contract

- Boundary under work: bounded nonblocking stack runtime loop around the tick primitive.
- Allowed dependency direction: runtime owns loop sequencing/idleness/readiness policy while device, stack adapter, egress, policy, and audit remain behind existing traits; no OS readiness API leaks into policy/audit.
- Dependency-risk assessment: single-tick orchestration is not enough for alpha operation. A loop contract must repeatedly run nonblocking device ingest and maintenance, advance audit sequences safely, and expose shutdown/idleness behavior without hardwiring epoll/tokio into lower layers.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/device/audit.
- Observed results: added `StackRuntimeLoopConfig`, `StackRuntimeLoopStep`, `StackRuntimeLoopOutcome`, and `run_stack_runtime_loop`. The loop repeatedly runs nonblocking stack ticks, always runs maintenance, advances audit sequence/timestamps, aggregates maintenance counters, and stops on a configured idle streak. Added a test proving the loop makes maintenance progress on an idle device, then exits after the next idle tick. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 155 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime loop coordinates existing boundary crates only.
  - `cargo tree -p foxprox-device` — device remains readiness boundary.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: b7d689c.
- Remaining boundary risks: OS-specific readiness registration adapters remain.

## 2026-06-22 — Boundary objective: explicit HTTP proxy connection step

- Boundary under work: production-facing explicit HTTP proxy request IO through shared policy/audit/egress.
- Allowed dependency direction: runtime owns socket/session stepping; frontends parse only into normalized events; net applies policy/audit/egress; egress owns host response streams. Policy/audit still do not see parser or socket types.
- Dependency-risk assessment: parser and egress contracts exist, but alpha explicit proxy networking needs a concrete connection step that reads a bounded request head, applies shared policy/audit, forwards through shared egress, and writes an allowed/denied response without bypassing policy.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/frontends/egress/audit.
- Observed results: added `HostHttpResponse` to the shared egress contract and implemented it for mock/std HTTP responses. Added `process_one_http_proxy_request` in runtime to read a bounded HTTP proxy request head, parse through `foxprox-frontends`, run shared policy/audit/egress through `foxprox-net`, write forwarded HTTP response bytes for allowed requests, and write fail-closed 403/502 responses for denials. Added allowed and denied proxy session tests. All verification passed.
- Changed files:
  - `crates/foxprox-egress/src/lib.rs`
  - `crates/foxprox-runtime/Cargo.toml`
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 157 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime owns session IO and consumes frontends/net/egress contracts.
  - `cargo tree -p foxprox-frontends` — frontends remains core-only parser boundary.
  - `cargo tree -p foxprox-egress` — egress remains core-only host IO boundary.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 74d6146.
- Remaining boundary risks: full-duplex CONNECT tunnel pump and listener accept loop remain.

## 2026-06-22 — Boundary objective: explicit SOCKS5 CONNECT session step

- Boundary under work: production-facing SOCKS5 CONNECT IO through shared policy/audit/egress.
- Allowed dependency direction: runtime owns SOCKS session stepping; frontends own SOCKS wire parsing/reply codes; net/policy/audit/egress handle normalized events only.
- Dependency-risk assessment: SOCKS parser and policy-to-reply helpers exist, but alpha explicit proxy support needs a concrete session step that negotiates no-auth, parses CONNECT, applies shared policy/audit, opens shared egress for allowed destinations, and returns SOCKS replies for denials.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/frontends/egress/audit.
- Observed results: added `process_one_socks5_connect` in runtime. The step reads a bounded SOCKS5 greeting and CONNECT request, uses frontend-owned no-auth selection/parsing/reply mapping, runs shared policy/audit/egress through `foxprox-net`, writes success or denial replies, and reports whether an allowed tunnel stream was opened. Added allowed and denied SOCKS session tests. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 159 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — runtime session IO consumes existing frontend/net/egress contracts.
  - `cargo tree -p foxprox-frontends` — SOCKS wire details remain frontend/core-only.
  - `cargo tree -p foxprox-egress` — host connect remains egress-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 2c7f8bd.
- Remaining boundary risks: full-duplex CONNECT/SOCKS tunnel pump and listener accept loop remain.

## 2026-06-22 — Boundary objective: explicit proxy tunnel pump

- Boundary under work: bidirectional byte pumping for allowed CONNECT/SOCKS tunnels.
- Allowed dependency direction: runtime owns client-session pumping; egress exposes only `HostTcpStream`; frontends only parse setup handshakes; policy/audit are not given raw stream bytes.
- Dependency-risk assessment: HTTP CONNECT and SOCKS CONNECT steps can open egress streams, but alpha proxy networking needs bounded byte movement in both directions without letting parser or policy layers own tunnel IO.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/egress/audit.
- Observed results: added `pump_proxy_tunnel_once` with bounded client→host and host→client transfer over a generic client IO object and egress-owned `HostTcpStream`. Added a test proving bounded movement in both directions without exposing tunnel bytes to policy/audit or frontend parsers. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 160 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — tunnel pumping remains runtime-owned over egress traits.
  - `cargo tree -p foxprox-egress` — host stream details remain egress-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: cde5009.
- Remaining boundary risks: TCP listener accept loop remains.

## 2026-06-22 — Boundary objective: retain explicit proxy tunnel handles

- Boundary under work: explicit CONNECT/SOCKS session setup must return the egress-owned TCP stream needed by runtime tunnel pumps.
- Allowed dependency direction: runtime may retain `HostEgress::TcpStream` handles; frontends still only parse setup bytes; policy/audit see normalized events only; egress owns concrete sockets.
- Dependency-risk assessment: the CONNECT/SOCKS setup steps currently report `connected_tunnel` but discard the actual host stream, preventing the already-bounded tunnel pump from being composed into a production session loop.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/egress/frontends/audit.
- Observed results: added `ExplicitHttpProxySessionOutcome<T>` and `ExplicitSocks5SessionOutcome<T>`, plus `process_one_http_proxy_request_with_tunnel` and `process_one_socks5_connect_with_tunnel`. The existing summary APIs remain, while session APIs retain allowed `E::TcpStream` handles for tunnel pumping. Added HTTP CONNECT and SOCKS tests proving retained mock tunnel handles, shared policy/audit/egress, and frontend-local parsing/replies. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 161 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — session retention stays in runtime over egress-associated stream types.
  - `cargo tree -p foxprox-egress` — concrete socket ownership remains egress-private.
  - `cargo tree -p foxprox-frontends` — proxy wire parsing remains frontend/core-only.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: 34efb60.
- Remaining boundary risks: TCP listener accept loop remains.

## 2026-06-22 — Boundary objective: explicit proxy listener accept contract

- Boundary under work: nonblocking listener acceptance for explicit HTTP and SOCKS proxy sessions.
- Allowed dependency direction: runtime owns listener/client IO contracts; frontends parse accepted session bytes; egress owns host sockets; policy/audit receive normalized events only.
- Dependency-risk assessment: session setup, tunnel retention, and tunnel pumping exist, but alpha explicit proxy exposure still needs a listener boundary that accepts client streams without moving std listener types into policy/frontend/egress contracts.
- Verification commands planned: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, and dependency trees for runtime/frontends/egress/audit.
- Observed results: added runtime-owned `ProxyListener`, std `TcpListener` adaptation, `AcceptedHttpProxySession`, `AcceptedSocks5Session`, and one-client accept helpers for HTTP proxy and SOCKS5 sessions. `WouldBlock` maps to `None`, accepted std streams are set nonblocking, and accepted clients feed into the existing normalized session/policy/audit/egress flow. Added tests for an accepted HTTP CONNECT tunnel session and idle listener behavior. All verification passed.
- Changed files:
  - `crates/foxprox-runtime/src/lib.rs`
  - `progress.md`
  - `learnings.md`
- Verification commands run:
  - `cargo check --workspace` — passed.
  - `cargo test --workspace` — passed, 163 tests.
  - `cargo clippy --all-targets --all-features -- -D warnings` — passed.
  - `cargo tree -p foxprox-runtime` — listener/session orchestration remains runtime-owned.
  - `cargo tree -p foxprox-frontends` — frontend parser boundary remains core-only.
  - `cargo tree -p foxprox-egress` — concrete host sockets remain egress-owned.
  - `cargo tree -p foxprox-audit` — audit remains core-only.
- Commit hash after commit: pending.
- Remaining boundary risks: OS-specific privilege drop and privileged namespace smoke coverage remain.
