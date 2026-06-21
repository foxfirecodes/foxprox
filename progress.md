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

## 2026-06-21 Session Continue — ICMP echo reply packet write-back slice

- Slice attempted: add a minimal packet write-back proof by synthesizing an IPv4 ICMP echo reply from a parsed echo request fixture.
- Why next: this addresses the documented packet write-back milestone at the packet-core boundary before introducing privileged TUN IO.
- Verification plan: add checksum-covered tests that parse an echo request, synthesize a reply with source/destination reversal and ICMP type change, parse the reply back into a normalized ICMP event, and run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — ICMP echo reply packet write-back

- Slice attempted: minimal packet write-back proof for IPv4 ICMP echo requests.
- Why next: it validates source/destination reversal and checksum synthesis before privileged TUN write-back is introduced.
- What changed: added `synthesize_icmp_echo_reply`, packet-build errors, Internet checksum calculation, and focused tests proving echo reply synthesis, parse-back normalization, checksum validity, and refusal to synthesize from non-echo ICMP requests.
- Verification:
  - `cargo fmt --check` initially failed before formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 9 `foxprox-core` tests, 9 `foxprox-packet` tests, and 0 doc tests.
  - `cargo fmt --check` passed after formatting.
  - Focused checks passed: `cargo test -p foxprox-packet synthesizes_icmp_echo_reply_with_reversed_addresses_and_checksums` and `cargo test -p foxprox-packet refuses_to_synthesize_icmp_reply_from_non_echo_request`.
- What failed or surprised the agent: the focused verification briefly waited on Cargo's package-cache lock but completed successfully.
- What remains unproven: actual TUN fd write-back, ping inside a sandbox, ICMP policy allow/deny behavior, IPv4 checksum validation on ingress, and broader ICMP error synthesis.
- Commit: this commit.

## 2026-06-21 Session Continue — policy-gated packet handling slice

- Slice attempted: connect packet parsing, policy/audit evaluation, and ICMP echo reply synthesis behind a small broker-facing handler.
- Why next: this crosses frontend-style packet input through parser/core/policy/audit to outbound packet generation, reducing the next integration risk before real TUN IO.
- Verification plan: add a minimal `foxprox-broker` crate that processes one IPv4 packet, emits audit evidence, writes an echo reply only when policy allows ICMP, suppresses replies when policy denies, fails closed on malformed packets, and run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — policy-gated packet handling

- Slice attempted: connect inbound IPv4 packet bytes to parser normalization, policy/audit evaluation, and outbound ICMP echo reply synthesis.
- Why next: this reduces the frontend-to-core and policy-to-writeback integration risk before real TUN IO is available.
- What changed: added `crates/foxprox-broker` with `Ipv4PacketBroker::process_packet`, which emits a `PolicyEvaluation`, synthesizes echo replies only for allowed ICMP echo requests, suppresses denied/non-echo replies, and converts malformed packets into fail-closed audit evidence.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` initially failed on an unused test import, then passed after cleanup.
  - `cargo test --workspace` passed: 4 `foxprox-broker` tests, 9 `foxprox-core` tests, 9 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-broker allowed_icmp_echo_request_emits_audit_and_reply_packet`, `cargo test -p foxprox-broker denied_icmp_echo_request_is_audited_without_reply`, and `cargo test -p foxprox-broker malformed_packet_is_audited_fail_closed_without_reply`.
- What failed or surprised the agent: clippy caught an unused import in the new broker tests; no behavior changes were needed.
- What remains unproven: no real TUN reader/writer, async runtime loop, sandbox ping, TCP/UDP host egress, DNS server, or audit sink backpressure yet.
- Commit: this commit.

## 2026-06-21 Session Continue — audit record → JSON sink slice

- Slice attempted: turn structured in-memory audit records into externally observable JSON Lines with bounded sink behavior.
- Why next: audit logs are first-class alpha output, and this proves policy/audit evidence can cross a process/output boundary before runtime forwarding grows.
- Verification plan: add a `foxprox-audit` crate that serializes `AuditRecord` to JSON Lines, enforces bounded buffering/backpressure, verifies broker-produced ICMP audit output, and run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — audit record → JSON sink

- Slice attempted: serialize structured audit records to externally observable JSON Lines and enforce bounded audit buffering.
- Why next: alpha requires structured audit/log output and audit backpressure; this proves the policy/audit records can cross an output boundary.
- What changed: added `crates/foxprox-audit`, workspace serde/serde_json dependencies, `audit_record_to_json_line`, and `BoundedJsonAuditSink` with explicit backpressure errors. Tests serialize a broker-produced ICMP audit event and verify bounded sink behavior.
- Verification:
  - `cargo fmt --check` initially failed before formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 2 `foxprox-audit` tests, 4 `foxprox-broker` tests, 9 `foxprox-core` tests, 9 `foxprox-packet` tests, and 0 doc tests.
  - `cargo fmt --check` passed after formatting.
  - Focused checks passed: `cargo test -p foxprox-audit serializes_broker_audit_record_as_json_line` and `cargo test -p foxprox-audit bounded_sink_reports_backpressure_without_accepting_record`.
- What failed or surprised the agent: adding serde introduced 11 lockfile packages; no core serde derives were needed because the audit crate maps core records into a stable output schema.
- What remains unproven: file/stdout sinks, async audit flushing, integration with a runtime loop, and backpressure policy for live forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — config → policy → broker slice

- Slice attempted: load a minimal user-facing policy config and prove it controls broker packet behavior.
- Why next: alpha requires configurable default policy and rules; this turns hard-coded policy construction into a verified config-to-policy boundary.
- Verification plan: add a `foxprox-config` crate that parses TOML into `PolicyConfig`, supports default allow/deny, DNS broker resolvers, protocol/port/host/IP rule dimensions, verifies ICMP allow config produces an echo reply, verifies DNS resolver config preserves direct DNS bypass denial, and run formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — config → policy → broker

- Slice attempted: parse minimal TOML policy config into core policy and prove it controls broker packet handling.
- Why next: alpha requires configurable default policy and rules rather than hard-coded policy construction.
- What changed: added `crates/foxprox-config`, workspace `toml` dependency, TOML parsing for default allow/deny, deny behavior, DNS broker resolvers/direct-DNS setting, protocol rules, destination CIDRs/ports, hostname patterns, and hostname confidence. Tests verify config-loaded ICMP allow emits a broker echo reply, config-loaded DNS resolver keeps direct DNS bypass denied, and invalid protocol values fail validation.
- Verification:
  - `cargo fmt --check` initially failed before formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 2 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-config` tests, 9 `foxprox-core` tests, 9 `foxprox-packet` tests, and 0 doc tests.
  - `cargo fmt --check` passed after formatting.
  - Focused checks passed: `cargo test -p foxprox-config loaded_icmp_rule_allows_broker_echo_reply`, `cargo test -p foxprox-config loaded_dns_resolver_preserves_direct_dns_bypass_denial`, and `cargo test -p foxprox-config invalid_protocol_is_rejected`.
- What failed or surprised the agent: adding TOML introduced additional parser dependencies, but config validation could still map into existing core types without changing core serialization.
- What remains unproven: config file discovery/CLI loading, richer rule schema, user-facing diagnostics with source spans, reload behavior, and integration with a long-running runtime are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — CLI config → packet handler → audit JSON slice

- Slice attempted: add a minimal runtime harness that loads policy config from a file, reads one IPv4 packet from stdin, processes it through the broker, and emits JSON Lines audit plus optional outbound packet bytes.
- Why next: config loading, broker packet handling, and audit serialization are individually proven but not yet crossed through a user-facing process boundary; this reduces CLI/runtime integration risk before privileged TUN IO.
- Verification plan: add a `foxprox-cli` crate with a `packet-once` command, focused unit tests for config-controlled ICMP reply/audit output and default-deny behavior, run a real `cargo run -p foxprox-cli -- packet-once ...` fixture command, then run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Commit: pending.

## 2026-06-21 Slice Evidence — CLI config → packet handler → audit JSON

- Slice attempted: a user-facing `packet-once` runtime harness that loads TOML policy, reads one IPv4 packet from stdin, processes it through broker policy/audit/write-back, emits JSON Lines audit on stdout, and writes optional outbound packet bytes separately.
- Why next: config, broker packet handling, and audit JSON were proven independently; this crossed the process/CLI boundary before adding privileged long-running TUN IO.
- What changed: added `crates/foxprox-cli` with a `packet-once` command, reusable `process_packet_once` function, manual CLI parsing, config-file loading, stdin packet reading, JSON audit stdout, optional outbound packet file output, and focused tests for config-allowed ICMP replies, default-deny audit-only behavior, and invalid sandbox IDs.
- Verification:
  - `cargo fmt --check` initially failed for new CLI formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 2 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 3 `foxprox-config` tests, 9 `foxprox-core` tests, 9 `foxprox-packet` tests, and 0 doc tests.
  - Runtime proof passed: `cargo run -q -p foxprox-cli -- packet-once --config "$tmpdir/policy.toml" --sandbox runtime-proof --outbound "$tmpdir/reply.bin" < "$tmpdir/request.bin" > "$tmpdir/audit.jsonl"` emitted an allowed `icmp_message` JSON audit with rule `allow-icmp` and wrote a 35-byte outbound reply packet.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: stdout must remain JSON-only, so synthesized binary packet output is written to an explicit file rather than mixed with audit output.
- What remains unproven: no long-running TUN loop, no file/stdout audit sink trait in the runtime, no live bwrap setup helper, no TCP/UDP egress, and no DNS payload handling yet.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP DNS payload → DNS query audit slice

- Slice attempted: parse a real UDP/IPv4 DNS query payload into a normalized `DnsQuery` event and prove policy/audit records include the queried hostname.
- Why next: DNS is currently only classified by UDP/53 port; alpha requires broker DNS observations and hostname attribution foundations, so DNS payload parsing is the next narrow parser-to-policy/audit gap.
- Verification plan: add minimal DNS question parsing for uncompressed query names, qtype mapping, malformed DNS fail-closed behavior, update affected direct-DNS tests to use real query fixtures, and run formatting, clippy, focused packet/config tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP DNS payload → DNS query audit

- Slice attempted: parse UDP/IPv4 DNS question payloads into normalized `DnsQuery` events with hostname/query type and feed them through policy/audit.
- Why next: UDP/53 was previously only port-classified; alpha DNS observations need hostnames in structured audit before cache/correlation and broker resolver behavior can be meaningful.
- What changed: `foxprox-packet` now validates UDP length, parses uncompressed DNS question names, maps common qtypes, emits `NormalizedEvent::DnsQuery`, and treats malformed DNS payloads as fail-closed parse errors. Existing DNS bypass tests now use real DNS query fixtures, and config-to-broker DNS denial still passes through the new parser path.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 2 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 3 `foxprox-config` tests, 9 `foxprox-core` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused check attempt `cargo test -p foxprox-packet parses_udp_dns_query_packet_and_policy_denies_direct_external_dns malformed_dns_query_can_be_converted_to_fail_closed_event` failed because Cargo accepts only one test filter before `--`.
  - Focused checks then passed separately: `cargo test -p foxprox-packet parses_udp_dns_query_packet_and_policy_denies_direct_external_dns`, `cargo test -p foxprox-packet malformed_dns_query_can_be_converted_to_fail_closed_event`, and `cargo test -p foxprox-config loaded_dns_resolver_preserves_direct_dns_bypass_denial`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: Cargo's test CLI does not accept multiple bare test filters; use separate commands or broader substring filters.
- What remains unproven: DNS response parsing/cache, upstream DNS forwarding, broker resolver socket, DNS answer audit records, compression-pointer support, and hostname-to-flow attribution are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — DNS cache → flow attribution → domain policy slice

- Slice attempted: add the smallest hostname attribution cache that maps DNS answers to later transparent TCP/UDP flow events and proves domain policy decisions use the enriched hostname.
- Why next: DNS query audit now exposes hostnames, but transparent TCP/UDP flows still have no hostname attribution; alpha policy requires DNS-to-flow correlation before domain rules can govern TUN traffic.
- Verification plan: add a platform-independent `foxprox-inspect` crate with expiring DNS answer records, enrich parsed TCP/UDP events with medium-confidence DNS attribution, verify domain allow rules deny before enrichment and allow after enrichment, verify expiry and no overwrite of higher-confidence attribution, then run formatting, clippy, focused inspect tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — DNS cache → flow attribution → domain policy

- Slice attempted: medium-confidence DNS answer cache enrichment for transparent TCP/UDP flow events.
- Why next: DNS query parsing produced hostname audit evidence, but domain policy on later TUN flows still needed DNS-to-flow correlation.
- What changed: added `crates/foxprox-inspect` with `DnsAttributionCache`, expiring hostname-to-IP answer records, newest-answer lookup for reused IPs, and enrichment of TCP/UDP flow attempts only when no higher-confidence attribution is already present.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new inspect crate; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` initially failed on an unused test import, then passed after cleanup.
  - `cargo test --workspace` passed: 2 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 3 `foxprox-config` tests, 9 `foxprox-core` tests, 4 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect dns_cache_enriches_tcp_flow_for_domain_policy_and_audit`, `cargo test -p foxprox-inspect expired_dns_answer_does_not_enrich_flow`, and `cargo test -p foxprox-inspect dns_cache_does_not_overwrite_existing_high_confidence_attribution`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: the cache needs explicit freshness semantics even in a minimal version; otherwise shared-IP hostname reuse would be misleading. The current proof chooses the newest non-expired answer.
- What remains unproven: parsing DNS responses into cache records, cache eviction/resource limits, confidence downgrade rules for shared IPs, SNI/DNS mismatch integration with cached attribution, and live DNS resolver forwarding are still absent.
- Commit: this commit.
