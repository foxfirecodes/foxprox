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

## 2026-06-21 Session Continue — plaintext HTTP bytes → method/path policy/audit slice

- Slice attempted: parse plaintext HTTP request bytes into normalized `HttpRequest` events and enforce/audit host, method, and path-prefix policy.
- Why next: DNS attribution covers hostname-to-flow correlation, but alpha also requires transparent plaintext HTTP inspection with method/path visibility; this is a narrow frontend-to-core-to-policy/audit slice that does not require TCP forwarding yet.
- Verification plan: extend core policy/audit to carry HTTP method and path/query, extend config rule schema for methods/path prefixes, add inspect parsing for HTTP request line and Host header, verify allowed and denied method/path cases plus JSON audit fields, then run formatting, clippy, focused tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — plaintext HTTP bytes → method/path policy/audit

- Slice attempted: parse plaintext HTTP request bytes into normalized HTTP events and enforce/audit host, method, and path-prefix policy.
- Why next: transparent DNS attribution exists, but alpha also requires direct plaintext HTTP Host/method/path inspection; this proves that semantic HTTP metadata can cross inspection, policy, config, and audit boundaries without TCP forwarding yet.
- What changed: extended `foxprox-core` rules with HTTP method and path-prefix matchers, added HTTP method/path fields to `AuditRecord`, exposed them in JSON audit output, extended TOML rules with `http_methods` and `http_path_prefixes`, and added `foxprox-inspect::parse_plaintext_http_request` for request-line plus Host-header parsing.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 7 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect plaintext_http_request_parses_to_policy_event_and_audit`, `cargo test -p foxprox-inspect plaintext_http_method_or_path_mismatch_denies`, `cargo test -p foxprox-core http_rule_matches_method_host_port_and_path_prefix`, `cargo test -p foxprox-config loaded_http_method_and_path_rule_controls_http_request`, and `cargo test -p foxprox-audit serializes_http_method_and_path_audit_fields`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: no runtime/TCP stream integration exists yet, so the HTTP parser is intentionally byte-slice based and does not attempt incremental request buffering.
- What remains unproven: extracting HTTP bytes from real TCP streams, multiple requests per connection, absolute-form proxy requests, malformed HTTP fail-closed integration, and TCP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TLS ClientHello bytes → SNI policy/audit slice

- Slice attempted: parse TLS ClientHello bytes for SNI, compare against optional DNS attribution, and prove SNI/domain policy plus mismatch fail-closed behavior.
- Why next: plaintext HTTP metadata is covered, and alpha transparent HTTPS requires SNI visibility and SNI/DNS mismatch handling before forwarding can safely apply hostname rules.
- Verification plan: add a minimal ClientHello parser in `foxprox-inspect`, produce `TlsClientHello` normalized events, verify SNI allow rules, DNS/SNI mismatch denial, and missing-SNI denial, then run formatting, clippy, focused inspect tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TLS ClientHello bytes → SNI policy/audit

- Slice attempted: parse TLS ClientHello bytes for SNI and enforce transparent HTTPS SNI/DNS mismatch policy.
- Why next: plaintext HTTP method/path inspection was proven; transparent HTTPS alpha behavior requires visible SNI attribution and mismatch denial before domain-based HTTPS rules can be trusted.
- What changed: added `parse_tls_client_hello` and minimal TLS ClientHello/SNI extension parsing to `foxprox-inspect`, emits `TlsClientHello` normalized events, normalizes SNI hostnames, compares optional DNS attribution, marks missing SNI, and reuses existing policy fail-closed mismatch/missing-SNI decisions.
- Verification:
  - `cargo fmt --check` initially failed on new TLS parser formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 10 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect tls_client_hello_sni_allows_domain_policy_and_audit`, `cargo test -p foxprox-inspect tls_client_hello_dns_sni_mismatch_is_denied_before_allow_rule`, and `cargo test -p foxprox-inspect tls_client_hello_missing_sni_is_denied`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: a minimal ClientHello parser is enough for SNI evidence but still needs careful length checks at every variable-length TLS field.
- What remains unproven: fragmented/incremental TLS parsing from real TCP streams, ECH detection beyond missing-SNI policy, GREASE/edge extension coverage, QUIC TLS metadata, and integration with DNS cache in a live flow manager are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTPS CONNECT bytes → proxy policy/audit slice

- Slice attempted: parse explicit HTTP proxy `CONNECT` request bytes into normalized `HttpsConnect` events and prove host/port policy plus audit behavior.
- Why next: transparent HTTP/TLS metadata is covered; alpha also requires explicit proxy networking, and `CONNECT` is the smallest proxy frontend boundary that can be verified before stream forwarding.
- Verification plan: add CONNECT request parsing in inspection/frontend-adjacent code, verify host normalization, default port handling, allow/deny policy outcomes, malformed request rejection, then run formatting, clippy, focused tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTPS CONNECT bytes → proxy policy/audit

- Slice attempted: parse explicit HTTP proxy `CONNECT` request bytes into normalized HTTPS CONNECT events and evaluate host/port policy.
- Why next: transparent HTTP/TLS inspection is proven, but alpha explicit proxy support also needs CONNECT origin visibility through the same policy/audit backend.
- What changed: added `parse_https_connect_request` to `foxprox-inspect`, normalized CONNECT authority host/port, defaulted omitted CONNECT port to 443, rejected non-CONNECT methods, and updated core port matching so host-only events like `HttpsConnect`, `HttpRequest`, and `SocksConnect` can match destination port rules without requiring an IP endpoint.
- Verification:
  - `cargo fmt --check` initially failed on new CONNECT parser formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 13 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect https_connect_request_parses_to_host_port_policy_event`, `cargo test -p foxprox-inspect https_connect_request_defaults_to_port_443_and_denies_wrong_path`, and `cargo test -p foxprox-inspect https_connect_rejects_non_connect_method`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: the existing port matcher only looked at IP endpoints, so explicit proxy host-only events could not use port rules until core exposed an event-level destination port.
- What remains unproven: HTTP proxy forwarding, plaintext absolute-form HTTP proxy requests, CONNECT tunnel establishment, proxy error responses, and SOCKS5 CONNECT parsing are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — SOCKS5 CONNECT bytes → proxy policy/audit slice

- Slice attempted: parse SOCKS5 TCP CONNECT request bytes into normalized `SocksConnect` events and prove shared host/port policy and audit behavior.
- Why next: HTTPS CONNECT proxy metadata is covered; alpha explicit proxy networking also requires SOCKS5 TCP CONNECT support before forwarding is added.
- Verification plan: add SOCKS5 CONNECT request parsing for domain, IPv4, and IPv6 address forms, reject unsupported commands/address types, verify domain allow and IP audit behavior, then run formatting, clippy, focused tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — SOCKS5 CONNECT bytes → proxy policy/audit

- Slice attempted: parse SOCKS5 TCP CONNECT request bytes into normalized SOCKS events and evaluate shared policy/audit behavior.
- Why next: HTTPS CONNECT covered one explicit proxy mode; alpha also requires SOCKS5 TCP CONNECT support and rejects SOCKS UDP ASSOCIATE as out of scope.
- What changed: added `parse_socks5_connect_request` to `foxprox-inspect`, supports domain, IPv4, and IPv6 address forms, normalizes domain hosts, exposes destination IP where present, parses destination ports, and rejects unsupported versions, commands, reserved bytes, and address types.
- Verification:
  - `cargo fmt` was run for the new SOCKS parser/tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 16 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect socks5_domain_connect_parses_to_policy_event`, `cargo test -p foxprox-inspect socks5_ipv4_connect_exposes_destination_ip_for_audit`, and `cargo test -p foxprox-inspect socks5_rejects_udp_associate_command`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: SOCKS5 IP-address requests can still provide a host string for audit, but domain policy should rely on domain-form requests or later DNS attribution rather than treating IP strings as domain evidence.
- What remains unproven: SOCKS greeting negotiation, TCP stream forwarding, proxy response generation, authentication rejection, resource limits, and malformed request integration with a live proxy listener are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — DNS response bytes → cache → flow attribution slice

- Slice attempted: parse DNS response answer bytes into DNS attribution cache entries and prove a later transparent TCP flow receives hostname attribution from the parsed answer.
- Why next: DNS queries and manual cache insertion are proven, but alpha DNS correlation still lacks the real response-to-cache boundary needed for transparent hostname attribution.
- Verification plan: add DNS response answer parsing with compressed names for A/AAAA answers in `foxprox-inspect`, expose a cache `record_response` method, verify parsed response enrichment drives domain policy, verify malformed compression fails closed, then run formatting, clippy, focused tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — DNS response bytes → cache → flow attribution

- Slice attempted: parse DNS response answer bytes into attribution cache entries and use them to enrich a later transparent TCP flow.
- Why next: manual DNS cache insertion proved the cache-to-policy boundary, but real DNS response parsing was still missing from the DNS-to-flow correlation path.
- What changed: added `DnsAttributionCache::record_response`, DNS response answer parsing for A/AAAA IN records, compressed-name handling, TTL-based cache expiry, and fail-closed errors for malformed DNS response structure and compression pointer loops.
- Verification:
  - `cargo fmt --check` initially failed on new DNS response parser formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-inspect dns_response_records_answer_and_enriches_later_tcp_flow` and `cargo test -p foxprox-inspect dns_response_rejects_compression_pointer_loop`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: DNS compression pointers need loop protection even for this narrow response parser; the parser caps pointer jumps and treats loops as attribution-sensitive parse failures.
- What remains unproven: upstream DNS forwarding, DNS resolver socket behavior, CNAME chain attribution, cache eviction limits, negative responses, response/query transaction matching, and live UDP DNS forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP event → flow table → expiration slice

- Slice attempted: add a platform-independent UDP pseudo-flow manager that consumes normalized UDP/DNS/QUIC events, applies classification-specific idle timeouts, counts packets/bytes, and emits expiration evidence.
- Why next: UDP/DNS/QUIC classification and DNS attribution exist, but alpha UDP support also requires pseudo-flow lifecycle and configurable timeouts before forwarding or audit expiration records can be reliable.
- Verification plan: add a `foxprox-flow` crate, observe normalized UDP/DNS events into flow state, verify QUIC/DNS/generic timeout selection, byte counters, refresh behavior, attribution preservation, and expiration; run formatting, clippy, focused flow tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP event → flow table → expiration

- Slice attempted: platform-independent UDP pseudo-flow lifecycle tracking from normalized UDP/DNS/QUIC events.
- Why next: packet classification and attribution existed, but UDP alpha behavior needs flow state, byte counters, classification-specific idle timeouts, and expiration evidence before forwarding can be robust.
- What changed: added `crates/foxprox-flow` with configurable DNS/generic/QUIC idle timeouts, `UdpFlowKey`, `UdpFlowState`, observation results for created/updated/ignored events, byte/packet counters, attribution preservation, timeout refresh, and deterministic expiration removal.
- Verification:
  - `cargo fmt --check` initially failed on new flow test formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` initially failed because `Endpoint` has no `Ord` for `BTreeMap`; switched the flow table to `HashMap`, then clippy passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 4 `foxprox-config` tests, 10 `foxprox-core` tests, 4 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-flow quic_candidate_flow_uses_longer_timeout_and_expires`, `cargo test -p foxprox-flow repeated_udp_observation_refreshes_timeout_and_counts_bytes`, and `cargo test -p foxprox-flow dns_query_event_uses_dns_timeout`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: `Endpoint` intentionally lacks ordering, so flow state should not require ordered maps unless core endpoint ordering is deliberately added later.
- What remains unproven: UDP socket forwarding, reply routing to sandbox, expiration audit record emission, configurable timeout loading from TOML, resource limits, and direct multicast/broadcast denial are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TOML UDP timeouts → flow table behavior slice

- Slice attempted: load UDP pseudo-flow idle timeouts from user-facing TOML and prove they drive flow expiration behavior.
- Why next: UDP flow tracking has hard-coded defaults; alpha requires UDP/DNS/QUIC timeouts to be configurable before runtime forwarding relies on them.
- Verification plan: extend `foxprox-config` with a validated combined config carrying `UdpFlowTimeouts`, reject zero timeout values, verify a loaded DNS timeout expires a flow at the configured deadline, then run formatting, clippy, focused config tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TOML UDP timeouts → flow table behavior

- Slice attempted: load UDP pseudo-flow idle timeouts from TOML and prove they control flow expiration behavior.
- Why next: UDP flow tracking existed with defaults only; alpha requires DNS/generic/QUIC timeouts to be configurable.
- What changed: added `FoxproxConfig` and `config_from_toml` to `foxprox-config`, retained `policy_config_from_toml` compatibility, parsed `[udp_timeouts]` values into `UdpFlowTimeouts`, applied defaults for omitted values, and rejected zero-second timeouts.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 6 `foxprox-config` tests, 10 `foxprox-core` tests, 4 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-config loaded_udp_timeouts_drive_flow_expiration` and `cargo test -p foxprox-config zero_udp_timeout_is_rejected`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: adding runtime config while preserving the existing policy-only loader required a small compatibility wrapper so existing CLI/broker tests did not need to know about flow settings yet.
- What remains unproven: CLI/runtime consumption of the combined config, config reload behavior, source-span diagnostics, resource limits, and expiration audit emission are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP flow expiration → structured audit slice

- Slice attempted: turn UDP pseudo-flow expiration evidence into structured audit records with sandbox/frontend/protocol/byte-count metadata.
- Why next: flow expiration is tracked but not externally observable; alpha audit requirements include UDP flow expiration and byte counts.
- Verification plan: extend core/audit kinds for lifecycle observation, retain sandbox/frontend in flow state, emit expiration audit records from `ExpiredUdpFlow`, verify JSON output includes `udp_flow_expired`, byte count, hostname attribution, and idle-timeout reason, then run formatting, clippy, focused flow/audit tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP flow expiration → structured audit

- Slice attempted: emit externally serializable audit records when UDP pseudo-flows expire.
- Why next: UDP flow state and expiration existed but were not observable as first-class audit output, despite alpha requiring UDP flow expiration audit events and byte counts.
- What changed: added `AuditKind::UdpFlowExpired` and `AuditDecision::Observed`, serialized them in JSON audit output, retained sandbox/frontend in `UdpFlowState`, added `ExpiredUdpFlow::audit_record`, and included protocol classification, endpoints, hostname attribution, idle-timeout reason, and byte counts in expiration records.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 6 `foxprox-config` tests, 10 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-flow expired_udp_flow_emits_structured_audit_record` and `cargo test -p foxprox-audit bounded_sink_reports_backpressure_without_accepting_record`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: lifecycle audit events need an observed/non-decision audit state; overloading allow/deny/fail-closed would make expiration logs misleading.
- What remains unproven: runtime scheduling of expiration scans, writing expiration audit to a sink in a live loop, TCP flow close audit, UDP forwarding, and resource-limit enforcement are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP multicast/broadcast default-deny policy slice

- Slice attempted: enforce alpha fail-closed/default-deny behavior for UDP multicast and broadcast destinations even when the global default policy is allow, while preserving explicit allow rules.
- Why next: UDP flow lifecycle is now tracked, but alpha policy requires LAN discovery/multicast/broadcast to be denied by default unless explicitly enabled.
- Verification plan: add core policy checks for UDP/DNS/QUIC multicast and IPv4 broadcast destinations after explicit rules but before default policy, verify default-allow denies multicast/broadcast, verify an explicit allow rule can opt in, then run formatting, clippy, focused core tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP multicast/broadcast default-deny policy

- Slice attempted: deny UDP multicast and IPv4 broadcast destinations by default even when global default policy is allow, while permitting explicit opt-in rules.
- Why next: alpha requires LAN discovery/multicast/broadcast to be denied by default, and UDP flow support made this policy gap more important before forwarding.
- What changed: `PolicyEngine` now checks UDP/DNS/QUIC destination IPs for IPv4 multicast, IPv4 limited broadcast, and IPv6 multicast after explicit rule matching but before global default policy. Denials use reason `udp-multicast-broadcast-denied`; explicit allow rules can still opt in to specific multicast destinations.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 6 `foxprox-config` tests, 12 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-core udp_multicast_and_broadcast_are_denied_before_default_allow` and `cargo test -p foxprox-core explicit_rule_can_allow_udp_multicast_destination`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: the policy check belongs after explicit rules, not before them, so documented explicit support can be added by configuration without changing core logic.
- What remains unproven: configurable multicast/broadcast allowances in user-facing examples, IPv4 subnet-directed broadcast detection, live UDP forwarding behavior, and ICMP unreachable synthesis for denied UDP are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — ICMP default policy/config slice

- Slice attempted: add explicit ICMP defaults for essential errors and configurable ping, with unusual ICMP denied even under global default allow.
- Why next: packet ICMP parsing and echo replies exist, but alpha ICMP policy requires essential errors allowed, ping configurable, and unsupported/unusual ICMP denied by default.
- Verification plan: add `IcmpPolicy` to core/config, enforce rules after explicit policy rules and before global default, update default echo denial expectations, verify essential error allow, configured echo allow, unusual default-allow denial, TOML `icmp.allow_echo`, then run formatting, clippy, focused tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — ICMP default policy/config

- Slice attempted: explicit ICMP default policy for essential errors, configurable echo, and unusual ICMP denial.
- Why next: ICMP packets and echo replies were parse/synthesis tested, but alpha policy requires essential ICMP errors allowed, ping configurable, and unusual ICMP denied by default.
- What changed: added `IcmpPolicy` to `PolicyConfig`, applied ICMP defaults after explicit rules and before global default policy, allowed essential ICMPv4 error types 3/11/12 by default, denied echo/unusual ICMP by default with reason `icmp-default-deny`, added TOML `[icmp] allow_echo` and `allow_essential_errors`, and updated broker/CLI expectations for default ping denial.
- Verification:
  - `cargo fmt --check` initially failed on formatting; `cargo fmt` was run.
  - `cargo clippy --workspace --all-targets -- -D warnings` initially exposed missing `icmp` fields in explicit test `PolicyConfig` literals; fixed those, then clippy passed.
  - `cargo test --workspace` initially failed because the CLI default-deny ICMP assertion still expected `default-deny`; updated it to `icmp-default-deny`, then workspace tests passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 7 `foxprox-config` tests, 14 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 10 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-core icmp_defaults_allow_essential_errors_but_not_echo_or_unusual_types`, `cargo test -p foxprox-core configured_icmp_echo_allows_ping_without_broad_icmp_allow`, `cargo test -p foxprox-config loaded_icmp_echo_policy_allows_ping`, and `cargo test -p foxprox-broker denied_icmp_echo_request_is_audited_without_reply`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: adding protocol-specific defaults changes the reason observed by generic packet/CLI paths; tests that asserted global default-deny needed to assert the more specific ICMP denial instead.
- What remains unproven: ICMPv6 distinctions, ICMP unreachable synthesis for denied UDP/TCP, path-MTU handling, ping runtime through TUN, and user-facing config examples are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — IPv6 packet parser → normalized policy events slice

- Slice attempted: add basic IPv6 packet parsing for TCP connect attempts, UDP/DNS/QUIC flows, and ICMPv6 messages into existing normalized events.
- Why next: IPv4 parsing is proven, but architecture scope includes IPv6 parsing and ICMPv6 basics; this reduces parser coverage risk without requiring TUN privileges.
- Verification plan: add `parse_ipv6_packet`/fail-closed helpers in `foxprox-packet`, reject malformed payload lengths and unsupported extension headers, verify IPv6 TCP SYN, UDP/443 QUIC, broker DNS resolver policy, ICMPv6 message normalization, and malformed fail-closed behavior, then run formatting, clippy, focused packet tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — IPv6 packet parser → normalized policy events

- Slice attempted: basic IPv6 packet parsing into existing normalized policy events.
- Why next: IPv4 parser coverage was strong, but documented architecture includes IPv6/ICMPv6; adding platform-independent IPv6 parsing reduces packet-core scope risk before TUN/runtime integration.
- What changed: added `parse_ipv6_packet` and `parse_ipv6_packet_fail_closed` to `foxprox-packet`, parses fixed-header IPv6 TCP SYN connect attempts, UDP DNS queries, UDP/443 QUIC candidates, and ICMPv6 type/code messages, rejects malformed payload lengths, and treats IPv6 extension headers as unsupported/fail-closed in this minimal parser.
- Verification:
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 7 `foxprox-config` tests, 14 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 15 `foxprox-packet` tests, and 0 doc tests.
  - Focused checks passed: `cargo test -p foxprox-packet parses_ipv6_tcp_syn_into_connect_attempt`, `cargo test -p foxprox-packet parses_ipv6_dns_query_and_policy_allows_broker_resolver`, and `cargo test -p foxprox-packet malformed_ipv6_packet_can_be_converted_to_fail_closed_event`.
  - `cargo fmt --check` passed after focused checks.
- What failed or surprised the agent: the minimal IPv6 parser can share normalized events with IPv4 cleanly, but extension-header support should remain fail-closed until a deliberate parser slice handles hop-by-hop/routing/fragment semantics.
- What remains unproven: IPv6 extension header traversal, IPv6 fragmentation policy beyond fail-closed extension rejection, ICMPv6 essential-error defaults, IPv6 checksums, and broker/TUN runtime dispatch between IPv4 and IPv6 are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — ICMPv6 default policy slice

- Slice attempted: extend ICMP default policy to distinguish IPv4 and IPv6 ICMP semantics after IPv6 packet parsing.
- Why next: IPv6 packet parsing now emits ICMPv6 messages, but core policy still only recognizes IPv4 essential errors and echo requests; alpha requires ICMP/ICMPv6 basics to fail closed except documented essentials.
- Verification plan: update `PolicyEngine` ICMP defaults so IPv6 essential errors (types 1–4) are allowed when configured, IPv6 echo request (type 128/code 0) is controlled by `allow_echo`, and unusual ICMPv6 remains denied even under global default allow; run focused core/packet tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — ICMPv6 default policy

- Slice attempted: distinguish IPv4 and IPv6 ICMP default policy semantics.
- Why next: IPv6 parser support produced ICMPv6 normalized events, but default policy still recognized only IPv4 error and echo type numbers.
- What changed: core ICMP defaults now infer ICMPv6 from IPv6 endpoints, allow ICMPv6 essential errors types 1–4 when configured, allow ICMPv6 echo request type 128 only when `allow_echo` is enabled, and continue denying neighbor discovery/unusual ICMPv6 before global default allow.
- Verification:
  - `cargo fmt --check` passed.
  - Focused checks passed: `cargo test -p foxprox-core icmpv6` ran 2 ICMPv6 policy tests successfully.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 4 `foxprox-broker` tests, 3 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 15 `foxprox-packet` tests, and doc tests.
- What failed or surprised the agent: no failures; the existing endpoint IP family was enough to avoid adding protocol-version fields to `IcmpMessage`.
- What remains unproven: ICMPv6 echo reply synthesis, neighbor discovery handling, IPv6 extension-header traversal, IPv6 checksums, and broker/TUN runtime dispatch between IPv4 and IPv6 are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — IP version dispatch → broker/CLI audit slice

- Slice attempted: replace the IPv4-only broker/CLI packet path with an IP-version-dispatching handler that can process IPv4 and IPv6 packets through the same policy/audit boundary.
- Why next: packet parsing and ICMPv6 defaults are verified separately, but the broker-facing runtime path still assumes IPv4; alpha TUN handling must dispatch mixed IP packets before live TUN IO is useful.
- Verification plan: add a platform-independent `IpPacketBroker` that dispatches by version nibble, fails closed for unknown/empty packets, preserves IPv4 echo reply synthesis, processes IPv6 without write-back synthesis, update `packet-once` to use it, and run focused broker/CLI tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — IP version dispatch → broker/CLI audit

- Slice attempted: process mixed IPv4/IPv6 packet bytes through one broker-facing packet handler and CLI harness.
- Why next: IPv4 and IPv6 parsers existed, but the broker/CLI runtime path still assumed IPv4; live TUN IO will need version dispatch at this boundary.
- What changed: added `IpPacketBroker` with first-nibble IP version dispatch, fail-closed unsupported/empty IP packet handling, IPv6 parsing through policy/audit, IPv4-only echo reply synthesis guard, kept `Ipv4PacketBroker` as a compatibility wrapper, and updated `packet-once` to use the version-dispatching broker.
- Verification:
  - `cargo fmt --check` initially failed on formatting; `cargo fmt` was run.
  - Focused broker checks passed: `cargo test -p foxprox-broker ip_broker` ran 3 dispatch/fail-closed/reply-suppression tests.
  - Focused CLI check passed: `cargo test -p foxprox-cli ipv6` verified IPv6 ICMPv6 audit output without reply bytes.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 15 `foxprox-packet` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: no behavioral failures; keeping IPv4 reply synthesis behind an address-family/type guard prevents accidental ICMPv6 echo handling by the IPv4 packet builder.
- What remains unproven: real TUN reads/writes, ICMPv6 echo reply synthesis, IPv6 extension header traversal, TCP/UDP forwarding, and long-running runtime audit flushing are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTPS CONNECT frontend preflight → policy/audit/response slice

- Slice attempted: turn parsed HTTPS CONNECT metadata into a proxy-frontend preflight handler that evaluates shared policy, emits audit evidence, and produces deterministic client response bytes for allowed, denied, and malformed requests.
- Why next: CONNECT parsing and policy rules are proven, but explicit proxy support still lacks a frontend boundary that converts request bytes into policy/audit plus externally observable proxy behavior.
- Verification plan: add a `foxprox-proxy` crate with an HTTP CONNECT preflight handler, map parse failures to fail-closed unsupported audit, return `200 Connection Established` only for allowed decisions and `403 Forbidden` for denied/fail-closed decisions, serialize audit output in tests, then run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTPS CONNECT frontend preflight → policy/audit/response

- Slice attempted: explicit HTTP proxy CONNECT preflight from request bytes to policy/audit and client-visible response bytes.
- Why next: CONNECT parser and policy support existed, but there was no frontend boundary proving proxy request bytes produce shared policy/audit output and deterministic allow/deny behavior.
- What changed: added `crates/foxprox-proxy` with `HttpProxyPreflight`, `HttpConnectPreflight`, and `HttpProxyResponse`; CONNECT requests are parsed as `FrontendKind::HttpProxy`, allowed decisions return `HTTP/1.1 200 Connection Established`, denied decisions return `HTTP/1.1 403 Forbidden`, and malformed CONNECT requests become fail-closed unsupported audit events with a 403 response.
- Verification:
  - `cargo fmt --check` initially failed on formatting; `cargo fmt` was run.
  - `cargo test -p foxprox-proxy` passed 3 focused tests covering allowed CONNECT audit/200 response, denied CONNECT 403 response, and malformed request fail-closed/403 behavior.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 3 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: the policy helper names are `HostnamePattern::new(".example.com")` and `with_minimum_hostname_confidence`; the initial test used non-existent shortcut names and failed to compile.
- What remains unproven: CONNECT tunnel establishment, host TCP egress, plaintext HTTP proxy absolute-form handling, SOCKS5 frontend response negotiation, proxy listener sockets, and backpressure in a live proxy runtime are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — SOCKS5 CONNECT frontend preflight → policy/audit/response slice

- Slice attempted: turn SOCKS5 CONNECT request bytes into shared policy/audit evaluation and deterministic SOCKS5 response bytes.
- Why next: HTTP CONNECT preflight now proves one explicit proxy frontend path; alpha also requires SOCKS5 TCP CONNECT support through the same policy/audit backend and fail-closed malformed handling.
- Verification plan: extend `foxprox-proxy` with a SOCKS5 CONNECT preflight handler after method negotiation, return success only for allowed policy decisions, return rule-denied and general-failure replies for denied/fail-closed outcomes, serialize audit in tests, then run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — SOCKS5 CONNECT frontend preflight → policy/audit/response

- Slice attempted: SOCKS5 CONNECT request preflight from request bytes to shared policy/audit and client-visible SOCKS5 replies.
- Why next: HTTP CONNECT preflight covered one explicit proxy path; SOCKS5 TCP CONNECT needed equivalent policy/audit integration and malformed-request fail-closed behavior.
- What changed: extended `foxprox-proxy` with `Socks5Preflight`, `Socks5ConnectPreflight`, and `Socks5Response`; CONNECT requests after method negotiation are parsed as `FrontendKind::Socks5`, allowed decisions return SOCKS5 success (`0x00`), policy denials return connection-not-allowed (`0x02`), and malformed/unsupported requests become fail-closed unsupported audit events with general failure (`0x01`).
- Verification:
  - `cargo fmt --check` initially failed on formatting; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-proxy socks5` ran 3 SOCKS5 tests covering allowed audit/success response, denied ruleset response, and malformed UDP ASSOCIATE fail-closed/general-failure response.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-flow` tests, 18 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 6 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: no behavior failures; SOCKS5 has useful distinct reply codes for policy denial versus malformed/unsupported requests, so the preflight exposes that difference.
- What remains unproven: SOCKS5 greeting negotiation, TCP egress/tunnel bridging, listener runtime, proxy authentication rejection, and flow byte-count/close audit for proxied streams are still absent.
- Commit: this commit.
