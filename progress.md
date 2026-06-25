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

## 2026-06-21 Session Continue — explicit HTTP proxy request → policy/audit/response slice

- Slice attempted: parse explicit HTTP proxy absolute-form requests into normalized HTTP events and add a proxy preflight that evaluates policy/audit and returns denial responses for blocked or malformed requests.
- Why next: HTTPS CONNECT and SOCKS5 preflights exist, but alpha explicit proxy support also requires plaintext HTTP proxy requests with host/method/path visibility through the same policy/audit backend.
- Verification plan: add an absolute-form HTTP proxy parser, preserve origin path/query rather than the full URL as the policy path, expose scheme in audit output, add `HttpProxyPreflight::handle_http_request` with allowed-forward/forbidden responses, and run focused inspect/proxy/audit tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — explicit HTTP proxy request → policy/audit/response

- Slice attempted: explicit plaintext HTTP proxy absolute-form request preflight through policy/audit and denial response behavior.
- Why next: HTTPS CONNECT and SOCKS5 preflights were covered; alpha also requires HTTP proxy requests with origin host, method, and path visibility through the shared policy engine.
- What changed: added `parse_http_proxy_request` for absolute-form `http://host[:port]/path?query` requests, preserving origin path/query for policy; added `http_scheme` to core audit records and JSON output; added `HttpProxyPreflight::handle_http_request` returning a forward action for allowed requests and a 403 response action for denied or malformed requests.
- Verification:
  - Focused inspect checks passed: `cargo test -p foxprox-inspect http_proxy` ran 2 tests for absolute-form extraction and origin-form rejection.
  - Focused proxy checks passed: `cargo test -p foxprox-proxy http_proxy` ran 3 tests for allowed audit/forward, denied 403, and malformed fail-closed 403 behavior.
  - Focused audit check passed: `cargo test -p foxprox-audit serializes_http_method_scheme_and_path_audit_fields`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 9 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; explicit HTTP proxy requests need a separate absolute-form parser so policy path prefixes see `/path?query` rather than the entire URL.
- What remains unproven: HTTP response forwarding through host egress, CONNECT tunnel bridging, SOCKS5 greeting negotiation, listener sockets, and proxy flow close/byte-count audit are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — host TCP egress proof slice

- Slice attempted: add the first shared host TCP egress backend proof independent of proxy/TUN frontends.
- Why next: proxy and transparent policy preflights now produce allowed connect intents, but alpha requires all allowed traffic to leave through a shared host egress backend rather than frontend-specific sockets.
- Verification plan: add a `foxprox-egress` crate with typed TCP targets and a blocking host TCP connector, verify a local loopback listener receives bytes over an egress-owned socket, verify connection failures produce meaningful errors, then run formatting, clippy, focused egress tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — host TCP egress proof

- Slice attempted: shared host TCP egress backend proof with a real loopback socket.
- Why next: policy/proxy preflights can now authorize connect intents, but alpha requires all egress to go through a shared backend rather than frontend-owned sockets.
- What changed: added `crates/foxprox-egress` with typed `TcpTarget`, `TcpEgress` trait, blocking `HostTcpEgress`, `TcpEgressConnection`, timeout validation, target validation, resolution/connect errors, and a loopback integration test proving bytes cross an egress-owned TCP stream.
- Verification:
  - `cargo test -p foxprox-egress` passed 3 focused tests: loopback connect/byte exchange, target validation, and connect-failure diagnostics.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 3 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 9 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; a local loopback listener gives concrete egress evidence without depending on external network access.
- What remains unproven: UDP egress sockets, DNS upstream forwarding, proxy-to-egress stream bridging, TUN TCP forwarding/smoltcp integration, resource limits, and async backpressure are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTPS CONNECT preflight → host TCP egress slice

- Slice attempted: connect an allowed HTTPS CONNECT proxy preflight to the shared host TCP egress backend and prove bytes reach a loopback target only after policy allows.
- Why next: CONNECT policy/response and host TCP egress are individually proven, but no frontend path yet uses the shared egress backend for an allowed connect intent.
- Verification plan: add proxy-to-egress tunnel establishment for CONNECT requests, return 200 with an egress connection on success, 403 without egress for policy denial, 502 for egress connect failure, verify loopback byte exchange through the returned egress connection, then run focused proxy tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTPS CONNECT preflight → host TCP egress

- Slice attempted: establish host TCP egress after an allowed HTTPS CONNECT proxy preflight.
- Why next: CONNECT policy/response handling and host TCP egress were proven independently, but no frontend path consumed the shared egress backend for allowed proxy traffic.
- What changed: `foxprox-proxy` now depends on `foxprox-egress`, adds `HttpConnectTunnel`, `HttpProxyResponse::BadGateway`, and `HttpProxyPreflight::establish_connect_tunnel`; policy-denied/malformed requests do not call egress, allowed requests open a host TCP connection via `TcpEgress`, and egress connect failures return a 502 response with retained diagnostics.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-proxy connect_tunnel` ran 3 tests proving allowed CONNECT opens a loopback egress connection and exchanges bytes, denied CONNECT does not call egress, and allowed preflight plus failed egress returns `502 Bad Gateway`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 3 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 12 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; the preflight had to retain the parsed CONNECT target separately because audit records intentionally do not include host-only destination ports as endpoints.
- What remains unproven: full bidirectional tunnel pumping after sending the 200 response, plaintext HTTP proxy forwarding, SOCKS5 egress integration, TCP flow close/byte-count audit, async resource limits, and TUN TCP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — SOCKS5 CONNECT preflight → host TCP egress slice

- Slice attempted: connect an allowed SOCKS5 CONNECT preflight to the shared host TCP egress backend.
- Why next: HTTPS CONNECT now reaches shared egress, but SOCKS5 TCP CONNECT still stops at policy/response preflight; alpha requires SOCKS TCP destinations to use the same host egress layer.
- Verification plan: add SOCKS5 tunnel establishment that opens egress only after allow decisions, returns ruleset-denied without egress on policy denial, returns general failure on egress errors, verify loopback byte exchange through the returned connection, then run focused proxy tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — SOCKS5 CONNECT preflight → host TCP egress

- Slice attempted: establish host TCP egress after an allowed SOCKS5 CONNECT preflight.
- Why next: HTTPS CONNECT used shared egress, but SOCKS5 CONNECT still stopped before opening host sockets.
- What changed: added `Socks5ConnectTunnel` and `Socks5Preflight::establish_connect_tunnel`; allowed SOCKS5 CONNECT requests open host TCP egress, policy denials do not call egress and retain ruleset-denied response code, and egress failures return SOCKS5 general failure with retained diagnostics. Shared target extraction now supports HTTPS CONNECT and SOCKS domain/IP forms.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-proxy socks5_tunnel` ran 3 tests proving allowed SOCKS5 CONNECT opens loopback egress and exchanges bytes, denied SOCKS5 does not call egress, and allowed preflight plus failed egress returns general failure.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 3 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 15 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; SOCKS IP-form requests are useful for deterministic loopback egress tests because the parsed event can produce an IP target without DNS resolution.
- What remains unproven: SOCKS5 greeting negotiation, full bidirectional stream pumping, plaintext HTTP proxy forwarding, UDP egress/DNS upstream forwarding, TCP close/byte-count audit, and TUN TCP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — host UDP egress proof slice

- Slice attempted: add a shared host UDP egress backend proof with real loopback datagram exchange.
- Why next: UDP flow tracking, DNS classification, and UDP policy exist, but there is no host UDP socket backend for DNS/UDP forwarding; alpha requires UDP forwarding and DNS upstream egress.
- Verification plan: extend `foxprox-egress` with typed UDP target/session support, verify a loopback UDP server receives a datagram and replies through an egress-owned socket, validate target errors, then run focused egress tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — host UDP egress proof

- Slice attempted: shared host UDP egress backend proof with real loopback datagram exchange.
- Why next: UDP policy/flow tracking existed, but no shared UDP socket backend was available for future UDP forwarding or DNS upstream queries.
- What changed: extended `foxprox-egress` with `UdpTarget`, `UdpEgress` trait, `HostUdpEgress`, `UdpEgressSession`, UDP-specific resolve/bind/connect errors, read-timeout validation, and a loopback UDP datagram exchange test.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-egress udp` ran 2 tests for UDP loopback datagram exchange and shared TCP/UDP target validation.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 4 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 15 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; UDP `connect` sets a default peer for send/recv but does not prove remote reachability until a datagram exchange test does so.
- What remains unproven: UDP forwarding from normalized flow events, DNS upstream query/response handling, reply routing to sandbox, UDP resource limits, and live expiration scheduling are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — DNS UDP upstream → response cache slice

- Slice attempted: forward a DNS query over the shared UDP egress backend, receive a DNS response, and record response answers into the attribution cache.
- Why next: UDP egress and DNS response parsing/cache are proven separately; alpha DNS foundation requires broker-controlled DNS queries to go upstream and feed hostname attribution.
- Verification plan: add a `foxprox-dns` crate with a UDP upstream forwarder using `UdpEgress`, test against a loopback UDP DNS fixture server that returns an A answer, verify response bytes and cache enrichment of a later TCP flow, then run focused DNS tests plus formatting, clippy, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — DNS UDP upstream → response cache

- Slice attempted: forward DNS query bytes to an upstream server through shared UDP egress and record returned answers into the DNS attribution cache.
- Why next: UDP egress and DNS response parsing existed independently, but broker DNS foundation needs upstream response bytes to feed hostname attribution for later transparent flows.
- What changed: added `crates/foxprox-dns` with `UdpDnsForwarder`, `DnsForwardResult`, and `DnsForwardError`; the forwarder validates query length, uses `UdpEgress` to send/receive one DNS datagram, records A/AAAA answers through `DnsAttributionCache::record_response`, and exposes response bytes plus answer count.
- Verification:
  - `cargo test -p foxprox-dns` passed 2 focused tests: loopback UDP DNS fixture forwarding/answer caching/later TCP flow attribution, and short-query rejection before egress.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 2 `foxprox-dns` tests, 4 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 15 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed.
- What failed or surprised the agent: no failures; forwarding can record cache entries without parsing the original query because the DNS response answer parser already validates and extracts compressed answer names.
- What remains unproven: DNS listener reachable from sandbox, DNS denial response synthesis, direct DNS bypass runtime interception, negative response handling, transaction matching, and UDP reply packet routing to TUN are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — DNS broker datagram → policy/upstream/response slice

- Slice attempted: handle one broker-received DNS datagram by parsing the question, evaluating shared policy/audit, forwarding allowed queries through UDP egress, and synthesizing client-visible DNS error responses for denied or malformed queries.
- Why next: upstream DNS forwarding and DNS query audit are individually proven, but the DNS broker boundary still lacks request policy enforcement and denial/fail-closed responses before a live listener is added.
- Verification plan: extend `foxprox-dns` with a single-datagram handler, verify allowed queries reach a loopback upstream and populate attribution cache, denied queries return DNS REFUSED without calling egress, malformed queries fail closed with FORMERR, then run formatting, clippy, focused DNS tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — DNS broker datagram → policy/upstream/response

- Slice attempted: single-datagram broker DNS handling from raw query bytes to policy/audit, upstream UDP forwarding, attribution-cache recording, and client-visible denial/error responses.
- Why next: DNS upstream forwarding and DNS query audit existed separately, but a broker resolver boundary still needed to prove that allowed queries forward, denied queries do not egress, and malformed queries fail closed with deterministic responses.
- What changed: `foxprox-dns` now has `DnsBrokerDatagramHandler`, `DnsDatagramResult`, broker-side DNS question parsing into `DnsQuery` events, fail-closed unsupported events for malformed queries, REFUSED response synthesis for policy denials, FORMERR for malformed queries, and SERVFAIL for allowed queries whose upstream forwarding fails.
- Verification:
  - `cargo fmt --check` initially failed on formatting in `foxprox-dns`; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-dns dns_broker_handler -- --nocapture` ran 3 tests covering allowed forwarding/cache attribution, denied REFUSED without egress, and malformed FORMERR without egress.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-dns` tests, 4 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 15 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: broker DNS handling needed a small request parser separate from response parsing so malformed requests can still produce fail-closed audit and DNS error responses before any upstream egress is attempted.
- What remains unproven: live UDP listener reachability from the sandbox, transaction matching beyond one datagram, UDP reply packet routing back to TUN, negative response handling, DNS cache limits, and runtime integration with packet/flow loops are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTP proxy preflight → host TCP egress forwarding slice

- Slice attempted: connect an allowed explicit HTTP proxy absolute-form request to the shared host TCP egress backend and write an origin-form request to the upstream server.
- Why next: HTTP proxy policy preflight currently stops at a `Forward` action, while CONNECT and SOCKS already prove shared TCP egress; plaintext HTTP proxy forwarding is the next explicit-proxy alpha gap.
- Verification plan: extend `foxprox-proxy` with an HTTP request forwarding helper that only opens egress after allow, rewrites absolute-form to origin-form, verifies loopback upstream receives the rewritten request and responds, verifies denial skips egress, then run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTP proxy preflight → host TCP egress forwarding

- Slice attempted: allowed explicit HTTP proxy requests now open shared host TCP egress and write origin-form request bytes upstream.
- Why next: HTTP proxy preflight previously stopped at a `Forward` action, while CONNECT/SOCKS already used shared TCP egress; this closes the plaintext HTTP proxy egress gap for the explicit proxy path.
- What changed: `foxprox-proxy` now has `HttpRequestForward` and `HttpProxyPreflight::forward_http_request`, extracts the HTTP proxy host/port target, rewrites absolute-form request lines to origin-form path/query for upstream servers, opens egress only after an allowed policy decision, returns 403 without egress on denial/malformed input, and returns 502 diagnostics on connect/write failures.
- Verification:
  - `cargo fmt --check` initially failed on formatting in `foxprox-proxy`; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-proxy http_proxy_forward -- --nocapture` ran 3 tests covering loopback egress forwarding with origin-form rewrite, denied request without egress, and allowed request with failed egress returning Bad Gateway.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-dns` tests, 4 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 18 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: no behavior failures; the forwarding helper can reuse the parsed `HttpRequest` event as control state for target and path rewrite instead of reparsing the absolute URI separately.
- What remains unproven: streaming response/body pump, hop-by-hop header handling, listener runtime, CONNECT/SOCKS bidirectional pumps, TCP flow close/byte-count audit, and TUN TCP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — SOCKS5 greeting negotiation slice

- Slice attempted: add the missing SOCKS5 method-negotiation boundary before CONNECT preflight so real clients can be accepted only when no-authentication is offered.
- Why next: SOCKS5 CONNECT parsing/egress exists but assumes negotiation has already completed; alpha SOCKS5 frontend behavior needs deterministic greeting responses and rejection of unsupported authentication before request handling.
- Verification plan: add `Socks5Preflight::handle_greeting`, accept version 5 with method 0x00, reject unsupported auth, malformed lengths, and wrong versions with no-acceptable-methods, then run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — SOCKS5 greeting negotiation

- Slice attempted: SOCKS5 method-negotiation handling before CONNECT request parsing.
- Why next: SOCKS5 CONNECT policy/egress assumed the method-negotiation phase had already completed; real SOCKS5 clients need deterministic no-auth acceptance or unsupported-auth rejection first.
- What changed: added `Socks5GreetingPreflight`, `Socks5GreetingResponse`, and `Socks5Preflight::handle_greeting`; alpha accepts only SOCKS5 method `0x00` (no authentication) and rejects unsupported methods, malformed method counts, empty method lists, and non-SOCKS5 versions with `0x05 0xff`.
- Verification:
  - `cargo fmt --check` initially failed on formatting in a new assertion; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-proxy socks5_greeting -- --nocapture` ran 2 tests covering no-auth acceptance and unsupported/malformed greeting rejection.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-dns` tests, 4 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 20 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after formatting.
- What failed or surprised the agent: no behavior failures; method-count length validation is enough for the greeting boundary without coupling it to later CONNECT policy evaluation.
- What remains unproven: listener state machine joining greeting plus CONNECT, proxy authentication rejection in a live stream, full SOCKS stream pumping, TCP close/byte-count audit, and runtime resource limits are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TCP egress bridge byte-pump slice

- Slice attempted: add a reusable blocking TCP bridge that copies bytes bidirectionally between a frontend client stream and a shared host egress connection, returning byte-count evidence.
- Why next: proxy paths can establish egress connections, but CONNECT/SOCKS still lack a tunnel pump; a deterministic loopback bridge proof reduces that runtime forwarding gap before listener state machines are added.
- Verification plan: extend `foxprox-egress` with a `bridge_tcp_streams` helper and byte-count stats, verify a local client sends bytes through the bridge to an upstream loopback server and receives the response, then run formatting, clippy, focused egress tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TCP egress bridge byte-pump

- Slice attempted: reusable blocking TCP bridge between a frontend client stream and a shared host egress connection.
- Why next: proxy CONNECT/SOCKS paths could establish egress but did not yet prove a tunnel pump; this adds byte-moving evidence without introducing listener state machines or async runtime complexity.
- What changed: `foxprox-egress` now exposes `TcpBridgeStats` and `bridge_tcp_streams`, which copies client→target and target→client concurrently until EOF, shuts down write halves, and returns byte counts for later flow-close audit integration.
- Verification:
  - `cargo fmt --check` passed.
  - Focused check passed: `cargo test -p foxprox-egress tcp_bridge -- --nocapture` verified a loopback client sent `ping` through the bridge to an upstream egress server, received `pong`, and reported 4 bytes in each direction.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-dns` tests, 5 `foxprox-egress` tests, 5 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 20 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no failures; an EOF-driven blocking bridge is enough for deterministic local tunnel evidence, though async/backpressure and cancellation remain future runtime work.
- What remains unproven: integrating the bridge with CONNECT/SOCKS listener state machines, TCP flow close audit records, resource limits/cancellation, TUN TCP forwarding, and async backpressure are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TCP bridge stats → flow close audit slice

- Slice attempted: convert TCP bridge byte-count evidence into a structured TCP flow-close audit record.
- Why next: the TCP bridge now returns byte counts, but alpha audit requires TCP flow closed events with byte counts; this is the smallest policy-independent close-audit boundary before proxy listener integration.
- Verification plan: extend core/audit schema with `tcp_flow_closed` and directional byte counts, add a `ClosedTcpFlow` helper in `foxprox-flow`, verify JSON output includes total and directional counts, then run formatting, clippy, focused flow/audit tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TCP bridge stats → flow close audit

- Slice attempted: convert TCP bridge byte-count evidence into externally serializable TCP flow-close audit.
- Why next: the bridge returns byte counts, and alpha audit requires TCP flow closed events with byte counts before proxy/TUN runtimes can claim lifecycle observability.
- What changed: added `AuditKind::TcpFlowClosed`, directional byte-count fields to `AuditRecord`/JSON output, and `ClosedTcpFlow` in `foxprox-flow` with observed close audit records carrying source/destination, hostname attribution, total bytes, direction bytes, and close reason.
- Verification:
  - `cargo fmt --check` passed.
  - Focused checks passed: `cargo test -p foxprox-flow closed_tcp_flow -- --nocapture` verified `tcp_flow_closed` JSON with total and directional byte counts; `cargo test -p foxprox-audit serializes_broker_audit_record_as_json_line` verified existing audit serialization still works.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 5 `foxprox-dns` tests, 5 `foxprox-egress` tests, 6 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 20 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no failures; adding optional directional byte fields preserved existing audit records while allowing TCP close records to be more precise than a single total.
- What remains unproven: automatic emission of close audit from proxy listener bridge completion, TUN TCP flow close integration, durations/error reasons, and audit backpressure behavior in live forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP DNS listener one-datagram runtime slice

- Slice attempted: expose the DNS broker handler through a real UDP socket boundary for one datagram, sending the synthesized or upstream response back to the client.
- Why next: DNS datagram policy/upstream handling is proven in memory, but alpha needs a DNS broker reachable by sandbox traffic; a one-datagram loopback listener is the smallest live socket proof before long-running runtime loops.
- Verification plan: add a `serve_one_udp_query` helper in `foxprox-dns`, verify a loopback client sends a DNS query to the broker socket, the broker forwards to a loopback upstream, records attribution, and sends the upstream response back; run formatting, clippy, focused DNS tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP DNS listener one-datagram runtime

- Slice attempted: serve one broker DNS datagram over a real UDP socket and send the response back to the client.
- Why next: DNS request policy/upstream handling was in-memory only; a live socket boundary proves the DNS broker can be reached by UDP traffic before adding long-running runtime loops or sandbox routing.
- What changed: added `DnsServeOneResult`, `DnsServeError`, and `serve_one_udp_query` to `foxprox-dns`; the helper validates the socket local address matches the configured broker resolver, receives one datagram, maps peer/local addresses to normalized endpoints, invokes the DNS handler, and sends any synthesized/upstream response to the peer.
- Verification:
  - `cargo fmt --check` initially failed on formatting in `foxprox-dns`; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-dns udp_dns_listener -- --nocapture` verified a loopback client sent a DNS query to the broker UDP socket, the broker forwarded to a loopback upstream, returned the upstream response to the client, and populated attribution cache for a later TCP flow.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 6 `foxprox-dns` tests, 5 `foxprox-egress` tests, 6 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 20 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; binding the broker socket on an ephemeral port required policy rules to match the actual resolver endpoint rather than assuming port 53 in tests.
- What remains unproven: long-running DNS runtime loop, sandbox-reachable resolver address from TUN/netns setup, concurrent queries, transaction matching beyond one datagram, cache limits, and UDP response packet routing through TUN are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTP proxy TCP listener one-request runtime slice

- Slice attempted: serve one explicit HTTP proxy TCP connection through a real listener socket, policy preflight, shared egress, upstream response read, and client response write-back.
- Why next: HTTP proxy forwarding works as a helper, but alpha explicit proxy support needs a listener-facing runtime boundary; a one-request loopback server is the smallest live proof before full concurrent proxy loops.
- Verification plan: add `serve_one_http_proxy_connection` to `foxprox-proxy`, verify a loopback client sends an absolute-form HTTP request to the proxy listener, the proxy forwards origin-form to a loopback upstream and returns the upstream response, then run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTP proxy TCP listener one-request runtime

- Slice attempted: serve one explicit HTTP proxy request through a real TCP listener socket, policy preflight, shared egress, upstream response read, and client write-back.
- Why next: HTTP proxy forwarding existed as a helper but not as a listener-facing runtime boundary; alpha explicit proxy support needs observable client-to-proxy-to-upstream behavior.
- What changed: added `HttpProxyServeOneResult`, `HttpProxyServeOutcome`, `HttpProxyServeError`, request-head reading with a size limit, and `serve_one_http_proxy_connection`; the helper accepts one TCP client, reads one HTTP proxy request head, invokes the existing policy/egress path, writes upstream responses back to the client, or emits deterministic 403/502 responses.
- Verification:
  - `cargo fmt --check` passed.
  - Focused check passed: `cargo test -p foxprox-proxy http_proxy_listener -- --nocapture` verified a loopback client sent an absolute-form HTTP request to the proxy listener, the upstream loopback server received an origin-form request, and the client received the upstream `pong` response.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 6 `foxprox-dns` tests, 5 `foxprox-egress` tests, 6 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 21 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; a one-request listener can reuse the existing forwarding helper and remain intentionally limited to header-only plaintext HTTP until body streaming/backpressure is added.
- What remains unproven: long-running/concurrent HTTP proxy listener loop, request body streaming, CONNECT/SOCKS listener runtimes, tunnel close-audit integration, resource limits beyond request-head size, and TUN forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — HTTPS CONNECT listener tunnel runtime slice

- Slice attempted: serve one HTTP CONNECT proxy TCP connection through a real listener, establish shared egress, send the 200 response, and bridge tunnel bytes bidirectionally with byte-count evidence.
- Why next: plaintext HTTP proxy has a listener runtime and CONNECT has preflight/egress plus a generic bridge, but no listener-facing CONNECT tunnel path yet; this is the next explicit-proxy runtime gap.
- Verification plan: add `serve_one_http_connect_connection`, verify a loopback client receives `200 Connection Established`, sends bytes through the tunnel to an upstream server, receives the response, and gets bridge stats; run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — HTTPS CONNECT listener tunnel runtime

- Slice attempted: serve one HTTP CONNECT proxy TCP connection through listener accept, policy preflight, shared egress, 200 response, and bidirectional tunnel bridge.
- Why next: CONNECT preflight/egress and generic TCP bridging were proven separately, but no listener-facing CONNECT runtime existed for explicit proxy clients.
- What changed: added `HttpConnectServeOneResult`, `HttpConnectServeOutcome`, and `serve_one_http_connect_connection`; it accepts one TCP client, reads a bounded CONNECT request head, establishes egress only after allow, writes the CONNECT response, bridges tunnel bytes with `bridge_tcp_streams`, and reports bridge stats or denial/error response outcomes.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new CONNECT listener code; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-proxy http_connect_listener -- --nocapture` verified a loopback client received `200 Connection Established`, sent `ping` through the proxy tunnel to an upstream server, received `pong`, and the listener returned 4-byte bridge stats in both directions.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 6 `foxprox-dns` tests, 5 `foxprox-egress` tests, 6 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 22 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; writing the CONNECT response before starting the bridge keeps client-visible proxy semantics separate from tunnel byte copying.
- What remains unproven: SOCKS5 listener runtime, close-audit emission from listener completion, concurrent listener loops, cancellation/resource limits, and transparent TUN TCP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — SOCKS5 listener tunnel runtime slice

- Slice attempted: serve one SOCKS5 TCP connection through a real listener, method negotiation, CONNECT policy/egress, success response, and bidirectional bridge.
- Why next: SOCKS5 greeting, CONNECT preflight/egress, and generic bridging are proven separately; alpha SOCKS5 support still needs a listener-facing state machine that joins those boundaries.
- Verification plan: add `serve_one_socks5_connection`, read and validate greeting/request bytes, verify a loopback client negotiates no-auth, receives success, tunnels `ping`/`pong` to an upstream server, and returns bridge stats; run formatting, clippy, focused proxy tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — SOCKS5 listener tunnel runtime

- Slice attempted: serve one SOCKS5 connection through listener accept, no-auth greeting, CONNECT request, shared egress, SOCKS success response, and bidirectional bridge.
- Why next: SOCKS5 greeting, CONNECT policy/egress, and TCP bridging existed separately, but alpha SOCKS5 support needed a listener-facing state machine that joins them.
- What changed: added `Socks5ServeOneResult`, `Socks5ServeOutcome`, `Socks5ServeError`, SOCKS greeting/request readers, and `serve_one_socks5_connection`; it accepts one TCP client, negotiates no-auth only, reads CONNECT requests for IPv4/domain/IPv6 targets, establishes egress after policy allow, writes SOCKS response bytes, and bridges tunnel traffic with stats.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new SOCKS listener test/helper code; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-proxy socks5_listener -- --nocapture` verified a loopback client negotiated no-auth, received SOCKS success, sent `ping` through the proxy to an upstream server, received `pong`, and the listener returned 4-byte bridge stats in both directions.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 `foxprox-audit` tests, 7 `foxprox-broker` tests, 4 `foxprox-cli` tests, 7 `foxprox-config` tests, 16 `foxprox-core` tests, 6 `foxprox-dns` tests, 5 `foxprox-egress` tests, 6 `foxprox-flow` tests, 20 `foxprox-inspect` tests, 15 `foxprox-packet` tests, 23 `foxprox-proxy` tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the listener can keep greeting negotiation unaudited while CONNECT preflight still emits policy/audit evidence.
- What remains unproven: long-running/concurrent SOCKS listener loop, listener close-audit emission, cancellation/resource limits, proxy environment injection, and transparent TUN forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — bwrap setup command contract slice

- Slice attempted: encode the documented bwrap-compatible network setup command shape as validated integration-backend output.
- Why next: proxy/DNS listener slices now provide sandbox-reachable services, but alpha setup still lacks a verified backend contract for launching `foxproxsetup` under bwrap with temporary `CAP_NET_ADMIN`, `/dev/net/tun`, and proxy environment injection.
- Verification plan: add a `foxprox-integrations` crate with a bwrap command planner, validate required target/setup arguments, verify command args include `--unshare-user`, `--unshare-net`, `--cap-add CAP_NET_ADMIN`, `/dev/net/tun`, `foxproxsetup -- target`, and proxy env vars; run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — bwrap setup command contract

- Slice attempted: verified bwrap-compatible setup command planning for `foxproxsetup` network setup.
- Why next: DNS/proxy services now have live listener proofs, but alpha setup needs a documented launch contract that grants temporary `CAP_NET_ADMIN`, exposes `/dev/net/tun`, runs `foxproxsetup -- target`, and injects proxy environment values without tying broker core to bwrap.
- What changed: added `crates/foxprox-integrations` with `ProxyEnvironment`, `BwrapSetupConfig`, `CommandPlan`, `IntegrationPlanError`, and `plan_bwrap_setup`; the planner validates required programs/target argv and emits the documented bwrap argument shape including `--unshare-user`, `--unshare-net`, `--cap-add CAP_NET_ADMIN`, `/dev/net/tun` dev-bind, proxy `--setenv` values, and setup-helper delimiter.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new crate; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-integrations -- --nocapture` ran 2 tests covering command shape and validation failures.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed including the new `foxprox-integrations` crate: 3 audit, 7 broker, 4 cli, 7 config, 16 core, 6 dns, 5 egress, 6 flow, 20 inspect, 2 integrations, 15 packet, 23 proxy tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the command contract can be verified without executing bwrap, keeping bwrap semantics isolated in an integration crate.
- What remains unproven: actual `foxproxsetup` helper execution, TUN creation/configuration, fd handoff, capability drop, bwrap process lifecycle, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — setup helper fd handoff slice

- Slice attempted: prove the setup-to-broker file-descriptor handoff boundary with SCM_RIGHTS over a Unix socket pair.
- Why next: bwrap command planning now wraps `foxproxsetup`, but alpha setup still needs the helper to pass the TUN fd to the host broker; fd passing is the narrowest privileged-adjacent boundary that can be verified without creating a real TUN device.
- Verification plan: add fd handoff helpers in `foxprox-integrations`, send a temporary file descriptor over a Unix socket pair, receive it as owned broker-side state, verify the received fd can read the expected contents, then run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — setup helper fd handoff

- Slice attempted: prove the setup-helper-to-broker fd handoff boundary with SCM_RIGHTS over a Unix stream.
- Why next: bwrap command planning verified `foxproxsetup -- target`, but alpha setup requires the helper to send the TUN fd to the host-side broker; fd passing is the narrowest setup boundary that can be tested without privileged TUN creation.
- What changed: added Unix-only `fd_handoff` helpers in `foxprox-integrations`, including `send_setup_fd`, `receive_setup_fd`, `ReceivedFd`, and `FdHandoffError`; the crate now uses a small documented unsafe conversion from SCM_RIGHTS raw fds to `OwnedFd` and closes any extra received fds.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new fd handoff module; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-integrations fd_handoff -- --nocapture` sent a temporary file descriptor over a Unix socket pair and verified the broker-side owned fd could read `tun-fd-proof`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 audit, 7 broker, 4 cli, 7 config, 16 core, 6 dns, 5 egress, 6 flow, 20 inspect, 3 integrations, 15 packet, 23 proxy tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: `recvmsg` borrows the receive buffer through its message object, so marker bytes must be read after extracting fd/control-message data inside a narrower scope.
- What remains unproven: opening `/dev/net/tun`, creating/configuring a real TUN device, passing that real TUN fd through this channel, helper capability drop, and broker consumption of the received fd are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — Linux TUN open/ioctl fail-early slice

- Slice attempted: add the first Linux TUN device frontend primitive that opens `/dev/net/tun`, issues `TUNSETIFF`, returns an owned fd on success, and reports explicit setup errors on failure.
- Why next: fd handoff is proven, but the setup helper still cannot create the TUN fd it must hand off; a narrow TUN open/ioctl primitive addresses the highest setup risk while allowing verification to pass on hosts without effective `CAP_NET_ADMIN` by asserting fail-early diagnostics.
- Verification plan: add `foxprox-device` with typed TUN create config/errors, validate interface names, run a live `/dev/net/tun` create attempt that must either produce an owned fd or a clear open/ioctl error, then run formatting, clippy, focused device tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — Linux TUN open/ioctl fail-early

- Slice attempted: Linux-specific TUN create primitive that opens `/dev/net/tun`, issues `TUNSETIFF`, returns an owned fd on success, and reports explicit fail-early errors on unsupported/unauthorized hosts.
- Why next: fd handoff is proven, but setup still needs a real TUN fd to hand off; this establishes the ioctl-facing boundary while keeping Linux details out of broker core.
- What changed: added `crates/foxprox-device` with `TunCreateConfig`, `TunDevice`, `TunCreateError`, and `create_tun`; validates interface names, opens configurable TUN device paths, calls `TUNSETIFF` for TUN/no-PI mode, wraps the fd in `OwnedFd`, and isolates reviewed unsafe ioctl/buffer/fd conversions in the Linux device crate.
- Verification:
  - Focused check passed: `cargo test -p foxprox-device -- --nocapture` ran 3 tests covering invalid interface names, missing TUN device path open failure, and a live `/dev/net/tun` create attempt that must either succeed or report a clear open/ioctl error.
  - `cargo fmt --check` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, now including 3 `foxprox-device` tests plus the prior workspace suites.
  - Final `cargo fmt --check` passed.
- What failed or surprised the agent: the host exposes `/dev/net/tun`, but the test is written to accept either a successful transient TUN fd or an explicit permission/ioctl failure because effective `CAP_NET_ADMIN` is environment-dependent.
- What remains unproven: assigning IP/MTU, bringing the interface up, configuring routes/DNS, executing inside bwrap, capability drop, fd handoff of an actual TUN fd, and sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — setup helper TUN interface configuration commands slice

- Slice attempted: execute the setup helper's Linux `ip` command sequence for TUN MTU/link/address/default-route configuration with validation and failure diagnostics.
- Why next: TUN fd creation now exists, but alpha setup also requires assigning address/MTU, bringing the interface up, and configuring a route before traffic can reach the broker.
- Verification plan: add setup network configuration helpers in `foxprox-integrations`, run them against a fake `ip` executable that records invocations, verify exact link/address/route commands and fail-early validation/errors, then run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — setup helper TUN interface configuration commands

- Slice attempted: execute the sandbox-side `ip` command sequence needed to configure a created TUN interface.
- Why next: TUN fd creation exists, but alpha setup also requires setting MTU, bringing the interface up, assigning sandbox IP/CIDR, and adding a default route.
- What changed: `foxprox-integrations` now includes `TunInterfaceSetupConfig`, `TunInterfaceSetupError`, and `configure_tun_interface`; it validates setup inputs and runs `ip link set dev <iface> mtu <mtu> up`, `ip addr add <cidr> dev <iface>`, and `ip route add default dev <iface>` with explicit command failure/IO diagnostics.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new setup helpers/tests; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-integrations configure_tun_interface -- --nocapture` ran 3 tests using a fake `ip` executable to verify exact link/address/route command invocations, input validation before execution, and command failure diagnostics.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 6 `foxprox-integrations` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; fake executable tests provide command-boundary evidence without requiring root or mutating the host network namespace.
- What remains unproven: running these commands inside bwrap, DNS resolver file configuration, actual route effects, cleanup on partial setup failure, capability drop after setup, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — setup helper DNS resolver file slice

- Slice attempted: write the sandbox resolver configuration that points DNS traffic at the broker-controlled resolver.
- Why next: TUN interface commands are covered, but alpha setup also requires configuring DNS to the broker resolver so direct external DNS can be denied and broker DNS observations can feed attribution.
- Verification plan: add a resolv.conf writer in `foxprox-integrations`, validate resolver IP input, write deterministic nameserver/options content to a temp file, verify overwrite behavior and invalid path diagnostics, then run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — setup helper DNS resolver file

- Slice attempted: write sandbox resolver configuration that points DNS at the broker-controlled resolver.
- Why next: TUN link/address/route commands are covered, but alpha DNS attribution and direct-DNS denial require sandbox DNS to use the broker resolver.
- What changed: `foxprox-integrations` now includes `ResolverConfig`, `ResolverConfigError`, and `write_broker_resolv_conf`; it writes deterministic `resolv.conf` content with broker `nameserver` and `options ndots:0`, overwriting stale resolvers and reporting path/write errors.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new resolver config code/tests; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-integrations resolv_conf -- --nocapture` verified broker nameserver output, overwrite behavior, empty path rejection, and write failure diagnostics.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 8 `foxprox-integrations` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; writing resolver state is best kept as a narrow file-boundary helper so actual mount namespace/resolv.conf path decisions can stay in setup integration code.
- What remains unproven: binding this helper to the real sandbox `/etc/resolv.conf`, mount namespace writeability, cleanup/restoration behavior, live DNS queries through the configured resolver, and bwrap execution are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — setup sequence configure → resolver → fd handoff slice

- Slice attempted: compose the setup-helper primitives into one ordered setup sequence that configures the TUN interface, writes broker DNS resolver config, and sends the setup fd to the broker.
- Why next: TUN fd creation, interface commands, resolver writing, and fd passing are individually proven but not yet crossed in a single setup-to-broker sequence.
- Verification plan: add a Unix setup sequence helper in `foxprox-integrations`, test with a fake `ip` executable, temp resolver file, temp fd, and Unix socket pair; verify commands/files and broker-side fd receipt; verify command failure prevents fd handoff; run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — setup sequence configure → resolver → fd handoff

- Slice attempted: compose setup-helper primitives into an ordered sequence that configures the TUN interface, writes broker DNS resolver config, and hands the setup fd to the broker.
- Why next: individual setup boundaries existed, but alpha setup needs them to happen in one fail-closed sequence before target exec.
- What changed: added Unix-only `SetupSequenceConfig`, `SetupSequenceResult`, `SetupSequenceError`, and `fd_handoff::run_setup_sequence`; the sequence runs interface commands, writes resolver config, then sends the fd over SCM_RIGHTS, stopping before resolver write and fd handoff if interface setup fails.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new setup sequence code/tests; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-integrations setup_sequence -- --nocapture` verified fake `ip` command execution, resolver file content, broker-side fd receipt/readback, and fail-closed behavior that prevents resolver write/fd handoff when interface setup fails.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 10 `foxprox-integrations` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; ordering matters because sending the fd before route/DNS setup succeeds would let the broker proceed while the sandbox network is only partially configured.
- What remains unproven: real TUN fd creation feeding this sequence, execution inside bwrap, capability drop, target exec, cleanup of partially applied real network state, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — real TUN create → setup sequence handoff slice

- Slice attempted: connect the Linux TUN creation primitive to the setup sequence so a real created TUN fd can be configured and handed to the broker, while failing before commands/handoff when TUN creation fails.
- Why next: the setup sequence works with an existing fd, and device creation works independently; alpha setup needs these combined before `foxproxsetup` can be meaningful.
- Verification plan: add a Linux-only integration helper that calls `foxprox_device::create_tun` then runs the existing configure/resolver/fd-handoff sequence; verify a missing TUN path fails before fake `ip` commands, resolver writes, or fd handoff; run formatting, clippy, focused integration tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — real TUN create → setup sequence handoff

- Slice attempted: connect the Linux TUN creation primitive to the ordered setup configuration and fd handoff sequence.
- Why next: setup sequence worked only with an already-existing fd, while `foxprox-device` could create a TUN fd independently; alpha setup needs one production-shaped helper path that creates the TUN and only then configures/routes/resolver/handoff.
- What changed: `foxprox-integrations` now depends on `foxprox-device` on Linux and exposes `fd_handoff::run_linux_tun_setup_sequence`, which calls `foxprox_device::create_tun` and then runs interface configuration, resolver writing, and fd handoff. `SetupSequenceError` now distinguishes TUN creation failure from later setup failures.
- Verification:
  - `cargo fmt --check` initially failed on formatting in the new Linux setup test; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-integrations linux_tun_setup_sequence -- --nocapture` verified a missing TUN path fails at TUN creation before fake `ip` commands, resolver writes, or fd handoff.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 11 `foxprox-integrations` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; failing before any setup side effects is important because a missing/unauthorized TUN device should not leave partial routes or resolver state behind.
- What remains unproven: successful privileged TUN creation/configuration/handoff in bwrap, capability drop, target exec, broker read loop over received fd, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP flow table resource limit slice

- Slice attempted: enforce a configurable maximum number of UDP pseudo-flows so forwarding state cannot grow without bound.
- Why next: UDP flow lifecycle and expiration are implemented, but alpha robustness requires resource limits before live UDP forwarding relies on the flow table.
- Verification plan: extend `UdpFlowTable` with an optional max-flow limit, reject creation of new flows when full while allowing updates to existing flows, verify expiration frees capacity, then run formatting, clippy, focused flow tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP flow table resource limit

- Slice attempted: enforce a maximum active UDP pseudo-flow count in the flow table.
- Why next: UDP flow lifecycle and expiration are implemented, but live UDP forwarding needs resource limits to avoid unbounded flow-state growth.
- What changed: `UdpFlowTable` now carries an optional `max_flows`, exposes `with_max_flows`, and returns `UdpFlowObservation::LimitReached` when a new flow would exceed the limit; updates to existing flows are still allowed, and expiration frees capacity for later new flows.
- Verification:
  - `cargo fmt --check` initially failed on formatting for the new enum variant; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-flow udp_flow_limit -- --nocapture` verified limit rejection for a second new flow, permitted updates to the existing flow, and capacity reuse after expiration.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 7 `foxprox-flow` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the limit belongs on new-flow creation only so active flows can refresh/close cleanly even when the table is full.
- What remains unproven: loading max-flow limits from TOML, runtime action when limits are hit, audit events for resource-limit drops, TCP/proxy connection limits, and async backpressure are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TOML resource limit → UDP flow table slice

- Slice attempted: load the UDP max-flow resource limit from TOML and prove it constructs a limited `UdpFlowTable`.
- Why next: UDP flow limits exist in code, but runtime configuration cannot yet set them; alpha requires resource limits to be configurable rather than hard-coded.
- Verification plan: extend `FoxproxConfig` with resource limits, parse `[resource_limits] udp_max_flows`, reject zero values, verify the loaded limit rejects a second flow in `UdpFlowTable`, then run formatting, clippy, focused config tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TOML resource limit → UDP flow table

- Slice attempted: load the UDP max-flow resource limit from TOML and prove it constructs a limited flow table.
- Why next: `UdpFlowTable` limits existed but were not user-configurable; alpha robustness requires resource limits to come from runtime config.
- What changed: `FoxproxConfig` now includes `ResourceLimits`, parses `[resource_limits] udp_max_flows`, rejects zero values, and preserves policy-only config compatibility.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-config udp_max_flows -- --nocapture` verified a loaded max flow count rejects a second UDP flow and zero `udp_max_flows` is rejected.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 9 `foxprox-config` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the first workspace verification output was interrupted before doc tests, but rerunning `cargo test --workspace && cargo fmt --check` completed successfully.
- What remains unproven: runtime action/audit when UDP limits are hit, TCP/proxy connection limits, CLI consumption of combined runtime limits beyond tests, and async audit backpressure in live forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — UDP flow resource limit → audit slice

- Slice attempted: turn UDP flow resource-limit rejections into structured audit records so limit drops are externally visible.
- Why next: configurable UDP flow limits can reject new flows, but alpha audit/robustness requires denied traffic and resource-limit behavior to be audited rather than silently ignored.
- Verification plan: enrich `UdpFlowObservation::LimitReached` with event metadata, add an audit-record helper with denied/drop reason and byte count, verify JSON output includes `udp_flow`, denied decision, `udp-flow-limit-reached`, attempted endpoints, and limit metadata; run formatting, clippy, focused flow/audit tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — UDP flow resource limit → audit

- Slice attempted: turn UDP flow resource-limit rejections into structured audit records.
- Why next: configurable UDP flow limits could reject new flows but did not provide external evidence; alpha robustness requires denied/dropped traffic to be audited.
- What changed: `UdpFlowObservation::LimitReached` now carries `UdpFlowLimitRejection` metadata with sandbox/frontend/endpoints/classification/attribution/limit/bytes/time, and `UdpFlowLimitRejection::audit_record` emits a denied/drop `udp_flow` record with reason `udp-flow-limit-reached`. Integration tests now use unique temp paths to avoid parallel fake-executable collisions discovered during workspace verification.
- Verification:
  - `cargo fmt --check` initially failed on formatting in `foxprox-flow`; `cargo fmt` was run.
  - Focused checks passed: `cargo test -p foxprox-flow udp_flow_limit -- --nocapture` verified both limit behavior and JSON denial audit output; `cargo test -p foxprox-config udp_max_flows -- --nocapture` verified TOML-loaded limits still construct limited flow tables.
  - First workspace test run exposed a parallel-test temp path collision/Text-file-busy in integration fake `ip` scripts; tests were updated to use unique temp paths.
  - `cargo test -p foxprox-integrations -- --nocapture` passed after the temp-path fix.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed: 3 audit, 7 broker, 4 cli, 9 config, 16 core, 3 device, 6 dns, 5 egress, 8 flow, 20 inspect, 11 integrations, 15 packet, 23 proxy tests, and doc tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: fake executable paths based only on process id can collide under parallel tests; include a time-based unique suffix for temp paths.
- What remains unproven: runtime sink emission when a live UDP packet hits the limit, TCP/proxy connection limits, configurable audit/backpressure behavior under load, and live UDP forwarding are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — received fd → packet IO adapter slice

- Slice attempted: wrap an owned setup-received fd in a broker-facing packet IO adapter that can read inbound packet bytes and write outbound packet bytes.
- Why next: setup fd handoff is proven, but broker consumption of the received fd is still absent; a narrow fd-backed packet IO adapter connects setup handoff to the existing packet broker/write-back boundary.
- Verification plan: add `TunPacketIo` to `foxprox-device`, test it over a Unix stream fd stand-in by reading inbound bytes and writing outbound bytes across the fd boundary, then run formatting, clippy, focused device tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — received fd → packet IO adapter

- Slice attempted: wrap an owned setup-received fd in a broker-facing packet IO adapter for reading inbound packet bytes and writing outbound packet bytes.
- Why next: setup fd handoff and packet broker/write-back were proven separately; broker runtime still needed a narrow fd-backed IO boundary for consuming the received TUN fd.
- What changed: `foxprox-device` now exposes `TunPacketIo` and `TunIoError`; it accepts an `OwnedFd`, validates maximum packet length, reads one packet-sized byte buffer, writes outbound packet bytes, and rejects oversized writes before touching the fd.
- Verification:
  - `cargo fmt --check` initially failed on formatting in `foxprox-device`; `cargo fmt` was run.
  - Focused check passed: `cargo test -p foxprox-device tun_packet_io -- --nocapture` verified inbound read and outbound write across a Unix stream fd stand-in plus oversized packet rejection.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 4 `foxprox-device` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; a Unix stream fd is enough for packet IO boundary evidence while real TUN fd behavior remains covered by the TUN create primitive.
- What remains unproven: wiring `TunPacketIo` to the broker loop, continuous TUN read/write scheduling, received real TUN fd from bwrap setup, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — TUN fd packet IO → broker/audit/write-back slice

- Slice attempted: process one packet directly from a TUN-like fd adapter through config, broker policy/audit, and write synthesized outbound packets back to the fd.
- Why next: `TunPacketIo` can read/write a received fd and `packet-once` can process in-memory bytes, but the broker runtime still lacks an fd-to-broker-to-fd proof.
- Verification plan: add a CLI/runtime helper that reads one packet from `TunPacketIo`, runs `IpPacketBroker`, serializes audit JSON, writes outbound reply packets to the same fd, and verifies over a Unix stream fd stand-in using an ICMP echo request; run formatting, clippy, focused CLI tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — TUN fd packet IO → broker/audit/write-back

- Slice attempted: process one packet directly from a TUN-like fd adapter through config, broker policy/audit, and write synthesized outbound packets back to the same fd.
- Why next: `TunPacketIo` and in-memory `packet-once` processing were separate; broker runtime needed an fd-to-broker-to-fd proof for received setup fds.
- What changed: `foxprox-cli` now depends on `foxprox-device` and exposes `process_tun_io_once`, which reads one packet from `TunPacketIo`, runs existing TOML policy and `IpPacketBroker`, serializes audit JSON, and writes any synthesized reply packet bytes back through `TunPacketIo`.
- Verification:
  - Focused check passed: `cargo test -p foxprox-cli tun_io_once -- --nocapture` verified an ICMP echo request sent over a Unix stream fd stand-in produced allowed JSON audit and wrote an ICMP echo reply back to the fd peer.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 5 `foxprox-cli` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the existing packet-once core was reusable once fd IO was isolated in the device crate.
- What remains unproven: continuous TUN event loop, real received TUN fd from bwrap setup, packet batching/MTU behavior, and live sandbox ping are still absent.
- Commit: this commit.

## 2026-06-21 Session Continue — bounded TUN fd packet loop slice

- Slice attempted: process multiple packets from the TUN fd adapter in a bounded loop, emitting audit for each packet and writing replies back to the fd.
- Why next: one-shot TUN fd processing works, but a broker runtime needs repeated packet handling; a bounded deterministic loop is the smallest step before long-running scheduling.
- Verification plan: add `process_tun_io_packets` with an explicit packet limit, test two ICMP echo datagrams over a Unix datagram fd stand-in and verify two audit lines plus two reply packets, then run formatting, clippy, focused CLI tests, and workspace tests.
- Commit: pending.

## 2026-06-21 Slice Evidence — bounded TUN fd packet loop

- Slice attempted: process multiple packets from the TUN fd adapter in a bounded loop, emitting audit for each packet and writing replies back to the fd.
- Why next: one-shot TUN fd processing works, but broker runtime needs repeated packet handling before a long-running scheduler can be trusted.
- What changed: `process_tun_io_once` now delegates to new `process_tun_io_packets`, which loops up to an explicit packet limit, stops on empty reads, collects per-packet summaries, and writes each synthesized reply through `TunPacketIo`.
- Verification:
  - Focused check passed: `cargo test -p foxprox-cli tun_io_packet_loop -- --nocapture` verified two ICMP echo datagrams over a Unix datagram fd stand-in produced two allowed JSON audit summaries and two echo replies.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 6 `foxprox-cli` tests and all existing workspace tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: stream fds are fine for one-shot IO, but datagram fds better preserve packet boundaries for multi-packet tests.
- What remains unproven: unbounded/long-running runtime scheduling, graceful shutdown, real TUN fd readiness, and live sandbox traffic are still absent.
- Commit: this commit.

## 2026-06-22 Session Continue — executable foxproxsetup command slice

- Slice attempted: implement a real `foxproxsetup` command contract that connects to a broker Unix socket, configures sandbox TUN networking, writes resolver config, hands the TUN fd to the broker, and then execs the target in production shape.
- Why next: bwrap planning, TUN create/configuration, fd handoff, and broker fd consumption were proven as library slices, but Milestone 0 still needs an executable setup-helper boundary.
- Verification plan: add a `foxproxsetup` binary and CLI setup subcommand, parse the minimal documented setup arguments, expose a test seam that injects a TUN-like fd, prove fd handoff and resolver/ip-command ordering with a broker Unix listener and fake `ip`, then run focused tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — executable foxproxsetup command

- Slice attempted: implement a real `foxproxsetup` command contract that connects to the broker Unix socket, configures sandbox TUN networking, writes resolver config, hands the TUN fd to the broker, and execs the target in production shape.
- Why next: bwrap planning, TUN create/configuration, fd handoff, and broker fd consumption were proven as library slices; Milestone 0 still needed an executable setup-helper boundary.
- What changed: `foxprox-cli` now builds a standalone `foxproxsetup` binary and accepts a `setup` subcommand. The setup parser accepts `--broker-socket`, `--tun-name`, `--tun-device`, `--address-cidr`, `--mtu`, `--resolv-conf`, `--broker-dns`, `--ip-program`, and `-- TARGET...`. The Linux production path creates the TUN fd, runs the existing setup sequence, closes setup-side TUN state, and `exec`s the target. A test seam runs the same setup sequence with an injected TUN-like fd.
- Verification:
  - Focused check passed: `cargo test -p foxprox-cli setup_ -- --nocapture` verified documented argument parsing and end-to-end setup command behavior with a broker Unix listener, fake `ip`, resolver file write, SCM_RIGHTS fd handoff, and broker-side `TunPacketIo` read/write over the received fd.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including the new `foxproxsetup` binary test target and 8 `foxprox-cli` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: `AsRawFd` bounds were simpler and clearer as an explicit `RawFd` test seam; clippy also required removing a needless `return` in the Linux-only setup entrypoint.
- What remains unproven: actual privileged bwrap execution, `/dev/net/tun` creation inside a bwrap net namespace, capability drop before target exec, and live sandbox packet logs are still absent.
- Commit: this commit.

## 2026-06-22 Session Continue — setup helper drops CAP_NET_ADMIN before exec slice

- Slice attempted: make the executable setup helper drop sandbox network setup capability before it execs the target.
- Why next: `foxproxsetup` now exists and can hand off a TUN fd, but Milestone 0 still explicitly requires that `CAP_NET_ADMIN` not remain available to the target process.
- Verification plan: add a Linux capability helper that clears `CAP_NET_ADMIN` from effective/permitted/inheritable sets, call it between setup fd handoff and target exec, unit-test the pure capability-set mutation, then run focused integration/CLI tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — setup helper drops CAP_NET_ADMIN before exec

- Slice attempted: make the executable setup helper drop sandbox network setup capability before it execs the target.
- Why next: `foxproxsetup` can now hand off a TUN fd, but Milestone 0 explicitly requires that `CAP_NET_ADMIN` not remain available to the target process.
- What changed: `foxprox-integrations` now has a Linux capability helper that reads current capability sets with `capget`, clears `CAP_NET_ADMIN` from effective/permitted/inheritable sets with `capset`, and verifies the capability is gone. `foxproxsetup` calls this helper after fd handoff and setup-side TUN fd close, immediately before target `exec`.
- Verification:
  - Focused check passed: `cargo test -p foxprox-integrations capability_sets -- --nocapture` verified the pure capability-set mutation clears `CAP_NET_ADMIN` from all current-process sets while leaving other slots untouched.
  - Focused setup command checks still passed: `cargo test -p foxprox-cli setup_ -- --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 12 `foxprox-integrations` tests and 8 `foxprox-cli` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the `libc` crate does not expose the Linux capability structs/constants used here, so the helper defines the small `repr(C)` `capget/capset` layouts and `CAP_NET_ADMIN = 12` directly.
- What remains unproven: a privileged live run proving `capget/capset` succeeds inside the bwrap setup context, and live target process evidence that `CAP_NET_ADMIN` is absent after exec.
- Commit: this commit.

## 2026-06-22 Session Continue — bwrap plan passes foxproxsetup args slice

- Slice attempted: update the bwrap launch plan so the executable `foxproxsetup` command receives the broker socket and network setup arguments it now requires.
- Why next: `foxproxsetup` has a real parser, but the existing bwrap plan still only inserted `foxproxsetup -- target...`, which would fail in a real launch.
- Verification plan: add a reusable setup-helper argument planner to `foxprox-integrations`, thread it into `BwrapSetupConfig`, prove arguments appear before the target `--` separator, then run focused integration tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — bwrap plan passes foxproxsetup args

- Slice attempted: update the bwrap launch plan so the executable `foxproxsetup` command receives the broker socket and network setup arguments it now requires.
- Why next: `foxproxsetup` has a real parser, but the existing bwrap plan still only inserted `foxproxsetup -- target...`, which would fail in a real launch.
- What changed: `foxprox-integrations` now has `SetupHelperArgs` for the broker socket, TUN name/device, address, MTU, resolver path, broker DNS, and `ip` program. `BwrapSetupConfig` can carry those args and `plan_bwrap_setup` inserts them after the setup helper path and before the target `--` separator.
- Verification:
  - Focused check passed: `cargo test -p foxprox-integrations bwrap_plan -- --nocapture` verified legacy planning still works and the configured setup-helper args appear before the target separator.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 13 `foxprox-integrations` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the executable setup command made an existing integration gap visible immediately: bwrap planning and setup parser had drifted apart.
- What remains unproven: a host launcher that binds the broker socket, starts bwrap, receives the TUN fd, and feeds it into the broker packet loop is still absent; live bwrap/TUN execution remains unproven.
- Commit: this commit.

## 2026-06-22 Live Evidence — bwrap foxproxsetup creates TUN, hands fd, drops cap, and logs sandbox packets

- Slice attempted: run the newly implemented `foxproxsetup` inside a real bwrap user/network namespace and prove the broker side receives a live TUN fd with target-generated packets.
- Why next: the setup command, capability drop, bwrap planning, and fd IO paths were tested independently; Milestone 0 needed live environment evidence.
- Commands/evidence:
  - Built the helper: `cargo build -p foxprox-cli --bin foxproxsetup`.
  - Ran `bwrap --unshare-user --unshare-net --cap-add CAP_NET_ADMIN --dev-bind / / --dev-bind /dev/net/tun /dev/net/tun target/debug/foxproxsetup ... -- /bin/sh -c "capsh --print | grep '^Current:' > cap.log"` with a Python broker socket receiving SCM_RIGHTS. Evidence: broker log `marker=b'foxprox-fd'`, resolver file generated, and target cap log `Current: =` after exec.
  - Ran the same bwrap/setup path with target `/usr/bin/python3 -c "import socket; ... sendto(b'hi', ('10.125.0.1', 5353))"`. The Python broker listener received the setup fd and read a packet from TUN: `packet_len=30`, `packet_hex=4500001e2bcd40004011fa050a7d00020a7d0001d05e14e9000a9d2c6869` (IPv4 UDP from 10.125.0.2 to 10.125.0.1 containing `hi`).
- What failed or surprised the agent: `ping` after capability drop failed because the target no longer had raw-socket capability (`missing cap_net_raw+p`), but a normal UDP socket from Python generated a clean TUN packet and better matches the target-without-setup-caps requirement.
- What this proves: bwrap can grant temporary `CAP_NET_ADMIN` to `foxproxsetup`; `/dev/net/tun` is usable; setup creates/configures TUN and route; resolver config is written; fd handoff works across the process boundary; setup drops capabilities before exec; and target traffic appears on the broker's received TUN fd.
- What remains unproven: broker process automation around launching bwrap, continuous packet processing of the live received fd, synthetic reply write-back into the live namespace, and TCP forwarding via a userspace stack.
- Commit: this evidence-only commit.

## 2026-06-22 Session Continue — broker control listener for setup fd slice

- Slice attempted: replace ad-hoc broker-side setup socket handling with a reusable Rust control listener that binds the setup socket and accepts the `foxproxsetup` fd handoff.
- Why next: live evidence used a Python listener; the host-side broker/launcher still needs a first-class Rust boundary for receiving the setup fd before feeding it to `TunPacketIo`.
- Verification plan: add a broker control listener to the fd handoff module, test bind/connect/SCM_RIGHTS receive with a TUN-like fd stand-in, then run focused integration tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — broker control listener for setup fd

- Slice attempted: replace ad-hoc broker-side setup socket handling with a reusable Rust control listener that binds the setup socket and accepts the `foxproxsetup` fd handoff.
- Why next: live evidence used a Python listener; the host-side broker/launcher still needed a first-class Rust boundary for receiving the setup fd before feeding it to `TunPacketIo`.
- What changed: `foxprox-integrations::fd_handoff` now exposes `BrokerControlListener` and `BrokerControlError`. The listener binds a Unix socket path, reports its path for setup-helper args, accepts one setup connection, and returns the received `OwnedFd` via the existing SCM_RIGHTS validation path.
- Verification:
  - Focused check passed: `cargo test -p foxprox-integrations broker_control -- --nocapture` verified bind/connect/SCM_RIGHTS receive with a TUN-like fd stand-in and confirmed the broker side can read from the received fd.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 14 `foxprox-integrations` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the fd stand-in must be opened read/write before handoff; a write-only file descriptor transfers successfully but fails broker-side readback.
- What remains unproven: spawning bwrap from a Rust launcher while the listener is active, and directly connecting the accepted live TUN fd to the broker packet loop in-process.
- Commit: this commit.

## 2026-06-22 Session Continue — codify live bwrap setup smoke test slice

- Slice attempted: turn the manual live bwrap/foxproxsetup proof into an ignored Rust smoke test that future developers can run explicitly.
- Why next: live setup evidence is valuable but easy to lose if it only lives in `progress.md`; an ignored test preserves the exact proof shape without making default workspace tests depend on bwrap/user namespaces.
- Verification plan: add an ignored Linux integration test that runs `foxproxsetup` inside bwrap, sends UDP from the target namespace, receives the TUN fd on the Rust broker control listener, and reads the target-generated packet; run the ignored test explicitly plus default workspace checks.
- Commit: pending.

## 2026-06-22 Slice Evidence — codified live bwrap setup smoke test

- Slice attempted: turn the manual live bwrap/foxproxsetup proof into an ignored Rust smoke test that future developers can run explicitly.
- Why next: live setup evidence is valuable but easy to lose if it only lives in `progress.md`; an ignored test preserves the exact proof shape without making default workspace tests depend on bwrap/user namespaces.
- What changed: added `crates/foxprox-cli/tests/live_bwrap_setup.rs`, an ignored Linux integration test that runs `foxproxsetup` inside bwrap with temporary `CAP_NET_ADMIN`, sends UDP from the target namespace, receives the setup fd on the Rust `BrokerControlListener`, and reads the target-generated IPv4 UDP packet from `TunPacketIo`.
- Verification:
  - Explicit live smoke passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed; the live smoke test compiled and was reported ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the prior manual proof translated cleanly once the Rust broker control listener existed.
- What remains unproven: live write-back/reply into the bwrap namespace and TCP forwarding through a userspace stack.
- Commit: this commit.

## 2026-06-22 Session Continue — live TUN write-back smoke slice

- Slice attempted: extend the live bwrap setup smoke test from ingress-only packet logging to broker write-back into the sandbox namespace.
- Why next: Milestone 0 live setup is proven, and in-memory/fd-stand-in packet write-back is proven; the remaining Milestone 1 gap is a live packet written by the broker back through the bwrap-created TUN fd and received by a target process.
- Verification plan: have the ignored live smoke test target send UDP and wait for a reply; have the broker thread parse the inbound IPv4 UDP packet, synthesize a minimal IPv4/UDP response, write it to `TunPacketIo`, then assert the target exits successfully and the original packet was observed. Run the ignored live test explicitly plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — live TUN write-back smoke

- Slice attempted: extend the live bwrap setup smoke test from ingress-only packet logging to broker write-back into the sandbox namespace.
- Why next: Milestone 0 live setup was proven, and in-memory/fd-stand-in packet write-back was proven; the remaining Milestone 1 gap was a live packet written by the broker back through the bwrap-created TUN fd and received by a target process.
- What changed: the ignored live bwrap smoke test now has the target Python process send UDP and wait for a response. The broker test thread parses the inbound IPv4 UDP packet from `TunPacketIo`, synthesizes a minimal IPv4/UDP response with payload `ok`, writes it back through the same TUN fd, and the target exits successfully only if it receives `ok`.
- Verification:
  - Explicit live smoke passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed; the live smoke test remains compiled but ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: IPv4 UDP checksum can be zero for this smoke path, so the minimal response only needs a correct IPv4 header checksum to reach the target socket through TUN.
- What this proves: in a real bwrap namespace, broker-side code can receive the live TUN fd, read target traffic, write an IP packet back to the same fd, and have the unprivileged target process receive it.
- What remains unproven: production broker integration for live TUN packet loops, DNS/UDP forwarding semantics through live TUN, and TCP forwarding via a userspace stack.
- Commit: this commit.

## 2026-06-22 Session Continue — reusable IPv4 UDP write-back builder slice

- Slice attempted: promote the live-smoke-only IPv4 UDP response builder into the packet crate so UDP/TUN forwarding can reuse it.
- Why next: the live write-back proof worked, but its packet synthesis lived inside an ignored test; production UDP forwarding needs reusable, tested packet construction outside test code.
- Verification plan: add a public IPv4 UDP response builder with parser validation and checksum tests in `foxprox-packet`, update the live bwrap smoke test to use it, then run focused packet/live tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — reusable IPv4 UDP write-back builder

- Slice attempted: promote the live-smoke-only IPv4 UDP response builder into the packet crate so UDP/TUN forwarding can reuse it.
- Why next: the live write-back proof worked, but its packet synthesis lived inside an ignored test; production UDP forwarding needs reusable, tested packet construction outside test code.
- What changed: `foxprox-packet` now exposes `synthesize_ipv4_udp_response`, which validates a received IPv4 UDP datagram, reverses IPv4 addresses and UDP ports, inserts a response payload, computes the IPv4 header checksum, and leaves the IPv4 UDP checksum at zero. The live bwrap smoke test now uses this production packet builder instead of local helper code.
- Verification:
  - Focused packet checks passed: `cargo test -p foxprox-packet udp_response -- --nocapture`.
  - Explicit live smoke still passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 17 `foxprox-packet` tests and the ignored live smoke compiled by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; moving the helper clarified that IPv4 UDP write-back is a packet primitive, not just live-test glue.
- What remains unproven: forwarding a TUN UDP payload through a host UDP egress socket and writing the host response back through TUN.
- Commit: this commit.

## 2026-06-22 Session Continue — TUN UDP datagram → host UDP egress response slice

- Slice attempted: forward one parsed TUN IPv4 UDP datagram through the host UDP egress backend and synthesize the host response back into an IPv4 UDP packet for TUN write-back.
- Why next: live TUN ingress/write-back and reusable UDP response synthesis are proven; Milestone 4 still needs an unfiltered UDP forwarding proof through host sockets.
- Verification plan: expose a packet-level IPv4 UDP datagram parser, add a runtime helper that sends the UDP payload through `UdpEgress`, receives one response, and builds a TUN response packet; prove it against a loopback UDP server, then run focused tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — TUN UDP datagram → host UDP egress response

- Slice attempted: forward one parsed TUN IPv4 UDP datagram through the host UDP egress backend and synthesize the host response back into an IPv4 UDP packet for TUN write-back.
- Why next: live TUN ingress/write-back and reusable UDP response synthesis were proven; Milestone 4 still needed an unfiltered UDP forwarding proof through host sockets.
- What changed: `foxprox-packet` now exposes `Ipv4UdpDatagram` and `parse_ipv4_udp_datagram`. `foxprox-cli` now has `forward_ipv4_udp_packet_once`, which parses an IPv4 UDP packet, sends the payload through `UdpEgress`, receives one host response, and uses `synthesize_ipv4_udp_response` to build the TUN response packet.
- Verification:
  - Focused packet checks passed: `cargo test -p foxprox-packet ipv4_udp -- --nocapture`.
  - Focused forwarding check passed: `cargo test -p foxprox-cli udp_packet_once -- --nocapture`, proving payload `hello` reached a loopback UDP server and response `world` became a reversed IPv4 UDP packet for the sandbox.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 18 `foxprox-packet` tests and 9 `foxprox-cli` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the existing `HostUdpEgress` backend was enough once packet parsing/response building were available as primitives.
- What remains unproven: wiring this forwarding helper to `TunPacketIo` and proving it live through the bwrap-created TUN fd.
- Commit: this commit.

## 2026-06-22 Session Continue — TUN fd UDP forwarding helper slice

- Slice attempted: wire the one-packet UDP egress helper directly to `TunPacketIo`, reading one packet from a TUN-like fd and writing the synthesized UDP response back.
- Why next: UDP forwarding through host egress is proven for in-memory packets, but runtime code needs the fd-backed read/write boundary to use it.
- Verification plan: add `forward_tun_udp_packet_once`, test it over a Unix datagram fd stand-in with a loopback UDP server, then run focused CLI tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — TUN fd UDP forwarding helper

- Slice attempted: wire the one-packet UDP egress helper directly to `TunPacketIo`, reading one packet from a TUN-like fd and writing the synthesized UDP response back.
- Why next: UDP forwarding through host egress was proven for in-memory packets, but runtime code needs the fd-backed read/write boundary to use it.
- What changed: `foxprox-cli` now exposes `forward_tun_udp_packet_once`, which reads one packet from `TunPacketIo`, forwards its UDP payload through `UdpEgress`, builds a response packet, writes it back to the same fd, and returns the response bytes for evidence/logging.
- Verification:
  - Focused check passed: `cargo test -p foxprox-cli tun_udp_forwarding -- --nocapture`, using a Unix datagram fd stand-in plus loopback UDP upstream; payload `from-tun` reached host UDP egress and response `to-tun` was written back to the fd peer as a reversed IPv4 UDP packet.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 10 `foxprox-cli` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; datagram fd stand-ins continue to be the simplest way to prove packet boundaries around TUN-like IO.
- What remains unproven: the same helper running against the live bwrap-created TUN fd with a real target socket and host UDP upstream.
- Commit: this commit.

## 2026-06-22 Session Continue — live bwrap UDP forwarding through host egress slice

- Slice attempted: upgrade the live bwrap smoke test so target UDP traffic is forwarded through a host UDP socket before the broker writes the response back through TUN.
- Why next: fd-backed UDP forwarding is proven with stand-ins; Milestone 4 needs the same behavior against a live bwrap-created TUN fd and unprivileged target socket.
- Verification plan: add a loopback host UDP upstream to the ignored live smoke test, have the broker thread read the live TUN packet and call the production UDP forwarding helper, then assert the target receives the upstream response. Run the ignored live test explicitly plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — live bwrap UDP forwarding through host egress

- Slice attempted: upgrade the live bwrap smoke test so target UDP traffic is forwarded through a host UDP socket before the broker writes the response back through TUN.
- Why next: fd-backed UDP forwarding was proven with stand-ins; Milestone 4 needed the same behavior against a live bwrap-created TUN fd and unprivileged target socket.
- What changed: the ignored live bwrap smoke now starts a loopback host UDP upstream. The broker thread reads packets from the live received TUN fd, uses the production `forward_ipv4_udp_packet_once` helper to send payload `hi` to host UDP egress, receives upstream payload `ok`, writes the synthesized IPv4 UDP packet back to TUN, and the bwrap target Python socket exits successfully only after receiving `ok`.
- Verification:
  - Explicit live smoke passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed; the live smoke remains ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the helper could run live once the broker thread skipped non-UDP packets by retrying until forwarding succeeded.
- What this proves: a target inside a real bwrap network namespace can send UDP through TUN, the broker can forward the payload to a host UDP socket, and the target can receive the host response through TUN.
- What remains unproven: long-running UDP flow table integration/live multi-flow behavior, DNS policy integration over live TUN, and TCP forwarding via a userspace stack.
- Commit: this commit.

## 2026-06-22 Session Continue — TUN DNS packet → broker DNS handler slice

- Slice attempted: connect IPv4 UDP packets from TUN to the existing DNS broker handler and synthesize DNS responses back into IPv4 UDP packets.
- Why next: generic UDP forwarding works live, but DNS has policy/audit/cache semantics that should not be bypassed by raw UDP forwarding.
- Verification plan: add a DNS crate helper that parses a TUN IPv4 UDP packet, calls `DnsBrokerDatagramHandler`, records DNS answers, and wraps the DNS response in an IPv4 UDP response packet. Prove allowed forwarding/cache and denied REFUSED response paths, then run focused DNS tests plus workspace checks.
- Commit: pending.

## 2026-06-22 Slice Evidence — TUN DNS packet → broker DNS handler

- Slice attempted: connect IPv4 UDP packets from TUN to the existing DNS broker handler and synthesize DNS responses back into IPv4 UDP packets.
- Why next: generic UDP forwarding works live, but DNS has policy/audit/cache semantics that should not be bypassed by raw UDP forwarding.
- What changed: `foxprox-dns` now depends on `foxprox-packet` and exposes `handle_tun_dns_packet`. It parses an IPv4 UDP packet from TUN, derives the sandbox UDP source endpoint, calls `DnsBrokerDatagramHandler`, records DNS answers through the existing cache path, and wraps allowed/denied DNS responses in synthesized IPv4 UDP response packets for TUN write-back.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-dns tun_dns_packet -- --nocapture`, proving both allowed upstream forwarding/cache recording and denied REFUSED response wrapping without egress.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 8 `foxprox-dns` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the DNS cache constructor takes no TTL argument; TTL handling is internal to recorded DNS answers.
- What remains unproven: live bwrap DNS query through the TUN DNS handler and integration of DNS attribution with later live TCP/UDP flows.
- Commit: this commit.

## 2026-06-22 Session Continue — live bwrap DNS-over-TUN handler slice

- Slice attempted: prove a target DNS query inside bwrap travels through the live TUN fd into the DNS broker handler, through host UDP upstream, and back to the target as a DNS response packet.
- Why next: `handle_tun_dns_packet` is unit-proven; live generic UDP forwarding is proven; DNS policy/cache behavior still needs live TUN evidence.
- Verification plan: add an ignored live DNS smoke using `DnsBrokerDatagramHandler`, fake host UDP DNS upstream, and bwrap target Python DNS query to the broker-side TUN IP. Run it explicitly plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — live bwrap DNS-over-TUN handler

- Slice attempted: prove a target DNS query inside bwrap travels through the live TUN fd into the DNS broker handler, through host UDP upstream, and back to the target as a DNS response packet.
- Why next: `handle_tun_dns_packet` was unit-proven; live generic UDP forwarding was proven; DNS policy/cache behavior still needed live TUN evidence.
- What changed: the ignored live bwrap test file now includes a second smoke test that starts a fake host DNS UDP upstream, runs bwrap/`foxproxsetup`, has target Python send a DNS A query to the broker-side TUN IP, routes the live TUN packet through `DnsBrokerDatagramHandler`, writes the synthesized DNS response packet back through TUN, and asserts the target received a NOERROR response containing the expected A record.
- Verification:
  - Explicit live smoke passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture` with both live tests passing.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed; both live bwrap tests compile and remain ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; direct Python DNS packet construction kept the target unprivileged and avoided relying on system resolver behavior inside bwrap.
- What this proves: live bwrap/TUN DNS traffic can use the actual DNS broker policy/cache/forwarding path, not just raw UDP forwarding.
- What remains unproven: live attribution of a later non-DNS flow using the DNS cache, and TCP forwarding through a userspace stack.
- Commit: this commit.

## 2026-06-22 Session Continue — smoltcp raw-IP device SYN/SYN-ACK slice

- Slice attempted: introduce the first smoltcp integration proof by feeding one raw IPv4 TCP SYN packet into a raw-IP smoltcp device and capturing the emitted SYN-ACK packet for TUN write-back.
- Why next: Milestones 0/1 and UDP/DNS live paths now have evidence; the next alpha gate is the smoltcp TCP forwarding path. The smallest useful slice is proving a TUN-shaped IP packet can enter smoltcp and produce outbound IP bytes.
- Verification plan: add a `foxprox-tcp` crate with an in-memory smoltcp `Device` using `Medium::Ip`, test a listening TCP socket receives a crafted SYN and emits a SYN-ACK, then run focused tcp tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — smoltcp raw-IP device SYN/SYN-ACK

- Slice attempted: introduce the first smoltcp integration proof by feeding one raw IPv4 TCP SYN packet into a raw-IP smoltcp device and capturing the emitted SYN-ACK packet for TUN write-back.
- Why next: Milestones 0/1 and UDP/DNS live paths now have evidence; the next alpha gate is the smoltcp TCP forwarding path. The smallest useful slice is proving a TUN-shaped IP packet can enter smoltcp and produce outbound IP bytes.
- What changed: added `crates/foxprox-tcp` with an in-memory smoltcp `Device` using `Medium::Ip`. The device queues inbound raw IP packets and captures outbound raw IP packets, giving a deterministic adapter shape for future `TunPacketIo` integration.
- Verification:
  - Focused check passed: `cargo test -p foxprox-tcp -- --nocapture`. The test fed a crafted IPv4 TCP SYN from 10.0.0.2:49152 to 10.0.0.1:8080 into a listening smoltcp TCP socket and asserted smoltcp emitted an IPv4 SYN-ACK from 10.0.0.1:8080 back to 10.0.0.2:49152.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including the new `foxprox-tcp` crate test and doc test.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: `DeviceCapabilities` is non-exhaustive in smoltcp, so the implementation must mutate `DeviceCapabilities::default()` rather than constructing it with a struct literal.
- What remains unproven: smoltcp stream accept/read/write bridging to host TCP sockets, live TUN fd device integration, and full sandbox `curl` forwarding.
- Commit: this commit.

## 2026-06-22 Session Continue — smoltcp handshake payload receive slice

- Slice attempted: extend the smoltcp proof from SYN/SYN-ACK to an established TCP socket receiving client payload bytes after handshake.
- Why next: SYN/SYN-ACK proves raw packet ingress/egress, but TCP forwarding requires stream data extraction before host bridging can be added.
- Verification plan: feed SYN, capture server sequence from SYN-ACK, feed ACK+payload from the client, poll smoltcp, and assert the listening socket can read the payload. Run focused tcp tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — smoltcp handshake payload receive

- Slice attempted: extend the smoltcp proof from SYN/SYN-ACK to an established TCP socket receiving client payload bytes after handshake.
- Why next: SYN/SYN-ACK proves raw packet ingress/egress, but TCP forwarding requires stream data extraction before host bridging can be added.
- What changed: `foxprox-tcp` now tests a full minimal client-to-smoltcp handshake progression: feed SYN, capture the server sequence from smoltcp's SYN-ACK, feed ACK+PSH payload from the client, poll smoltcp, and read payload bytes from the accepted socket.
- Verification:
  - Focused check passed: `cargo test -p foxprox-tcp -- --nocapture`, with `smoltcp_socket_receives_payload_after_handshake` proving the socket receives `hello`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 2 `foxprox-tcp` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; smoltcp accepted a minimal ACK+PSH packet once the test echoed back the server sequence from SYN-ACK.
- What remains unproven: sending data from smoltcp back to the sandbox after host egress response, and bridging accepted socket payloads to real host TCP streams.
- Commit: this commit.

## 2026-06-22 Session Continue — smoltcp socket send emits outbound payload slice

- Slice attempted: prove data written into an established smoltcp socket becomes outbound raw IP packet bytes for TUN write-back.
- Why next: smoltcp can now receive stream payload from raw packets; TCP forwarding also needs host response bytes to be sent back toward the sandbox.
- Verification plan: after the existing handshake/payload receive proof, write `world` to the smoltcp socket, poll, capture TX packets, and assert an outbound TCP packet carries `world` back to the client tuple. Run focused tcp tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — smoltcp socket send emits outbound payload

- Slice attempted: prove data written into an established smoltcp socket becomes outbound raw IP packet bytes for TUN write-back.
- Why next: smoltcp could receive stream payload from raw packets; TCP forwarding also needs host response bytes to be sent back toward the sandbox.
- What changed: extended the smoltcp handshake test to write `world` into the established socket after reading client payload `hello`, poll smoltcp, and assert the captured outbound raw IP packet carries `world` back to the client tuple.
- Verification:
  - Focused check passed: `cargo test -p foxprox-tcp -- --nocapture`, with the renamed `smoltcp_socket_receives_and_sends_payload_after_handshake` proving both receive and send directions.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 2 `foxprox-tcp` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; clearing ACK-only TX packets before writing response bytes made the payload-carrying packet assertion deterministic.
- What remains unproven: host TCP socket bridging and live TUN fd integration for smoltcp.
- Commit: this commit.

## 2026-06-22 Session Continue — smoltcp payload → host TCP relay slice

- Slice attempted: bridge one received smoltcp TCP payload to a host TCP stream and send the host response back through smoltcp.
- Why next: smoltcp can receive and emit payload bytes; the alpha TCP gate next requires opening host TCP sockets and moving bytes between smoltcp streams and host sockets.
- Verification plan: add a one-shot relay helper that drains available smoltcp socket bytes to a `Read+Write` host stream, reads one host response, sends it into the smoltcp socket, and prove it with a loopback TCP server plus raw-packet smoltcp handshake. Run focused tcp tests plus workspace checks.
- Commit: pending.

## 2026-06-22 Slice Evidence — smoltcp payload → host TCP relay

- Slice attempted: bridge one received smoltcp TCP payload to a host TCP stream and send the host response back through smoltcp.
- Why next: smoltcp can receive and emit payload bytes; the alpha TCP gate next requires opening host TCP sockets and moving bytes between smoltcp streams and host sockets.
- What changed: `foxprox-tcp` now exposes `relay_tcp_socket_once`, which drains one available smoltcp TCP payload into any `Read + Write` host stream, reads one host response, sends that response back through the smoltcp socket, and returns directional byte counts.
- Verification:
  - Focused check passed: `cargo test -p foxprox-tcp -- --nocapture`. The smoltcp handshake test now relays `hello` to a loopback host TCP server, reads `world`, sends `world` back through smoltcp, polls, and asserts the outbound raw IP packet contains `world` for the sandbox tuple.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 2 `foxprox-tcp` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; a `Read + Write` host abstraction keeps the first relay helper independent of concrete egress configuration while still proving host socket bridging.
- What remains unproven: live TUN fd integration for smoltcp and a long-running TCP bridge loop.
- Commit: this commit.

## 2026-06-22 Session Continue — live bwrap smoltcp TCP forwarding slice

- Slice attempted: prove a real bwrap target TCP connection can traverse the received TUN fd, enter smoltcp, relay payload to a host TCP socket, and receive the host response through TUN.
- Why next: smoltcp host-stream relay is unit-proven; the remaining high-risk TCP gate is live TUN integration.
- Verification plan: expose a small `SmoltcpTcpServer` wrapper in `foxprox-tcp`, add an ignored live bwrap TCP smoke using target Python `socket.connect/send/recv`, a host loopback TCP server, and the broker's live received TUN fd. Run the ignored live test explicitly plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — live bwrap smoltcp TCP forwarding

- Slice attempted: prove a real bwrap target TCP connection can traverse the received TUN fd, enter smoltcp, relay payload to a host TCP socket, and receive the host response through TUN.
- Why next: smoltcp host-stream relay was unit-proven; the remaining high-risk TCP gate was live TUN integration.
- What changed: `foxprox-tcp` now exposes `SmoltcpTcpServer`, a small raw-IP smoltcp server wrapper with packet ingress, TX packet capture, receive readiness, and one-shot host stream relay. The ignored live bwrap test now includes a TCP smoke: target Python connects to 10.129.0.1:8080, sends `hi`, the broker feeds live TUN packets into smoltcp, relays `hi` to a host loopback TCP server, receives `ok`, writes smoltcp's outbound packets back through TUN, and the target receives `ok`.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-tcp -- --nocapture` and `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`; all three live bwrap smokes passed, including the new TCP smoltcp/host-stream path.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed after fixing a clippy useless-conversion warning in the smoltcp IP address setup.
  - `cargo test --workspace` passed; the three live bwrap tests compile and remain ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures in the live TCP smoke; the smoltcp wrapper only needed to skip non-ready packets and relay once when `can_recv` became true.
- What this proves: the alpha TCP gate now has live evidence for TUN fd → smoltcp TCP accept → host TCP stream → smoltcp response → TUN fd → sandbox target receive.
- What remains unproven: long-running/multi-connection TCP scheduling, policy-gated smoltcp connection opens, connection close/error audit, and production launcher orchestration.
- Commit: this commit.

## 2026-06-22 Session Continue — launcher spawns setup and receives fd slice

- Slice attempted: add a Rust launcher orchestration boundary that spawns a setup command while a broker control listener is active, then returns the received setup fd and child status.
- Why next: live bwrap tests manually assemble Command + BrokerControlListener; production needs a reusable launcher primitive connecting bwrap planning to broker fd receipt.
- Verification plan: add a generic `run_setup_command_and_receive_fd` helper in integrations, test it with a fake setup script that connects to the broker socket and sends an fd through existing SCM_RIGHTS helper, then run focused integration tests plus workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — launcher spawns setup and receives fd

- Slice attempted: add a Rust launcher orchestration boundary that spawns a setup command while a broker control listener is active, then returns the received setup fd and child status.
- Why next: live bwrap tests manually assembled `Command` plus `BrokerControlListener`; production needs a reusable launcher primitive connecting bwrap planning to broker fd receipt.
- What changed: `foxprox-integrations::fd_handoff` now exposes `run_setup_command_and_receive_fd`, returning the received fd plus child exit status. This provides the host-side orchestration seam for future bwrap launchers: spawn setup command, accept SCM_RIGHTS fd, then wait for setup completion.
- Verification:
  - Focused check passed: `cargo test -p foxprox-integrations launcher_spawns -- --nocapture`, using a Python child process that connects to the broker socket and sends a read/write fd with SCM_RIGHTS; the Rust launcher received the fd and verified broker-side readability.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 15 `foxprox-integrations` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; using a child process instead of an in-process thread gives real spawn/wait evidence without requiring bwrap in default tests.
- What remains unproven: using this helper with the full bwrap command plan in a non-ignored runtime path and supervising long-running target lifetime.
- Commit: this commit.

## 2026-06-22 Session Continue — launcher returns live child after fd handoff slice

- Slice attempted: split setup spawn/fd accept from child wait so the broker can process traffic while the target is still running.
- Why next: `run_setup_command_and_receive_fd` waits immediately after fd receipt, which is fine for setup-only tests but not for real bwrap sessions where the target may block waiting for broker packet handling.
- Verification plan: add `spawn_setup_command_and_accept_fd` returning the child handle plus received fd, refactor the existing run helper through it, and test that the caller can read the fd before waiting for child completion. Run focused integration tests plus workspace checks.
- Commit: pending.

## 2026-06-22 Slice Evidence — launcher returns live child after fd handoff

- Slice attempted: split setup spawn/fd accept from child wait so the broker can process traffic while the target is still running.
- Why next: `run_setup_command_and_receive_fd` waits immediately after fd receipt, which is fine for setup-only tests but not for real bwrap sessions where the target may block waiting for broker packet handling.
- What changed: `foxprox-integrations::fd_handoff` now exposes `spawn_setup_command_and_accept_fd`, returning a live child handle plus the received setup fd. `run_setup_command_and_receive_fd` now builds on that helper and waits only in the convenience wrapper.
- Verification:
  - Focused checks passed: `cargo test -p foxprox-integrations launcher_ -- --nocapture`, proving both immediate-wait and live-child variants. The live-child test reads the handed-off fd before waiting for the child to exit.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 16 `foxprox-integrations` tests.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; keeping the child live after fd handoff matches the actual bwrap target lifecycle much better.
- What remains unproven: replacing the manual command construction in ignored live tests with this orchestration helper for full bwrap sessions.
- Commit: this commit.

## 2026-06-22 Slice Evidence — live bwrap test uses live-child launcher seam

- Slice attempted: use the new live-child launcher seam in a real bwrap smoke so fd handoff and target supervision match production shape.
- Why next: the helper existed but live bwrap smokes still manually started the command and accepted fds inside a broker thread; using the helper proves it works for a target that remains blocked on broker TCP forwarding after fd handoff.
- What changed: the live bwrap TCP smoke now builds the bwrap/`foxproxsetup` command, calls `spawn_setup_command_and_accept_fd`, feeds the received fd into `SmoltcpTcpServer`, relays traffic, and waits for the still-live bwrap child only after broker forwarding completes.
- Verification:
  - Focused live check passed: `cargo test -p foxprox-cli --test live_bwrap_setup live_bwrap_tcp -- --ignored --nocapture`.
  - All explicit live smokes passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; receiving the fd first and only then starting packet processing still works because the target's SYN waits in the TUN stream until the broker loop starts.
- What remains unproven: packaging this into a user-facing long-running launcher command and supervising multi-connection sessions.
- Commit: this commit.

## 2026-06-22 Session Continue — production-shaped bwrap TCP once launcher slice

- Slice attempted: move the live bwrap TCP smoke's orchestration into reusable CLI/runtime code that launches bwrap/`foxproxsetup`, accepts the TUN fd, runs one smoltcp TCP relay to a host stream, and waits for the target after forwarding.
- Why next: live TCP forwarding is proven, and the live-child launcher seam is proven, but the actual broker-side TCP launch/relay behavior still lives mostly in an ignored test instead of product code.
- Verification plan: add a `BwrapTcpOnceConfig`/`run_bwrap_tcp_once` helper in `foxprox-cli`, promote `foxprox-tcp` to a production dependency, refactor the ignored live TCP smoke to call the helper, then run focused live TCP, all live smokes, and workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — production-shaped bwrap TCP once launcher

- Slice attempted: move the live bwrap TCP smoke's orchestration into reusable CLI/runtime code that launches bwrap/`foxproxsetup`, accepts the TUN fd, runs one smoltcp TCP relay to a host stream, and waits for the target after forwarding.
- Why next: live TCP forwarding was proven, and the live-child launcher seam was proven, but the broker-side TCP launch/relay behavior still lived mostly in an ignored test instead of product code.
- What changed: `foxprox-cli` now promotes `foxprox-tcp` to a production dependency and exposes `BwrapTcpOnceConfig`, `BwrapTcpOnceSummary`, and `run_bwrap_tcp_once`. The helper binds the broker control socket, plans the bwrap/`foxproxsetup` command, accepts the received TUN fd, feeds packets into `SmoltcpTcpServer`, relays one sandbox payload to a host TCP stream, writes smoltcp responses back through TUN, and then waits for the target child. `foxprox-integrations::BwrapSetupConfig` now accepts caller-supplied extra bwrap args so the network broker integration can be composed with a separate sandbox/filesystem runtime instead of hardcoding those policy choices.
- Verification:
  - Focused integration checks passed: `cargo test -p foxprox-integrations bwrap_plan -- --nocapture`, including a new proof that caller-supplied sandbox args are inserted before `foxproxsetup`.
  - Focused live TCP check passed: `cargo test -p foxprox-cli --test live_bwrap_setup live_bwrap_tcp -- --ignored --nocapture`, with the ignored live TCP smoke now using `run_bwrap_tcp_once` instead of local orchestration.
  - All explicit live smokes passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 17 integration tests and the ignored live smokes compiling by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; the missing abstraction was not smoltcp but the ownership/lifecycle seam that keeps the bwrap child alive while broker code relays the first TCP flow.
- What remains unproven: a fully unbounded multi-connection TCP scheduler and a polished end-user sandbox CLI; the alpha evidence now has product-code launcher orchestration for the one-flow TCP proof.
- Commit: this commit.

## 2026-06-22 Session Continue — live sandbox curl through smoltcp launcher slice

- Slice attempted: prove an ordinary application (`curl`) inside the live bwrap namespace can use the reusable bwrap TCP once launcher path to fetch an HTTP response through TUN, smoltcp, and a host TCP server.
- Why next: Python socket TCP forwarding is proven, but the remaining alpha-facing confidence gap is a real user tool performing application-level TCP/HTTP over the production-shaped launcher helper.
- Verification plan: add an ignored live curl smoke that skips when `/usr/bin/curl` is unavailable, serves one HTTP response from a host loopback `TcpListener`, runs `curl http://<broker-tun-ip>:8080/` inside bwrap through `run_bwrap_tcp_once`, and checks the host saw an HTTP GET plus the launcher relayed nonzero bytes in both directions. Run the focused live curl smoke, all live smokes, and workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — live sandbox curl through smoltcp launcher

- Slice attempted: prove an ordinary application (`curl`) inside the live bwrap namespace can use the reusable bwrap TCP once launcher path to fetch an HTTP response through TUN, smoltcp, and a host TCP server.
- Why next: Python socket TCP forwarding was proven, but the remaining alpha-facing confidence gap was a real user tool performing application-level TCP/HTTP over the production-shaped launcher helper.
- What changed: the ignored live bwrap test suite now includes `live_bwrap_curl_fetches_http_through_smoltcp_launcher`. It starts a host loopback HTTP server, runs `curl --max-time 5 --silent --show-error http://10.130.0.1:8080/` inside bwrap via `run_bwrap_tcp_once`, and asserts the host saw `GET / HTTP/1.1` plus nonzero byte counts in both relay directions.
- Verification:
  - Focused live curl check passed: `cargo test -p foxprox-cli --test live_bwrap_setup live_bwrap_curl -- --ignored --nocapture`.
  - All explicit live smokes passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`, now covering UDP, DNS, Python TCP, and curl-over-TCP.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed; the live curl smoke compiles and remains ignored by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: curl's response body appears in `--nocapture` output because the smoke intentionally exercises the real target stdout path; this is harmless evidence that the application received `ok`.
- What remains unproven: unbounded production scheduling and polished CLI UX; the documented alpha forwarding proof now includes live curl-level TCP evidence through the reusable launcher path.
- Commit: this commit.

## 2026-06-22 Slice Evidence — TCP launcher emits open/close audit evidence

- Slice attempted: add structured TCP open/close audit evidence to the production-shaped bwrap TCP once launcher.
- Why next: reviewer pass found the forwarding proof complete but flagged Milestone 2 validation text requiring connection open/close/error events to be logged. `run_bwrap_tcp_once` relayed bytes but returned only byte/status evidence.
- What changed: `BwrapTcpOnceConfig` now carries a sandbox id and minimal policy config. `run_bwrap_tcp_once` parses the first TUN TCP connect packet, evaluates it through the shared `PolicyEngine`, records the resulting `tcp_connect` JSON audit line, denies before host connect when policy rejects the flow, and records a `tcp_flow_closed` audit line with directional byte counts after target exit. The live TCP and curl smokes now assert both audit lines are produced.
- Verification:
  - Focused live TCP and curl checks passed: `cargo test -p foxprox-cli --test live_bwrap_setup live_bwrap_tcp -- --ignored --nocapture` and `cargo test -p foxprox-cli --test live_bwrap_setup live_bwrap_curl -- --ignored --nocapture`.
  - All explicit live smokes passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`, covering UDP, DNS, Python TCP, and curl-over-TCP.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: the first assertion expected `tcp_connect_attempt`, but the stable audit schema name is `tcp_connect`; the test was corrected to match the existing audit schema.
- What remains unproven: fully unbounded multi-connection scheduling and polished user-facing launcher UX. The alpha Milestone 2 validation requirement for open/close logs is now covered by the reusable launcher summary and live smokes.
- Commit: this commit.

## 2026-06-22 Session Continue — user-facing bwrap TCP once command slice

- Slice attempted: expose the production-shaped bwrap/TUN/smoltcp TCP once launcher through the `foxprox-cli` process boundary and prove it with live curl.
- Why next: the reusable helper exists and emits audit, but the alpha has no user-facing launcher command beyond `packet-once` and `setup`.
- Verification plan: add a `bwrap-tcp-once` command parser that builds `BwrapTcpOnceConfig`, emits audit JSON lines on stdout, unit-test parser shape, run a live ignored curl smoke through the CLI binary, then run all live smokes and workspace clippy/tests/fmt.
- Commit: pending.

## 2026-06-22 Slice Evidence — user-facing bwrap TCP once command

- Slice attempted: expose the production-shaped bwrap/TUN/smoltcp TCP once launcher through the `foxprox-cli` process boundary and prove it with live curl.
- Why next: the reusable helper existed and emitted audit, but alpha had no user-facing launcher command beyond `packet-once` and `setup`.
- What changed: `foxprox-cli` now accepts `bwrap-tcp-once`, parsing bwrap/setup paths, broker socket, TUN setup args, smoltcp listener address/port, upstream host TCP address, sandbox id, sizing limits, extra bwrap args, and target argv. The command runs `run_bwrap_tcp_once`, emits the generated audit JSON lines to stdout, and fails if the target exits unsuccessfully. Parser coverage was added for the documented command shape. A new ignored live smoke invokes the actual CLI binary, runs curl inside bwrap, and asserts stdout contains `tcp_connect` and `tcp_flow_closed` audit records.
- Verification:
  - Focused parser check passed: `cargo test -p foxprox-cli bwrap_tcp_once_arg_parser -- --nocapture`.
  - Focused live CLI check passed: `cargo test -p foxprox-cli --test live_bwrap_setup live_cli_bwrap_tcp_once -- --ignored --nocapture`.
  - All explicit live smokes passed: `cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture`, now 5/5 including the CLI command smoke.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `cargo test --workspace` passed, including 11 `foxprox-cli` unit tests and the ignored live CLI smoke compiling by default.
  - `cargo fmt --check` passed after workspace tests.
- What failed or surprised the agent: no behavior failures; exposing extra bwrap args as repeatable `--extra-bwrap-arg` keeps the command useful for live proof without pretending to own complete sandbox filesystem policy.
- What remains unproven: a polished long-running multi-flow broker daemon. The documented alpha milestone proofs and a user-facing one-flow live curl command now have direct evidence.
- Commit: this commit.
