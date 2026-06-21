# Progress Ledger

## 2026-06-21 — Alpha scope observability foundation

### Behavior under work
Implemented the platform-independent alpha broker core in Rust with observable policy decisions, audit records, flow lifecycle state, DNS attribution and DNS query/refusal parsing, proxy/transparent event normalization, packet validation/write-back primitives, setup planning, and bounded audit backpressure that fails closed through `BrokerCore`.

### Expected evidence
- Structured audit serialization tests assert stable fields and denial context.
- Policy tests assert allow, deny, fail-closed, direct-DNS bypass, DoT default denial, SNI mismatch, hostname attribution, proxy, SOCKS, ICMP, unsupported, and QUIC decisions.
- Flow lifecycle tests assert UDP/QUIC creation, byte counts, expiration, DNS cache attribution, and emitted audit kinds.
- Packet tests assert malformed/fragment/unsupported fail-closed visibility and ICMP echo reply checksums/reversal.
- Backpressure tests assert bounded audit buffers do not grow unbounded.
- Setup-plan tests assert bwrap-compatible command shape without coupling broker core to bwrap runtime execution.

### Commands run
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, 37 unit tests after DNS foundation additions.

### Evidence excerpts
- `audit::tests::audit_record_serializes_stable_structured_fields ... ok`
- `audit::tests::audit_ledger_backpressure_is_bounded_and_observable ... ok`
- `broker::tests::broker_core_fails_closed_when_audit_is_backpressured ... ok`
- `dns::tests::parses_dns_query_with_structured_qtype ... ok`
- `dns::tests::malformed_dns_query_is_rejected ... ok`
- `dns::tests::refused_response_preserves_question_and_sets_rcode ... ok`
- `policy::tests::direct_external_dns_fails_closed_with_audit_context ... ok`
- `policy::tests::domain_rule_without_hostname_has_specific_denial_reason ... ok`
- `policy::tests::dot_is_denied_by_default_but_can_be_explicitly_allowed ... ok`
- `policy::tests::sni_dns_mismatch_is_denied_with_specific_event ... ok`
- `flow::tests::udp_flow_lifecycle_emits_create_quic_and_expire_audit ... ok`
- `packet::tests::fragmented_ipv4_fails_closed_with_structured_audit ... ok`
- `packet::tests::short_tcp_udp_and_icmp_headers_fail_closed ... ok`
- `packet::tests::icmp_echo_reply_swaps_addresses_and_recomputes_checksums ... ok`
- `setup::tests::bwrap_plan_contains_alpha_network_setup_contract ... ok`
- `setup::tests::bwrap_plan_passes_setup_control_fd_to_helper ... ok`

### Interpretation
The alpha core now exposes decision-relevant behavior through structured audit records and tests that assert stable fields, denial reasons, frontend source, attribution source, byte counts, durations, and bounded audit-buffer behavior. A reviewer pass identified missing malformed-packet guards, misleading UDP flow decisions, timestamp defaults, ICMP default mismatch, setup-control fd modeling, and zero-capacity backpressure evidence; those were fixed with focused tests. Runtime forwarding is still represented as platform-independent contracts/harness primitives rather than privileged TUN/smoltcp/socket execution.

### Changed files
- `Cargo.lock`
- `crates/foxprox-core/Cargo.toml`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/audit.rs`
- `crates/foxprox-core/src/broker.rs`
- `crates/foxprox-core/src/dns.rs`
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/inspect.rs`
- `crates/foxprox-core/src/packet.rs`
- `crates/foxprox-core/src/policy.rs`
- `crates/foxprox-core/src/setup.rs`
- `crates/foxprox-core/src/types.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Real TUN fd I/O, bwrap execution, fd handoff, smoltcp TCP bridging, explicit proxy listeners, DNS upstream forwarding, and host socket egress require privileged/integration crates and runtime environments. The current implementation locks down the platform-independent observable contracts those runtime layers must emit.
- Independent reviewer run `96f9f4db-0ed0-4317-86ae-a79c6cab374d` failed acceptance finalization but wrote findings. Blocker/high findings were addressed except for full privileged runtime implementation, which remains the next alpha milestone.

### Commit
- `7b462c2` — observable alpha broker core foundation.
- `7227fce` — reviewer fixes for packet validation, timestamps, ICMP defaults, flow audit semantics, setup fd modeling, and backpressure evidence.
- `5d1aa6d` — DNS query parser and refused-response foundation.

## 2026-06-21 — Explicit proxy parser observability cycle

### Behavior under work
Add platform-independent HTTP proxy and SOCKS5 CONNECT request parsing that emits normalized `PolicyRequest` values using the shared policy/audit backend, including malformed proxy requests that fail closed with structured denial evidence.

### Expected evidence
- HTTP absolute-form and `CONNECT` proxy requests produce `http_request_decision` / `https_connect_decision` audit records with explicit proxy hostname attribution, origin, method, and path/authority details.
- SOCKS5 TCP CONNECT requests for domain and IP destinations produce `socks_connect_decision` audit records with destination host attribution or endpoint IP/port.
- Malformed/unsupported proxy requests produce `unsupported_denied` audit records with `reason=proxy_malformed` and `frontend` set to the proxy that observed them.

### Commands run
- `cargo fmt --check` — initially failed because new `proxy.rs` needed formatting.
- `cargo fmt` — applied formatting.
- `cargo test --all-targets --all-features` — passed, 42 unit tests.
- `cargo fmt --check` — passed after formatting.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `proxy::tests::http_proxy_absolute_form_emits_origin_aware_policy_request ... ok`
- `proxy::tests::http_connect_emits_https_connect_decision ... ok`
- `proxy::tests::socks5_domain_connect_emits_socks_decision_with_attribution ... ok`
- `proxy::tests::socks5_ip_connect_keeps_endpoint_visible ... ok`
- `proxy::tests::malformed_proxy_request_fails_closed_with_structured_detail ... ok`

### Interpretation
Explicit proxy parsing is now represented as a first-class platform-independent frontend contract instead of only hand-built policy requests. HTTP proxy and SOCKS5 CONNECT metadata normalize into shared `PolicyRequest` paths, and malformed proxy input carries a bounded `proxy_parse_error` detail through the shared structured audit ledger.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/policy.rs`
- `crates/foxprox-core/src/proxy.rs`
- `progress.md`

### Remaining blind spots
- The parser/harness does not yet accept sockets or bridge traffic; listener/runtime work remains for explicit proxy frontend execution.

### Commit
- `37d676b` — observable explicit HTTP/SOCKS proxy parsing.

## 2026-06-21 — DNS handler observability cycle

### Behavior under work
Add a platform-independent DNS broker handler that receives UDP/53 payload bytes, parses DNS questions, evaluates them through `BrokerCore`, returns REFUSED on denied/malformed paths, forwards allowed questions through a mockable upstream interface, and records returned address observations into the DNS attribution cache and audit ledger before responses are released.

### Expected evidence
- Allowed broker-DNS queries call the upstream, return the upstream response, and produce structured `dns_query_decision` records with hostname/qtype and returned addresses.
- Denied DNS policy decisions return bounded REFUSED responses without contacting upstream.
- Malformed DNS payloads fail closed with structured parse-error audit details.
- DNS observation audit backpressure prevents releasing upstream responses and leaves observable `audit_backpressure` evidence.

### Commands run
- `cargo fmt` — applied formatting for `dns_handler.rs`.
- `cargo test --all-targets --all-features` — passed, 47 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `dns_handler::tests::allowed_query_returns_upstream_response_and_observes_addresses ... ok`
- `dns_handler::tests::denied_query_returns_refused_without_upstream ... ok`
- `dns_handler::tests::malformed_query_fails_closed_with_parse_detail ... ok`
- `dns_handler::tests::address_observation_backpressure_blocks_upstream_response_release ... ok`
- `dns_handler::tests::response_address_parser_extracts_a_answers_and_ttl ... ok`

### Interpretation
The DNS broker path is now observable as a composed behavior rather than isolated parser/cache primitives. Allowed queries must record both the policy decision and returned-address observation before the upstream response is released; denied or malformed inputs produce REFUSED/no-response behavior with structured audit reasons. Address-observation backpressure is treated as fail-closed to avoid invisible hostname attribution state.

### Changed files
- `crates/foxprox-core/src/broker.rs`
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-core/src/lib.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- DNS upstream exchange is still a mockable trait rather than an async socket implementation. Runtime UDP listener and real upstream resolver integration remain later alpha work.

### Commit
- `d1e3181` — observable DNS broker handler.

## 2026-06-21 — TUN packet harness observability cycle

### Behavior under work
Add a platform-independent TUN/device harness boundary that reads inbound IP packet bytes from a replaceable source, emits `packet_observed`/malformed structured audit records, routes ICMP echo requests through the existing write-back proof, and records outbound packet write evidence without requiring privileged TUN setup.

### Expected evidence
- Valid inbound IPv4 UDP packets produce `packet_observed` audit records with source/destination endpoints, protocol, frontend, byte length, and IP version.
- Malformed or unsupported packet bytes produce fail-closed structured audit records without writing responses.
- ICMP echo requests produce validated outbound reply bytes and a bounded write-back audit detail.

### Commands run
- `cargo fmt` — applied formatting for `tun.rs`.
- `cargo test --all-targets --all-features` — passed, 51 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tun::tests::valid_ipv4_udp_packet_emits_structured_packet_observed_audit ... ok`
- `tun::tests::malformed_packet_fails_closed_without_write ... ok`
- `tun::tests::icmp_echo_request_writes_reply_after_write_back_audit ... ok`
- `tun::tests::write_back_audit_backpressure_prevents_unobserved_reply ... ok`

### Interpretation
The TUN-facing boundary now has a deterministic in-memory harness that proves packet read/write behavior and structured observability without requiring privileges. Inbound packet observation and outbound ICMP write-back are both audit-gated; if the write-back audit cannot be recorded, the harness fails closed and does not emit an unobservable reply packet.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/tun.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- The harness does not open Linux `/dev/net/tun` or configure namespaces. It defines the bounded observable contract that a privileged Linux frontend can implement next.
