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

### Commit
- `84a5f10` — observable TUN packet harness.

## 2026-06-21 — UDP forwarding harness observability cycle

### Behavior under work
Add a mockable UDP forwarding proof that evaluates outbound datagrams through the shared policy/audit core, records UDP/QUIC flow lifecycle evidence, sends allowed datagrams through a replaceable egress sink, routes reply byte counts back into flow state, and suppresses egress for denied or audit-backpressured paths.

### Expected evidence
- Allowed UDP datagrams produce `udp_packet_decision`, `udp_flow_created`, and fake egress send evidence.
- Denied multicast/direct-DNS paths produce structured denial audit and no egress sends.
- QUIC candidate UDP/443 flows produce `quic_candidate_flow_created` and use the longer QUIC timeout.
- Flow lifecycle audit backpressure prevents unobservable egress sends.

### Commands run
- `cargo fmt` — applied formatting for `udp.rs`.
- `cargo test --all-targets --all-features` — passed, 56 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `udp::tests::allowed_udp_datagram_records_decision_flow_and_fake_egress ... ok`
- `udp::tests::denied_multicast_udp_does_not_send ... ok`
- `udp::tests::direct_external_dns_udp_does_not_send ... ok`
- `udp::tests::quic_candidate_records_lifecycle_and_uses_quic_timeout ... ok`
- `udp::tests::flow_lifecycle_backpressure_prevents_unobservable_send ... ok`

### Interpretation
UDP forwarding now has a mockable egress proof connected to shared policy/audit and UDP flow lifecycle state. Allowed datagrams are sent only after policy and lifecycle audit records are appended; denied multicast/direct-DNS paths do not reach egress; QUIC candidates get visible classification and timeout evidence.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/udp.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- UDP egress is still in-memory rather than host sockets, and inbound replies update byte counts but do not yet synthesize/write packets back through a real TUN stack.

### Commit
- `e111714` — observable UDP forwarding harness.

## 2026-06-21 — TCP forwarding harness observability cycle

### Behavior under work
Add a mockable TCP forwarding proof that evaluates connect attempts through the shared policy/audit core before opening host egress, bridges deterministic byte chunks in both directions through a replaceable egress stream, and emits `tcp_flow_closed` audit evidence with byte counts and duration.

### Expected evidence
- Allowed TCP connect attempts append `tcp_connect_decision`, open fake egress exactly once, bridge sandbox/host bytes, and append `tcp_flow_closed` with byte counts.
- Denied TCP connect attempts emit structured denial audit and never open host egress.
- Audit backpressure before connect or close prevents unobservable egress/open or close accounting.

### Commands run
- `cargo fmt` — applied formatting for `tcp.rs` and `flow.rs`.
- `cargo test --all-targets --all-features` — passed, 59 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tcp::tests::allowed_tcp_connect_opens_egress_bridges_bytes_and_logs_close ... ok`
- `tcp::tests::denied_tcp_connect_does_not_open_egress ... ok`
- `tcp::tests::close_audit_backpressure_is_visible ... ok`

### Interpretation
TCP forwarding now has a deterministic host-egress proof behind a replaceable trait. Policy/audit evaluation gates host connect attempts, denied connects never open egress, and close events include byte counts and duration. Close-audit backpressure is visible through `audit_backpressure`; real runtime stream code will need the same lifecycle accounting boundary around asynchronous close/error paths.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/tcp.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- This is not a `smoltcp` adapter or host socket runtime yet. It establishes the shared connect/bridge/close evidence contract that smoltcp/async socket integration must satisfy.

### Commit
- `d5e8f39` — observable TCP forwarding harness.

## 2026-06-21 — IPv6 packet observability cycle

### Behavior under work
Extend the packet core and TUN harness from IPv4-only parsing to a version-dispatching IP parser with IPv6 TCP/UDP/ICMPv6 endpoint visibility and fail-closed structured audit for unsupported IPv6 extension/fragment paths.

### Expected evidence
- IPv6 UDP packets parse into source/destination endpoints and emit `packet_observed` with `ip_version=6`.
- IPv6 TCP/ICMPv6 basic headers expose protocol-specific metadata.
- IPv6 extension/fragment or malformed packets fail closed with structured parse-error audit and no write-back.

### Commands run
- `cargo fmt` — applied formatting for packet/TUN updates.
- `cargo test --all-targets --all-features` — initially found a TUN malformed-packet expectation still assuming IPv4-only parsing; updated it to the version-dispatch parse error.
- `cargo test --all-targets --all-features` — passed, 62 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `packet::tests::parses_ipv6_udp_tcp_and_icmpv6_metadata ... ok`
- `packet::tests::ipv6_fragment_and_extension_headers_fail_closed_with_audit ... ok`
- `tun::tests::valid_ipv6_udp_packet_emits_ip_version_six_audit ... ok`
- `tun::tests::malformed_packet_fails_closed_without_write ... ok`

### Interpretation
Packet parsing now dispatches on IP version and exposes IPv6 TCP/UDP/ICMPv6 metadata through the same normalized endpoint model. Unsupported IPv6 fragment/extension paths fail closed with structured audit evidence, and the TUN harness records `ip_version=6` for observable packet provenance.

### Changed files
- `crates/foxprox-core/src/packet.rs`
- `crates/foxprox-core/src/tun.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- IPv6 extension headers are intentionally fail-closed rather than walked; ICMPv6 write-back/NDP behavior remains out of this pure parser slice.

### Commit
- `3ff222e` — observable IPv6 packet parsing.

## 2026-06-21 — Policy config validation observability cycle

### Behavior under work
Add explicit policy configuration validation and reload audit evidence so malformed rule/default/timeout/DNS settings fail closed with structured reasons before a broker runtime starts using them.

### Expected evidence
- Invalid CIDR prefixes, missing broker DNS resolvers, empty rule IDs, invalid default decisions, and zero UDP timeouts are reported as structured validation errors.
- Valid configs produce `policy_reload` audit records with rule count/default/QUIC/DNS settings.
- Invalid configs produce `policy_reload` fail-closed audit records with stable error codes.

### Commands run
- `cargo fmt` — applied formatting for policy validation changes.
- `cargo test --all-targets --all-features` — passed, 64 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `policy::tests::policy_config_validation_reports_structured_errors ... ok`
- `policy::tests::valid_policy_config_reload_audit_summarizes_runtime_settings ... ok`

### Interpretation
Policy configuration now has an explicit validation surface and structured reload audit evidence. Invalid default decisions, empty DNS resolver sets, zero UDP timeouts, empty rule IDs, and invalid CIDR prefixes fail closed with stable error codes before runtime use; valid reloads record rule count and key default settings.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/policy.rs`
- `progress.md`

### Remaining blind spots
- The repo still lacks a CLI/config-file loader; validation is available as the core contract that a launcher/runtime must call before applying policy.

### Commit
- `62910ce` — observable policy config validation.

## 2026-06-21 — Policy rule dimension coverage cycle

### Behavior under work
Fill documented policy rule dimensions that were still implicit or missing: sandbox profile scoping, HTTP method matching, and explicit origin scheme/host/port matching for proxy and transparent HTTP decisions.

### Expected evidence
- Rules can match only a specific sandbox profile and produce stable rule IDs in audit.
- HTTP method/path rules distinguish allowed and denied methods with structured `http_method`/`http_path` details.
- Origin tuple rules match scheme, host, and port for explicit proxy requests.

### Commands run
- `cargo fmt` — applied formatting for policy rule dimension changes.
- `cargo test --all-targets --all-features` — passed, 67 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `policy::tests::http_method_rule_distinguishes_methods_with_audit_details ... ok`
- `policy::tests::origin_tuple_rule_matches_explicit_proxy_origin ... ok`
- `policy::tests::sandbox_profile_rule_scopes_policy ... ok`

### Interpretation
Policy rules now cover documented dimensions for sandbox profile, HTTP method, and origin tuple matching. Audit output keeps method/path/origin/rule IDs visible so denied method mismatches and allowed origin/profile matches are explainable from structured records.

### Changed files
- `crates/foxprox-core/src/policy.rs`
- `progress.md`

### Remaining blind spots
- Profile values are supplied by callers through `SandboxIdentity`; launcher/runtime identity discovery is still outside this core slice.

## 2026-06-21 — Reviewer blocker fix cycle

### Behavior under work
Address independent reviewer blockers in audit-gated runtime harnesses: TUN parsed packets must still pass policy before allow/write-back; DNS cache updates must happen only after returned-address audit succeeds; UDP flow state must not retain unsent or unaudited lifecycle bytes when audit/egress fails.

### Expected evidence
- Default-denied parsed TUN UDP packets return a policy denial after `packet_observed`; ICMP echo write-back requires `allow_ping=true` and is suppressed when ping is denied.
- DNS observation audit backpressure returns REFUSED and leaves no DNS cache attribution.
- UDP lifecycle audit backpressure leaves no flow state and no egress sends; egress send failure rolls back the flow update.

### Commands run
- `cargo fmt --check` — passed before fixes; `cargo test --all-targets --all-features` passed with 67 tests, confirming reviewer validation-staleness finding no longer applied to current committed state.
- `cargo fmt` — applied formatting for blocker fixes.
- `cargo test --all-targets --all-features` — passed, 70 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tun::tests::default_denied_tun_packet_is_observed_then_denied_without_write ... ok`
- `tun::tests::icmp_echo_request_is_denied_when_ping_is_not_allowed ... ok`
- `tun::tests::icmp_echo_request_writes_reply_after_write_back_audit ... ok`
- `dns_handler::tests::address_observation_backpressure_blocks_upstream_response_release ... ok`
- `udp::tests::flow_lifecycle_backpressure_prevents_unobservable_send ... ok`
- `udp::tests::egress_send_failure_rolls_back_flow_state ... ok`

### Interpretation
Reviewer blockers were valid and fixed. TUN parsing is no longer treated as authorization: parsed packets are observed, then evaluated through policy before allow/write-back; ping defaults now deny ICMP echo as documented. DNS returned-address cache state is committed only after observation audit succeeds. UDP flow state rolls back when lifecycle audit backpressures or fake egress send fails, avoiding retained byte counts for unsent datagrams.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/tun.rs`
- `crates/foxprox-core/src/udp.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- TCP close-audit backpressure remains observable after bytes have already crossed in the harness; real async runtime will need stronger reservation/guaranteed close-ledger design before production use.

## 2026-06-21 — Explicit proxy forwarding harness observability cycle

### Behavior under work
Add a platform-independent explicit proxy frontend harness that parses HTTP proxy / HTTPS CONNECT / SOCKS5 CONNECT request bytes, evaluates normalized requests through the shared policy/audit core, and calls a mockable proxy egress only for allowed decisions.

### Expected evidence
- Allowed HTTP proxy and SOCKS5 CONNECT requests append shared frontend decision audit and invoke fake proxy egress with parsed metadata.
- Denied HTTPS CONNECT requests append structured denial audit and do not invoke egress.
- Malformed HTTP proxy bytes fail closed with `proxy_malformed` audit detail and no egress.

### Commands run
- `cargo fmt` — applied formatting for `proxy_frontend.rs`.
- `cargo test --all-targets --all-features` — passed, 74 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `proxy_frontend::tests::allowed_http_proxy_request_forwards_after_shared_audit ... ok`
- `proxy_frontend::tests::denied_https_connect_does_not_forward ... ok`
- `proxy_frontend::tests::malformed_http_proxy_request_fails_closed_without_forwarding ... ok`
- `proxy_frontend::tests::allowed_socks_connect_forwards_after_shared_audit ... ok`

### Interpretation
Explicit proxy requests now have a frontend harness, not just parsers. HTTP proxy, HTTPS CONNECT, and SOCKS5 CONNECT bytes are normalized into shared policy/audit decisions before mock egress is invoked; malformed and denied paths stay observable and do not forward.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/proxy_frontend.rs`
- `progress.md`

### Remaining blind spots
- This is not a socket listener or HTTP runtime yet; it defines the observable parse→policy→egress contract that listener code must implement.
