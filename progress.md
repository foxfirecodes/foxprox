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

## 2026-06-21 — UDP resource limit observability cycle

### Behavior under work
Add an explicit UDP active-flow resource limit to the forwarding harness so resource exhaustion is denied and audited before additional flow state or egress sends occur.

### Expected evidence
- When the active-flow limit is reached, a new UDP flow returns `deny_drop` with `resource_limit`, appends a structured `udp_packet_decision` audit record, and does not send to egress.
- Existing flows may continue under the limit without creating additional flow state.

### Commands run
- `cargo fmt` — applied formatting for UDP limit changes.
- `cargo test --all-targets --all-features` — passed, 76 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `udp::tests::active_flow_limit_denies_new_flow_without_egress ... ok`
- `udp::tests::active_flow_limit_allows_existing_flow_updates ... ok`

### Interpretation
UDP forwarding now has an explicit active-flow resource limit with structured denial evidence. New flows beyond the configured limit are blocked before state mutation or egress, while existing flows can continue updating byte counts under the limit.

### Changed files
- `crates/foxprox-core/src/udp.rs`
- `progress.md`

### Remaining blind spots
- Resource limits currently cover UDP active flows only; TCP/proxy concurrency and byte-buffer limits remain future robustness slices.

## 2026-06-21 — Reviewer round 2 DNS/UDP/error-path fixes

### Behavior under work
Address second-review high-risk gaps: validate upstream DNS responses before releasing/caching attribution, expire UDP flows before applying active-flow limits, and make post-allow egress/upstream failures observable with structured `broker_error` audit records.

### Expected evidence
- Mismatched/truncated upstream DNS responses return REFUSED, append `dns_upstream_error=malformed_response`, and leave cache empty.
- UDP active-flow limits ignore expired flows after expiration audit succeeds.
- UDP/TCP/proxy egress failures append bounded `broker_error` evidence with frontend/protocol/error details.

### Commands run
- `cargo fmt` — applied formatting for reviewer-round-2 fixes.
- `cargo test --all-targets --all-features` — passed, 82 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `dns_handler::tests::mismatched_upstream_response_fails_closed_without_cache_update ... ok`
- `dns_handler::tests::malformed_upstream_response_fails_closed_without_release ... ok`
- `udp::tests::active_flow_limit_expires_stale_flow_before_denying_new_flow ... ok`
- `udp::tests::egress_send_failure_rolls_back_flow_state ... ok`
- `tcp::tests::tcp_egress_error_is_audited_after_allow ... ok`
- `proxy_frontend::tests::proxy_egress_error_is_audited_after_allow ... ok`
- `packet::tests::malformed_ipv4_checksum_and_transport_lengths_fail_closed ... ok`

### Interpretation
Second review findings were addressed for DNS response validation, stale UDP flow limits, egress-error observability, and packet malformed-path validation. DNS upstream responses are validated against transaction ID/question/answer ownership before release or cache commit. UDP active-flow limits now expire stale flows first and fail closed if expiration audit cannot be recorded. UDP/TCP/proxy egress errors now append `broker_error` evidence. IPv4 packet parsing now rejects bad header checksums, invalid UDP lengths, invalid TCP data offsets, and invalid ICMP checksums.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-core/src/packet.rs`
- `crates/foxprox-core/src/proxy_frontend.rs`
- `crates/foxprox-core/src/tcp.rs`
- `crates/foxprox-core/src/udp.rs`
- `progress.md`
- `learnings.md`

### Remaining blind spots
- Transparent HTTP/TLS inspection is still parser/policy-unit coverage rather than a reachable TCP harness path. Real smoltcp/socket runtime remains outside the platform-independent harness layer.

## 2026-06-21 — Transparent TCP inspection integration cycle

### Behavior under work
Connect transparent HTTP/TLS byte inspection to the TCP forwarding harness so direct TCP stream bytes can enrich policy decisions instead of only standalone parser tests.

### Expected evidence
- Direct plaintext HTTP request bytes on TCP/80 produce `transparent_http_decision` audit with Host/method/path and gate egress through HTTP policy rules.
- TLS ClientHello SNI on TCP/443 can be compared against DNS cache attribution; mismatches deny before egress with `sni_dns_mismatch_denied` evidence.
- TLS ClientHello without SNI is treated as hidden-SNI and denied before egress unless policy explicitly allows an IP/port path.

### Commands run
- `cargo fmt` — applied formatting for transparent TCP inspection integration.
- `cargo test --all-targets --all-features` — passed, 86 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tcp::tests::transparent_http_bytes_gate_egress_with_origin_policy ... ok`
- `tcp::tests::transparent_http_policy_denial_prevents_egress ... ok`
- `tcp::tests::tls_sni_dns_mismatch_from_stream_bytes_denies_before_egress ... ok`
- `tcp::tests::tls_client_hello_missing_sni_is_hidden_sni_denied ... ok`

### Interpretation
Transparent TCP byte inspection now reaches the forwarding harness. Direct HTTP request bytes on TCP/80 are parsed into Host/method/path attribution before policy evaluation and egress. TLS ClientHello bytes on TCP/443 can produce SNI attribution, compare against DNS cache attribution, deny SNI/DNS mismatches before egress, and treat ClientHello-without-SNI as hidden-SNI denial evidence.

### Changed files
- `crates/foxprox-core/src/tcp.rs`
- `progress.md`

### Remaining blind spots
- The harness still represents a deterministic stream chunk, not full smoltcp stream reassembly or async socket bridging. TLS/HTTP parsers are connected to the harness but not yet to a real TUN TCP stack.

## 2026-06-21 — Runtime config schema observability cycle

### Behavior under work
Add an explicit serde-compatible runtime configuration schema tying setup, policy, audit capacity, proxy listener settings, UDP limits, and DNS upstream together with validation and structured audit evidence.

### Expected evidence
- Valid runtime config serializes stable structured fields and emits `broker_started` audit summary details.
- Invalid setup/policy/audit/listener/resource-limit values produce stable validation error codes and fail-closed `broker_error` audit evidence.

### Commands run
- `cargo fmt` — applied formatting for `config.rs`.
- `cargo test --all-targets --all-features` — passed, 88 unit tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `config::tests::runtime_config_serializes_stable_alpha_fields_and_audit ... ok`
- `config::tests::runtime_config_validation_reports_setup_policy_and_limit_errors ... ok`

### Interpretation
The core now exposes a serde-compatible alpha runtime configuration schema for setup, policy, audit capacity, DNS upstream, proxy listener toggles, and UDP active-flow limits. Validation catches setup, policy, audit, listener, and resource-limit errors with stable codes and fail-closed `broker_error` audit evidence.

### Changed files
- `crates/foxprox-core/src/config.rs`
- `crates/foxprox-core/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Config loading from CLI/files is still not implemented; this commit provides the schema and validation contract that CLI/runtime layers must use.

## 2026-06-21 — CLI config validation observability cycle

### Behavior under work
Add a minimal `foxprox` CLI crate that can validate a runtime JSON config file and emit the same structured audit line the runtime would use before startup.

### Expected evidence
- Valid config JSON exits success and prints a `broker_started` audit JSON line.
- Invalid config JSON exits with a validation failure code and prints a fail-closed `broker_error` audit JSON line with stable error codes.
- Malformed JSON exits with parse-error evidence rather than panicking.

### Commands run
- `cargo fmt` — applied formatting for `foxprox-cli`.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests and 88 core tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_cli::tests::validate_config_text_prints_broker_started_audit_for_valid_config ... ok`
- `foxprox_cli::tests::validate_config_text_prints_fail_closed_audit_for_invalid_config ... ok`
- `foxprox_cli::tests::malformed_config_json_prints_parse_error_audit ... ok`
- `foxprox_cli::tests::default_config_prints_json_config ... ok`

### Interpretation
The workspace now includes a minimal `foxprox` CLI surface for config validation/default generation. Config validation emits machine-readable audit JSON on success and fail-closed config errors, including malformed JSON parse errors, so startup config issues are externally visible before runtime networking starts.

### Changed files
- `Cargo.toml`
- `Cargo.lock`
- `crates/foxprox-cli/Cargo.toml`
- `crates/foxprox-cli/src/lib.rs`
- `crates/foxprox-cli/src/main.rs`
- `progress.md`

### Remaining blind spots
- CLI currently validates/generates config only; it does not launch bwrap, open TUN, or start runtime forwarding listeners.

## 2026-06-21 — Reviewer round 3 TLS policy fix cycle

### Behavior under work
Fix round-3 review findings for transparent TLS policy: hidden-SNI/malformed ClientHello denials must allow only explicit IP/port policy exceptions and malformed TLS bytes must not silently fall through to ordinary TCP allow.

### Expected evidence
- Missing-SNI ClientHello with an explicit TCP destination CIDR/port allow rule is allowed and opens egress.
- Missing-SNI ClientHello without an explicit IP/port allow is denied as `hidden_sni`.
- Truncated/malformed ClientHello on TCP/443 is denied before egress under default allow with structured `tls_client_hello_error` audit detail.

### Commands run
- `cargo fmt` — applied formatting for TLS policy fixes.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests and 90 core tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tcp::tests::hidden_sni_explicit_ip_port_allow_opens_egress ... ok`
- `tcp::tests::tls_client_hello_missing_sni_is_hidden_sni_denied ... ok`
- `tcp::tests::malformed_tls_client_hello_is_hidden_sni_denied_with_detail ... ok`

### Interpretation
Hidden-SNI behavior now matches the docs: it is denied by default but an explicit TCP IP/CIDR + port allow rule can permit it. Malformed/truncated TLS ClientHello bytes on TCP/443 no longer fall through to ordinary TCP default allow; they produce structured `tls_client_hello_error` detail and hidden-SNI denial evidence unless an explicit IP/port policy allows the opaque flow.

### Changed files
- `crates/foxprox-core/src/policy.rs`
- `crates/foxprox-core/src/tcp.rs`
- `progress.md`

### Remaining blind spots
- QUIC UDP flows still lack DNS-cache hostname attribution in the UDP forwarding harness; this is the next transparent attribution gap to close.

## 2026-06-21 — QUIC DNS attribution observability cycle

### Behavior under work
Close the remaining transparent QUIC attribution gap by letting UDP/443 forwarding requests use DNS cache hostname attribution and separating QUIC policy-decision audit from QUIC flow-lifecycle audit.

### Expected evidence
- QUIC UDP/443 with DNS-cache attribution can match hostname policy rules and emits `udp_packet_decision` plus `quic_candidate_flow_created` lifecycle evidence.
- QUIC hostname policy without attribution is denied with `hostname_attribution_required` and no egress.
- QUIC-disabled policy denial emits a packet-decision audit rather than a duplicate flow-created decision event.

### Commands run
- `cargo fmt` — applied formatting for QUIC attribution changes.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests and 92 core tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `udp::tests::quic_hostname_policy_uses_dns_cache_attribution ... ok`
- `udp::tests::quic_hostname_policy_without_attribution_denies_before_egress ... ok`
- `udp::tests::quic_candidate_records_lifecycle_and_uses_quic_timeout ... ok`

### Interpretation
Transparent QUIC candidate decisions can now consume DNS-cache attribution before egress. Hostname-based QUIC policy allows only when attribution is present, otherwise it denies with `hostname_attribution_required`. QUIC policy decisions now emit `udp_packet_decision` while `quic_candidate_flow_created` remains a flow-lifecycle event, removing duplicate decision/lifecycle event ambiguity.

### Changed files
- `crates/foxprox-core/src/policy.rs`
- `crates/foxprox-core/src/udp.rs`
- `progress.md`

### Remaining blind spots
- QUIC metadata parsing remains best-effort candidate classification by UDP/443/payload shape; no full QUIC/TLS metadata parser or HTTP/3 semantic inspection is implemented.

## 2026-06-21 — Append-only audit sink observability cycle

### Behavior under work
Add a replaceable append-only JSON-lines audit sink abstraction so bounded in-memory decisions can also be durably serialized through a stable sink contract.

### Expected evidence
- Audit records written to a JSONL sink produce one structured JSON object per line with stable fields.
- Sink write failures return structured errors instead of silently dropping audit output.
- Multiple records preserve append order in the sink output.

### Commands run
- `cargo fmt` — applied formatting for audit sink changes.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests and 94 core tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `audit::tests::json_line_audit_sink_appends_stable_records_in_order ... ok`
- `audit::tests::json_line_audit_sink_surfaces_write_errors ... ok`

### Interpretation
Audit output now has a replaceable append-only JSON-lines sink contract in addition to the bounded in-memory ledger. Tests prove stable one-record-per-line serialization, append order, and visible write errors for sink failures.

### Changed files
- `crates/foxprox-core/src/audit.rs`
- `crates/foxprox-core/src/lib.rs`
- `progress.md`

### Remaining blind spots
- The sink is a generic `Write` abstraction; CLI/runtime file path wiring and sink backpressure policy remain future runtime integration work.

## 2026-06-21 — Reviewer round 4 protocol edge fix cycle

### Behavior under work
Address round-4 high findings: tighten hidden-SNI explicit exceptions, wire payload-detected QUIC candidates through UDP policy/lifecycle paths, and extend malformed IPv6 transport validation.

### Expected evidence
- Hidden-SNI is allowed only by explicit TCP CIDR+port rules; port-only or CIDR-only rules still deny.
- UDP long-header QUIC candidates on non-443 ports use QUIC policy, DNS attribution, audit classification, and QUIC timeout.
- IPv6 UDP invalid length and TCP invalid data offset fail closed with structured parse errors.

### Commands run
- `cargo fmt` — applied formatting for round-4 protocol edge fixes.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests and 98 core tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tcp::tests::hidden_sni_explicit_ip_port_allow_opens_egress ... ok`
- `tcp::tests::hidden_sni_port_only_or_cidr_only_rules_do_not_open_egress ... ok`
- `udp::tests::non_443_long_header_quic_uses_dns_attribution_and_quic_timeout ... ok`
- `udp::tests::non_443_long_header_quic_respects_quic_disabled_policy ... ok`
- `packet::tests::malformed_ipv6_transport_lengths_fail_closed ... ok`

### Interpretation
Round-4 findings were fixed. Hidden-SNI explicit exceptions now require an explicit TCP CIDR+port rule, preventing broad port-only opaque TLS allows. Payload-detected QUIC candidates on non-443 ports now use QUIC policy, DNS attribution, QUIC timeout, and QUIC lifecycle audit. IPv6 TCP/UDP malformed transport length checks now match IPv4 fail-closed validation behavior.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/packet.rs`
- `crates/foxprox-core/src/policy.rs`
- `crates/foxprox-core/src/tcp.rs`
- `crates/foxprox-core/src/udp.rs`
- `progress.md`

### Remaining blind spots
- Full QUIC/TLS metadata parsing is still not implemented; long-header classification is a candidate signal only.

## 2026-06-21 — Host socket egress proof observability cycle

### Behavior under work
Add a concrete blocking host-socket egress crate that implements the core TCP and UDP egress traits for loopback-testable host networking while preserving the core parse→policy→audit→egress boundary.

### Expected evidence
- TCP host egress connects to a local listener, sends sandbox bytes, reads the host response, and can be driven through `TcpForwarder` audit/byte-count behavior.
- UDP host egress sends a datagram to a local UDP socket and can be driven through `UdpForwarder` audit/egress behavior.
- Host egress connection/send failures map to structured egress errors rather than panics.

### Commands run
- `cargo fmt` — applied formatting for `foxprox-egress`.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests, 98 core tests, and 3 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_tcp_egress_connects_and_exchanges_bytes_through_forwarder ... ok`
- `foxprox_egress::tests::blocking_udp_egress_sends_datagram_through_forwarder ... ok`
- `foxprox_egress::tests::missing_endpoint_maps_to_egress_errors ... ok`

### Interpretation
The workspace now has concrete host-socket TCP and UDP egress implementations outside `foxprox-core`, preserving the core boundary while proving loopback host networking through the existing policy/audit forwarding harnesses. Missing endpoints map to structured egress errors for observable broker error paths.

### Changed files
- `Cargo.toml`
- `Cargo.lock`
- `crates/foxprox-egress/Cargo.toml`
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- TCP egress is a blocking proof that writes one sandbox byte slice and reads until EOF/limit; it is not the final async smoltcp stream bridge.

## 2026-06-21 — Reviewer round 5 DNS answer-class fix cycle

### Behavior under work
Fix DNS upstream response validation so answer resource-record classes must match the validated question class before returned A/AAAA addresses can be audited or cached for hostname attribution.

### Expected evidence
- Upstream response with matching transaction/question/name but wrong answer class returns REFUSED/fail-closed, appends `dns_upstream_error=malformed_response`, and leaves DNS cache empty.
- Valid IN-class A responses still parse and cache as before.

### Commands run
- `cargo fmt` — applied formatting for DNS answer-class validation.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests, 99 core tests, and 3 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `dns_handler::tests::wrong_answer_class_fails_closed_without_cache_update ... ok`
- `dns_handler::tests::allowed_query_returns_upstream_response_and_observes_addresses ... ok`

### Interpretation
DNS upstream validation now rejects answer RRs whose class differs from the validated question class before returned addresses can be audited or committed to attribution cache. This prevents false hostname attribution from same-name, wrong-class answers while preserving valid IN-class response handling.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `progress.md`

### Remaining blind spots
- DNS validation still handles the subset of A/AAAA response metadata needed for alpha attribution; richer RRsets and CNAME chains remain future DNS resolver work.

## 2026-06-21 — TUN-like packet device IO adapter cycle

### Behavior under work
Add a concrete device crate with a TUN-like packet IO adapter that implements the core `PacketDevice` trait over replaceable `Read`/`Write` objects, preserving packet-boundary reads and bounded MTU buffers without putting OS-specific unsafe code in the core.

### Expected evidence
- Packet bytes read from a TUN-like IO object are processed by `TunPacketHarness` and produce structured `packet_observed` audit evidence.
- ICMP write-back through the adapter writes reply bytes to the underlying sink after audit gating.
- Read/write IO failures map to structured `DeviceIoError` values instead of panics.

### Commands run
- `cargo fmt` — applied formatting for `foxprox-device`.
- `cargo test --all-targets --all-features` — passed, 4 CLI tests, 99 core tests, 3 device tests, and 3 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — initially failed on a test default-field reassignment; fixed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed after fix.

### Evidence excerpts
- `foxprox_device::tests::tun_io_device_feeds_packet_harness_observation ... ok`
- `foxprox_device::tests::tun_io_device_writes_icmp_reply_after_audit ... ok`
- `foxprox_device::tests::tun_io_device_maps_read_write_failures ... ok`

### Interpretation
The workspace now has a concrete TUN-like packet IO adapter outside `foxprox-core`. It implements the core `PacketDevice` trait over replaceable `Read`/`Write` objects, feeds packets into the audited TUN harness, writes ICMP replies after audit gating, and maps IO failures into structured device errors.

### Changed files
- `Cargo.toml`
- `Cargo.lock`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-device/Cargo.toml`
- `crates/foxprox-device/src/lib.rs`
- `progress.md`

### Remaining blind spots
- This is a TUN-like IO adapter, not Linux `/dev/net/tun` creation or namespace configuration. OS-specific TUN opening/handoff remains a runtime integration gap.

## 2026-06-21 — bwrap setup plan CLI observability cycle

### Behavior under work
Expose the existing bwrap-compatible setup plan through the `foxprox` CLI so callers can inspect the exact bwrap/setup command contract and setup audit evidence before attempting privileged runtime execution.

### Expected evidence
- `foxprox plan-bwrap <config> -- <target...>` emits structured JSON containing bwrap args, `foxproxsetup` command, proxy environment, and setup audit record.
- Missing target separator/command and invalid config emit fail-closed audit JSON rather than panicking.

### Commands run
- `cargo fmt` — applied formatting for bwrap plan CLI changes.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 99 core tests, 3 device tests, and 3 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_cli::tests::plan_bwrap_prints_plan_and_setup_audit ... ok`
- `foxprox_cli::tests::plan_bwrap_missing_target_prints_fail_closed_audit ... ok`

### Interpretation
The `foxprox` CLI can now emit an inspectable bwrap-compatible setup plan from runtime config and target command, including the exact `foxproxsetup` command, bwrap args, proxy environment, and `setup_plan_created` audit record. Invalid invocation paths produce fail-closed audit JSON.

### Changed files
- `crates/foxprox-cli/src/lib.rs`
- `progress.md`

### Remaining blind spots
- The CLI still does not execute bwrap or configure TUN; it exposes the setup contract for inspection before privileged runtime work.

## 2026-06-21 — Round-6 high findings cycle

### Behavior under work
Fix reviewer high notes before further alpha runtime work: DNS upstream validation must reject same-name IN-class address records whose RR type does not match the validated query type, and TUN write-back failures must be auditable without implying a successful write.

### Expected evidence
- AAAA-query responses that contain A answer RRs fail closed, return REFUSED, record `dns_upstream_error=malformed_response`, and leave attribution cache empty.
- ICMP TUN write-back audit is explicitly a write attempt; device write failures append structured `broker_error` evidence before returning `DeviceIoError::WriteFailed`.

### Commands run
- `cargo fmt` — applied formatting for DNS RR-type and TUN write-failure audit fixes.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, and 3 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — initially failed on `Option::is_none_or` because the workspace MSRV is Rust 1.80; replaced with an explicit `match`.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed after the MSRV-safe helper change.

### Evidence excerpts
- `dns_handler::tests::wrong_answer_type_fails_closed_without_cache_update ... ok`
- `dns_handler::tests::wrong_answer_class_fails_closed_without_cache_update ... ok`
- `tun::tests::icmp_echo_write_failure_is_audited_without_success_claim ... ok`

### Interpretation
Round-6 high findings are fixed. Validated DNS responses now reject address RR types that do not match the original query type before any hostname attribution cache commit. TUN write-back evidence now explicitly records a `write_phase=attempt`, and device write failure appends structured `broker_error` evidence with `device_io_error=write_failed` before surfacing `DeviceIoError::WriteFailed`.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-core/src/tun.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- DNS still validates only the alpha-relevant address attribution subset; full CNAME/SVCB/HTTPS chain handling remains future resolver work.
- TUN write success is represented by the absence of a device error after an audited write attempt; adding a post-write success record would require a separate non-gating telemetry path to avoid unobserved writes on audit backpressure.

## 2026-06-21 — smoltcp IP stack adapter proof cycle

### Behavior under work
Add an alpha userspace stack adapter crate using `smoltcp` with an in-memory IP-medium device, proving that raw IP packets can enter the selected stack and bounded outbound packets can be emitted without leaking smoltcp types into policy/core modules.

### Expected evidence
- A valid IPv4 ICMP echo request injected as a TUN-style IP packet is consumed by `smoltcp` and emits an IPv4 echo reply packet.
- The adapter reports bounded poll evidence (`packets_emitted`, `outbound_bytes`, `poll_result`) and exposes MTU/queue behavior for later TUN fd wiring.

### Commands run
- `cargo fmt` — applied formatting for the new stack adapter crate.
- `cargo test -p foxprox-stack --all-targets --all-features` — initially failed because `smoltcp::iface::Interface` does not implement `Debug`; removed the derive and reran successfully with 2 stack tests passed.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, 3 egress tests, and 2 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply ... ok`
- `foxprox_stack::tests::in_memory_ip_device_exposes_bounded_mtu_capabilities ... ok`

### Interpretation
The workspace now includes a `foxprox-stack` adapter crate that uses `smoltcp` behind a narrow boundary. An in-memory IP-medium device accepts raw TUN-style IP packets, `Interface::poll` processes them, and outbound IP packets are captured with bounded poll evidence. The first proof shows an IPv4 ICMP echo request entering smoltcp and an echo reply leaving the stack.

### Changed files
- `Cargo.toml`
- `Cargo.lock`
- `crates/foxprox-stack/Cargo.toml`
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This proves the smoltcp/IP-packet boundary and outbound packet emission, not full TCP host-socket bridging yet.
- The adapter still uses an in-memory device; wiring `foxprox-device` TUN IO and host egress loops into the stack remains future runtime work.

## 2026-06-21 — smoltcp-to-packet-device bridge cycle

### Behavior under work
Wire the smoltcp adapter proof to the core `PacketDevice` contract so a TUN-like packet source can feed smoltcp and smoltcp-emitted IP packets can be audited and written back through the same device abstraction.

### Commands run
- `cargo fmt` — applied formatting for the bridge additions.
- `cargo test -p foxprox-stack --all-targets --all-features` — passed, 3 stack tests.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, 3 egress tests, and 3 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_and_writes_stack_output ... ok`
- `foxprox_stack::tests::smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply ... ok`

### Interpretation
The stack proof now includes a bridge from the core `PacketDevice` trait into smoltcp and back out to the packet device. Both inbound and outbound stack packets are structured as `packet_observed` audit records with `stack=smoltcp`; outbound writes are gated by a `write_phase=attempt` audit before device write.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `progress.md`

### Remaining blind spots
- TCP accept/connect byte bridging through smoltcp sockets is still outstanding.
- The bridge still uses in-memory packet devices in tests; real `/dev/net/tun` fd opening and bwrap handoff are not complete.

## 2026-06-21 — Round-7 smoltcp bridge policy gate cycle

### Behavior under work
Fix the reviewer blocker in `SmoltcpTunBridge`: TUN packets must be observed and then evaluated by the broker before smoltcp receives them, so default-denied ICMP/TCP/UDP traffic cannot cause stack output or device writes.

### Expected evidence
- Default-denied ICMP echo traffic through the smoltcp bridge emits a policy decision, does not poll/inject smoltcp, and writes no reply.
- Explicitly ping-allowed ICMP echo traffic still reaches smoltcp, emits a reply, records inbound policy decision evidence, and gates outbound write with structured write-attempt audit.

### Commands run
- `cargo fmt` — applied formatting for smoltcp bridge policy gate changes.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, 3 egress tests, and 4 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tun_bridge_default_denies_before_stack_poll_or_write ... ok`
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_and_writes_stack_output ... ok`

### Interpretation
The round-7 blocker is fixed. `SmoltcpTunBridge` now appends inbound packet observation, then calls the shared broker policy evaluator before injecting any packet into smoltcp. Default-denied ICMP traffic emits an `icmp_decision` denial, performs no stack poll output, and writes no packet. Explicitly ping-allowed traffic still reaches smoltcp and writes the audited echo reply.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `progress.md`

### Remaining blind spots
- The bridge now preserves the existing TUN policy gate, but full smoltcp TCP socket accept/connect and host TCP byte bridging are still outstanding.

## 2026-06-21 — smoltcp TCP listener proof cycle

### Behavior under work
Extend the smoltcp adapter from ICMP packet emission into a TCP socket proof: the stack should listen on a broker IP/port, complete a minimal TCP handshake from injected sandbox packets, and expose received stream bytes without leaking smoltcp APIs into core.

### Expected evidence
- Injected SYN produces a SYN-ACK IP packet from smoltcp.
- Injected ACK plus PSH/ACK payload reaches a smoltcp TCP listener and can be drained as stream bytes.
- The proof remains bounded/in-memory and keeps remaining host egress byte-bridge work explicit.

### Commands run
- `cargo fmt` — applied formatting for smoltcp TCP listener proof.
- `cargo test -p foxprox-stack --all-targets --all-features` — initially passed with warnings for unused TCP flag constants; removed unused constants.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, 3 egress tests, and 5 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tcp_listener_accepts_handshake_and_receives_bytes ... ok`
- `foxprox_stack::tests::smoltcp_tun_bridge_default_denies_before_stack_poll_or_write ... ok`

### Interpretation
The smoltcp adapter now proves more than packet-level ICMP: it can host a TCP listener, produce a SYN-ACK from an injected SYN, accept the completing ACK, and expose payload bytes from an injected PSH/ACK as TCP stream data. This keeps smoltcp socket details inside `foxprox-stack` while preserving the core policy/audit boundary.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This proof drains stream bytes from smoltcp but does not yet connect those bytes to `foxprox-egress` host TCP sockets or bridge host responses back through the smoltcp socket.

### Commands run
- `cargo fmt` — applied formatting for smoltcp TCP egress bridge changes.
- `cargo test -p foxprox-stack --all-targets --all-features` — passed, 7 stack tests.
- `cargo test --all-targets --all-features` — passed, 6 CLI tests, 101 core tests, 3 device tests, 3 egress tests, and 7 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tcp_stream_bridges_host_response_back_to_stack_packets ... ok`
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_tcp_egress_and_flow_close ... ok`
- `foxprox_stack::tests::smoltcp_tcp_listener_accepts_handshake_and_receives_bytes ... ok`

### Interpretation
The smoltcp TCP path now proves a bounded host-egress bridge shape: bytes drained from an accepted smoltcp TCP stream are sent through a `TcpEgress` implementation, response bytes are pushed back into the smoltcp socket, and smoltcp emits outbound IP packets carrying the host response. The `SmoltcpTunBridge` variant evaluates the shared broker policy before opening egress and appends structured `tcp_connect_decision` plus `tcp_flow_closed` evidence with byte counts.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The bridge proof still uses in-memory TCP packets and mock egress in tests; real `/dev/net/tun`, async host sockets, and continuous bidirectional stream scheduling remain runtime integration work.

## 2026-06-21 — foxproxsetup helper plan cycle

### Behavior under work
Make the bwrap `foxproxsetup` helper contract observable as its own structured setup plan, including TUN creation/configuration, route/DNS/proxy setup, fd handoff intent, capability drop, and target exec steps.

### Expected evidence
- Core setup tests assert structured helper steps for `ip tuntap`, address/MTU/link up, default route, DNS, proxy reachability, fd handoff, capability drop, and exec.
- A `foxproxsetup` CLI binary can parse the same flag shape emitted by `BwrapSetupPlan` and output helper plan JSON plus structured setup audit.

### Commands run
- `cargo fmt` — applied formatting for setup helper plan and `foxproxsetup` CLI binary.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 3 egress tests, and 7 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `setup::tests::setup_helper_plan_contains_network_setup_and_exec_contract ... ok`
- `setup::tests::setup_helper_plan_audit_is_structured ... ok`
- `foxprox_cli::tests::foxproxsetup_plan_parses_bwrap_helper_flags ... ok`
- `foxprox_cli::tests::foxproxsetup_missing_target_prints_fail_closed_audit ... ok`

### Interpretation
The bwrap setup helper is now represented by a structured `SetupHelperPlan`, and the workspace builds a `foxproxsetup` binary that parses the same flag shape emitted by `BwrapSetupPlan`. The helper plan captures TUN creation/configuration, route, DNS, proxy reachability, fd handoff intent, setup capability drop, and target exec as observable steps with structured audit.

### Changed files
- `crates/foxprox-core/src/setup.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-cli/Cargo.toml`
- `crates/foxprox-cli/src/lib.rs`
- `crates/foxprox-cli/src/setup_main.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- `foxproxsetup` is still plan-first and does not execute privileged `ip` commands, send a real TUN fd, or exec the target. Real privileged setup execution remains runtime integration work.

## 2026-06-21 — Round-9 TCP bridge observability fixes cycle

### Behavior under work
Fix round-9 high/blocker findings before further runtime work: TCP stream egress responses emitted by smoltcp must be audited and written to the packet device, TCP egress decision/close records must preserve the accepted sandbox source endpoint, and the setup helper plan must include closing setup-only file descriptors before exec.

### Expected evidence
- `SmoltcpTunBridge::bridge_first_tcp_stream_to_egress` writes newly emitted host-response packets to the underlying `PacketDevice` after structured `to_sandbox` write-attempt audit.
- TCP connect/close audit records include the accepted smoltcp stream's sandbox source endpoint.
- `SetupHelperPlan` includes `close_setup_fds` before `exec_target`, with structured evidence.

### Commands run
- `cargo fmt` — applied formatting for round-9 TCP bridge and setup helper fixes.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 3 egress tests, and 7 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_tcp_egress_and_flow_close ... ok`
- `setup::tests::setup_helper_plan_contains_network_setup_and_exec_contract ... ok`
- `foxprox_cli::tests::foxproxsetup_plan_parses_bwrap_helper_flags ... ok`

### Interpretation
Round-9 findings are fixed. The smoltcp TCP bridge now derives the accepted sandbox peer endpoint from smoltcp socket metadata, includes it in TCP connect/close/error audit records, collects newly emitted host-response IP packets, gates each `to_sandbox` packet with structured write-attempt audit, and writes them through the underlying `PacketDevice`. The setup helper plan now includes `close_setup_fds` with explicit `closes_setup_only_fds=true` evidence before capability drop and target exec.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `crates/foxprox-core/src/setup.rs`
- `crates/foxprox-cli/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Packet writes are still exercised through in-memory devices; real TUN fd IO and continuous async scheduling remain runtime integration work.
- `foxproxsetup` remains plan-first and still does not execute privileged setup commands or fd passing.

## 2026-06-21 — Round-10 TCP packet-device write failure audit cycle

### Behavior under work
Fix the round-10 high finding: smoltcp TCP response packet writes through `PacketDevice` must record structured broker error evidence before returning on device write failure.

### Expected evidence
- A failing packet device in `SmoltcpTunBridge::bridge_first_tcp_stream_to_egress` returns `TcpEgressError::BridgeFailed` only after appending `broker_error` with `device_io_error=write_failed`, `direction=to_sandbox`, `stack=smoltcp`, and TCP stream endpoint details.
- Successful TCP response write path remains unchanged and continues to emit `packet_observed` write-attempt plus `tcp_flow_closed` byte-count audit.

### Commands run
- `cargo fmt` — applied formatting for round-10 write-failure audit fix.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 3 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — initially failed on default-constructing a unit test device; fixed by constructing the unit struct directly.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed after the test fix.

### Evidence excerpts
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_tcp_response_write_failure ... ok`
- `foxprox_stack::tests::smoltcp_tun_bridge_audits_tcp_egress_and_flow_close ... ok`

### Interpretation
Round-10 high finding is fixed. Smoltcp TCP response packet device write failures now append structured `broker_error` evidence with `device_io_error=write_failed`, `direction=to_sandbox`, `stack=smoltcp`, and TCP stream endpoint details before returning `TcpEgressError::BridgeFailed`. Successful TCP response writes continue to emit write-attempt packet audit and flow-close byte counts.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `progress.md`

### Remaining blind spots
- The failing write path is covered with an in-memory failing `PacketDevice`; real TUN fd write errors remain part of future runtime integration.

## 2026-06-21 — Concrete DNS UDP upstream egress cycle

### Behavior under work
Close the DNS upstream blind spot by adding a concrete UDP socket `DnsUpstream` implementation outside `foxprox-core`, so the DNS broker handler can exchange real UDP datagrams with an upstream resolver while preserving core policy/audit validation.

### Expected evidence
- A local UDP resolver receives the original DNS query bytes through `BlockingDnsUpstream` and returns a response that `DnsBrokerHandler` validates, audits, and commits to DNS attribution cache.
- UDP socket timeout/IO failures map to `DnsUpstreamError::Unavailable` so the handler fails closed with structured `dns_upstream_error=unavailable`/`malformed_response` paths rather than panicking.

### Commands run
- `cargo fmt` — applied formatting for concrete DNS upstream egress.
- `cargo test -p foxprox-egress --all-targets --all-features` — initially failed on an ambiguous `parse()` type in the new DNS test; fixed with explicit `IpAddr` type and reran successfully with 5 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 5 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_upstream_exchanges_query_through_dns_handler ... ok`
- `foxprox_egress::tests::blocking_dns_upstream_unavailable_maps_to_handler_fail_closed ... ok`

### Interpretation
DNS upstream forwarding now has a concrete host UDP socket implementation behind the core `DnsUpstream` trait. A local UDP resolver test proves the broker sends the original DNS query bytes, validates the returned response, emits structured returned-address audit, and commits attribution. Timeout/IO failure maps to `DnsUpstreamError::Unavailable`, which the handler converts into fail-closed REFUSED plus structured `dns_upstream_error` evidence.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is a blocking UDP upstream proof, not the final async DNS runtime listener. Real resolver configuration, retry policy, and socket lifecycle integration remain runtime work.

## 2026-06-22 — Round-11 DNS upstream source validation cycle

### Behavior under work
Fix round-11 high finding: concrete UDP DNS upstream egress must reject responses whose source socket address does not match the configured upstream resolver before the DNS handler can validate and commit hostname attribution.

### Expected evidence
- A wrong-source but otherwise payload-valid DNS response maps to `DnsUpstreamError::Unavailable`, causing `DnsBrokerHandler` to fail closed with REFUSED and structured `dns_upstream_error=unavailable`.
- Valid responses from the configured upstream still pass validation, audit returned addresses, and commit attribution.

## 2026-06-22 — Round-11 DNS upstream source validation fix

### Commands run
- `cargo fmt` — applied formatting for DNS upstream source validation.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 6 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 6 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_upstream_rejects_wrong_source_response ... ok`
- `foxprox_egress::tests::blocking_dns_upstream_exchanges_query_through_dns_handler ... ok`
- `foxprox_egress::tests::blocking_dns_upstream_unavailable_maps_to_handler_fail_closed ... ok`

### Interpretation
Round-11 high finding is fixed. `BlockingDnsUpstream` now verifies the UDP response peer equals the configured upstream resolver before releasing bytes to `DnsBrokerHandler`. Wrong-source but payload-valid DNS answers map to `DnsUpstreamError::Unavailable`; the handler fails closed with REFUSED, emits structured `dns_upstream_error=unavailable`, and leaves the DNS attribution cache empty. Valid configured-upstream responses still audit and cache normally.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Source validation is implemented in the blocking UDP proof; final async resolver runtime still needs equivalent peer validation and retry/lifecycle behavior.

## 2026-06-22 — DNS upstream socket config cycle

### Behavior under work
Make the concrete DNS upstream egress configurable from runtime config by carrying a full upstream socket address, not just an IP address, while keeping validation/audit schema observable.

### Expected evidence
- Runtime config default serializes `dns_upstream` as `1.1.1.1:53` and validation audit records the same socket address.
- Invalid zero DNS upstream port fails config validation with structured `dns_upstream_port_zero` evidence.
- `BlockingDnsUpstream` can be constructed from `BrokerRuntimeConfig`, preserving peer-source validation against the configured socket address.

### Commands run
- `cargo fmt` — applied formatting for DNS upstream socket config.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 6 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `config::tests::runtime_config_serializes_stable_alpha_fields_and_audit ... ok`
- `config::tests::runtime_config_validation_reports_setup_policy_and_limit_errors ... ok`
- `foxprox_egress::tests::blocking_dns_upstream_exchanges_query_through_dns_handler ... ok`

### Interpretation
Runtime config now carries `dns_upstream` as a full socket address (`1.1.1.1:53` by default), validates non-zero upstream ports with structured `dns_upstream_port_zero` evidence, and records the socket address in validation audit. `BlockingDnsUpstream::from_runtime_config` uses that exact socket address, aligning config, source validation, and concrete UDP egress behavior.

### Changed files
- `crates/foxprox-core/src/config.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Config now carries the resolver socket identity, but there is still no long-running async DNS listener wiring runtime config into a process lifecycle.

## 2026-06-22 — Blocking DNS broker UDP listener proof cycle

### Behavior under work
Add a concrete blocking UDP broker listener proof that receives DNS datagrams on a sandbox-reachable socket, runs them through `DnsBrokerHandler`, and sends allowed/refused responses back to the client with structured step evidence.

### Expected evidence
- A local UDP client can send a DNS query to the broker socket and receive the upstream-validated response through `BlockingDnsBrokerServer::handle_one`.
- The listener step result records client address, response length, send status, and policy decision.
- Denied/refused paths remain handler-owned and observable through broker audit records.

## 2026-06-22 — Round-12 DNS source-mismatch evidence and listener proof

### Commands run
- `cargo fmt` — applied formatting for DNS source-mismatch evidence and blocking broker listener proof.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 8 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 8 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_upstream_rejects_wrong_source_response ... ok`
- `foxprox_egress::tests::blocking_dns_broker_server_handles_one_allowed_query ... ok`
- `foxprox_egress::tests::blocking_dns_broker_server_sends_refused_for_denied_query ... ok`

### Interpretation
Round-12 high finding is fixed: wrong-source DNS replies now map to `DnsUpstreamError::SourceMismatch`, producing structured `dns_upstream_error=source_mismatch` and preserving fail-closed/no-cache behavior. The egress crate also now includes a blocking DNS broker UDP listener proof that receives one client datagram, delegates policy/upstream/cache behavior to `DnsBrokerHandler`, sends a response when available, and returns structured step evidence including client, query length, response length, send status, decision, and reason.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The DNS listener proof is blocking and single-step; final runtime still needs async lifecycle management, retry policy, and integration with sandbox setup/broker process supervision.

## 2026-06-22 — Round-13 DNS listener send-failure fix

### Commands run
- `cargo fmt` — applied formatting for DNS listener send-failure handling.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 9 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 9 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_broker_server_audits_send_failure_and_rolls_back_cache ... ok`
- `foxprox_egress::tests::blocking_dns_broker_server_handles_one_allowed_query ... ok`
- `foxprox_egress::tests::blocking_dns_broker_server_sends_refused_for_denied_query ... ok`

### Interpretation
Round-13 high finding is fixed. `BlockingDnsBrokerServer::handle_one` now reports response send failure as structured step evidence (`send_status=send_failed`, `sent_response=false`, fail-closed/resource-limit decision), appends a `broker_error` audit with `dns_client_send_failed`, and rolls back the just-committed DNS observation so attribution cache state only reflects responses delivered to the sandbox. Successful send paths still report `send_status=sent` and preserve handler audit/cache behavior.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Send-failure rollback is implemented for the blocking listener proof; final async DNS runtime must preserve the same delivery-gated attribution behavior.

## 2026-06-22 — Round-14 DNS rollback precision cycle

### Behavior under work
Fix round-14 high finding: DNS client-send rollback must remove only the just-inserted observation instance, not all equal historical observations, so a failed duplicate response cannot erase prior successfully delivered attribution.

### Expected evidence
- `DnsCache::rollback_observation` removes one matching observation per address.
- A broker listener sequence with one successful DNS response followed by an identical same-timestamp send failure keeps the earlier delivered attribution in cache while still auditing the failed send.

## 2026-06-22 — Round-14 precise DNS rollback fix

### Commands run
- `cargo fmt` — applied formatting for precise DNS rollback changes.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 10 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 10 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_send_failure_rolls_back_only_latest_duplicate_observation ... ok`
- `foxprox_egress::tests::blocking_dns_broker_server_audits_send_failure_and_rolls_back_cache ... ok`

### Interpretation
Round-14 high finding is fixed. DNS rollback now removes only one matching observation per address, preserving older delivered attributions even when a later identical same-timestamp DNS response fails client delivery. The integration regression proves a successful send followed by an identical failed send keeps attribution available while still recording `dns_client_send_failed` evidence.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Rollback precision is covered in the blocking DNS listener proof; async runtime must use the same delivery-token/rollback semantics.

## 2026-06-22 — Blocking HTTP proxy listener proof cycle

### Behavior under work
Add a concrete single-step TCP listener proof for explicit HTTP proxy traffic, so a sandbox-reachable TCP connection can feed `ExplicitProxyFrontend`, return a client-visible status, and expose structured listener step evidence.

### Expected evidence
- A local TCP client can send an absolute-form HTTP proxy request to `BlockingHttpProxyServer::handle_one`, which routes through the shared policy/audit frontend and returns a response on the client socket.
- Denied proxy requests produce client-visible denial status and structured step evidence without forwarding to egress.
- Client response write failures emit structured `broker_error` evidence before returning step failure.

## 2026-06-22 — Blocking HTTP proxy listener proof

### Commands run
- `cargo fmt` — applied formatting for blocking HTTP proxy listener proof.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 12 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 12 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_http_proxy_server_handles_allowed_request ... ok`
- `foxprox_egress::tests::blocking_http_proxy_server_denies_without_forwarding ... ok`

### Interpretation
The egress crate now includes a concrete single-step blocking HTTP proxy listener proof. A local TCP client can connect, send an absolute-form HTTP proxy request, and receive a client-visible status while `BlockingHttpProxyServer` delegates parse/policy/egress to the shared `ExplicitProxyFrontend`. Allowed requests forward through the configured proxy egress and emit `http_request_decision`; denied CONNECT requests return 403, do not forward, and preserve policy audit evidence. Listener step results expose client address, request length, response length, status code, send status, decision, reason, and forwarded flag.

### Changed files
- `crates/foxprox-core/src/proxy_frontend.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The listener proof writes synthetic proxy status responses and handles one accepted connection; final async proxy runtime still needs streaming HTTP response/CONNECT tunneling, SOCKS listener sockets, and process lifecycle supervision.

## 2026-06-22 — Round-15 HTTP proxy listener failure-path fix

### Commands run
- `cargo fmt` — applied formatting for round-15 proxy listener fixes.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 14 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 14 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_http_proxy_server_audits_client_send_failure_with_sandbox_id ... ok`
- `foxprox_egress::tests::blocking_http_proxy_server_maps_egress_failure_to_client_status ... ok`

### Interpretation
Round-15 high findings are fixed. HTTP proxy listener client-response write failures now audit `http_proxy_client_send_failed` under the real `ExplicitProxyFrontend` sandbox id instead of a hard-coded listener label, and deterministic regression coverage asserts `send_status=send_failed` plus sandbox attribution. Allowed proxy egress failures no longer escape the listener before client-visible evidence: the frontend still records `proxy_egress_send_failed`, while the listener returns a structured fail-closed step and attempts a 502 response to the client.

### Changed files
- `crates/foxprox-core/src/proxy_frontend.rs`
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Explicit proxy runtime still lacks SOCKS5 TCP listener/tunnel proof, streaming HTTP response/CONNECT tunneling, and async lifecycle supervision.

## 2026-06-22 — Blocking SOCKS5 listener proof cycle

### Behavior under work
Add a concrete single-step TCP listener proof for SOCKS5 CONNECT traffic: accept a sandbox-reachable TCP connection, complete the no-auth method handshake, parse the CONNECT request through `ExplicitProxyFrontend`, return a client-visible SOCKS5 reply, and expose structured listener step evidence.

### Expected evidence
- Allowed SOCKS5 domain CONNECT reaches shared policy/audit, forwards through proxy egress, and returns a success reply.
- Denied SOCKS5 CONNECT returns a failure reply and does not forward.
- Malformed/unsupported SOCKS paths fail closed with structured step evidence.

## 2026-06-22 — Blocking SOCKS5 listener proof

### Commands run
- `cargo fmt` — applied formatting for blocking SOCKS5 listener proof.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 17 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 103 core tests, 3 device tests, 17 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_socks5_proxy_server_handles_allowed_connect ... ok`
- `foxprox_egress::tests::blocking_socks5_proxy_server_denies_without_forwarding ... ok`
- `foxprox_egress::tests::blocking_socks5_proxy_server_rejects_unsupported_greeting ... ok`

### Interpretation
The egress crate now includes a concrete single-step blocking SOCKS5 proxy listener proof. A local TCP client can complete the no-auth method handshake, send a SOCKS5 CONNECT request, route through shared `ExplicitProxyFrontend` policy/audit, and receive a SOCKS5 reply. Allowed domain CONNECTs forward through configured proxy egress and emit `socks_connect_decision`; denied IP CONNECTs return connection-not-allowed without forwarding; unsupported greetings fail closed with structured listener step evidence. Step evidence includes client address, greeting length, request length, response length, reply code, send status, decision, reason, and forwarded flag.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Explicit proxy listeners are still blocking single-step proofs. Final runtime still needs bidirectional CONNECT stream tunneling, HTTP response streaming, asynchronous accept loops, and lifecycle supervision integrated with sandbox setup.

## 2026-06-22 — Blocking explicit proxy host egress proof cycle

### Behavior under work
Add concrete host-socket explicit proxy egress for HTTP proxy forwarding and SOCKS5 CONNECT destinations, keeping host socket APIs outside `foxprox-core` while proving listener/frontend decisions can reach a real local TCP peer.

### Expected evidence
- HTTP proxy egress connects to a local host TCP listener and sends the parsed proxy request bytes after shared policy/audit allow.
- SOCKS5 CONNECT egress opens a local host TCP connection for an allowed destination.
- Missing or unavailable destinations fail closed via existing proxy egress error paths.

## 2026-06-22 — Round-16 SOCKS hardening and explicit proxy egress proof

### Commands run
- `cargo fmt` — applied formatting for SOCKS hardening and explicit proxy egress proof.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 104 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 21 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 104 core tests, 3 device tests, 21 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::proxy::tests::socks5_nonzero_reserved_byte_fails_closed_with_structured_detail ... ok`
- `foxprox_egress::tests::blocking_socks5_proxy_server_fails_closed_for_truncated_connect_request ... ok`
- `foxprox_egress::tests::blocking_socks5_proxy_server_rejects_nonzero_reserved_byte_without_forwarding ... ok`
- `foxprox_egress::tests::blocking_socks5_proxy_server_rejects_unsupported_greeting ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_http_egress_reaches_host_socket_after_policy ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_opens_host_socket_after_policy ... ok`

### Interpretation
Round-16 blocker/high findings are fixed and the earlier clippy evidence overclaim is corrected by rerunning the full validation sequence successfully. SOCKS5 CONNECT parsing now rejects nonzero RSV bytes with stable `unsupported_socks_reserved` evidence. Unsupported greetings and truncated CONNECT reads no longer escape as unstructured listener errors: they fail closed with client-visible SOCKS failure replies, structured step evidence, and shared `unsupported_denied` audit records. The listener regression also proves malformed RSV requests do not forward to egress.

The egress crate now includes `BlockingExplicitProxyEgress`, a concrete host-socket proof for explicit HTTP proxy forwarding and SOCKS5 CONNECT. Tests show allowed proxy requests reach a local host TCP peer only after shared policy/audit allow evidence has been recorded.

### Changed files
- `crates/foxprox-core/src/proxy.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Explicit proxy host egress is still blocking and proof-oriented: it does not yet stream bidirectional CONNECT bytes, relay host HTTP responses to clients, supervise async accept loops, or integrate listener lifecycle with bwrap/TUN setup.

## 2026-06-22 — Setup helper execution harness cycle

### Behavior under work
Add a bounded setup-helper execution harness over the existing `SetupHelperPlan`, using an injectable command runner so setup step ordering, fail-closed behavior, and structured evidence can be tested without embedding Linux-specific command execution in `foxprox-core`.

### Expected evidence
- Successful setup execution records each step and produces `tun_configured` audit evidence before target exec in the harness.
- A failing setup step stops execution before later privileged/drop/exec steps and emits structured `broker_error` evidence with step name/index.

## 2026-06-22 — Setup helper execution harness

### Commands run
- `cargo fmt` — applied formatting for setup execution harness.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 106 core tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 106 core tests, 3 device tests, 21 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::setup::tests::setup_execution_harness_records_successful_steps ... ok`
- `foxprox_core::setup::tests::setup_execution_harness_stops_and_audits_failed_step ... ok`

### Interpretation
The setup helper path now has an executable harness over `SetupHelperPlan` using an injectable `SetupStepRunner`. Successful harness execution records all setup steps and emits structured `tun_configured` evidence with executed step count and target-exec readiness. A failing setup step stops execution before later setup/drop/exec steps and emits structured `broker_error` evidence with `setup_step`, `setup_step_index`, `setup_error`, and `completed_steps`.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/setup.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The harness intentionally does not run Linux `ip`, open `/dev/net/tun`, pass real fds, or exec a target process. Concrete privileged setup execution and fd handoff remain runtime integration work outside the platform-independent core.

## 2026-06-22 — Round-17 pre-exec setup and proxy DNS-boundary fix

### Commands run
- `cargo fmt` — applied formatting for round-17 fixes.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 106 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 23 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 106 core tests, 3 device tests, 23 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::setup::tests::setup_execution_harness_records_successful_steps ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_rejects_domain_without_host_dns ... ok`
- `foxprox_egress::tests::blocking_socks5_method_selection_write_failure_is_audited ... ok`

### Interpretation
Round-17 high findings are fixed. `SetupHelperPlan` now keeps target execution out of setup steps; the execution harness emits `tun_configured` after setup/close/drop steps and before target exec readiness, avoiding the impossible pattern where real exec would happen before audit evidence can be returned. `BlockingExplicitProxyEgress` no longer uses host DNS resolution for proxy domain destinations: HTTP egress requires an IP-literal host, SOCKS hostnames fail closed until an audited broker DNS resolution path exists, and an egress regression proves allowed SOCKS domain requests become structured `proxy_egress_send_failed` instead of using libc DNS. SOCKS5 method-selection success-reply write failures now produce structured `broker_error` evidence instead of escaping as an unobservable listener error.

### Changed files
- `crates/foxprox-core/src/setup.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Domain-based explicit proxy host egress needs an audited broker DNS resolution path before TCP connect.
- Setup execution remains an injectable harness, not real Linux `/dev/net/tun` creation, fd passing, or target exec.

## 2026-06-22 — Explicit proxy broker-DNS egress resolution

### Commands run
- `cargo fmt` — applied formatting for broker-DNS proxy egress resolution.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 107 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 24 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 107 core tests, 3 device tests, 24 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::flow::tests::dns_cache_resolves_hostname_to_unexpired_observed_addresses ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_domain_uses_broker_dns_cache_after_policy ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_rejects_domain_without_host_dns ... ok`

### Interpretation
Explicit proxy host egress now has a broker-DNS resolution proof without falling back to libc host DNS. `DnsCache` can return unexpired observed addresses for a hostname, and `BlockingExplicitProxyEgress` can be configured with that cache/time to resolve domain proxy destinations before host TCP connect. A SOCKS domain CONNECT regression proves an allowed hostname reaches a local TCP peer through the broker-DNS cache, while the no-cache regression continues to fail closed with structured `proxy_egress_send_failed` evidence instead of performing host DNS.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The proof uses a snapshot cache/time. Final async runtime must wire the live DNS broker cache into explicit proxy egress and handle cache expiry/retry/lifecycle continuously.

## 2026-06-22 — Round-18 proxy domain egress rollback

### Commands run
- `cargo fmt` — applied formatting for round-18 proxy domain rollback.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 107 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 23 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 107 core tests, 3 device tests, 23 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_rejects_domain_without_host_dns ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_http_egress_reaches_host_socket_after_policy ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_opens_host_socket_after_policy ... ok`

### Interpretation
Round-18 blocker is fixed by rolling back the snapshot-cache proxy domain egress path. `BlockingExplicitProxyEgress` no longer resolves proxy hostnames inside egress and only connects to IP-literal HTTP/SOCKS destinations. Domain SOCKS requests may still be policy-allowed by hostname, but concrete host egress fails closed with existing `proxy_egress_send_failed` evidence until resolution can happen in a per-request, audit-gated frontend path that records selected IP/source/TTL before opening a socket.

### Correction to prior entry
The prior “Explicit proxy broker-DNS egress resolution” entry overclaimed support for domain proxy destinations. The durable invariant after this fix is: domain proxy egress remains fail-closed in the concrete blocking egress proof unless/until an audited per-request resolver path is added.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Domain-based explicit proxy host egress still needs a per-request audited broker DNS resolution path with selected-IP/source/TTL evidence and audit-backpressure gating before TCP connect.

## 2026-06-22 — Audit-gated explicit proxy DNS resolution

### Commands run
- `cargo fmt` — applied formatting for audit-gated proxy DNS resolution.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 109 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 24 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 109 core tests, 3 device tests, 24 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::proxy_frontend::tests::http_proxy_domain_resolution_is_audited_before_egress ... ok`
- `foxprox_core::proxy_frontend::tests::socks_domain_resolution_is_audited_before_egress ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_http_domain_uses_frontend_broker_dns_resolution ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_egress_rejects_domain_without_host_dns ... ok`

### Interpretation
The round-19 compile/format blocker is fixed and the proxy domain path is now implemented at the correct boundary. Domain resolution happens in `ExplicitProxyFrontend` with a per-request timestamp and optional broker DNS cache, not inside host egress. The frontend appends `proxy_destination_resolved` evidence with `resolution_source=broker_dns`, `selected_ip`, DNS query type, TTL remaining, hostname attribution, and destination IP before policy evaluation and before socket egress. If no audited DNS cache entry exists, concrete egress remains fail-closed. Blocking HTTP proxy egress proves a domain request can reach a local TCP peer only after frontend broker-DNS resolution evidence and policy allow evidence are recorded.

### Changed files
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/proxy.rs`
- `crates/foxprox-core/src/proxy_frontend.rs`
- `crates/foxprox-core/src/types.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The DNS cache is still passed into the frontend as a snapshot for these proofs. Final runtime must wire the live delivered-response DNS cache into proxy frontends and keep the per-request resolution audit/backpressure boundary while handling continuous expiry/retry/lifecycle.
