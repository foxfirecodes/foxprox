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

## 2026-06-22 — Proxy DNS resolution backpressure and SOCKS egress proof

### Commands run
- `cargo fmt` — applied formatting for proxy DNS resolution hardening.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 110 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 25 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 110 core tests, 3 device tests, 25 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::proxy_frontend::tests::proxy_dns_resolution_backpressure_fails_closed_before_egress ... ok`
- `foxprox_egress::tests::blocking_explicit_proxy_socks_domain_uses_frontend_broker_dns_resolution ... ok`

### Interpretation
The audit-gated proxy DNS path now proves backpressure behavior and SOCKS host egress as well as HTTP. If `proxy_destination_resolved` cannot be appended, the frontend returns `audit_backpressure` and does not call egress. SOCKS domain CONNECT now reaches concrete blocking host egress only when the frontend resolves via broker DNS cache and first records selected-IP/source/TTL evidence; no-cache SOCKS domain egress remains fail-closed.

### Changed files
- `crates/foxprox-core/src/proxy_frontend.rs`
- `crates/foxprox-egress/src/lib.rs`
- `progress.md`

### Remaining blind spots
- Live runtime still needs shared mutable DNS-cache wiring across the DNS listener and explicit proxy frontends rather than snapshot cache injection.

## 2026-06-22 — Round-20 HTTP IP-literal policy visibility fix

### Commands run
- `cargo fmt` — applied formatting for HTTP IP-literal policy visibility fix.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 112 core tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 112 core tests, 3 device tests, 25 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::proxy_frontend::tests::http_proxy_ip_literal_cidr_deny_blocks_before_egress ... ok`
- `foxprox_core::proxy_frontend::tests::http_connect_ip_literal_cidr_deny_blocks_before_egress ... ok`

### Interpretation
Round-20 high finding is fixed. HTTP proxy and CONNECT IP-literal authorities now populate destination IP in the policy request even without broker-DNS resolution, so CIDR and address-class policy checks are visible before host egress. Regressions prove HTTP and CONNECT loopback CIDR deny rules block before `ExplicitProxyEgress` is called and record the IP destination in structured audit evidence.

### Changed files
- `crates/foxprox-core/src/proxy.rs`
- `crates/foxprox-core/src/proxy_frontend.rs`
- `progress.md`

### Remaining blind spots
- Live runtime still needs shared mutable DNS-cache wiring and async proxy/TUN lifecycle integration, but IP-literal proxy destinations are now policy/audit-visible in the core contract.

## 2026-06-22 — Shared DNS cache wiring proof

### Commands run
- `cargo fmt` — applied formatting for shared DNS cache wiring.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 113 core tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 113 core tests, 3 device tests, 25 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::dns_handler::tests::shared_dns_cache_feeds_proxy_resolution_after_delivered_query ... ok`

### Interpretation
The DNS/proxy cache wiring blind spot is reduced from snapshot-only injection to a shared cache contract. `SharedDnsCache` allows `DnsBrokerHandler` to commit/rollback delivered DNS observations into a shared cache while `ExplicitProxyFrontend` resolves proxy domain destinations from that same cache with per-request timestamps. The regression proves a DNS handler observation can feed a separate proxy frontend, which then emits `proxy_destination_resolved` evidence and forwards with selected IP metadata.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-core/src/flow.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/proxy_frontend.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is still a synchronous shared-cache proof, not full async runtime supervision. The runtime must wire DNS listener delivery rollback and proxy accept loops to the same shared cache under real task scheduling.

## 2026-06-22 — Runtime lifecycle ledger harness

### Commands run
- `cargo fmt` — applied formatting for runtime lifecycle harness.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 116 core tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 116 core tests, 3 device tests, 25 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::runtime::tests::runtime_lifecycle_records_start_and_clean_exit ... ok`
- `foxprox_core::runtime::tests::runtime_lifecycle_exit_backpressure_fails_closed ... ok`
- `foxprox_core::runtime::tests::runtime_lifecycle_exit_before_start_is_rejected_without_audit ... ok`

### Interpretation
The core now has a platform-independent runtime lifecycle ledger harness. Runtime components such as TUN, smoltcp stack, DNS listener, and explicit proxy listeners can be represented in `network_session_start` evidence with component counts/names, and shutdown emits `network_session_exit` with duration and status. Exit audit backpressure is fail-closed and leaves `audit_backpressure` evidence instead of silently dropping lifecycle state.

### Changed files
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/runtime.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is a lifecycle ledger harness, not an async process/task supervisor. Final runtime must attach real listener tasks, TUN fd loops, child process exit status, and cleanup actions to this lifecycle boundary.

## 2026-06-22 — Round-23 delivery-gated shared DNS cache fix

### Commands run
- `cargo fmt` — applied formatting for delivery-gated shared DNS cache fix.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 116 core tests.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 26 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 116 core tests, 3 device tests, 26 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_core::dns_handler::tests::shared_dns_cache_feeds_proxy_resolution_after_delivered_query ... ok`
- `foxprox_egress::tests::blocking_dns_send_failure_does_not_publish_to_shared_proxy_cache ... ok`
- `foxprox_egress::tests::blocking_dns_send_failure_rolls_back_only_latest_duplicate_observation ... ok`

### Interpretation
Round-23 blocker is fixed. DNS handler query processing now returns a pending observation without publishing it to the shared DNS cache. `BlockingDnsBrokerServer` commits the observation only after a successful client send, preserving delivery-gated attribution semantics for proxy frontends sharing that cache. A send-failure regression proves failed DNS delivery does not publish to shared cache and a proxy using that cache cannot resolve the domain; the duplicate failure regression still proves prior delivered attribution survives later failed duplicate responses.

### Changed files
- `crates/foxprox-core/src/dns_handler.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Delivery-gated shared-cache semantics are proven in the blocking DNS listener. Final async DNS runtime must preserve the same commit-after-send boundary under concurrent task scheduling.

## 2026-06-22 — Round-24 runtime lifecycle state hardening

### Commands run
- `cargo fmt` — applied formatting for runtime lifecycle state-machine changes.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 5 runtime lifecycle tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 118 core tests, 3 device tests, 26 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_exit_before_start_is_audited_and_rejected ... ok`
- `runtime::tests::runtime_lifecycle_duplicate_start_is_audited_without_new_start_record ... ok`
- `runtime::tests::runtime_lifecycle_exit_is_terminal ... ok`
- `runtime::tests::runtime_lifecycle_records_start_and_clean_exit ... ok`

### Interpretation
Round-24 lifecycle findings are fixed. `RuntimeLifecycleHarness` now uses an explicit lifecycle state (`not_started`, `running`, `exited`) instead of an optional start timestamp. Invalid transitions are fail-closed and externally observable through structured `broker_error` audit records with `runtime_error`, `attempted_transition`, and `lifecycle_state`; successful exit is terminal, preventing duplicate or orphan lifecycle records for one sandbox session.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/types.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Lifecycle state is still a platform-independent harness. Final async runtime supervision must attach real listener tasks, TUN fd loops, child process exit status, and cleanup actions while preserving the same terminal lifecycle ledger semantics.

## 2026-06-22 — Blocking DNS/HTTP runtime wiring proof

### Commands run
- `cargo fmt` — applied formatting for blocking runtime wiring harness.
- `cargo test -p foxprox-egress blocking_dns_http_runtime --all-targets --all-features` — passed, targeted runtime wiring proof.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 118 core tests, 3 device tests, 27 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `foxprox_egress::tests::blocking_dns_send_failure_does_not_publish_to_shared_proxy_cache ... ok`
- `runtime::tests::runtime_lifecycle_exit_is_terminal ... ok`

### Interpretation
Added `BlockingDnsHttpRuntime` in `foxprox-egress` to bind DNS and HTTP proxy listeners through one shared DNS cache and one lifecycle harness. The regression drives real UDP DNS listener I/O, verifies the delivered DNS response populates the shared cache, then drives real TCP HTTP proxy listener I/O and verifies proxy domain resolution uses `resolution_source=broker_dns` before the allow/forward decision. Lifecycle start/exit evidence brackets the listener wiring proof.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The harness is still blocking/single-step and covers DNS + HTTP proxy only. The final runtime still needs concurrent async task scheduling, SOCKS listener inclusion, TUN fd loops, child process supervision, and cleanup actions while preserving shared-cache and lifecycle boundaries.

## 2026-06-22 — Blocking DNS/HTTP/SOCKS runtime wiring proof

### Commands run
- `cargo fmt` — applied formatting for SOCKS-inclusive blocking runtime harness.
- `cargo test -p foxprox-egress blocking_proxy_runtime --all-targets --all-features` — passed, targeted DNS-to-SOCKS runtime wiring proof.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 118 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`
- `foxprox_egress::tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `foxprox_egress::tests::blocking_dns_send_failure_does_not_publish_to_shared_proxy_cache ... ok`

### Interpretation
Added `BlockingProxyRuntime` to bind DNS, HTTP proxy, and SOCKS5 proxy listeners through a single `SharedDnsCache` and lifecycle harness. The new regression drives real UDP DNS delivery, then real TCP SOCKS5 greeting/connect listener I/O, and proves a SOCKS domain destination resolves from delivered broker DNS with structured `proxy_destination_resolved` evidence before `socks_connect_decision` and forwarding. Lifecycle start evidence includes all three listener components.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The runtime proof is still blocking/single-step. Final alpha runtime still needs concurrent async task scheduling, TUN fd loops, smoltcp integration under the runtime supervisor, child process exit status, and cleanup actions.

## 2026-06-22 — Runtime cleanup ledger evidence

### Commands run
- `cargo fmt` — applied formatting for cleanup ledger additions.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 7 runtime lifecycle tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 120 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_exit_records_cleanup_success ... ok`
- `runtime::tests::runtime_lifecycle_cleanup_failure_is_fail_closed_and_terminal ... ok`
- `runtime::tests::runtime_lifecycle_exit_is_terminal ... ok`

### Interpretation
Added `RuntimeCleanupAction` and `RuntimeCleanupReport`, plus `RuntimeLifecycleHarness::exit_with_cleanup`, so `network_session_exit` records cleanup attempts and failures with structured fields: `cleanup_status`, `cleanup_actions`, `cleanup_count`, `failed_cleanup_actions`, and `failed_cleanup_count`. Cleanup failure turns the exit decision into `fail_closed` with `SetupFailed` while preserving terminal lifecycle semantics.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Cleanup is still a platform-independent ledger contract. Final runtime must attach concrete cleanup actions for listener sockets, TUN fd, smoltcp state, setup control fd, and child process supervision.

## 2026-06-22 — Runtime listener configuration evidence

### Commands run
- `cargo fmt` — applied formatting for listener configuration evidence.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 9 runtime lifecycle/listener tests.
- `cargo test -p foxprox-egress blocking_dns_http_runtime --all-targets --all-features` — passed, DNS/HTTP runtime listener proof.
- `cargo test -p foxprox-egress blocking_proxy_runtime --all-targets --all-features` — passed, DNS/HTTP/SOCKS runtime listener proof.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 122 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_records_listener_configuration ... ok`
- `runtime::tests::runtime_lifecycle_listener_config_backpressure_fails_closed ... ok`
- `foxprox_egress::tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`

### Interpretation
Addressed the round-27 high observability note for listener readiness evidence. `RuntimeLifecycleHarness` can now emit structured `proxy_listener_configured` records through `RuntimeListenerConfig`, including listener component, protocol/frontend mapping, bind address, and reachable address. The blocking DNS/HTTP and DNS/HTTP/SOCKS runtime proofs record listener configuration after bind and before claiming runtime readiness, and their exits now include cleanup actions for the configured listeners.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Shared policy/audit is still represented by shared core subsystem types and per-component broker ledgers, not a single shared runtime audit sink. Final runtime still needs concrete async supervision, TUN/smoltcp task wiring, child exit status, and real cleanup execution.

## 2026-06-22 — Aggregate runtime audit evidence

### Commands run
- `cargo fmt` — applied formatting for aggregate runtime audit access.
- `cargo test -p foxprox-egress blocking_dns_http_runtime --all-targets --all-features` — passed, DNS/HTTP runtime aggregate audit proof.
- `cargo test -p foxprox-egress blocking_proxy_runtime --all-targets --all-features` — passed, DNS/HTTP/SOCKS runtime aggregate audit proof.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 122 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`
- Aggregate assertions cover `network_session_start`, `dns_query_decision`, `proxy_destination_resolved`, `http_request_decision`/`socks_connect_decision`, and `network_session_exit` for one runtime proof.

### Interpretation
Added aggregate audit accessors to the blocking runtime harnesses so validation can inspect lifecycle, listener configuration, DNS, and proxy decision records as one session evidence set. This narrows the round-27 concern about fragmented observability while preserving each component's bounded broker ledger behavior in the current blocking proof.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is an aggregate snapshot over component ledgers, not yet a single shared async audit sink. Final runtime still needs one concrete supervised audit output path with global backpressure behavior across all concurrently running tasks.

## 2026-06-22 — Retire blocking runtime listeners on cleanup

### Commands run
- `cargo fmt` — applied formatting for runtime listener retirement and aggregate ordering fix.
- `cargo test -p foxprox-egress blocking_dns_http_runtime --all-targets --all-features` — passed, DNS/HTTP runtime cleanup regression.
- `cargo test -p foxprox-egress blocking_proxy_runtime --all-targets --all-features` — passed, DNS/HTTP/SOCKS runtime cleanup regression.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 122 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`
- Post-exit assertions prove `handle_dns_once`, `handle_http_proxy_once`, and `handle_socks5_proxy_once` fail after cleanup instead of accepting more listener work.
- Aggregate assertions prove `network_session_start` is first and `network_session_exit` is last in the returned session evidence set.

### Interpretation
Addressed round-29/round-30 high findings. Blocking runtime `exit` now archives component audit records and retires listener handles before emitting cleanup-complete evidence, so cleanup claims correspond to resources no longer callable through the runtime. Aggregate audit access now returns lifecycle startup/configuration, component records, and session exit in session order rather than placing exit before earlier DNS/proxy decisions.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The blocking harness now retires owned listener handles, but final runtime still needs real async task cancellation/joining, OS fd/socket cleanup, global audit backpressure, TUN/smoltcp task cleanup, and child-process supervision.

## 2026-06-22 — Child process exit ledger evidence

### Commands run
- `cargo fmt` — applied formatting for child exit lifecycle evidence.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 11 runtime lifecycle tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 124 core tests, 3 device tests, 28 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_records_clean_child_exit ... ok`
- `runtime::tests::runtime_lifecycle_child_failure_is_fail_closed ... ok`
- `runtime::tests::runtime_lifecycle_exit_is_terminal ... ok`

### Interpretation
Added `RuntimeChildExit` and `RuntimeLifecycleHarness::exit_with_cleanup_and_child` so `network_session_exit` can include supervised child status fields (`child_status`, `child_process_id`, `child_exit_code`, `child_signal`). Clean child exits preserve an allow session exit when cleanup succeeds; signaled/non-zero child termination is fail-closed with `RuntimeState` while preserving terminal lifecycle semantics.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Child process status is still injected into a platform-independent lifecycle harness. Final runtime must wire this to a real spawned child, task joins, and OS process status collection.

## 2026-06-22 — Ordered aggregate runtime audit and unknown child fail-closed

### Commands run
- `cargo fmt` — applied formatting for ordered aggregate audit and child-status hardening.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 12 runtime lifecycle tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_preserves_interleaved_component_order --all-targets --all-features` — passed, interleaved aggregate ordering regression.
- `cargo test -p foxprox-egress blocking_proxy_runtime --all-targets --all-features` — passed, blocking proxy runtime regressions.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 125 core tests, 3 device tests, 29 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_unknown_child_status_is_fail_closed ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_aggregate_preserves_interleaved_component_order ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`

### Interpretation
Addressed round-31 and round-32 high findings. Blocking runtime aggregate audit records are now archived after each handled lifecycle/DNS/proxy event instead of grouped by component at read time; a regression drives HTTP activity before a later DNS query and proves aggregate order preserves that interleaving before session exit. Runtime listener cleanup now calls `exit_with_cleanup` before retiring handles, so exit audit backpressure cannot silently retire listeners without session-exit evidence. Unknown/incomplete child status (`RuntimeChildExit::default`) is now fail-closed with structured `child_status=unknown` evidence.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Aggregate ordering is proven for blocking single-step runtime calls. Final runtime still needs a single supervised async audit output path with global backpressure across lifecycle, DNS, proxy, TUN/smoltcp, child wait, task joins, and cleanup.

## 2026-06-22 — Blocking child supervisor proof

### Commands run
- `cargo fmt` — applied formatting for blocking child supervisor proof.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, clean and non-zero child supervision tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 125 core tests, 3 device tests, 31 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_child_supervisor_captures_clean_child_exit_for_lifecycle ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_nonzero_exit_is_fail_closed_in_lifecycle ... ok`
- `runtime::tests::runtime_lifecycle_unknown_child_status_is_fail_closed ... ok`

### Interpretation
Added `BlockingChildSupervisor`, a concrete host process runner that spawns a child, waits for completion, and converts the observed process id/exit code into `RuntimeChildExit`. Regression tests feed real child process results into `RuntimeLifecycleHarness`: clean child exit produces structured allow evidence, while non-zero exit remains fail-closed. This complements the platform-independent child exit contract with a concrete blocking supervision proof.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The child supervisor is blocking and one-shot. Final runtime still needs async child wait integration, signal handling, task cancellation/join ordering, and unified audit backpressure across all runtime tasks.

## 2026-06-22 — Sequence-based aggregate audit and supervision error evidence

### Commands run
- `cargo fmt` — applied formatting for sequence-based aggregate cursors and child supervision error evidence.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 14 runtime lifecycle tests.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 3 blocking child supervisor tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_backpressure_replacement --all-targets --all-features` — passed, aggregate backpressure replacement regression.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 127 core tests, 3 device tests, 33 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_missing_child_process_id_is_fail_closed ... ok`
- `runtime::tests::runtime_lifecycle_child_supervision_error_is_audited ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_spawn_failure_is_audited ... ok`
- `foxprox_egress::tests::blocking_proxy_runtime_aggregate_captures_backpressure_replacement ... ok`

### Interpretation
Addressed round-33 and round-34 high findings. Aggregate runtime archive cursors now use last seen audit `sequence` per ledger, so lossy backpressure replacement records are captured even when bounded ledger length does not grow. Lifecycle exit backpressure is archived before returning an error, and listener handles are retired only after successful exit evidence. Child exit status is clean only with a known process id and zero exit code; missing process id with exit code 0 is now fail-closed. Added observable child supervision error evidence and a blocking spawn-failure regression that emits structured `broker_error` details.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Signal capture is now wired on Unix via `ExitStatusExt`, but signal-specific testing is still not covered. The final runtime still needs async process supervision, cancellation/join ordering, and one global audit sink/backpressure path across all tasks.

## 2026-06-22 — Signal-aware child supervision and bracketing

### Commands run
- `cargo fmt` — applied formatting for signal-aware child supervision and supervision-error evidence.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 4 blocking child supervisor tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 127 core tests, 3 device tests, 34 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `foxprox_egress::tests::blocking_child_supervisor_captures_clean_child_exit_for_lifecycle ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_nonzero_exit_is_fail_closed_in_lifecycle ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_signal_exit_is_fail_closed_in_lifecycle ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_spawn_failure_is_audited ... ok`

### Interpretation
Addressed round-34 supervision concerns. Blocking child supervisor tests now start lifecycle evidence before launching the child so `network_session_start`/`network_session_exit` bracket child lifetime. On Unix, `BlockingChildSupervisor` preserves signal termination via `ExitStatusExt::signal()`, producing `child_status=signaled` / `child_signal` lifecycle evidence. Spawn failure is converted into structured `broker_error` evidence through `RuntimeLifecycleHarness::record_child_supervision_error`.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Wait-failure is still difficult to trigger deterministically in the blocking proof. Final runtime still needs async child supervision, task cancellation/join ordering, and unified audit backpressure across all runtime tasks.

## 2026-06-22 — Runtime audit fan-in contract and child-status terminality

### Commands run
- `cargo fmt` — applied formatting for runtime audit fan-in and child-status terminality fixes.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 17 runtime tests.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 4 blocking child supervisor tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 130 core tests, 3 device tests, 34 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_child_process_without_status_is_fail_closed ... ok`
- `runtime::tests::runtime_audit_fan_in_ingests_sequence_ordered_sources ... ok`
- `runtime::tests::runtime_audit_fan_in_backpressure_is_observable ... ok`
- `foxprox_egress::tests::blocking_child_supervisor_signal_exit_is_fail_closed_in_lifecycle ... ok`

### Interpretation
Addressed round-36 child-session terminality. If `RuntimeComponent::ChildProcess` is part of a session, exit without `RuntimeChildExit` now records `child_status=unknown` and fails closed. Added `RuntimeAuditFanIn` as a platform-independent contract for a future unified audit output path: it ingests per-source records by audit sequence, skips duplicates, and emits structured `audit_backpressure` evidence with source and attempted kind when the fan-in ledger is full.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- `RuntimeAuditFanIn` is still an in-memory contract, not a concrete async writer shared by runtime tasks. Final runtime must wire lifecycle, listener, TUN/smoltcp, child, and cleanup tasks into one supervised sink with real backpressure propagation.

## 2026-06-22 — Preserve fan-in cursor across partial backpressure

### Commands run
- `cargo fmt` — applied formatting for fan-in cursor fix.
- `cargo test -p foxprox-core runtime::tests::runtime_audit_fan_in --all-targets --all-features` — passed, 3 fan-in tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 131 core tests, 3 device tests, 34 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_audit_fan_in_backpressure_preserves_accepted_cursor ... ok`
- `runtime::tests::runtime_audit_fan_in_backpressure_is_observable ... ok`
- `runtime::tests::runtime_audit_fan_in_ingests_sequence_ordered_sources ... ok`

### Interpretation
Addressed round-37 high finding. `RuntimeAuditFanIn::ingest` now persists the per-source cursor for records accepted before a later record hits audit backpressure. This preserves the skip-duplicates contract under bounded-ledger pressure while still returning structured `audit_backpressure` evidence for the blocked source sequence.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Fan-in is still a platform-independent contract only; concrete async runtime wiring must connect actual lifecycle, listener, TUN/smoltcp, child wait, join/cancel, cleanup, and audit sink tasks into this fail-closed pattern.

## 2026-06-22 — Child supervisor session emits terminal failure on spawn error

### Commands run
- `cargo fmt` — applied formatting for blocking child session helper.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 5 blocking child supervisor tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 131 core tests, 3 device tests, 35 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_child_supervisor_session_spawn_failure_exits_fail_closed ... ok`
- `tests::blocking_child_supervisor_spawn_failure_is_audited ... ok`
- `tests::blocking_child_supervisor_signal_exit_is_fail_closed_in_lifecycle ... ok`

### Interpretation
Added `BlockingChildSupervisor::run_session_to_exit`, a concrete blocking proof that brackets child execution with lifecycle evidence. It starts the lifecycle before spawning, records structured `child_supervision_error` on spawn failure, and emits terminal `network_session_exit` that fail-closes with `child_status=unknown` when no child status exists. This closes the earlier overclaim where spawn failure evidence could stop at `broker_error` without terminal session exit.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is still a blocking single-child proof. The final runtime still needs async child wait, task cancellation/join handling, TUN/smoltcp listener shutdown, and one shared audit sink with propagated backpressure.

## 2026-06-22 — Record runtime task joins and preserve child-session backpressure evidence

### Commands run
- `cargo fmt` — applied formatting for runtime task join and child-session error changes.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 20 runtime tests.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 6 blocking child supervisor tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 133 core tests, 3 device tests, 36 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed again after full tests.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_records_task_join_report ... ok`
- `runtime::tests::runtime_lifecycle_task_join_failure_is_fail_closed ... ok`
- `tests::blocking_child_supervisor_session_backpressure_returns_partial_lifecycle ... ok`
- `tests::blocking_child_supervisor_session_spawn_failure_exits_fail_closed ... ok`

### Interpretation
Added structured task-join evidence to `network_session_exit` via `RuntimeTaskJoinReport`: completed/cancelled tasks record `task_join_status=complete`, while failed/join-failed tasks fail closed with `DenialReason::RuntimeState` and structured task counts. Addressed round-39 child-session backpressure concern by returning `BlockingChildSessionError::Lifecycle` with the partial `RuntimeLifecycleHarness`, so bounded-ledger backpressure still leaves caller-visible `broker_error` / `audit_backpressure` evidence.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Task-join evidence is still modeled by a synchronous lifecycle report. The final runtime still needs concrete async task supervision, real join/cancel ordering for listener/TUN/smoltcp loops, and one shared audit sink with propagated backpressure.

## 2026-06-22 — Wire task-join report into blocking proxy runtime exit

### Commands run
- `cargo fmt` — applied formatting for blocking runtime task-report wiring.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 20 runtime tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit_records_task_join_failure --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_child_supervisor --all-targets --all-features` — passed, 6 blocking child supervisor tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — initially caught test-only imports, then passed after moving them into the test module.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 133 core tests, 3 device tests, 37 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_exit_records_task_join_failure ... ok`
- `runtime::tests::runtime_lifecycle_task_join_failure_is_fail_closed ... ok`
- `tests::blocking_child_supervisor_session_backpressure_returns_partial_lifecycle ... ok`

### Interpretation
`BlockingDnsHttpRuntime` and `BlockingProxyRuntime` now expose `exit_with_task_report(...)`, which records task join/cancel/failure status on the lifecycle exit ledger while preserving listener cleanup/retirement behavior. A proxy runtime regression proves a join-failed SOCKS listener task produces fail-closed `network_session_exit` with structured `task_join_status`, `runtime_tasks`, and `failed_runtime_task_count` fields, then retires listeners.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The task report is still caller-provided; final async runtime must derive it from real task handles, child wait futures, TUN/smoltcp loops, and listener accept loops.

## 2026-06-22 — Audit TUN read failures before packet loop exit

### Commands run
- `cargo fmt` — applied formatting for TUN read-failure audit changes.
- `cargo test -p foxprox-core tun::tests::tun_read_failure_is_audited_fail_closed --all-targets --all-features` — passed.
- `cargo test -p foxprox-core tun::tests --all-targets --all-features` — passed, 9 TUN tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 134 core tests, 3 device tests, 37 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed again after full tests.

### Evidence excerpts
- `tun::tests::tun_read_failure_is_audited_fail_closed ... ok`
- `tun::tests::icmp_echo_write_failure_is_audited_without_success_claim ... ok`
- `tun::tests::write_back_audit_backpressure_prevents_unobserved_reply ... ok`

### Interpretation
Closed a packet-loop observability gap: `TunPacketHarness::process_next_packet` now emits structured fail-closed `broker_error` evidence when the packet device read fails before returning `DeviceIoError::ReadFailed`. The record includes `frontend=tun`, `direction=from_sandbox`, `device_io_error=read_failed`, and `DenialReason::SetupFailed`, complementing the existing write-failure evidence.

### Changed files
- `crates/foxprox-core/src/tun.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- TUN processing is still a single-step harness. A concrete runtime loop still needs to convert read/write failures into task join outcomes, cleanup ordering, aggregate audit fan-in, and final `network_session_exit` evidence.

## 2026-06-22 — Fail closed on incomplete runtime task reports

### Commands run
- `cargo fmt` — applied formatting for task-report completeness checks.
- `cargo test -p foxprox-core runtime::tests::runtime_lifecycle_missing_task_join_is_fail_closed --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit_fails_closed_for_partial_task_report --all-targets --all-features` — passed.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 21 runtime tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit --all-targets --all-features` — passed, 2 blocking proxy runtime exit tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 135 core tests, 3 device tests, 38 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_missing_task_join_is_fail_closed ... ok`
- `tests::blocking_proxy_runtime_exit_fails_closed_for_partial_task_report ... ok`
- `runtime::tests::runtime_lifecycle_task_join_failure_is_fail_closed ... ok`

### Interpretation
Addressed round-41 high finding. A supplied `RuntimeTaskJoinReport` is now checked against the components that were started for the runtime session. Missing component outcomes produce `task_join_status=incomplete`, structured `missing_runtime_tasks` / `missing_runtime_task_count`, and a fail-closed `network_session_exit` with `DenialReason::RuntimeState`. Blocking proxy runtime coverage proves a DNS-only successful report for a DNS/HTTP/SOCKS runtime no longer overclaims a clean exit.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Component-level coverage is still coarse: final async runtime should derive concrete expected task names from spawned handles rather than only checking that each component has at least one outcome.

## 2026-06-22 — Add bounded TUN packet loop task outcome

### Commands run
- `cargo fmt` — applied formatting for TUN packet-loop report changes.
- `cargo test -p foxprox-core tun::tests::tun_packet_loop --all-targets --all-features` — passed, 2 packet-loop tests.
- `cargo test -p foxprox-core tun::tests --all-targets --all-features` — passed, 11 TUN tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 137 core tests, 3 device tests, 38 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed again after full tests.

### Evidence excerpts
- `tun::tests::tun_packet_loop_reports_read_failure_task_outcome ... ok`
- `tun::tests::tun_packet_loop_reports_idle_completion ... ok`
- `tun::tests::tun_read_failure_is_audited_fail_closed ... ok`

### Interpretation
Added `TunPacketLoopReport` and `TunPacketHarness::process_packet_loop(...)` as a bounded platform-independent packet-loop proof. Idle completion reports `RuntimeTaskStatus::Completed`; device read/write failure reports `RuntimeTaskStatus::Failed` and preserves existing structured device-error audit evidence; exhausting the caller-supplied packet budget reports `RuntimeTaskStatus::Cancelled` rather than overclaiming completion. This connects packet-loop behavior to the runtime task-join evidence model.

### Changed files
- `crates/foxprox-core/src/tun.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The loop is still synchronous and caller-driven. Final runtime must attach it to real async TUN fd readiness, smoltcp polling, global audit fan-in, and lifecycle cleanup.

## 2026-06-22 — Prove all TUN loop outcomes and named task expectations

### Commands run
- `cargo fmt` — applied formatting for named task expectations and additional TUN loop tests.
- `cargo test -p foxprox-core runtime::tests::runtime_lifecycle_missing_expected_task_name_is_fail_closed --all-targets --all-features` — passed.
- `cargo test -p foxprox-core tun::tests::tun_packet_loop --all-targets --all-features` — passed, 4 TUN packet-loop tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit --all-targets --all-features` — passed, 2 blocking proxy runtime exit tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 140 core tests, 3 device tests, 38 egress tests, and 8 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_missing_expected_task_name_is_fail_closed ... ok`
- `tun::tests::tun_packet_loop_reports_budget_cancellation ... ok`
- `tun::tests::tun_packet_loop_reports_write_failure_task_outcome ... ok`
- `tun::tests::tun_packet_loop_reports_read_failure_task_outcome ... ok`
- `tun::tests::tun_packet_loop_reports_idle_completion ... ok`

### Interpretation
Addressed round-43 validation highs by directly testing every `TunPacketHarness::process_packet_loop` terminal branch: idle completion, budget cancellation, read failure, and write failure. Also strengthened runtime task coverage by adding `RuntimeTaskExpectation` and `RuntimeLifecycleHarness::start_with_task_expectations(...)`; when expectations are provided, exit compares reported outcomes by component and task name, records named `missing_runtime_tasks`, and fail-closes incomplete task reports. Blocking DNS/HTTP/SOCKS runtimes now record named listener task expectations at lifecycle start.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-core/src/tun.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Named expectations are still declared by harness code. A final async runtime must derive them from actual spawned task handles and feed real join/cancel results into lifecycle exit and audit fan-in.

## 2026-06-22 — Add smoltcp bridge loop task outcome

### Commands run
- `cargo fmt` — applied formatting for smoltcp bridge-loop report changes.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop --all-targets --all-features` — passed.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_read_failure_is_audited_and_reported --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 140 core tests, 3 device tests, 38 egress tests, and 10 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::smoltcp_tun_bridge_read_failure_is_audited_and_reported ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_budget_cancellation ... ok`
- `tests::smoltcp_tun_bridge_audits_and_writes_stack_output ... ok`
- `tests::smoltcp_tun_bridge_audits_tcp_response_write_failure ... ok`

### Interpretation
Added `SmoltcpBridgeLoopReport` and `SmoltcpTunBridge::process_packet_loop(...)` to mirror the TUN packet-loop task model for the userspace stack bridge. Device read failures now emit structured `broker_error` evidence with `stack=smoltcp`, `direction=from_sandbox`, and `device_io_error=read_failed`, and the loop returns a failed `RuntimeTaskOutcome`. Budget exhaustion returns a cancelled smoltcp bridge task outcome instead of claiming completion.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The smoltcp loop is still synchronous/caller-bounded. Final runtime must drive it from actual TUN readiness and smoltcp timers and join it through the named task expectation model.

## 2026-06-22 — Require named task reports for expected runtime tasks

### Commands run
- `cargo fmt` — applied formatting for task-report completeness fixes and smoltcp loop proof.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 24 runtime tests.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit --all-targets --all-features` — passed, 2 blocking proxy runtime exit tests.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop --all-targets --all-features` — passed.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_read_failure_is_audited_and_reported --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 142 core tests, 3 device tests, 38 egress tests, and 10 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_expected_tasks_without_report_fail_closed ... ok`
- `runtime::tests::runtime_lifecycle_incomplete_expectation_list_keeps_component_coverage ... ok`
- `runtime::tests::runtime_lifecycle_missing_expected_task_name_is_fail_closed ... ok`
- `tests::smoltcp_tun_bridge_read_failure_is_audited_and_reported ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_budget_cancellation ... ok`

### Interpretation
Addressed round-44 high findings. If lifecycle start includes named `RuntimeTaskExpectation`s, exit without any `RuntimeTaskJoinReport` now fails closed with `task_join_status=not_recorded` and all expected task names listed as missing. Named expectations no longer weaken component coverage: components without any named expectation are still listed in `missing_runtime_tasks`. Blocking runtimes declare named listener expectations, so plain `exit(...)` can no longer silently claim task completion when expected task evidence is absent.

Also extended the smoltcp bridge proof committed in `a00f13c`: the smoltcp TUN bridge now has a bounded loop report with failed read and budget-cancelled task outcomes, matching the TUN loop task model.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Runtime task expectations are still harness-declared. The final async runtime must derive expected task names from actual spawned handles and route real join/cancel results through lifecycle exit and global audit fan-in.

## 2026-06-22 — Complete smoltcp loop terminal-branch proof

### Commands run
- `cargo fmt` — applied formatting for additional smoltcp loop tests.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop --all-targets --all-features` — passed, 3 smoltcp loop tests.
- `cargo test -p foxprox-stack --all-targets --all-features` — passed, 12 stack tests.
- `cargo clippy -p foxprox-stack --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 142 core tests, 3 device tests, 38 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::smoltcp_tun_bridge_loop_reports_idle_completion ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_budget_cancellation ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_write_failure ... ok`
- `tests::smoltcp_tun_bridge_read_failure_is_audited_and_reported ... ok`

### Interpretation
Completed smoltcp bridge-loop terminal-branch coverage: idle completion reports `completed`, budget exhaustion reports `cancelled`, and write/read device failures report failed task outcomes with structured device-error audit evidence. `FailingWritePacketDevice` now supports scripted inbound packets so the smoltcp bridge loop can prove output-write failure from `process_packet_loop(...)`, not only direct TCP response bridging.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The smoltcp and TUN loop proofs remain synchronous. Final runtime must drive them from real async readiness/timers and derive task outcomes from actual task handles.

## 2026-06-22 — Add runtime task supervisor registry contract

### Commands run
- `cargo fmt` — applied formatting for task supervisor registry changes.
- `cargo test -p foxprox-core runtime::tests::runtime_task_supervisor --all-targets --all-features` — passed, 2 task supervisor tests.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 26 runtime tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed during targeted validation.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 144 core tests, 3 device tests, 38 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed after full tests.

### Evidence excerpts
- `runtime::tests::runtime_task_supervisor_derives_expectations_and_join_report ... ok`
- `runtime::tests::runtime_task_supervisor_rejects_unknown_and_duplicate_outcomes ... ok`
- `runtime::tests::runtime_lifecycle_expected_tasks_without_report_fail_closed ... ok`

### Interpretation
Added a platform-independent `RuntimeTaskSupervisor` registry contract. Runtime code can register task handles with component/name metadata, derive `RuntimeTaskExpectation`s for lifecycle start, record one terminal outcome per handle, and build a `RuntimeTaskJoinReport` for exit. The registry rejects unknown handles and duplicate outcomes, preventing untracked or double-counted task results from feeding lifecycle evidence. A regression proves that omitting one registered task outcome produces a named `missing_runtime_tasks` fail-closed exit when the supervisor-derived report is consumed.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The supervisor is still synchronous and handle-like, not an async executor integration. Final runtime must bind registered handles to actual spawned tasks/futures and feed real join/cancel outcomes into the registry.

## 2026-06-22 — Reject duplicate supervised task names and add audit fan-in drain proof

### Commands run
- `cargo fmt` — applied formatting for supervisor and audit drain changes.
- `cargo test -p foxprox-core runtime::tests::runtime_task_supervisor --all-targets --all-features` — passed, 2 supervisor tests.
- `cargo test -p foxprox-core runtime::tests::runtime_audit_fan_in --all-targets --all-features` — passed, 5 fan-in tests.
- `cargo test -p foxprox-core runtime::tests --all-targets --all-features` — passed, 28 runtime tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 146 core tests, 3 device tests, 38 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_task_supervisor_rejects_unknown_duplicate_names_and_duplicate_outcomes ... ok`
- `runtime::tests::runtime_task_supervisor_derives_expectations_and_join_report ... ok`
- `runtime::tests::runtime_audit_fan_in_drains_to_json_sink_once ... ok`
- `runtime::tests::runtime_audit_fan_in_sink_failure_is_observable ... ok`

### Interpretation
Addressed round-46 high finding. `RuntimeTaskSupervisor::register_task(...)` now returns a `Result` and rejects duplicate `(component, task_name)` registrations before they can create ambiguous expected task coverage. Unknown task handles and duplicate outcomes remain rejected.

Also added `RuntimeAuditFanIn::drain_to_sink(...)`, a concrete sink-drain proof for the fan-in ledger. Successful drain advances a drain cursor so repeated drains skip already-written records; sink write failure returns `RuntimeAuditDrainError::SinkWriteFailed` and records structured fail-closed `broker_error` evidence (`runtime_error=audit_sink_write_failed`, attempted sequence, and last drained sequence).

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The fan-in drain proof is synchronous and in-memory. Final runtime still needs one async audit writer task and backpressure propagation from real task fan-in to lifecycle exit/cleanup.

## 2026-06-22 — Add blocking runtime task-set proof

### Commands run
- `cargo fmt` — applied formatting for blocking runtime task-set proof.
- `cargo test -p foxprox-egress blocking_runtime_task_set --all-targets --all-features` — passed, 3 blocking task-set tests.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed during targeted validation.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 146 core tests, 3 device tests, 41 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed after full tests.

### Evidence excerpts
- `tests::blocking_runtime_task_set_feeds_clean_lifecycle_exit ... ok`
- `tests::blocking_runtime_task_set_panic_is_join_failed ... ok`
- `tests::blocking_runtime_task_set_rejects_duplicate_task_names ... ok`
- `runtime::tests::runtime_task_supervisor_rejects_unknown_duplicate_names_and_duplicate_outcomes ... ok`

### Interpretation
Added `BlockingRuntimeTaskSet`, a concrete `std::thread`-backed proof that registered runtime task handles can derive lifecycle expectations and join reports from actual spawned work. Clean/completed and cancelled thread outcomes produce a clean lifecycle exit; a panicking thread maps to `RuntimeTaskStatus::JoinFailed` and fail-closes `network_session_exit`; duplicate task names are rejected through the core supervisor before spawning ambiguous tasks.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is a blocking thread proof, not async runtime scheduling. Final runtime still needs actual listener/TUN/smoltcp/child tasks registered through the supervisor and drained through one shared audit fan-in path.

## 2026-06-22 — Preserve undrained audit records and reject duplicate direct expectations

### Commands run
- `cargo fmt` — applied formatting for lifecycle expectation and fan-in drain fixes.
- `cargo test -p foxprox-core runtime::tests::runtime_audit_fan_in --all-targets --all-features` — passed, 6 fan-in tests.
- `cargo test -p foxprox-core runtime::tests::runtime_lifecycle_duplicate_task_expectations_are_rejected --all-targets --all-features` — passed.
- `cargo test -p foxprox-core runtime::tests::runtime_task_supervisor --all-targets --all-features` — passed, 2 task supervisor tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 148 core tests, 3 device tests, 41 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_duplicate_task_expectations_are_rejected ... ok`
- `runtime::tests::runtime_audit_fan_in_sink_failure_preserves_full_undrained_ledger ... ok`
- `runtime::tests::runtime_audit_fan_in_sink_failure_is_observable ... ok`
- `runtime::tests::runtime_task_supervisor_rejects_unknown_duplicate_names_and_duplicate_outcomes ... ok`

### Interpretation
Addressed round-48 highs. `RuntimeLifecycleHarness::start_with_task_expectations(...)` now rejects duplicate direct `(component, task_name)` expectations with structured fail-closed `broker_error` evidence, closing the bypass around supervisor duplicate-name checks. `RuntimeAuditFanIn::drain_to_sink(...)` no longer lossy-appends sink-failure evidence into the same bounded ledger; it returns a structured `failure_record` in `RuntimeAuditDrainError::SinkWriteFailed`, preserving full undrained ledger contents for retry while still surfacing fail-closed sink failure evidence to the caller.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Audit sink failure evidence is returned to the caller, not yet routed to a separate durable emergency sink. Final runtime should define where that failure record is persisted when the primary audit sink is unavailable.

## 2026-06-22 — Add emergency sink path for fan-in drain failures

### Commands run
- `cargo fmt` — applied formatting for emergency fan-in drain changes.
- `cargo test -p foxprox-core runtime::tests::runtime_audit_fan_in --all-targets --all-features` — passed, 7 fan-in tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 149 core tests, 3 device tests, 41 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_audit_fan_in_writes_sink_failure_to_emergency_sink ... ok`
- `runtime::tests::runtime_audit_fan_in_sink_failure_preserves_full_undrained_ledger ... ok`
- `runtime::tests::runtime_audit_fan_in_drains_to_json_sink_once ... ok`

### Interpretation
Added `RuntimeAuditFanIn::drain_to_sink_with_failure_sink(...)`, allowing a caller to provide an emergency/failure sink for the structured `audit_sink_write_failed` record when the primary audit sink rejects a record. The primary drain cursor remains unchanged and undrained records stay in the fan-in ledger, while the failure sink receives the broker-error evidence when available.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The emergency sink is still caller-provided and synchronous. Final runtime should define a concrete fallback destination and bounded behavior when both primary and emergency sinks fail.

## 2026-06-23 — Make fallback audit and blocking task spawn failures observable

### Commands run
- `cargo fmt` — applied formatting for fan-in and blocking task-set changes.
- `cargo test -p foxprox-core runtime::tests::runtime_audit_fan_in --all-targets --all-features` — passed, 8 fan-in tests.
- `cargo test -p foxprox-egress blocking_runtime_task_set --all-targets --all-features` — passed, 4 blocking task-set tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 150 core tests, 3 device tests, 42 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_audit_fan_in_emergency_sink_failure_is_observable ... ok`
- `runtime::tests::runtime_audit_fan_in_writes_sink_failure_to_emergency_sink ... ok`
- `tests::blocking_runtime_task_set_spawn_failure_is_join_failed ... ok`
- `tests::blocking_runtime_task_set_panic_is_join_failed ... ok`

### Interpretation
Addressed round-49/round-50 high review notes. `RuntimeAuditDrainError::SinkWriteFailed` now includes an optional structured `failure_sink_error_record` (`runtime_error=audit_emergency_sink_write_failed`) when the emergency audit sink also fails, while preserving the undrained primary ledger and drain cursor. `BlockingRuntimeTaskSet::spawn_task(...)` now routes through `std::thread::Builder::spawn`, converts OS thread creation failure into a registered `join_failed` task outcome, and returns `BlockingRuntimeTaskSetError::SpawnFailed`; feeding that report into lifecycle exit produces fail-closed task join evidence instead of a panic or missing task.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The emergency sink destination is still caller-provided; final runtime should choose the concrete fallback sink and bounded retry policy.
- The blocking task-set proof is still synchronous/thread-based. Final runtime still needs async task handles, cancellation ordering, and real listener/TUN/smoltcp task registration.

## 2026-06-23 — Bound blocking task joins with timeout evidence

### Commands run
- `cargo fmt` — applied formatting for task timeout changes.
- `cargo test -p foxprox-egress blocking_runtime_task_set --all-targets --all-features` — passed, 5 blocking task-set tests.
- `cargo test -p foxprox-core runtime::tests::runtime_lifecycle_task_join_failure_is_fail_closed --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 150 core tests, 3 device tests, 43 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_runtime_task_set_timeout_is_fail_closed ... ok`
- `tests::blocking_runtime_task_set_spawn_failure_is_join_failed ... ok`
- `tests::blocking_runtime_task_set_panic_is_join_failed ... ok`
- `runtime::tests::runtime_lifecycle_task_join_failure_is_fail_closed ... ok`

### Interpretation
Added `RuntimeTaskStatus::TimedOut` as a failed task outcome and extended `BlockingRuntimeTaskSet` with `join_all_with_timeout(...)`. Blocking tasks now publish completion status through a bounded receiver path; if status is not observed before the timeout, the task report records `timed_out`, and lifecycle exit emits fail-closed `network_session_exit` evidence with `task_join_status=failed`, the specific timed-out task name, and failed task counts.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Commit checkpoints
- `1a90eba Make fallback runtime failures observable` was validated by round-51 review: no blocker/high findings.

### Remaining blind spots
- The timeout path detaches still-running blocking threads after recording `timed_out`; final async runtime should actively signal cancellation and then join with a bounded deadline.
- Listener/TUN/smoltcp tasks still need concrete registration and cancellation wiring in the final runtime.

## 2026-06-23 — Add cooperative cancellation proof for blocking runtime tasks

### Commands run
- `cargo fmt` — applied formatting for cancellable task-set changes.
- `cargo test -p foxprox-egress blocking_runtime_task_set --all-targets --all-features` — passed, 6 blocking task-set tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 150 core tests, 3 device tests, 44 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_runtime_task_set_cancellation_is_joined_cleanly ... ok`
- `tests::blocking_runtime_task_set_timeout_is_fail_closed ... ok`
- `tests::blocking_runtime_task_set_spawn_failure_is_join_failed ... ok`

### Interpretation
Extended the blocking task-set proof with cooperative cancellation. `BlockingRuntimeTaskSet::spawn_cancellable_task(...)` gives tasks a `BlockingRuntimeCancellationToken`, `request_cancellation()` signals all cancellable tasks, and `join_all_with_timeout(...)` records either clean `cancelled` outcomes or fail-closed `timed_out` outcomes. The clean cancellation regression proves lifecycle exit records `runtime_tasks=dns_listener:dns_accept_loop:cancelled`, `task_join_status=complete`, and `failed_runtime_task_count=0`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
Round-52 validation observed a transient compile blocker in the in-flight cancellation worktree (`BlockingRuntimeTask` missing `cancellation`). The final implementation sets the field, and the full validation suite above passed.

### Remaining blind spots
- Cancellation is cooperative and thread-based; final runtime still needs concrete async task handles, per-listener/TUN/smoltcp cancellation tokens, and bounded shutdown ordering wired into the real runtime.

## 2026-06-23 — Wire blocking runtime exit to cancellable task sets

### Commands run
- `cargo fmt` — applied formatting for runtime/task-set exit wiring.
- `cargo test -p foxprox-egress blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_runtime_task_set --all-targets --all-features` — passed, 6 blocking task-set tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 150 core tests, 3 device tests, 45 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks ... ok`
- `tests::blocking_runtime_task_set_cancellation_is_joined_cleanly ... ok`
- `tests::blocking_runtime_task_set_timeout_is_fail_closed ... ok`

### Interpretation
Added `exit_with_task_set(...)` to the blocking DNS/HTTP and full proxy runtimes. Runtime exit now can own the shutdown handoff: request cooperative task cancellation, bounded-join the task set, feed the task report into lifecycle exit, then archive component audit and close listeners. The full proxy regression proves all expected listener tasks are cancelled and joined with structured `network_session_exit` evidence (`task_join_status=complete`, `runtime_tasks=...:cancelled`, zero failed/missing counts) and that listeners are unavailable after exit.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Commit checkpoints
- Round-53 review validated `bb3fae1` and `3dda4cd`: no blocker/high findings.

### Remaining blind spots
- This is still a blocking/thread runtime proof. Final runtime still needs real accept-loop task registration, TUN/smoltcp task cancellation, and async shutdown ordering with concrete sockets/devices.

## 2026-06-23 — Add external cancellation proof for TUN packet loops

### Commands run
- `cargo fmt` — applied formatting for TUN loop cancellation changes.
- `cargo test -p foxprox-core tun::tests::tun_packet_loop_reports_external_cancellation --all-targets --all-features` — passed.
- `cargo test -p foxprox-core tun::tests::tun_packet_loop_reports --all-targets --all-features` — passed, 5 TUN loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 151 core tests, 3 device tests, 45 egress tests, and 12 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tun::tests::tun_packet_loop_reports_external_cancellation ... ok`
- `tun::tests::tun_packet_loop_reports_budget_cancellation ... ok`
- `tun::tests::tun_packet_loop_reports_read_failure_task_outcome ... ok`
- `tun::tests::tun_packet_loop_reports_write_failure_task_outcome ... ok`

### Interpretation
Added `TunPacketHarness::process_packet_loop_until(...)`, which checks an external cancellation predicate before each TUN read and reports the existing structured `tun_device:tun_packet_loop:cancelled` task outcome without consuming more packets. The regression proves cancellation after one packet leaves observable packet/decision audit for the processed packet and exits with a cancelled task outcome rather than relying only on a packet budget.

### Changed files
- `crates/foxprox-core/src/tun.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The smoltcp bridge loop still only has budget/idle/read-write outcomes and should accept the same external cancellation style before final runtime shutdown wiring claims TUN/smoltcp cancellation complete.

## 2026-06-23 — Add external cancellation proof for smoltcp bridge loops

### Commands run
- `cargo fmt` — applied formatting for smoltcp bridge cancellation changes.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop_reports_external_cancellation --all-targets --all-features` — passed.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop_reports --all-targets --all-features` — passed, 4 smoltcp loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 151 core tests, 3 device tests, 45 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::smoltcp_tun_bridge_loop_reports_external_cancellation ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_budget_cancellation ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_idle_completion ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_write_failure ... ok`

### Interpretation
Added `SmoltcpTunBridge::process_packet_loop_until(...)`, matching the raw TUN harness cancellation contract. The bridge checks an external cancellation predicate before each packet read and returns structured `smoltcp_stack:smoltcp_tun_bridge_loop:cancelled` task evidence while preserving audit records for packets already processed.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The final runtime still needs to connect these cancellation predicates to concrete async/task cancellation tokens and real TUN fd readiness/timers.

## 2026-06-23 — Close blocking listeners even when exit audit is backpressured

### Commands run
- `cargo fmt` — applied formatting for cleanup/backpressure tests.
- `cargo test -p foxprox-egress blocking_ --all-targets --all-features` — passed, 46 filtered blocking tests including exit-backpressure cleanup regressions.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 151 core tests, 3 device tests, 47 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_exit_backpressure_still_closes_listeners ... ok`
- `tests::blocking_proxy_runtime_exit_backpressure_still_closes_listeners ... ok`
- `tests::blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks ... ok`

### Interpretation
Addressed round-54 high feedback and the round-56 validation clippy overclaim. Blocking DNS/HTTP and full proxy runtime shutdown now archives lifecycle/component evidence and retires listener handles before returning an exit audit-backpressure error. Regression tests fill the lifecycle ledger so `network_session_exit` is backpressured, assert the returned `AuditBackpressure { attempted_kind: NetworkSessionExit }`, and then prove DNS/HTTP/SOCKS handlers are unavailable after exit. Removed the transient unused imports that made clippy fail after the smoltcp cancellation commit.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
- Round-54 validation found listener cleanup could be skipped on exit audit backpressure; fixed here.
- Round-56 validation found clippy failed due transient unused imports; fixed here.

### Remaining blind spots
- The real blocking accept loops still need nonblocking/cancellation-aware accept semantics before claiming actual listener tasks can stop while blocked in `accept()`.
- Raw TUN and smoltcp cancellation predicates still need concrete fd readiness/wakeup integration for blocked reads.

## 2026-06-23 — Make listener accept and TUN idle paths cancellation-aware

### Commands run
- `cargo fmt` — applied formatting for nonblocking listener/TUN changes.
- `cargo test -p foxprox-device tun_io_device_maps_would_block_to_idle_read --all-targets --all-features` — passed.
- `cargo test -p foxprox-core tun::tests::tun_packet_loop_reports_cancellation_before_idle_read --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_proxy_listener_tasks_cancel_without_clients --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 48 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::tun_io_device_maps_would_block_to_idle_read ... ok`
- `tun::tests::tun_packet_loop_reports_cancellation_before_idle_read ... ok`
- `tests::blocking_proxy_listener_tasks_cancel_without_clients ... ok`
- `tests::blocking_proxy_runtime_exit_backpressure_still_closes_listeners ... ok`

### Interpretation
Addressed round-55 high feedback. The `PacketDevice` contract now explicitly requires nonblocking or time-bounded reads so cancellation can be observed between packet reads, and `TunIoPacketDevice` maps `WouldBlock` to `Ok(None)`. Added a TUN loop regression that cancels before an idle read without emitting spurious audit. HTTP and SOCKS listener sockets are now nonblocking, and the listener-task regression proves actual HTTP/SOCKS accept-loop tasks with no clients can observe cancellation and join as `cancelled` instead of hanging in `accept()`.

### Changed files
- `crates/foxprox-core/src/tun.rs`
- `crates/foxprox-device/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
- Round-55 high findings called out cancellation not being observable while TUN reads or HTTP/SOCKS accepts were blocked. This commit establishes nonblocking idle semantics and tests cancellation with idle/no-client paths.

### Remaining blind spots
- Concrete Linux TUN fd creation still needs to set/verify nonblocking mode when the real fd-backed adapter lands.
- Final async runtime still needs fd readiness/timer integration rather than polling sleeps in blocking proof tasks.

## 2026-06-23 — Extend idle cancellation proof to DNS listener tasks

### Commands run
- `cargo fmt` — applied formatting for DNS listener idle-cancellation changes.
- `cargo test -p foxprox-egress blocking_dns_listener_task_cancels_without_packets --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_proxy_listener_tasks_cancel_without_clients --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 49 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_listener_task_cancels_without_packets ... ok`
- `tests::blocking_proxy_listener_tasks_cancel_without_clients ... ok`
- `tests::blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks ... ok`

### Interpretation
Extended listener idle-cancellation proof to DNS. `BlockingDnsBrokerServer::bind(...)` now configures its UDP socket as nonblocking, allowing no-packet-ready iterations to return promptly. The DNS listener task regression moves an actual `BlockingDnsBrokerServer` into a cancellable task, runs it with no packets, requests cancellation, and proves the task joins with `dns_listener:dns_accept_loop:cancelled`. Together with the HTTP/SOCKS no-client test, all blocking listener kinds now have idle cancellation coverage.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- These are still blocking/thread proofs with polling sleeps. Final async runtime should use readiness/timer primitives and feed actual listener/TUN/smoltcp task reports into lifecycle exit and audit fan-in.

## 2026-06-23 — Distinguish DNS idle receive from listener failure

### Commands run
- `cargo fmt` — applied formatting for DNS idle-step changes.
- `cargo test -p foxprox-egress blocking_dns_broker_server_reports_idle_without_failure --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_dns_listener_task_cancels_without_packets --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 50 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_broker_server_reports_idle_without_failure ... ok`
- `tests::blocking_dns_listener_task_cancels_without_packets ... ok`
- `tests::blocking_proxy_listener_tasks_cancel_without_clients ... ok`

### Interpretation
Addressed round-59 high feedback. `BlockingDnsBrokerServer::handle_one(...)` now returns `Ok(None)` for nonblocking idle receive (`WouldBlock`/`TimedOut`) instead of conflating no-packet-ready with `DnsUpstreamError::Unavailable`. Handled packets return `Ok(Some(DnsBrokerStepResult))`, while actual socket errors still fail. The idle regression asserts no audit is emitted for idle, and the DNS listener cancellation test continues to prove idle loops can observe cancellation and join as `cancelled`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
- Round-59 correctness flagged that DNS idle receive was represented as unavailable and masked by ignoring errors in the cancellation loop. This commit makes idle a first-class `None` result and preserves real errors separately.

### Remaining blind spots
- Final runtime still needs async/readiness integration and structured task failure evidence for real DNS socket errors inside registered listener tasks.

## 2026-06-23 — Distinguish idle listener accepts from failures

### Commands run
- `cargo fmt` — applied formatting for idle listener result changes.
- `cargo test -p foxprox-egress reports_idle_without_failure --all-targets --all-features` — passed, 3 idle listener tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 52 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_broker_server_reports_idle_without_failure ... ok`
- `tests::blocking_http_proxy_server_reports_idle_without_failure ... ok`
- `tests::blocking_socks5_proxy_server_reports_idle_without_failure ... ok`
- `tests::blocking_dns_listener_task_cancels_without_packets ... ok`
- `tests::blocking_proxy_listener_tasks_cancel_without_clients ... ok`

### Interpretation
Extended the idle-vs-failure distinction to all blocking listener frontends. DNS/HTTP/SOCKS `handle_one(...)` now returns `Ok(None)` for no packet/client ready (`WouldBlock`/timeout) and `Ok(Some(step))` for handled requests, reserving `Err(...)` for actual listener/socket failures. Idle regressions assert no spurious audit records are emitted for no-ready events, while cancellation task tests prove idle listener loops can still join cleanly as `cancelled`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
- Round-59 correctness flagged DNS `WouldBlock` being conflated with `Unavailable`; fixed and generalized to HTTP/SOCKS accepts so cancellation loops do not need to ignore expected idle as if it were a failure.

### Remaining blind spots
- Final runtime still needs actual task-loop wrappers that convert repeated idle, real listener failures, cancellation, and timeouts into registered task outcomes and fan-in audit evidence.

## 2026-06-23 — Feed real listener loops into lifecycle task evidence

### Commands run
- `cargo test -p foxprox-egress blocking_listener_loop_tasks_feed_lifecycle_exit --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 53 egress tests, and 13 stack tests.
- `cargo fmt` — applied formatting after the listener-loop wrapper test changed layout.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_tasks_feed_lifecycle_exit ... ok`
- `tests::blocking_dns_broker_server_reports_idle_without_failure ... ok`
- `tests::blocking_http_proxy_server_reports_idle_without_failure ... ok`
- `tests::blocking_socks5_proxy_server_reports_idle_without_failure ... ok`

### Interpretation
Added `run_until_cancelled(...)` loop wrappers for DNS, HTTP, and SOCKS blocking listener servers. These wrappers consume the idle-vs-handled-vs-error `handle_one(...)` result directly: idle continues, handled traffic resets the idle budget, cancellation returns `RuntimeTaskStatus::Cancelled`, and real listener errors return `RuntimeTaskStatus::Failed`. The lifecycle regression runs actual DNS/HTTP/SOCKS listener loop tasks through `BlockingRuntimeTaskSet`, requests cancellation, joins them, and verifies `network_session_exit` records all three listener tasks as `cancelled` with `task_join_status=complete` and zero failed tasks.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Review follow-up
- Round-61 validation identified real listener task-loop wrappers as the next runtime gap. This commit adds the wrappers and proves their clean cancellation path is fed into lifecycle evidence. Real listener error injection remains a future targeted proof.

### Remaining blind spots
- Need deterministic listener error injection or adapter traits to prove `run_until_cancelled(...) -> Failed` for actual socket failures without relying on OS-specific invalid handles.
- Final async runtime still needs readiness/timer integration, task registration, cancellation/join ordering, and fan-in audit drain for concrete runtime tasks.

## 2026-06-23 — Add reusable listener loop status mapping

### Commands run
- `cargo fmt` — applied formatting for listener-loop helper changes.
- `cargo test -p foxprox-egress blocking_listener_loop --all-targets --all-features` — passed, 3 listener-loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 55 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_helper_reports_real_errors_as_failed ... ok`
- `tests::blocking_listener_loop_helper_resets_idle_budget_after_work ... ok`
- `tests::blocking_listener_loop_tasks_feed_lifecycle_exit ... ok`

### Interpretation
Refactored DNS/HTTP/SOCKS `run_until_cancelled(...)` wrappers through a shared `run_blocking_listener_loop_until_cancelled(...)` helper. The helper has deterministic tests proving real step errors map to `RuntimeTaskStatus::Failed`, handled work resets the idle budget, and idle exhaustion/cancellation is bounded as `cancelled`. Existing listener-loop lifecycle proof continues to show actual listener tasks feeding `cancelled` outcomes into structured `network_session_exit` task evidence.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Need concrete adapter-level tests for actual OS listener/socket errors once the listener abstraction can inject them without unsafe fd manipulation.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Fix listener loop cancellation overclaim and client-read handling

### Commands run
- `cargo fmt` — applied formatting for listener-loop follow-up changes.
- `cargo test -p foxprox-egress blocking_listener_loop --all-targets --all-features` — passed, 4 listener-loop tests.
- `cargo test -p foxprox-egress blocking_http_proxy_server_read_timeout_is_audited_request_failure --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 57 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_helper_reserves_cancelled_for_observed_cancellation ... ok`
- `tests::blocking_listener_loop_helper_resets_idle_budget_after_work ... ok` now expects `RuntimeTaskStatus::TimedOut` for idle-budget exhaustion without cancellation.
- `tests::blocking_http_proxy_server_read_timeout_is_audited_request_failure ... ok`

### Interpretation
Round-62/63 review found two high-risk overclaims: idle-budget exhaustion was being reported as `cancelled`, and HTTP client read timeouts could become listener-task failures. The shared listener loop now reports idle-budget exhaustion as `timed_out` and reserves `cancelled` for observed cancellation. DNS/HTTP/SOCKS run-loop wrappers also append structured `broker_error` evidence before returning `failed` on listener-loop errors. HTTP request read errors are handled as per-request fail-closed malformed proxy decisions, keeping the listener alive instead of converting a slow/reset client into a task failure.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Still need adapter-level listener/socket error injection to prove real OS accept/recv failures hit the new `listener_loop_error` audit path deterministically.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Add structured listener-loop error audit assertions

### Commands run
- `cargo fmt` — applied formatting for listener-loop audit assertion changes.
- `cargo test -p foxprox-egress blocking_listener_loop --all-targets --all-features` — passed, 5 listener-loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 58 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_error_recorders_append_structured_broker_errors ... ok`
- `tests::blocking_listener_loop_helper_reports_real_errors_as_failed ... ok`
- `tests::blocking_listener_loop_tasks_feed_lifecycle_exit ... ok`

### Interpretation
Round-64 review found no blocker/high issues and identified deterministic listener error-path evidence as the next gap. Added assertions for DNS, HTTP, and SOCKS listener error recorders so task failures retain structured `broker_error` evidence: `runtime_error=listener_loop_error`, listener component, listener task name, and listener error detail. This narrows the prior blind spot from “no structured error-path proof” to “still no OS-level accept/recv fault injection against concrete sockets.”

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Need real adapter-level/OS listener error injection so DNS/HTTP/SOCKS `run_until_cancelled(...)` can be proven to hit these recorders from concrete accept/recv failures without unsafe fd manipulation.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Complete listener-loop audit field assertions

### Commands run
- `cargo fmt` — applied formatting for audit assertion follow-up.
- `cargo test -p foxprox-egress blocking_listener_loop_error_recorders_append_structured_broker_errors --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_listener_loop --all-targets --all-features` — passed, 5 listener-loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 58 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_error_recorders_append_structured_broker_errors ... ok`
- The test now asserts typed `frontend`/`protocol` fields and `runtime_error=listener_loop_error` detail for DNS, HTTP, and SOCKS listener-loop error records.

### Interpretation
Round-65 review found no blocker/high issues but noted that the previous assertions did not fully cover HTTP/SOCKS `runtime_error` and typed frontend/protocol fields. This follow-up closes that assertion gap so the test matches the progress/learnings claims for all three listener frontends.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Need real adapter-level/OS listener error injection so DNS/HTTP/SOCKS `run_until_cancelled(...)` can be proven to hit these recorders from concrete accept/recv failures without unsafe fd manipulation.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Fail closed on partial HTTP proxy reads

### Commands run
- `cargo fmt` — applied formatting for HTTP proxy partial-read changes.
- `cargo test -p foxprox-egress blocking_http_proxy_server_partial_request_timeout_is_not_forwarded --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_http_proxy_server_read_timeout_is_audited_request_failure --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 59 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_http_proxy_server_partial_request_timeout_is_not_forwarded ... ok`
- `tests::blocking_http_proxy_server_read_timeout_is_audited_request_failure ... ok`

### Interpretation
Round-66 validation found that a parseable HTTP request line followed by a read timeout could still be forwarded because the request reader returned partial bytes. The HTTP proxy reader now only returns bytes after complete header termination (`\r\n\r\n`); EOF or read error before that returns an empty malformed request, producing fail-closed `UnsupportedDenied` / `ProxyMalformed` evidence and no egress forwarding. This makes the prior per-client read-timeout claim true for both empty and partial parseable request inputs.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Need real adapter-level/OS listener error injection so DNS/HTTP/SOCKS `run_until_cancelled(...)` can be proven to hit listener-loop error recorders from concrete accept/recv failures without unsafe fd manipulation.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Add precise partial HTTP read audit evidence

### Commands run
- `cargo fmt` — applied formatting for HTTP read evidence changes.
- `cargo test -p foxprox-egress blocking_http_proxy_server_read_timeout_is_audited_request_failure --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_http_proxy_server_partial_request_timeout_is_not_forwarded --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 59 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_http_proxy_server_read_timeout_is_audited_request_failure ... ok`
- `tests::blocking_http_proxy_server_partial_request_timeout_is_not_forwarded ... ok`

### Interpretation
Round-67 validation found fail-closed behavior was correct but audit evidence still collapsed empty and partial HTTP reads into an empty malformed parse error. The HTTP proxy read path now records a structured `broker_error` before the malformed decision with typed HTTP proxy frontend/protocol, client source endpoint, `read_status`, observed byte count, and `error=http_proxy_client_read_incomplete`. The empty-timeout and partial-timeout regressions assert both the precise read evidence and the final fail-closed malformed decision.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Need real adapter-level/OS listener error injection so DNS/HTTP/SOCKS `run_until_cancelled(...)` can be proven to hit listener-loop error recorders from concrete accept/recv failures without unsafe fd manipulation.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Prove listener socket error paths through run loops

### Commands run
- `cargo fmt` — applied formatting for listener socket adapter changes.
- `cargo test -p foxprox-egress blocking_listener_loop_socket_errors_are_audited_and_failed --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_listener_loop --all-targets --all-features` — passed, 6 listener-loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 60 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_socket_errors_are_audited_and_failed ... ok`
- `tests::blocking_listener_loop_error_recorders_append_structured_broker_errors ... ok`
- `tests::blocking_listener_loop_tasks_feed_lifecycle_exit ... ok`

### Interpretation
Round-68 review found no blocker/high issues and kept adapter-level listener fault injection as the next runtime gap. The DNS, HTTP, and SOCKS listener structs now accept socket/listener adapter types with concrete `UdpSocket`/`TcpListener` defaults. Test adapters inject DNS recv and HTTP/SOCKS accept failures through the actual `run_until_cancelled(...)` wrappers, proving the wrappers return `RuntimeTaskStatus::Failed` and append structured `listener_loop_error` broker evidence instead of only testing the recorders directly.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The injected adapter failures prove the wrapper path without unsafe fd manipulation; they still are not kernel/OS-originated socket faults from live descriptors.
- Final async runtime still needs readiness/timer integration and audit fan-in wiring for real task loops.

## 2026-06-23 — Archive HTTP read-failure evidence into runtime aggregate

### Commands run
- `cargo fmt` — applied formatting for aggregate audit coverage.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 61 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`
- `tests::blocking_http_proxy_server_partial_request_timeout_is_not_forwarded ... ok`

### Interpretation
Round-69 review found no blocker/high issues and kept final runtime fan-in wiring as the next gap. Added runtime-level aggregate proof that `BlockingProxyRuntime::handle_http_proxy_once(...)` archives incomplete HTTP read evidence immediately: the aggregate includes lifecycle start records, the structured `http_proxy_client_read_incomplete` broker error with read status and observed byte count, and the final fail-closed malformed decision. This demonstrates real runtime aggregation for a listener-produced failure path rather than only frontend-local broker evidence.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Runtime aggregate is still an in-memory archived ledger, not a full async fan-in task draining to a sink with readiness/timer integration.
- Final async runtime still needs readiness/timer integration, real task registration/cancellation/join ordering, and sink-backed audit fan-in wiring.

## 2026-06-23 — Drain runtime aggregate audit records to sink

### Commands run
- `cargo fmt` — applied formatting for aggregate sink drain changes.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 61 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Interpretation
Added a sink-backed drain for `BlockingProxyRuntime` aggregate audit records. The drain writes currently aggregated lifecycle/listener records to `JsonLineAuditSink`, advances a runtime-owned cursor after successful writes, and a second drain writes zero records. The HTTP partial-read aggregate regression now proves the sink output includes session start, precise `http_proxy_client_read_incomplete` evidence, and the final malformed denial without duplicating on a repeated drain.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This is still a blocking-runtime aggregate drain; it is not a full async fan-in task with readiness/timer orchestration.
- Final async runtime still needs real task registration/cancellation/join ordering and bounded sink-backed fan-in across listener/TUN/smoltcp lifecycle sources.

## 2026-06-23 — Preserve aggregate drain cursor on sink failure

### Commands run
- `cargo fmt` — applied formatting for drain failure coverage.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 61 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Interpretation
Extended the sink-backed runtime aggregate drain proof with deterministic sink failure coverage. A failing sink returns an error before any record is counted as written; a subsequent good sink drain still emits all aggregate records, and a repeated successful drain emits zero records. This protects against silent audit loss on drain write failure while keeping the scope clearly limited to the blocking aggregate drain.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This remains a blocking-runtime aggregate drain, not full async fan-in with readiness/timer orchestration.
- Final async runtime still needs real task registration/cancellation/join ordering and bounded sink-backed fan-in across listener/TUN/smoltcp lifecycle sources.

## 2026-06-23 — Make aggregate drain cursor all-or-nothing on failure

### Commands run
- `cargo fmt` — applied formatting for aggregate drain cursor fix.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 61 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Interpretation
Round-72 correctness found that the aggregate sink drain cursor advanced after each successfully appended record, so a sink that failed after one successful record would cause a later retry to skip that first aggregate record. The drain now stages `start..end` and commits `drained_aggregate_audit_records = end` only after all appends succeed. The regression now covers both immediate sink failure and partial sink failure after one record, then verifies a later good sink drains the entire aggregate and a repeated good drain emits zero duplicates.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This remains a blocking-runtime aggregate drain, not full async fan-in with readiness/timer orchestration.
- Final async runtime still needs real task registration/cancellation/join ordering and bounded sink-backed fan-in across listener/TUN/smoltcp lifecycle sources.

## 2026-06-23 — Bridge blocking runtime sources into core fan-in

### Commands run
- `cargo fmt` — applied formatting for live fan-in bridge changes.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 61 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Interpretation
Added `BlockingProxyRuntime::ingest_live_audit_sources_into_fan_in(...)`, which feeds lifecycle, DNS, HTTP proxy, and SOCKS proxy ledgers into `RuntimeAuditFanIn` as separate named sources. The HTTP partial-read runtime regression now proves source-specific fan-in ingestion, duplicate-ingest suppression through source cursors, and sink drain output containing lifecycle start plus precise `http_proxy_client_read_incomplete` and malformed-denial evidence. This is a bridge from the blocking runtime to the core bounded fan-in API without flattening per-source sequence numbers into one ambiguous stream.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This bridges live blocking-runtime ledgers into core fan-in, but it is still invoked synchronously from tests rather than by an async fan-in task.
- Final async runtime still needs readiness/timer orchestration plus real task registration/cancellation/join ordering across listener/TUN/smoltcp sources.

## 2026-06-23 — Register audit fan-in as a runtime task

### Commands run
- `cargo fmt` — applied formatting for audit fan-in task coverage.
- `cargo test -p foxprox-egress blocking_audit_fan_in_loop_pumps_and_drains_until_cancelled --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 62 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_audit_fan_in_loop_pumps_and_drains_until_cancelled ... ok`

### Interpretation
Added an `audit_fan_in` runtime component/cleanup action and a bounded blocking fan-in pump loop. The new regression proves the pump drains fan-in records to a JSON sink, reports idle exhaustion as `timed_out`, can run under `BlockingRuntimeTaskSet` as `audit_fan_in_loop`, observes cancellation, and is recorded in lifecycle exit evidence as `audit_fan_in:audit_fan_in_loop:cancelled` with a clean task join report. This advances real task registration/cancellation/join coverage for fan-in while remaining a blocking harness rather than a production async scheduler.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The fan-in task proof uses a blocking harness and synthetic source records; it is not yet the final async readiness/timer-driven fan-in task over live listener/TUN/smoltcp sources.
- Final async runtime still needs readiness/timer orchestration across all concrete runtime tasks.

## 2026-06-23 — Fail closed on audit fan-in task errors

### Commands run
- `cargo fmt` — applied formatting for audit fan-in failure coverage.
- `cargo test -p foxprox-egress blocking_audit_fan_in_loop --all-targets --all-features` — passed, 2 audit fan-in loop tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_audit_fan_in_loop_pumps_and_drains_until_cancelled ... ok`
- `tests::blocking_audit_fan_in_loop_failure_is_lifecycle_fail_closed ... ok`

### Interpretation
Round-75 review found no blocker/high issues and kept final async fan-in as the remaining gap. Added failure-path coverage for the blocking audit fan-in runtime task: pump errors map to `RuntimeTaskStatus::Failed`, a task-set join records that failed outcome, and lifecycle exit fails closed with `audit_fan_in:audit_fan_in_loop:failed` and `failed_runtime_task_count=1`. This complements the prior clean cancellation evidence for the same fan-in task.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The fan-in task proof is still a blocking harness with synthetic source records; it is not yet final async readiness/timer-driven fan-in over live listener/TUN/smoltcp sources.
- Final async runtime still needs readiness/timer orchestration across all concrete runtime tasks.

## 2026-06-23 — Pump live runtime ledgers through fan-in loop

### Commands run
- `cargo fmt` — applied formatting for live fan-in loop coverage.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Interpretation
Extended the live blocking-runtime fan-in proof so `BlockingProxyRuntime` source ledgers are ingested and drained through the same bounded fan-in pump loop used by the audit fan-in task. The loop first ingests/drains lifecycle and HTTP partial-read records, then reaches idle and returns `timed_out`; sink output contains `network_session_start`, `http_proxy_client_read_incomplete`, and `unsupported_denied`. This ties live source-ledger fan-in to the pump loop semantics without claiming final async readiness/timer orchestration.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This still runs synchronously in the blocking harness; it is not yet the final async readiness/timer-driven fan-in task over live listener/TUN/smoltcp sources.
- Final async runtime still needs readiness/timer orchestration across all concrete runtime tasks.

## 2026-06-23 — Join listener and audit fan-in task outcomes together

### Commands run
- `cargo fmt` — applied formatting for combined listener/fan-in task coverage.
- `cargo test -p foxprox-egress blocking_listener_loop_tasks_feed_lifecycle_exit --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 152 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_listener_loop_tasks_feed_lifecycle_exit ... ok`

### Interpretation
Round-77 review found no blocker/high issues and left final async readiness orchestration as the next gap. Extended the existing listener-loop lifecycle regression so DNS, HTTP, SOCKS, and `audit_fan_in_loop` tasks are registered, cancelled, joined, and reported together. The `network_session_exit` evidence now includes `audit_fan_in:audit_fan_in_loop:cancelled` alongside the three listener task outcomes and includes audit fan-in cleanup coverage.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- The fan-in task in this combined lifecycle proof remains a blocking synthetic loop, not final async readiness/timer-driven fan-in over live listener/TUN/smoltcp sources.
- Final async runtime still needs readiness/timer orchestration across all concrete runtime tasks.

## 2026-06-23 — Fix fan-in drain cursor after partial sink failure

### Reviewer feedback
- Round-78 correctness review found a high issue: `RuntimeAuditFanIn::drain_to_sink_with_failure_sink(...)` advanced `last_drained_sequence` after each successful append. A sink failure after one successful record could leave the cursor advanced and cause retries to skip records.

### Commands run
- `cargo fmt` — applied formatting for core fan-in cursor fix and regression.
- `cargo test -p foxprox-core runtime_audit_fan_in_partial_sink_failure_retries_full_batch --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_audit_fan_in_partial_sink_failure_retries_full_batch ... ok`

### Fix
- Staged the fan-in drain cursor in a local `next_drained_sequence` and assigned `self.last_drained_sequence` only after all pending records append successfully.
- Added a two-record partial sink failure regression with a writer that accepts exactly one complete JSONL record, then fails. The test asserts:
  - first drain fails on sequence `2`,
  - failure evidence reports `last_drained_sequence=0`,
  - fan-in cursor remains `0`,
  - retry drains both records and advances to sequence `2`.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Final async runtime still needs readiness/timer orchestration and real audit fan-in ownership across live listener/TUN/smoltcp tasks.

## 2026-06-23 — Add audit fan-in ownership to blocking proxy runtime lifecycle

### Reviewer feedback
- Round-79 reviewers found no blocker/high issues in the fan-in cursor fix. The remaining concrete gap was real runtime ownership: `BlockingProxyRuntime::exit_with_task_report(...)` still only auto-derived DNS/HTTP/SOCKS cleanup, while audit fan-in coverage lived in standalone lifecycle tests.

### Commands run
- `cargo fmt` — applied formatting for blocking proxy runtime lifecycle updates.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 63 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_proxy_runtime_exit_with_task_set_cancels_and_joins_tasks ... ok`
- `tests::blocking_proxy_runtime_exit_fails_closed_for_partial_task_report ... ok`
- `tests::blocking_proxy_runtime_shares_delivered_dns_cache_with_socks_listener ... ok`

### Fix
- `BlockingProxyRuntime::bind(...)` now declares `RuntimeComponent::AuditFanIn` and the `audit_fan_in_loop` task expectation alongside DNS, HTTP, and SOCKS listener tasks.
- `BlockingProxyRuntime::exit_with_task_report(...)` now includes `RuntimeCleanupAction::AuditFanIn` in runtime cleanup evidence.
- Updated blocking proxy runtime lifecycle regressions so:
  - startup component evidence includes `audit_fan_in`,
  - cleanup action evidence includes `audit_fan_in`,
  - partial task reports fail closed when `audit_fan_in_loop` is missing,
  - task-set exit cancels and joins four tasks and records `audit_fan_in:audit_fan_in_loop:cancelled`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This adds blocking runtime lifecycle ownership/expectation for the fan-in task, but the fan-in loop remains synthetic in tests. Final async readiness/timer-driven orchestration over live listener/TUN/smoltcp sources remains outstanding.

## 2026-06-23 — Extend audit fan-in lifecycle ownership to DNS/HTTP runtime

### Reviewer feedback
- Round-80 review found no blocker/high issues. The next gap remained moving from isolated blocking proofs toward runtime-owned fan-in task registration and cleanup across concrete runtime variants.

### Commands run
- `cargo fmt` — applied formatting for DNS/HTTP runtime lifecycle updates.
- `cargo test -p foxprox-egress --all-targets --all-features` — passed, 63 egress tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `tests::blocking_dns_http_runtime_exit_backpressure_still_closes_listeners ... ok`

### Fix
- `BlockingDnsHttpRuntime::bind(...)` now declares `RuntimeComponent::AuditFanIn` and the `audit_fan_in_loop` task expectation alongside DNS and HTTP listener tasks.
- `BlockingDnsHttpRuntime::exit_with_task_report(...)` now includes `RuntimeCleanupAction::AuditFanIn` in cleanup evidence.
- Updated DNS/HTTP runtime regression expectations so startup `runtime_components` and exit `cleanup_actions` include `audit_fan_in`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Audit fan-in is now lifecycle-owned by both blocking runtime variants, but the fan-in loop remains blocking/synthetic. Final async readiness/timer-driven orchestration over live listener/TUN/smoltcp sources remains outstanding.

## 2026-06-23 — Add sink-backed live audit fan-in drain APIs

### Reviewer feedback
- Round-81 review found no blocker/high issues. The next runtime gap remained replacing synthetic fan-in plumbing with runtime-owned, sink-backed fan-in paths that can become the eventual readiness/timer task body.

### Commands run
- `cargo fmt` — applied formatting for fan-in drain API changes.
- `cargo test -p foxprox-egress blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_proxy_runtime_aggregate_captures_http_read_failures --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`
- `tests::blocking_proxy_runtime_aggregate_captures_http_read_failures ... ok`

### Fix
- Added `BlockingRuntimeAuditFanInDrainReport` with `made_progress()` so runtime-owned fan-in drains can drive idle/progress loops without open-coded accepted/drained counters.
- Added `BlockingRuntimeAuditFanInDrainError` to preserve typed ingest vs sink-drain failures.
- Added `drain_live_audit_sources_to_sink(...)` for both blocking runtime variants. Each method ingests live runtime ledgers into `RuntimeAuditFanIn`, drains to a `JsonLineAuditSink`, and returns source-ingest plus sink-drain evidence.
- Added DNS/HTTP runtime sink-backed fan-in assertions for `network_session_start`, `proxy_destination_resolved`, and `http_request_decision`, plus duplicate no-progress behavior.
- Reused the full blocking proxy runtime sink-backed method inside the bounded fan-in pump-loop regression.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This provides a reusable blocking sink-backed fan-in task body, but it is still not an async readiness/timer-driven runtime. The remaining gap is integrating this with live listener/TUN/smoltcp task scheduling and cancellation/join in the final async runtime.

## 2026-06-23 — Add shutdown final-drain API for live audit fan-in

### Reviewer feedback
- Round-82 review found no blocker/high issues. Reviewers identified shutdown/final-drain integration as part of the next runtime gap for the sink-backed fan-in body.

### Commands run
- `cargo fmt` — applied formatting for shutdown drain API and regression updates.
- `cargo test -p foxprox-egress blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 63 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`

### Fix
- Added `BlockingRuntimeAuditFanInShutdownDrainReport` with separate `before_exit` and `after_exit` drain reports.
- Added `BlockingRuntimeAuditFanInShutdownDrainError` to keep typed drain and lifecycle exit failures distinct.
- Added `exit_and_drain_live_audit_sources_to_sink(...)` for both blocking runtime variants. The method drains live sources before exit, performs lifecycle exit/cleanup, then drains again so `network_session_exit` reaches the sink after listener ownership has been closed.
- Updated DNS/HTTP runtime regression to prove:
  - duplicate pre-shutdown drain makes no progress,
  - shutdown `before_exit` makes no progress after the duplicate drain,
  - shutdown `after_exit` drains the lifecycle exit record,
  - JSONL sink output contains `network_session_start`, `proxy_destination_resolved`, `http_request_decision`, and `network_session_exit`.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Shutdown final-drain is still implemented in the blocking runtime harness. Final async readiness/timer-driven scheduling over live listener/TUN/smoltcp tasks remains outstanding.

## 2026-06-23 — Keep shutdown cleanup after pre-exit fan-in drain failure

### Reviewer feedback
- Round-83 correctness/validation found a high issue: `exit_and_drain_live_audit_sources_to_sink(...)` returned early when the pre-exit fan-in drain failed, so lifecycle exit/cleanup might not run and listeners could remain owned/open.

### Commands run
- `cargo fmt` — applied formatting for phase-specific shutdown drain errors and regressions.
- `cargo test -p foxprox-egress shutdown_drain --all-targets --all-features` — passed two shutdown drain tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_shutdown_drain_failure_still_exits_and_closes ... ok`
- `tests::blocking_proxy_runtime_shutdown_drain_emits_exit_and_closes_all_listeners ... ok`

### Fix
- Reworked `BlockingRuntimeAuditFanInShutdownDrainError` into phase-specific variants:
  - `PreExitDrain { error, exit, post_exit }`
  - `Exit { before_exit, error, post_exit }`
  - `PostExitDrain { before_exit, error }`
- Both blocking runtime shutdown-drain methods now always attempt lifecycle exit and post-exit drain after the pre-exit drain attempt.
- Added a DNS/HTTP regression where the audit sink fails during pre-exit drain. The method returns `PreExitDrain`, reports that lifecycle exit was still attempted successfully, attempts post-exit drain, records `network_session_exit`, and closes DNS/HTTP listeners.
- Added a full DNS/HTTP/SOCKS proxy runtime shutdown-drain regression proving direct full-runtime shutdown drain emits `network_session_exit`, includes SOCKS listener evidence, and closes all three listeners.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Shutdown fan-in cleanup is now fail-closed in the blocking runtime harness, but final async readiness/timer-driven orchestration over live listener/TUN/smoltcp sources remains outstanding.

## 2026-06-23 — Align TUN and smoltcp loop budget outcomes with timeout semantics

### Reviewer feedback
- Round-84 review found no blocker/high issues. The remaining runtime gap is final async readiness/timer orchestration over live listener/TUN/smoltcp sources. As a narrower step toward consistent runtime lifecycle evidence, TUN and smoltcp packet-loop budget exhaustion still overclaimed `cancelled` despite no observed cancellation.

### Commands run
- `cargo fmt` — applied formatting for TUN/smoltcp task outcome updates.
- `cargo test -p foxprox-core tun_packet_loop_reports_budget_timeout --all-targets --all-features` — passed.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_loop_reports_budget_timeout --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tun::tests::tun_packet_loop_reports_budget_timeout ... ok`
- `tests::smoltcp_tun_bridge_loop_reports_budget_timeout ... ok`

### Fix
- `TunPacketHarness::process_packet_loop_until(...)` now reports `RuntimeTaskStatus::TimedOut` when `max_packets` is exhausted without observing cancellation.
- `SmoltcpTunBridge::process_packet_loop_until(...)` now reports `RuntimeTaskStatus::TimedOut` when `max_packets` is exhausted without observing cancellation.
- Renamed and updated the budget tests so explicit cancellation remains `Cancelled`, idle completion remains `Completed`, failures remain `Failed`, and budget exhaustion is now `TimedOut`.

### Changed files
- `crates/foxprox-core/src/tun.rs`
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- TUN and smoltcp loop outcomes now distinguish timeout from cancellation, but there is still no final async readiness/timer-driven scheduler wiring live listener/TUN/smoltcp/fan-in tasks together.

## 2026-06-23 — Expose smoltcp next-poll timer evidence

### Reviewer feedback
- Round-85 review found no blocker/high issues. The remaining runtime gap is final readiness/timer-driven scheduling over live listener/TUN/smoltcp/fan-in tasks. As the next narrow step, smoltcp poll evidence did not expose the next timer deadline needed by a scheduler.

### Commands run
- `cargo test -p foxprox-stack smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply --all-targets --all-features` — passed.
- `cargo test -p foxprox-stack smoltcp_tcp_listener_accepts_handshake_and_receives_bytes --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 153 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::smoltcp_stack_consumes_ip_packet_and_emits_icmp_reply ... ok`
- `tests::smoltcp_tcp_listener_accepts_handshake_and_receives_bytes ... ok`

### Fix
- Added `next_poll_delay_ms: Option<u64>` to `StackPollEvidence`, populated from `Interface::poll_delay(...)` after every smoltcp poll.
- Preserved `None` for `StackPollEvidence::none()` and simple ICMP reply polling where no timer remains active.
- Added TCP handshake assertion that SYN/SYN-ACK polling produces a non-empty next-poll delay, giving the future runtime scheduler concrete timer evidence to wait on.

### Changed files
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- smoltcp timer readiness is now observable, but there is still no final async scheduler that consumes this timer evidence alongside listener readiness, TUN packet readiness, and sink-backed audit fan-in.

## 2026-06-23 — Add runtime readiness plan evidence

### Reviewer feedback
- Round-86 review found no blocker/high issues. The remaining gap is the final scheduler that consumes smoltcp timer evidence alongside listener readiness, TUN readiness, sink-backed fan-in, cancellation/join, and final drains.

### Commands run
- `cargo fmt` — applied formatting for readiness plan types and smoltcp conversion.
- `cargo test -p foxprox-core runtime_readiness_plan --all-targets --all-features` — passed three readiness-plan tests.
- `cargo test -p foxprox-stack smoltcp_tcp_listener_accepts_handshake_and_receives_bytes --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 156 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_readiness_plan_runs_ready_tasks_before_waiting ... ok`
- `runtime::tests::runtime_readiness_plan_uses_shortest_timer_when_no_task_ready ... ok`
- `runtime::tests::runtime_readiness_plan_reports_idle_without_ready_or_timer ... ok`
- `tests::smoltcp_tcp_listener_accepts_handshake_and_receives_bytes ... ok`

### Fix
- Added `RuntimeTaskReadiness` and `RuntimeReadinessPlan` to core runtime evidence.
- Readiness plans now expose:
  - immediate ready tasks,
  - shortest next timer delay when no task is ready,
  - idle state when neither readiness nor timers are present.
- Exported the new runtime readiness types from `foxprox-core`.
- Added `StackPollEvidence::runtime_timer_readiness()` so smoltcp `next_poll_delay_ms` becomes scheduler-ready evidence: zero delay is immediately ready, positive delay becomes a timer wait, and `None` remains idle.
- Extended the TCP handshake test to prove smoltcp timer evidence feeds a `RuntimeReadinessPlan` with `timer_wait` status and the expected delay.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-stack/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- This models readiness/timer decisions and connects smoltcp poll evidence to the model, but it is still not the final async scheduler. Listener readiness, TUN packet readiness, fan-in progress, cancellation/join, and shutdown final-drain must still be wired into a concrete runtime loop.

## 2026-06-23 — Record runtime readiness plans in lifecycle audit

### Commands run
- `cargo fmt` — applied formatting for runtime readiness audit records.
- `cargo test -p foxprox-core runtime_lifecycle_records_readiness_plan --all-targets --all-features` — passed.
- `cargo test -p foxprox-core runtime_lifecycle_rejects_readiness_plan_outside_running_state --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 158 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_records_readiness_plan ... ok`
- `runtime::tests::runtime_lifecycle_rejects_readiness_plan_outside_running_state ... ok`

### Fix
- Added `AuditKind::RuntimeReadiness`.
- Added `RuntimeLifecycleHarness::record_readiness_plan(...)` to emit structured scheduler-planning evidence while the runtime is running.
- Runtime readiness audit details include:
  - `readiness_status` (`ready`, `timer_wait`, or `idle`),
  - `ready_runtime_tasks`,
  - `ready_runtime_task_count`,
  - optional `next_ready_delay_ms`.
- Added rejection coverage proving readiness records outside the running lifecycle fail closed as `BrokerError` with `attempted_transition=record_readiness`.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/types.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Readiness/timer plans are now structured and auditable, but the final async scheduler still needs to consume real listener readiness, TUN packet readiness, smoltcp timers, fan-in progress, cancellation/join, and shutdown final-drain evidence.

## 2026-06-23 — Cover exited-state readiness audit rejection

### Reviewer feedback
- Round-88 review found no blocker/high issues. One minor evidence nit noted that readiness invalid-transition coverage asserted the `NotStarted` branch but not the `AlreadyExited` branch.

### Commands run
- `cargo fmt` — applied formatting for expanded readiness invalid-transition coverage.
- `cargo test -p foxprox-core runtime_lifecycle_rejects_readiness_plan_outside_running_state --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 158 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_lifecycle_rejects_readiness_plan_outside_running_state ... ok`

### Fix
- Expanded readiness invalid-transition coverage to assert the exited lifecycle branch.
- The test now verifies a post-exit readiness plan attempt returns `RuntimeLifecycleError::AlreadyExited`, emits fail-closed `BrokerError`, preserves `attempted_transition=record_readiness`, includes `runtime_error=already_exited`, keeps `lifecycle_state=exited`, carries `runtime_status=clean`, and records the prior runtime duration.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Readiness planning and invalid-transition evidence are now stronger, but the final async scheduler still needs to consume live listener/TUN/smoltcp/fan-in readiness and own cancellation/join/final-drain behavior.

## 2026-06-23 — Convert audit fan-in progress into readiness evidence

### Commands run
- `cargo fmt` — applied formatting for fan-in readiness helpers and runtime coverage.
- `cargo test -p foxprox-egress blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 158 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`

### Fix
- Added `BlockingRuntimeAuditFanInDrainReport::runtime_readiness()` to convert sink-backed fan-in progress into `RuntimeTaskReadiness` for `audit_fan_in:audit_fan_in_loop`.
- Added `record_readiness_plan(...)` methods to both blocking runtime variants so runtime-owned readiness plans are archived into lifecycle audit and aggregate records.
- Extended the DNS/HTTP runtime regression so:
  - a successful fan-in drain produces a `ready` readiness plan for `audit_fan_in:audit_fan_in_loop`,
  - the runtime records a `runtime_readiness` audit record before shutdown,
  - shutdown pre-exit drain captures that readiness record,
  - JSONL output includes `runtime_readiness`, and
  - lifecycle audit asserts the structured ready task evidence.

### Changed files
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Audit fan-in progress is now converted into readiness evidence, but listener readiness, TUN readiness, smoltcp timers, fan-in progress, cancellation/join, and shutdown final-drain still need to be consumed by a concrete async scheduler loop.

## 2026-06-23 — Add scheduler action evidence to readiness plans

### Commands run
- `cargo fmt` — applied formatting for scheduler action fields.
- `cargo test -p foxprox-core runtime_readiness_plan --all-targets --all-features` — passed three readiness-plan tests.
- `cargo test -p foxprox-core runtime_lifecycle_records_readiness_plan --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 158 core tests, 4 device tests, 65 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `runtime::tests::runtime_readiness_plan_runs_ready_tasks_before_waiting ... ok`
- `runtime::tests::runtime_readiness_plan_uses_shortest_timer_when_no_task_ready ... ok`
- `runtime::tests::runtime_readiness_plan_reports_idle_without_ready_or_timer ... ok`
- `runtime::tests::runtime_lifecycle_records_readiness_plan ... ok`
- `tests::blocking_dns_http_runtime_shares_delivered_dns_cache_between_listeners ... ok`

### Fix
- Added `RuntimeSchedulerAction` with stable details:
  - `run_ready_tasks`,
  - `wait_for_timer`,
  - `idle`.
- `RuntimeReadinessPlan::scheduler_action()` now exposes the scheduler action separately from `readiness_status`.
- `RuntimeLifecycleHarness::record_readiness_plan(...)` now records `scheduler_action` in `runtime_readiness` audit evidence.
- Updated core readiness-plan tests to assert the action for ready, timer-wait, and idle plans.
- Updated DNS/HTTP runtime readiness regression to assert `scheduler_action=run_ready_tasks` for fan-in readiness evidence.

### Changed files
- `crates/foxprox-core/src/runtime.rs`
- `crates/foxprox-core/src/lib.rs`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Scheduler actions are now typed and audited, but a concrete async scheduler loop still needs to consume real listener/TUN/smoltcp/fan-in readiness, run tasks, handle cancellation/join, and perform shutdown final drains.

## 2026-06-23 — Introduce Tokio async runtime task set

### Decision
- Asked for direction before introducing an async runtime dependency. User selected: introduce Tokio and start the real async scheduler path.

### Commands run
- `cargo fmt` — applied formatting for Tokio async task set and tests.
- `cargo test -p foxprox-egress async_runtime_task_set --all-targets --all-features` — passed two async task-set tests.
- `cargo test --all-targets --all-features` — passed, 8 CLI tests, 158 core tests, 4 device tests, 67 egress tests, and 13 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Evidence excerpts
- `tests::async_runtime_task_set_cancellation_is_joined_cleanly ... ok`
- `tests::async_runtime_task_set_timeout_is_fail_closed ... ok`

### Fix
- Added Tokio to `foxprox-egress` with `macros`, `rt`, and `time` features.
- Added `AsyncRuntimeTaskSet` and `AsyncRuntimeCancellationToken` using `tokio::spawn` and Tokio timeouts.
- Async task-set cancellation test proves:
  - cancellation is requested through a token,
  - the async task returns `RuntimeTaskStatus::Cancelled`,
  - lifecycle exit records `audit_fan_in:audit_fan_in_loop:cancelled` with clean task join status.
- Async timeout test proves:
  - an over-budget async task records `RuntimeTaskStatus::TimedOut`,
  - lifecycle exit fails closed with `RuntimeState`,
  - timed-out smoltcp task outcome is structured in `runtime_tasks`.

### Changed files
- `Cargo.lock`
- `crates/foxprox-egress/Cargo.toml`
- `crates/foxprox-egress/src/lib.rs`
- `learnings.md`
- `progress.md`

### Remaining blind spots
- Tokio task ownership/cancellation/join evidence is now present, but the final async scheduler still needs to consume real listener/TUN/smoltcp/fan-in readiness, run ready tasks or wait timers, and perform shutdown final-drain over live runtime sources.

## 2026-06-23 — Round-92 high fixed: await aborted async task joins

### Review
- Round-92 correctness found no blockers, but identified one high issue: `AsyncRuntimeTaskSet::join_all_with_timeout(...)` requested abort on timed-out Tokio tasks without awaiting the aborted `JoinHandle`, so lifecycle evidence could say `timed_out` before task cleanup/drop was confirmed.
- Round-92 validation found no blockers and confirmed Tokio introduction/progress scope were aligned.

### Fix
- After a Tokio join timeout, `AsyncRuntimeTaskSet::join_all_with_timeout(...)` now calls `join.abort()` and awaits the handle before recording `RuntimeTaskStatus::TimedOut`.
- Added `async_runtime_task_set_timeout_awaits_aborted_task_before_report`, using a drop flag to prove the timed-out task is dropped before the join report is returned.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_task_set --all-targets --all-features` — passed 3 async task-set tests.
- `cargo test --all-targets --all-features` — passed, including 68 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Async task timeout evidence now confirms abort completion before report emission, but cancellation is still polling-only. The next highest gap remains an awaitable/select-able cancellation mechanism and the concrete Tokio scheduler consuming live readiness/timers/fan-in sources with shutdown final drain.

## 2026-06-23 — Add awaitable async cancellation token

### Fix
- Extended `AsyncRuntimeCancellationToken` with an awaitable `cancelled()` method backed by `tokio::sync::Notify` plus an atomic cancellation state.
- Updated `AsyncRuntimeTaskSet::request_cancellation()` to wake waiting async tasks when cancellation is first requested.
- Added `async_runtime_cancellation_token_wakes_awaiting_task`, proving an async task blocked in `tokio::select!` wakes on cancellation and exits with `RuntimeTaskStatus::Cancelled` without sleep polling.

### Commands run
- `cargo fmt` — applied formatting.
- First validation attempt failed because `tokio::sync::Notify` requires Tokio's `sync` feature; fixed `crates/foxprox-egress/Cargo.toml` to include `sync`.
- `cargo test -p foxprox-egress async_runtime --all-targets --all-features` — passed 4 async runtime tests.
- `cargo test --all-targets --all-features` — passed, including 69 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Cancellation can now wake async tasks, but the concrete Tokio scheduler loop still needs to combine live listener/TUN/smoltcp/fan-in readiness, runtime timers, cancellation, joins, and shutdown final-drain behavior.

## 2026-06-23 — Add concrete Tokio scheduler step over readiness plans

### Fix
- Added `run_async_runtime_scheduler_step(...)` to record a `RuntimeReadinessPlan` and execute the matching Tokio scheduler action:
  - `run_ready_tasks` dispatches the ready task list to an async runner.
  - `wait_for_timer` awaits the shortest readiness timer or cancellation, whichever wins.
  - `idle` yields once or exits on cancellation.
- Added `AsyncRuntimeSchedulerStepReport` and `AsyncRuntimeSchedulerWaitStatus` so tests and callers can inspect the plan, scheduler action, dispatched tasks, and wait/cancellation outcome.
- Added scheduler-step tests proving:
  - ready DNS tasks are dispatched and readiness audit records `scheduler_action=run_ready_tasks`.
  - timer readiness records `scheduler_action=wait_for_timer` and waits for the timer.
  - cancellation can preempt a long timer wait.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler --all-targets --all-features` — passed 2 scheduler-step tests.
- `cargo test --all-targets --all-features` — passed, including 71 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The scheduler now executes concrete Tokio actions from audited readiness plans, but live source integration remains: DNS/HTTP/SOCKS listener readiness, TUN packet readiness, smoltcp timer evidence, fan-in progress, task spawning/joining, and shutdown final-drain still need to be wired into an end-to-end runtime loop.

## 2026-06-23 — Round-94 clean; add idle and bounded scheduler-loop evidence

### Review
- Round-94 correctness and validation found no blockers or high issues.
- Validation noted one minor non-blocking evidence gap: the scheduler step had an `idle` branch without direct scheduler-step test coverage.

### Fix
- Added direct idle scheduler-step coverage proving an idle readiness plan records `scheduler_action=idle`, dispatches no ready tasks, and yields once.
- Added `run_async_runtime_scheduler_loop_until_cancelled(...)`, a bounded Tokio scheduler loop that repeatedly gathers readiness from an injected source, records/executes scheduler steps, and stops on cancellation or a step limit.
- Added `AsyncRuntimeSchedulerLoopReport` and `AsyncRuntimeSchedulerLoopStatus`.
- Added loop coverage proving a ready DNS step dispatches first, a later smoltcp timer wait is preempted by cancellation, and readiness audit records the sequential scheduler actions.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler --all-targets --all-features` — passed 4 scheduler tests.
- Initial full validation found a clippy `redundant_closure` warning in the loop helper; replaced the closure with `&mut run_ready_tasks`.
- `cargo fmt` — reapplied formatting after clippy fix.
- `cargo test -p foxprox-egress async_runtime_scheduler --all-targets --all-features` — passed 4 scheduler tests.
- `cargo test --all-targets --all-features` — passed, including 73 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The scheduler loop is now concrete and cancellation-aware, but readiness is still supplied by an injected source. Remaining live-source integration: DNS/HTTP/SOCKS listener readiness, TUN packet readiness, smoltcp timer evidence, fan-in progress, task spawning/joining, and shutdown final-drain in an end-to-end runtime loop.

## 2026-06-23 — Round-95 high fixed: cancellation preempts ready dispatch

### Review
- Round-95 correctness found one high issue: `run_async_runtime_scheduler_step(...)` did not race the `run_ready_tasks` future against cancellation, so a pending ready-task runner could prevent cancellation and the loop step bound from being reached.
- Round-95 validation found no blockers and noted a low follow-up: the loop `StepLimitReached` branch was present but not directly asserted.

### Fix
- Updated the `run_ready_tasks` scheduler branch to use `tokio::select!` against `cancellation.cancelled()`.
- If cancellation wins during ready dispatch, the scheduler step reports `AsyncRuntimeSchedulerWaitStatus::Cancelled` and does not claim ready tasks were dispatched.
- Added `async_runtime_scheduler_step_cancellation_preempts_ready_dispatch`, using a drop flag to prove the pending ready-task future is dropped when cancellation wins.
- Added `async_runtime_scheduler_loop_reports_step_limit`, proving the bounded scheduler loop returns `StepLimitReached` after the configured number of idle scheduler steps and records ordered idle readiness evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler --all-targets --all-features` — passed 6 scheduler tests.
- `cargo test --all-targets --all-features` — passed, including 75 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Scheduler loop cancellation now covers ready dispatch, timer waits, and idle waits. Remaining runtime gap is live-source integration and shutdown final-drain: DNS/HTTP/SOCKS listener readiness, TUN packet readiness, smoltcp timer evidence, fan-in progress, task spawning/joining, and final audit drain in an end-to-end Tokio runtime loop.

## 2026-06-23 — Add readiness-source collection for scheduler loop

### Review
- Round-96 correctness and validation found no blockers or high issues.
- Both reviews identified the same next gap: live-source Tokio scheduler integration plus shutdown final-drain over DNS/HTTP/SOCKS readiness, TUN packet readiness, smoltcp timers, audit fan-in progress, task join/cancellation, and final sink drain.

### Fix
- Added `AsyncRuntimeReadinessSource` and `collect_async_runtime_readiness(...)` so the scheduler can collect readiness from heterogeneous live-source adapters while preserving source order.
- Added `run_async_runtime_scheduler_loop_with_sources_until_cancelled(...)`, which collects readiness from sources each iteration before recording/executing the audited scheduler step.
- Added collection coverage for DNS, HTTP, SOCKS, TUN, smoltcp timer, and audit fan-in readiness sources.
- Added loop coverage proving sources are polled on each iteration, a first ready DNS source dispatches, later smoltcp timer readiness waits, cancellation stops the loop, and readiness audit records the ordered scheduler actions.

### Commands run
- `cargo fmt` — applied formatting.
- Initial `cargo test -p foxprox-egress async_runtime --all-targets --all-features` failed because the expected ready-task detail ordering in the new source-order test was wrong; fixed the assertion to match `RuntimeReadinessPlan`'s source-preserving ready task order.
- `cargo fmt` — reapplied formatting.
- `cargo test -p foxprox-egress async_runtime --all-targets --all-features` — passed 12 async runtime tests.
- `cargo test --all-targets --all-features` — passed, including 77 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The scheduler loop now polls readiness-source adapters instead of only accepting a precomputed vector or step-index closure, but the sources in tests are still deterministic adapters. Remaining work is concrete adapters for real DNS/HTTP/SOCKS listeners, TUN packet readiness, smoltcp timer polling, fan-in drain progress, task joins, and shutdown final drain in an end-to-end Tokio runtime.

## 2026-06-23 — Add async task-set shutdown final-drain helper

### Fix
- Added `AsyncRuntimeAuditFanInShutdownDrainReport` and `AsyncRuntimeAuditFanInShutdownDrainError` to carry async task cancellation/join evidence alongside the existing shutdown fan-in drain report.
- Added `BlockingProxyRuntime::exit_with_async_task_set_and_drain_live_audit_sources_to_sink(...)`:
  - requests cancellation for an `AsyncRuntimeTaskSet`,
  - awaits async task joins with a timeout,
  - exits with the resulting `RuntimeTaskJoinReport`,
  - drains live audit sources before and after lifecycle exit through `RuntimeAuditFanIn`.
- Added `blocking_proxy_runtime_async_task_shutdown_drains_final_audit`, proving DNS/HTTP/SOCKS/audit-fan-in async tasks are cancelled and joined, lifecycle exit records clean task outcomes, the final drain includes `network_session_exit`, and listeners are closed after shutdown.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress blocking_proxy_runtime_async_task_shutdown_drains_final_audit --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 78 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Async task cancellation/join is now tied to shutdown final drain for the full blocking proxy runtime. Remaining work is still the true end-to-end Tokio runtime with concrete live readiness adapters for DNS/HTTP/SOCKS sockets, TUN packets, smoltcp timers, fan-in progress, and real task spawning/driving rather than synthetic async task bodies.

## 2026-06-23 — Add concrete listener and fan-in readiness source adapters

### Review
- Round-98 correctness and validation found no blockers or high issues.
- Both reviews identified the next highest gap as concrete live Tokio readiness adapters and true end-to-end runtime task driving.

### Fix
- Added `RuntimeAuditFanIn::undrained_record_count()` and `RuntimeAuditFanIn::runtime_readiness()` so audit fan-in readiness can be derived from real undrained fan-in records.
- Added `AsyncRuntimeReadinessSource` implementations for live blocking listener references:
  - `&BlockingDnsBrokerServer` -> `dns_listener:dns_accept_loop`
  - `&BlockingHttpProxyServer` -> `http_proxy_listener:http_proxy_accept_loop`
  - `&BlockingSocks5ProxyServer` -> `socks5_listener:socks5_accept_loop`
  - `&RuntimeAuditFanIn` -> `audit_fan_in:audit_fan_in_loop` based on undrained records
- Added core coverage proving fan-in readiness becomes ready after ingest and idle again after drain.
- Added egress coverage proving live `BlockingProxyRuntime` listener references plus a live fan-in instance produce ordered scheduler readiness for DNS/HTTP/SOCKS/fan-in.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-core runtime_audit_fan_in_reports_readiness_from_undrained_records --all-targets --all-features` — passed.
- `cargo test -p foxprox-egress async_runtime_readiness --all-targets --all-features` — passed 2 readiness tests.
- `cargo test --all-targets --all-features` — passed, including 159 core tests and 79 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Listener adapters currently model active nonblocking listener pollability, not OS-level readable readiness. Remaining final gap: actual Tokio socket/TUN/smoltcp readiness integration and real task driving, plus end-to-end final drain in a fully async runtime.

## 2026-06-23 — Wire scheduler-dispatched audit fan-in drain action

### Fix
- Added `run_async_runtime_audit_fan_in_ready_task(...)`, which checks dispatched ready tasks for `audit_fan_in:audit_fan_in_loop` and drains `RuntimeAuditFanIn` to a `JsonLineAuditSink` when present.
- Added `async_runtime_scheduler_dispatch_drains_ready_fan_in`, proving:
  - fan-in readiness is ready when the fan-in ledger has undrained records,
  - the audited scheduler step dispatches `audit_fan_in_loop`,
  - the dispatch drains one fan-in record to the sink,
  - fan-in readiness returns idle after the drain,
  - readiness audit records `scheduler_action=run_ready_tasks` and the fan-in ready task.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_dispatch_drains_ready_fan_in --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 159 core tests and 80 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Fan-in readiness/progress now has a concrete scheduler-dispatched drain action. Remaining final runtime gap is actual Tokio socket/TUN readiness and smoltcp timer integration with real listener/TUN task driving, not just blocking-reference pollability or deterministic harness dispatch.

## 2026-06-23 — Dispatch ready DNS listener task from scheduler action

### Review
- Round-100 correctness and validation found no blockers or high issues.
- Both reviews identified the remaining highest gap as actual Tokio socket/TUN readiness and smoltcp timer integration with real listener/TUN task driving.

### Fix
- Added `BlockingProxyRuntimeReadyTaskReport` and `BlockingProxyRuntime::dispatch_ready_proxy_listener_tasks(...)`.
- The dispatch helper maps scheduler-dispatched runtime task expectations to real listener one-step handlers:
  - `dns_listener:dns_accept_loop` -> `handle_dns_once(...)`
  - `http_proxy_listener:http_proxy_accept_loop` -> `handle_http_proxy_once(...)`
  - `socks5_listener:socks5_accept_loop` -> `handle_socks5_proxy_once(...)`
- Added `async_runtime_scheduler_dispatch_drives_ready_dns_listener_once`, proving an audited scheduler `run_ready_tasks` action can drive a real DNS listener step, send a DNS response, and archive DNS decision audit evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_dispatch_drives_ready_dns_listener_once --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 159 core tests and 81 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Scheduler-dispatched listener task driving is now proven for a real DNS listener one-step. HTTP/SOCKS dispatch paths exist but need comparable runtime tests. Final runtime gap remains actual Tokio socket/TUN readable readiness, smoltcp timer integration, and end-to-end async task driving rather than blocking one-step dispatch.

## 2026-06-23 — Add HTTP/SOCKS scheduler-dispatch listener coverage

### Review
- Round-101 correctness and validation found no blockers or high issues.
- Reviewers noted the HTTP/SOCKS dispatch branches existed but lacked comparable scheduler-dispatch runtime tests.

### Fix
- Added `async_runtime_scheduler_dispatch_drives_ready_http_and_socks_listeners_once`, proving a single audited `run_ready_tasks` scheduler action can drive both real HTTP and SOCKS listener one-step handlers.
- The test sends a real HTTP proxy request and SOCKS5 connect request to live bound listeners, dispatches `http_proxy_accept_loop` and `socks5_accept_loop` through the scheduler ready-task path, verifies allow/forwarded outcomes and client responses, and asserts archived `HttpRequestDecision` plus `SocksConnectDecision` evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_dispatch_drives_ready_http_and_socks_listeners_once --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 159 core tests and 82 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Scheduler-dispatched listener task driving now covers DNS, HTTP, and SOCKS one-step handlers. Final runtime gap remains actual Tokio OS-level socket/TUN readable readiness, smoltcp timer integration, and end-to-end async task driving/final drain rather than blocking one-step dispatch.

## 2026-06-23 — Add TUN packet readiness and ready-task dispatch evidence

### Fix
- Added `InMemoryPacketDevice::inbound_len()` and `InMemoryPacketDevice::runtime_readiness()` so TUN readiness can be derived from queued inbound packets in deterministic harnesses.
- Added `TunPacketHarness::process_ready_task(...)`, mapping `tun_device:tun_packet_loop` runtime task expectations to packet-loop processing.
- Added `tun_readiness_tracks_in_memory_inbound_packets_and_ready_dispatch`, proving queued TUN packets produce ready evidence, ready-task dispatch processes the packet and appends packet audit evidence, and readiness returns idle after the queue drains.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-core tun_readiness_tracks_in_memory_inbound_packets_and_ready_dispatch --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests and 82 egress tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- TUN scheduler evidence is still in-memory packet-queue readiness and blocking harness dispatch. Final gap remains real Tokio TUN fd readiness, smoltcp timer/readiness integration, and end-to-end async task driving/final drain.

## 2026-06-23 — Add smoltcp bridge ready-task dispatch evidence

### Review
- Round-103 correctness and validation found no blockers or high issues.
- Both reviews identified the next gap as real Tokio TUN fd readiness, smoltcp timer/readiness integration, and end-to-end async task driving/final drain.

### Fix
- Added `SmoltcpTunBridge::process_ready_task(...)`, mapping `smoltcp_stack:smoltcp_tun_bridge_loop` runtime task expectations to smoltcp bridge packet-loop processing.
- Added `smoltcp_tun_bridge_processes_ready_scheduler_task`, proving the ready-task mapping processes an inbound packet, emits/writes a stack output packet, records smoltcp packet audit evidence, and ignores unrelated ready tasks.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-stack smoltcp_tun_bridge_processes_ready_scheduler_task --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 82 egress tests, and 14 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Smoltcp ready-task dispatch now has deterministic bridge-loop evidence. Remaining final gap is integrating actual Tokio fd/socket/TUN readiness, smoltcp timer wakeups, and the full end-to-end async runtime loop with real task driving and shutdown final drain.

## 2026-06-23 — Add smoltcp timer-ready dispatch without TUN input

### Fix
- Added `SmoltcpIpStack::runtime_timer_readiness(now_ms)`, deriving `smoltcp_stack:smoltcp_tun_bridge_loop` readiness directly from `Interface::poll_delay(...)` at a scheduler timestamp.
- Added `SmoltcpIpStack::poll_ready_task(...)`, mapping `smoltcp_stack:smoltcp_tun_bridge_loop` ready task expectations to a direct stack poll without requiring a TUN packet read first.
- Added `smoltcp_timer_readiness_dispatch_polls_stack_without_tun_packet`, proving a smoltcp TCP timer plan starts as `wait_for_timer`, becomes ready at the due timestamp, and dispatches a stack poll from the ready task while ignoring unrelated ready tasks.

### Commands run
- `cargo fmt` — applied formatting.
- Initial targeted stack test compile failed because `Interface::poll_delay(...)` requires mutable access; fixed `runtime_timer_readiness` to take `&mut self`.
- `cargo test -p foxprox-stack smoltcp_timer_readiness_dispatch_polls_stack_without_tun_packet --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 82 egress tests, and 15 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Smoltcp timer readiness can now drive a stack poll without packet input in the deterministic stack adapter. Remaining final gap is still true Tokio fd/socket/TUN readiness and an end-to-end async runtime loop that wires live timers, live listener/TUN readiness, cancellation/join, audit fan-in, and shutdown final drain together.

## 2026-06-23 — Add bridge-level smoltcp timer dispatch write-back evidence

### Review
- Round-105 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest gap as timer-ready stack polling integrated with bridge-level auditing/writing of timer-generated outbound packets.

### Fix
- Added `SmoltcpTunBridge::poll_stack_ready_task(...)`, mapping `smoltcp_stack:smoltcp_tun_bridge_loop` ready tasks to a direct smoltcp stack poll that audits and writes any newly emitted outbound packets to the TUN-side packet device.
- Added `smoltcp_bridge_timer_dispatch_writes_retransmitted_stack_output`, proving a timer-ready smoltcp retransmission can be dispatched without a TUN packet read, emits one stack packet, writes it to the packet device, and records structured `to_sandbox`/`stack=smoltcp`/`write_phase=attempt` audit evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-stack smoltcp_bridge_timer_dispatch_writes_retransmitted_stack_output --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 82 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Smoltcp timer-ready bridge dispatch now audits and writes timer-generated outbound packets in the deterministic adapter. Remaining final runtime gap is actual Tokio fd/socket/TUN readiness and the full end-to-end async runtime loop wiring live timers, live listener/TUN readiness, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Add Tokio UDP socket readiness evidence

### Review
- Round-106 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest runtime gap as actual Tokio OS-level socket/TUN readiness plus end-to-end runtime loop wiring.

### Fix
- Enabled Tokio `net` support in `foxprox-egress`.
- Added `AsyncRuntimeIoReadinessStatus`, `AsyncRuntimeIoReadinessReport`, and `wait_for_async_udp_socket_readiness(...)`.
- Mapped actual `tokio::net::UdpSocket::readable()` readiness into `RuntimeTaskReadiness` for a named runtime component/task, with cancellation and timeout outcomes that do not mark the task ready.
- Added regression coverage proving a real loopback UDP datagram wakes Tokio OS-level readiness, feeds a `RuntimeReadinessPlan` with `scheduler_action=run_ready_tasks`, and leaves the packet available to be consumed by a later dispatch path.
- Added cancellation coverage proving socket readiness waits can be preempted before any packet arrives.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_udp_socket_readiness --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 84 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This narrows real Tokio OS socket readiness for UDP/DNS-style sockets only. Remaining final runtime gap is Tokio TCP listener readiness/accept integration, real TUN fd readiness, live smoltcp timer wake wiring, full ready-task dispatch in one end-to-end async runtime loop, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Add Tokio TCP listener accept readiness evidence

### Review
- Round-107 correctness and validation found no blockers or high issues.
- Reviewers identified Tokio TCP listener readiness/accept integration as one of the next highest runtime gaps.

### Fix
- Added `AsyncRuntimeTcpAcceptReport` and `accept_async_tcp_listener_when_ready(...)`.
- Mapped a real `tokio::net::TcpListener::accept()` loopback connection into `RuntimeTaskReadiness` for HTTP/SOCKS-style listener tasks, preserving the accepted stream and peer address for dispatch ownership.
- Added cancellation and timeout outcomes that leave readiness non-ready and return no accepted stream.
- Added regression coverage proving real OS TCP accept evidence feeds `RuntimeReadinessPlan` with `scheduler_action=run_ready_tasks` and the expected `http_proxy_listener:http_proxy_accept_loop` ready-task evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_tcp_listener_accept --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 87 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Tokio UDP socket readiness and TCP listener accept readiness now have focused OS-level evidence. Remaining final runtime gap is real TUN fd readiness, live smoltcp timer wake wiring, integrating these readiness/accept paths into one end-to-end async runtime loop with ready-task dispatch, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Add Tokio AsyncFd packet readiness evidence for the TUN task boundary

### Review
- Round-108 correctness and validation found no blockers or high issues.
- Reviewers identified real TUN fd readiness and integration into the end-to-end async loop as the next highest runtime gap.

### Fix
- Added Unix-only `wait_for_async_packet_fd_readiness(...)`, using `tokio::io::unix::AsyncFd` to wait for readability and map the result to `tun_device:tun_packet_loop` `RuntimeTaskReadiness`.
- Added regression coverage using a nonblocking OS fd pair to prove packet-like fd readability feeds a `RuntimeReadinessPlan` with `scheduler_action=run_ready_tasks` and leaves the bytes available for the later TUN dispatch path.
- Added cancellation coverage proving packet-fd readiness waits can be preempted before any packet arrives and remain non-ready.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_packet_fd_readiness --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 89 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This is Tokio `AsyncFd` packet-fd readiness evidence for the TUN scheduler boundary using a deterministic fd pair, not a real `/dev/net/tun` creation/handoff proof. Remaining final runtime gap is actual TUN device fd setup/handoff, live smoltcp timer wake wiring, and integrating UDP/TCP/packet-fd readiness into one end-to-end async runtime loop with ready-task dispatch, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Add AsyncFd packet ready-task read dispatch evidence

### Review
- Round-109 correctness and validation found no blockers or high issues.
- Reviewers identified the next gap as actual `/dev/net/tun` setup/handoff and a coupled AsyncFd read-dispatch loop that drains/clears readiness correctly.

### Fix
- Added `AsyncRuntimePacketFdReadReport` and Unix-only `read_async_packet_fd_ready_task(...)`.
- The helper ignores unrelated ready tasks, waits on `tokio::io::unix::AsyncFd`, reads packet bytes through `AsyncFdReadyGuard::try_io(...)` for `tun_device:tun_packet_loop`, and returns the bytes plus structured readiness status.
- Added regression coverage proving unrelated tasks do not consume bytes, a matching TUN ready task reads the packet and feeds `RuntimeReadinessPlan` with `scheduler_action=run_ready_tasks`, and a follow-up wait times out after the fd is drained/cleared.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_packet_fd_ready_task_reads_and_clears_readiness --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 90 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This proves AsyncFd packet-fd ready-task read dispatch and readiness clearing with a deterministic fd pair. It is still not real `/dev/net/tun` setup/handoff. Remaining final runtime gap is actual TUN device fd setup/handoff, live smoltcp timer wake wiring, and integrating UDP/TCP/packet-fd readiness plus dispatch into one end-to-end async runtime loop with cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Integrate live Tokio IO readiness reports in one scheduler step

### Review
- Round-110 correctness and validation found no blockers or high issues.
- Reviewers identified the next gap as integrating UDP/TCP/packet-fd readiness, smoltcp timer wakeups, cancellation/join, audit fan-in, and shutdown final drain into one end-to-end async runtime loop.

### Fix
- Added `collect_async_runtime_readiness_from_reports(...)` to fan in structured IO readiness/accept/read reports and additional runtime readiness into scheduler-ready task evidence.
- Added `async_runtime_scheduler_step_integrates_live_io_reports_and_dispatch`, proving one Tokio scheduler step can combine:
  - real UDP socket readiness for `dns_listener:dns_accept_loop`,
  - real TCP accept ownership for `http_proxy_listener:http_proxy_accept_loop`,
  - packet-fd readiness/read dispatch for `tun_device:tun_packet_loop`, and
  - `audit_fan_in:audit_fan_in_loop` readiness,
  then execute a cancellation-aware ready-task dispatch closure that consumes/owns each live input.
- The test asserts the unified `RuntimeReadinessPlan` records `scheduler_action=run_ready_tasks` and all expected ready task evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_step_integrates_live_io_reports_and_dispatch --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 91 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This is a bounded integration proof for live UDP/TCP/packet-fd readiness reports and dispatch in one scheduler step. It is not yet real `/dev/net/tun` setup/handoff, live smoltcp timer wake dispatch in the same loop, full task lifecycle ownership across repeated runtime iterations, or shutdown final-drain integration.

## 2026-06-23 — Cover packet-read branch in live readiness report collector

### Review
- Round-111 correctness and validation found no blockers or high issues.
- Reviewers noted a non-blocking coverage gap: the unified scheduler-step test appended packet-fd readiness manually after calling `collect_async_runtime_readiness_from_reports(...)`, so the helper's `packet_read_reports` branch/order was not directly exercised.

### Fix
- Added `async_runtime_report_collector_preserves_packet_readiness_order`, proving `collect_async_runtime_readiness_from_reports(...)` preserves source order across IO reports, TCP accept reports, packet-read reports, and additional readiness.
- The test asserts the resulting ready-task detail order includes `tun_device:tun_packet_loop` from the packet-read report branch before `audit_fan_in:audit_fan_in_loop` additional readiness.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_report_collector_preserves_packet_readiness_order --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 92 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The collector branch/order is now directly covered. Remaining final runtime gap is still actual `/dev/net/tun` setup/handoff, live smoltcp timer wake dispatch in the same repeated runtime loop, full lifecycle ownership, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Dispatch live smoltcp timer wake inside the Tokio scheduler loop

### Review
- Round-112 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest gap as actual `/dev/net/tun` setup/handoff plus live smoltcp timer wake dispatch in the same repeated async runtime loop with lifecycle ownership and shutdown final drain.

### Fix
- Added `foxprox-stack` as a dev-dependency of `foxprox-egress` so egress scheduler tests can exercise real stack timer readiness without changing production core layering.
- Added `async_runtime_scheduler_loop_dispatches_live_smoltcp_timer_wake`, proving the Tokio scheduler loop can collect a real `SmoltcpIpStack::runtime_timer_readiness(...)` timer-due task and dispatch it via `SmoltcpIpStack::poll_ready_task(...)` in the ready-task closure.
- The test drives a real smoltcp TCP SYN/SYN-ACK timer path, starts the scheduler loop at the due timestamp, records `scheduler_action=run_ready_tasks`, dispatches `smoltcp_stack:smoltcp_tun_bridge_loop`, and observes a retransmitted packet emitted by the stack poll.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_loop_dispatches_live_smoltcp_timer_wake --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 93 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This brings real smoltcp timer wake dispatch into the Tokio scheduler loop as test evidence, but it starts the loop at the due timestamp and does not yet prove the full production runtime waits until that deadline, owns repeated task lifecycles, or performs shutdown final drain. Actual `/dev/net/tun` setup/handoff also remains outside the proof.

## 2026-06-23 — Prove Tokio scheduler timer wait before smoltcp dispatch

### Review
- Round-113 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest runtime gap as proving the scheduler waits from a `timer_wait` plan until the smoltcp deadline, then dispatches, plus real `/dev/net/tun` setup/handoff and shutdown final-drain ownership.

### Fix
- Added `async_runtime_scheduler_loop_waits_then_dispatches_smoltcp_timer_wake`.
- The test starts the Tokio scheduler loop one millisecond before a real smoltcp retransmission deadline, records `scheduler_action=wait_for_timer`, observes `TimerElapsed`, then collects readiness again at the due timestamp and dispatches `smoltcp_stack:smoltcp_tun_bridge_loop` through `SmoltcpIpStack::poll_ready_task(...)`.
- The test asserts the lifecycle audit includes both `timer_wait`/`next_ready_delay_ms=1` evidence and the subsequent `run_ready_tasks` evidence for the smoltcp stack task.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_runtime_scheduler_loop_waits_then_dispatches_smoltcp_timer_wake --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 94 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This proves timer waiting and due dispatch in the bounded Tokio scheduler loop. Remaining final runtime gap is actual `/dev/net/tun` setup/handoff, live UDP/TCP/packet-fd readiness and smoltcp timer dispatch across the same production runtime ownership loop, cancellation/join, audit fan-in, and shutdown final drain.

## 2026-06-23 — Tie owned async scheduler task cancellation to shutdown final drain

### Review
- Round-114 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest runtime gap as production end-to-end ownership: actual `/dev/net/tun` setup/handoff, live UDP/TCP/packet-fd readiness plus smoltcp timer dispatch in the same loop, cancellation/join, audit fan-in, and shutdown final drain.

### Fix
- Added `async_owned_scheduler_task_shutdown_cancels_joins_and_drains`.
- The test runs a Tokio scheduler loop inside an `AsyncRuntimeTaskSet` cancellable `audit_fan_in_loop` task, lets the loop enter a long timer wait, then shuts down through `BlockingProxyRuntime::exit_with_async_task_set_and_drain_live_audit_sources_to_sink(...)`.
- The test proves shutdown cancellation wakes the owned scheduler loop, the task reports `RuntimeTaskStatus::Cancelled`, all async tasks join with complete status, the runtime emits `network_session_exit`, and fan-in final drain captures the cancelled `audit_fan_in_loop` task evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_owned_scheduler_task_shutdown_cancels_joins_and_drains --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 95 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This ties owned scheduler-loop cancellation/join to existing shutdown final-drain evidence, but it uses a synthetic long timer wait and does not yet combine real UDP/TCP/packet-fd/smoltcp readiness in one production-owned loop. Actual `/dev/net/tun` setup/handoff remains outside the proof.

## 2026-06-23 — Fix owned scheduler shutdown wait proof

### Review
- Round-115 correctness found a high issue: `async_owned_scheduler_task_shutdown_cancels_joins_and_drains` set its readiness flag before entering the scheduler loop, so shutdown cancellation could occur at the top-of-loop precheck without proving a cancellable timer wait step was entered.
- Round-115 validation found no additional blocker/high issues.

### Fix
- Reworked `async_owned_scheduler_task_shutdown_cancels_joins_and_drains` to signal after the readiness source creates the long timer-wait plan and to capture the owned scheduler loop report after shutdown joins it.
- Added assertions that the owned scheduler report contains exactly one step with `scheduler_action=wait_for_timer`, `wait_status=cancelled`, `next_ready_delay_ms=60000`, and no dispatched tasks before the task reports `RuntimeTaskStatus::Cancelled`.
- This removes the overclaim that cancellation necessarily woke an in-flight wait without evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_owned_scheduler_task_shutdown_cancels_joins_and_drains --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 95 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The owned scheduler shutdown proof now verifies a cancelled timer-wait step, but it still uses synthetic readiness. Remaining final runtime gap is actual `/dev/net/tun` setup/handoff plus a production-owned loop combining live UDP/TCP/packet-fd readiness and smoltcp timer dispatch with shutdown final drain.

## 2026-06-23 — Dispatch live Tokio IO from an owned scheduler task before shutdown drain

### Review
- Round-116 correctness and validation found no blockers or high issues.
- Reviewers identified the remaining gap as actual `/dev/net/tun` setup/handoff plus a production-owned loop combining live UDP/TCP/packet-fd readiness and smoltcp timer dispatch with shutdown final drain.

### Fix
- Added `async_owned_live_io_scheduler_task_dispatches_then_shutdown_drains`.
- The test runs an owned Tokio scheduler task inside `AsyncRuntimeTaskSet`, gathers real UDP socket readiness, real TCP accept ownership, and real packet-fd readiness, then dispatches all three live inputs plus audit-fan-in readiness through `run_async_runtime_scheduler_step(...)`.
- After live dispatch, the owned scheduler task enters a cancellation-aware timer wait; runtime shutdown cancels and joins it through `exit_with_async_task_set_and_drain_live_audit_sources_to_sink(...)`, preserving final `network_session_exit` and cancelled `audit_fan_in_loop` evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_owned_live_io_scheduler_task_dispatches_then_shutdown_drains --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 96 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This covers production-owned live UDP/TCP/packet-fd dispatch plus shutdown final drain. It does not include real smoltcp dispatch in the owned task because `SmoltcpIpStack` is not `Send` under the current `tokio::spawn`-based task set; smoltcp timer dispatch remains covered by bounded scheduler-loop tests. Actual `/dev/net/tun` setup/handoff remains outside the proof.

## 2026-06-23 — Add local async task ownership for non-Send smoltcp dispatch

### Review
- Round-117 correctness and validation found no blockers or high issues.
- Reviewers identified the next gap as real `/dev/net/tun` setup/handoff plus production integration of live UDP/TCP/packet-fd readiness, smoltcp timer/dispatch ownership despite non-Send constraints, cancellation/join, audit fan-in, and shutdown final drain in one runtime loop.

### Fix
- Added `AsyncLocalRuntimeTaskSet`, a `tokio::task::spawn_local`-backed task set for non-`Send` futures with the same cancellation and timeout join evidence shape as `AsyncRuntimeTaskSet`.
- Added `async_local_task_set_owns_non_send_smoltcp_timer_dispatch`, proving a local owned task can move non-`Send` `SmoltcpIpStack` state, dispatch real smoltcp timer readiness through the Tokio scheduler loop, then enter a cancellation-aware timer wait and join as `RuntimeTaskStatus::Cancelled`.
- This narrows the smoltcp ownership gap without weakening the existing Send-bound task set used for ordinary runtime tasks.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_local_task_set_owns_non_send_smoltcp_timer_dispatch --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 97 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Non-`Send` smoltcp state now has local task ownership evidence, but it is not yet wired into a production runtime loop with live UDP/TCP/packet-fd readiness, audit fan-in, and shutdown final drain. Actual `/dev/net/tun` setup/handoff remains outside the proof.

## 2026-06-23 — Drain local smoltcp task lifecycle evidence after cancellation

### Review
- Round-118 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest runtime gap as production integration: real `/dev/net/tun` setup/handoff and one owned runtime loop combining live UDP/TCP/packet-fd readiness, local smoltcp dispatch, audit fan-in, cancellation/join, and shutdown final drain.

### Fix
- Added `async_local_smoltcp_task_exit_drains_final_lifecycle_audit`.
- The test runs a non-`Send` smoltcp scheduler task under `AsyncLocalRuntimeTaskSet`, dispatches real smoltcp timer readiness, cancels and joins it as `RuntimeTaskStatus::Cancelled`, then feeds that join report into a lifecycle exit that expects `smoltcp_stack:smoltcp_tun_bridge_loop`.
- The test ingests lifecycle records into `RuntimeAuditFanIn`, drains them to a JSON sink, and asserts final drain evidence includes `network_session_start`, `network_session_exit`, `smoltcp_stack:smoltcp_tun_bridge_loop:cancelled`, `task_join_status=complete`, and smoltcp cleanup evidence.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_local_smoltcp_task_exit_drains_final_lifecycle_audit --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 98 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This ties local non-`Send` smoltcp task ownership to lifecycle exit and fan-in final drain evidence, but it is still a dedicated lifecycle proof. Remaining final runtime gap is one production-owned runtime loop combining live UDP/TCP/packet-fd readiness, local smoltcp dispatch, audit fan-in, cancellation/join, shutdown final drain, and actual `/dev/net/tun` setup/handoff.

## 2026-06-23 — Combine live IO, local smoltcp dispatch, cancellation, and final drain in one local runtime proof

### Review
- Round-119 correctness and validation found no blockers or high issues.
- Reviewers identified the next highest runtime gap as one production-owned runtime loop combining live UDP/TCP/packet-fd readiness, local smoltcp dispatch, audit fan-in, cancellation/join, shutdown final drain, and actual `/dev/net/tun` setup/handoff.

### Fix
- Added `async_local_scheduler_combines_live_io_smoltcp_and_final_drain`.
- The test uses a single `LocalSet`/`AsyncLocalRuntimeTaskSet` proof with a shared lifecycle to combine:
  - real UDP socket readiness and dispatch,
  - real TCP accept ownership,
  - real packet-fd readiness/read dispatch,
  - local non-`Send` smoltcp timer readiness/dispatch,
  - audit-fan-in readiness,
  - cancellation-aware timer wait and local task joins,
  - lifecycle exit with all expected runtime task outcomes, and
  - `RuntimeAuditFanIn` drain to JSON sink.
- The test asserts runtime readiness evidence, all five cancelled runtime task outcomes, `network_session_exit`, `task_join_status=complete`, and `cleanup_status=complete`.
- Fixed an intermediate clippy failure by taking ownership of the shared lifecycle out of `RefCell<Option<_>>` before awaited scheduler calls, then restoring it after the await.

### Commands run
- `cargo fmt` — applied formatting.
- `cargo test -p foxprox-egress async_local_scheduler_combines_live_io_smoltcp_and_final_drain --all-targets --all-features` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This is the strongest local runtime proof so far: live UDP/TCP/packet-fd readiness, local smoltcp dispatch, cancellation/join, lifecycle exit, and fan-in final drain share one lifecycle. Remaining final gap is converting this proof into production runtime wiring and replacing the deterministic packet-fd stand-in with actual `/dev/net/tun` setup/handoff.

## 2026-06-23 — Add safe Unix TUN fd handoff evidence

### Review
- Round-120 correctness found no blockers or high issues for `37ee711`.
- Validation output artifact contained only `(image?)`, but the correctness review confirmed validation evidence and the next highest gap remained production runtime wiring plus replacing the packet-fd stand-in with actual `/dev/net/tun` setup/handoff.

### Fix
- Added `unix-ancillary` to `foxprox-device` for safe SCM_RIGHTS fd passing without local unsafe code.
- Added Unix-only TUN fd handoff helpers:
  - `send_tun_fd(...)` sends a borrowed fd with a versioned `foxprox-tun-fd-v1:<tun_name>` payload.
  - `recv_tun_fd(...)` receives exactly one `OwnedFd`, validates the versioned tun-name payload, and returns structured success or fail-closed handoff evidence.
  - `ReceivedTunFd::into_file_device(...)` converts a received fd into a `TunIoPacketDevice<File>` ownership boundary.
  - `open_dev_net_tun_handoff(...)` / `open_tun_device_path(...)` provide the safe open/handoff evidence boundary for `/dev/net/tun` or an injected path.
- Added `TunFdHandoffReport`, `TunFdHandoffStatus`, and `TunFdHandoffErrorKind` with `tun_configured` success audit and fail-closed `broker_error` audit details including `handoff=scm_rights`, `handoff_status`, `fd_count`, `handoff_payload`, `device_path`, and `handoff_error`.
- Added tests proving:
  - a Unix fd sent over a control socket is received as packet-device ownership, can read sandbox-side bytes, can write replies, and emits `tun_configured` handoff audit evidence;
  - mismatched handoff payload fails closed with `broker_error` and `handoff_error=unexpected_payload`;
  - device-open success and missing-path failure emit structured success/fail-closed evidence.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 7 device tests.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 7 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This closes the safe fd handoff contract and packet-device ownership boundary, but it still does not configure a Linux TUN interface with `TUNSETIFF` or prove privileged namespace setup in CI. The remaining runtime gap is production wiring that runs the setup helper, receives the real `/dev/net/tun` fd, wraps it in async readiness, and drives it in the combined Tokio/LocalSet runtime loop with final shutdown drain.

## 2026-06-23 — Distinguish direct TUN fd open evidence from SCM_RIGHTS handoff

### Review
- Round-121 validation found no high issues.
- Round-121 correctness found no blockers but raised a high note: `open_tun_device_path(...)` was reporting successful plain path opens as `tun_configured` with `handoff=scm_rights`, and the test proved that overclaim with a temp regular file.

### Fix
- Added `AuditKind::TunFdOpened` for direct fd-open evidence.
- Added `TunFdHandoffSource::{ScmRights, DeviceOpen}` and records `fd_source` in handoff/open audit details.
- Direct open success now reports:
  - `kind=tun_fd_opened`,
  - `fd_source=device_open`,
  - `handoff_status=opened`,
  - no `handoff_payload`.
- SCM_RIGHTS send/receive still reports `tun_configured` with `fd_source=scm_rights` and the versioned handoff payload.
- Open failure remains fail-closed `broker_error` with `fd_source=device_open` and `handoff_error=open_failed`.
- Updated tests to assert the distinction and to prevent temp-file path-open evidence from overclaiming configured TUN handoff.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 7 device tests.
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 160 core tests.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 7 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Direct open evidence is now scoped accurately and no longer claims TUN configuration. Remaining production gap is still privileged setup/TUNSETIFF, real setup-helper execution and fd handoff, async wrapping of the received TUN fd, and integration into the combined Tokio/LocalSet runtime loop with shutdown final drain.

## 2026-06-23 — Feed SCM_RIGHTS TUN handoff into combined local runtime proof

### Review
- Round-122 correctness and validation found no blocker/high issues. Reviewers confirmed direct fd-open evidence is now scoped separately from SCM_RIGHTS configured handoff and the next gap remains privileged setup/TUNSETIFF plus production runtime wiring.

### Fix
- Added `foxprox-device` as a dev-dependency of `foxprox-egress`.
- Updated `async_local_scheduler_combines_live_io_smoltcp_and_final_drain` so the packet-fd readiness path now receives its TUN-side fd through the safe SCM_RIGHTS setup-control helper before wrapping it in Tokio `AsyncFd`.
- The combined local runtime proof now validates `tun_configured` handoff evidence (`fd_source=scm_rights`, `handoff_status=received`, `tun_name=foxprox0`) before using the received fd for packet readiness/read dispatch.
- This narrows the previous packet-fd stand-in: the fd is still a deterministic UnixStream pair for CI, but the ownership path now exercises the same safe handoff boundary the setup helper will use for a real TUN fd.

### Commands run
- `cargo test -p foxprox-egress async_local_scheduler_combines_live_io_smoltcp_and_final_drain --all-targets --all-features` — passed.
- `cargo clippy -p foxprox-egress --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 7 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The combined proof now includes safe setup-control fd handoff before async packet readiness, but it still does not create/configure a Linux TUN interface with `TUNSETIFF`, execute the real privileged setup helper, or run production wiring outside the deterministic test harness.

## 2026-06-23 — Drain TUN handoff evidence in combined local runtime proof

Commit: 68d6282

### Review
- Round-123 correctness and validation found no blocker/high issues. The only note was that the next highest gap remains real privileged `/dev/net/tun` setup/TUNSETIFF, setup-helper execution, and production runtime wiring beyond the deterministic local proof.

### Fix
- Extended `async_local_scheduler_combines_live_io_smoltcp_and_final_drain` so setup-control SCM_RIGHTS `tun_configured` evidence is not only asserted before `AsyncFd` wrapping, but also appended to a setup audit ledger.
- The final `RuntimeAuditFanIn` drain now ingests both the setup handoff ledger and lifecycle records, and the JSON sink assertions prove final drain output includes `tun_configured` and `fd_source=scm_rights` alongside runtime readiness, task cancellation, lifecycle exit, and cleanup evidence.
- This narrows the final-drain gap for setup handoff evidence while keeping scope bounded to a deterministic UnixStream-backed fd in CI.

### Commands run
- `cargo test -p foxprox-egress async_local_scheduler_combines_live_io_smoltcp_and_final_drain --all-targets --all-features` — passed.
- `cargo clippy -p foxprox-egress --all-targets --all-features -- -D warnings` — passed after fixing a test-only import warning.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 7 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Final drain now includes the safe setup-control handoff record, but the proof still does not create/configure a Linux TUN interface with `TUNSETIFF`, execute the real privileged setup helper, or run production runtime wiring outside the deterministic harness.

## 2026-06-23 — Add setup-helper TUN handoff executor evidence

Commit: c96d3d5

### Review
- Round-124 correctness and validation found no blocker/high issues. Reviewers confirmed the combined local runtime proof now drains setup-control SCM_RIGHTS handoff evidence through `RuntimeAuditFanIn` and that the next highest gap is real privileged `/dev/net/tun` creation/configuration with `TUNSETIFF`, setup-helper execution, and production runtime wiring beyond the deterministic harness.

### Fix
- Added a Unix-only `TunSetupDeviceOps` abstraction in `foxprox-device` for the setup-helper sequence: open TUN fd, configure the TUN, and send the fd over setup control.
- Added `execute_tun_setup_handoff(...)`, which runs that sequence, records ordered open/configure/handoff evidence, stops before handoff on configure failure, and emits a setup summary audit with `setup_status`, `completed_steps`, and `failed_step` details.
- Added tests proving:
  - successful setup execution records `tun_fd_opened`, `tun_configured` configure evidence, SCM_RIGHTS `tun_configured` handoff evidence, and hands off a packet-capable fd;
  - configure failure is fail-closed, records only completed pre-failure steps, and does not send the fd.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 9 device tests.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed after boxing the configure-error audit record to satisfy `clippy::result-large-err`.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 9 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The setup-helper sequence is now executable through injected operations with structured success/failure evidence, but the real privileged Linux implementation is still missing: actual `TUNSETIFF`, route/DNS/proxy configuration commands, real helper process execution, and production runtime wiring outside the deterministic harness.

## 2026-06-23 — Complete TUN setup handoff failure evidence

Commit: 0a88de3

### Review
- Round-125 correctness and validation found no blocker/high issues. Reviewers confirmed `execute_tun_setup_handoff(...)` is ordered, fail-closed before handoff on configure failure, and accurately scoped as deterministic injected operations rather than real privileged TUN setup.

### Fix
- Added `TunSetupHandoffReport::audit_records_with_summary(...)` so callers can drain ordered setup evidence plus the terminal setup summary audit together.
- Added handoff-send failure coverage: after successful open/configure, a failed `send_tun_fd` records fail-closed `broker_error` evidence with `fd_source=scm_rights` and `handoff_error=send_failed`, reports `failed_step=handoff_tun_fd`, and appends a summary failure audit.
- Extended success and configure-failure tests to assert the summary audit is included in the drainable setup record set.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 10 device tests.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 10 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The setup executor now covers configure and handoff-send fail-closed paths with drainable summary evidence, but real privileged Linux implementation is still missing: actual `TUNSETIFF`, route/DNS/proxy commands, real helper process execution, and production runtime wiring outside deterministic harnesses.

## 2026-06-23 — Cover TUN setup open failure evidence

Commit: c51e9e2

### Review
- Round-127 correctness and validation found no blocker/high issues. Reviewers confirmed the Round-126 progress hash issue was fixed and that the remaining highest gap is real privileged Linux TUN setup/configuration plus real setup-helper execution and production runtime wiring.

### Fix
- Extended the scripted setup ops to support an injected open failure.
- Added `tun_setup_handoff_executor_fails_closed_before_configure_on_open_error`, proving `execute_tun_setup_handoff(...)` stops before configure/handoff when opening the TUN fd fails.
- The new regression asserts no completed setup steps, `failed_step=open_tun`, no configure or handoff report, fail-closed `broker_error` evidence with `fd_source=device_open` and `handoff_error=open_failed`, and a drainable failed summary audit.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 11 device tests.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 11 device tests, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The setup executor now covers open, configure, and handoff-send fail-closed paths with drainable summary evidence, but real privileged Linux implementation is still missing: actual `TUNSETIFF`, route/DNS/proxy commands, real helper process execution, and production runtime wiring outside deterministic harnesses.

## 2026-06-23 — Add tun-rs Linux setup implementation

Commit: e6638d2

### Decision
- User explicitly chose to continue with actual implementation rather than harness-only work. The new path uses the existing setup handoff harness to validate real functionality.

### Review
- Round-129 correctness and validation found no blocker/high issues. Reviewers confirmed the Round-128 progress hash issue was fixed and the next highest gap remained real privileged Linux TUN setup/configuration, route/DNS/proxy commands, helper execution, and production runtime wiring.

### Fix
- Added `tun-rs` as a Linux-only `foxprox-device` dependency.
- Added `LinuxTunSetupOps`, a real Linux `TunSetupDeviceOps` implementation using the safe public `tun_rs::DeviceBuilder` / `SyncDevice` API under `#![forbid(unsafe_code)]`.
- `LinuxTunSetupOps::open_tun(...)` creates a named disabled TUN device with the configured MTU and returns `tun_fd_opened` evidence.
- `LinuxTunSetupOps::configure_tun(...)` configures the IPv4 sandbox address/prefix and enables the device, returning `tun_configured` evidence with `configured_by=tun-rs`.
- `LinuxTunSetupOps::send_tun_fd(...)` hands the real `SyncDevice` fd over the existing SCM_RIGHTS setup-control path.
- Added an ignored Linux integration test, `linux_tun_setup_ops_attempts_real_setup_handoff_when_privileged`, that can be run in a privileged environment with CAP_NET_ADMIN and `/dev/net/tun` to exercise real create/configure/handoff and receive the fd back through the existing handoff helper.

### Commands run
- `cargo test -p foxprox-device --all-targets --all-features` — passed, 11 device tests and 1 ignored privileged Linux test.
- `cargo clippy -p foxprox-device --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 160 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Actual Linux TUN create/configure/handoff now has a concrete implementation and an ignored privileged integration test, but unprivileged CI only compiles it. Remaining production gaps are route/DNS/proxy setup commands, real `foxproxsetup` process execution around this implementation, and production runtime wiring/final drain outside deterministic harnesses.

## 2026-06-23 — Wire foxproxsetup handoff execution path

Commit: d38d41a

### Review
- Round-131 correctness and validation found no blocker/high issues. Reviewers confirmed the Round-130 stale progress hash was fixed: the tun-rs Linux setup implementation section now records `Commit: e6638d2`, and the follow-up `141e469` only corrected that ledger entry.

### Fix
- Added a Unix `foxproxsetup` handoff execution path in `foxprox-cli` that reuses the existing setup flag parser, requires `--setup-control-fd`, executes `execute_tun_setup_handoff(...)` through injected `TunSetupDeviceOps`, and emits structured JSON containing setup status, ordered audit records plus summary, proxy environment, and target command.
- Added Linux `run_foxproxsetup_linux_handoff_with_control(...)` that backs the same CLI handoff execution path with real `LinuxTunSetupOps` from `foxprox-device`.
- Preserved the existing plan-first `run_foxproxsetup_args(...)` behavior so current bwrap plan/audit output remains stable.
- Added deterministic Unix tests proving successful setup handoff output includes `tun_fd_opened`, configure evidence, SCM_RIGHTS `tun_configured`, summary evidence, target/proxy context, and an actually receivable fd over the setup-control socket.
- Added fail-closed CLI execution coverage proving configure failure exits before handoff, returns exit code 2, and emits `broker_error` plus failed setup summary evidence.
- Added missing-control-fd coverage proving handoff execution fails closed before setup work when `--setup-control-fd` is absent.
- Added an ignored privileged Linux test for the real `LinuxTunSetupOps`-backed CLI handoff path.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 11 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 11 CLI tests + 1 ignored, 160 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This wires a safe, testable `foxproxsetup` handoff execution path around the real Linux TUN setup ops, but the production binary still does not reconstruct the setup-control `UnixStream` from an inherited raw fd, drop capabilities, close setup-only fds, or `exec` the target app. Route/DNS/proxy setup commands and production runtime/final-drain wiring also remain.

## 2026-06-23 — Add safe setup control socket handoff

Commit: 4735f46

### Review
- Round-132 correctness and validation found no blocker/high issues. Reviewers confirmed the `foxproxsetup` handoff execution path is accurately scoped, the progress ledger records implementation commit `d38d41a`, and the remaining gaps are production setup-control ownership, capability drop/close/exec, route/DNS/proxy commands, and runtime final-drain wiring.

### Fix
- Added optional `NetworkSetupConfig::setup_control_socket_path` with serde defaults so existing configs remain compatible.
- Added validation for empty setup-control socket paths and ambiguous fd+socket control configuration.
- Extended `SetupHelperPlan` and `BwrapSetupPlan` to carry a `--setup-control-socket` handoff path as a safe alternative to inherited raw-fd reconstruction.
- Added `run_foxproxsetup_handoff_connecting_with_ops(...)`, which parses normal `foxproxsetup` flags, safely connects to the configured Unix socket path with `UnixStream::connect`, then executes the existing handoff runner and emits the same structured setup/audit JSON.
- Added Linux `run_foxproxsetup_linux_handoff_connecting(...)` wrapper backed by real `LinuxTunSetupOps`.
- Added deterministic coverage proving the socket-path handoff can connect, send an fd over SCM_RIGHTS, and be received by the listening side, plus fail-closed coverage for missing/unreachable setup-control sockets.

### Commands run
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 161 core tests.
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 13 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo test --all-targets --all-features` — passed, including 13 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- This avoids local unsafe fd reconstruction by supporting a socket-path setup-control channel, but the actual `foxproxsetup` binary still defaults to the plan-first path and is not yet switched to execute setup/control handoff in production. Capability drop/close/exec, route/DNS/proxy setup commands, and production runtime/final-drain wiring remain.

## 2026-06-23 — Add foxproxsetup execute mode

Commit: 31e3e99

### Review
- Round-133 correctness and validation found no blocker/high issues. Reviewers confirmed the safe setup-control socket handoff entry is correctly scoped, records implementation commit `4735f46`, and remains honest about production gaps.

### Fix
- Added `run_foxproxsetup_entry_args(...)` and switched the `foxproxsetup` binary entrypoint to use it.
- `foxproxsetup` now defaults to the existing plan-first behavior unless invoked with `--execute-setup`.
- Added Linux execute-mode dispatch from `--execute-setup` to the safe socket-path handoff runner backed by real `LinuxTunSetupOps`.
- Added a Unix injectable execute-mode entrypoint for deterministic testing with scripted setup ops.
- When `NetworkSetupConfig::setup_control_socket_path` is configured, `BwrapSetupPlan` now emits `foxproxsetup --execute-setup ... --setup-control-socket <path> ...`, while existing fd/no-socket plans keep their previous plan-first command shape.
- Added tests proving execute mode connects to the safe control socket path, sends a receivable TUN fd via SCM_RIGHTS, and still preserves plan mode when `--execute-setup` is absent.

### Commands run
- `cargo test -p foxprox-core --all-targets --all-features` — passed, 161 core tests.
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 15 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 15 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The production `foxproxsetup` binary now has an explicit execute mode for the safe socket-control handoff path, but execute mode still only creates/configures/hands off the TUN fd. Capability drop/close/exec, route/DNS/proxy setup commands, and production runtime/final-drain wiring remain.

## 2026-06-23 — Add sandbox network command executor

Commit: ababf07

### Review
- Round-134 correctness and validation found no blocker/high issues. Reviewers confirmed `foxproxsetup --execute-setup` dispatch is correctly scoped and that the next highest gaps are privileged integration coverage plus route/DNS/proxy setup, capability drop/close/exec, and runtime final drain.

### Fix
- Added `SandboxSetupCommandRunner` and `SandboxSetupCommandReport` in `foxprox-cli` for the sandbox-side post-TUN network setup command phase.
- Added `CommandSandboxSetupRunner`, which maps setup steps to concrete actions:
  - runs the configured `ip route ...` command for default-route setup;
  - writes the broker DNS nameserver line to a configurable resolv.conf path;
  - treats proxy reachability as environment evidence supplied with the target command.
- Added `run_sandbox_network_setup_commands_with_runner(...)`, which runs route, DNS, and proxy setup steps from `SetupHelperPlan` in order, emits structured `tun_configured` success evidence, and fails closed with `broker_error` containing `setup_phase=sandbox_network_commands`, `setup_step`, `setup_error`, and completed-step evidence.
- Added deterministic tests proving route/DNS/proxy setup command ordering and fail-closed stop-before-later-steps behavior.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 17 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 17 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Route/DNS/proxy setup now has a concrete safe command-runner boundary and fail-closed evidence, but it is not yet wired into `foxproxsetup --execute-setup` after TUN handoff. Capability drop/close/exec and production runtime/final-drain wiring remain.

## 2026-06-23 — Run sandbox commands in foxproxsetup execute mode

Commit: a9ec120

### Review
- Round-135 correctness and validation found no blocker/high issues. Reviewers confirmed the sandbox network command executor is correctly scoped and records implementation commit `ababf07`, and identified the next gap as wiring that command phase into `foxproxsetup --execute-setup` after successful TUN handoff.

### Fix
- Added `run_foxproxsetup_execute_setup_connecting_with_ops_and_runner(...)`, which connects to the safe setup-control socket, runs TUN open/configure/SCM_RIGHTS handoff, then runs sandbox route/DNS/proxy setup commands only if the TUN handoff phase completed.
- Updated the Linux `foxproxsetup --execute-setup` dispatch to use real `LinuxTunSetupOps` plus `CommandSandboxSetupRunner`, so execute mode now covers TUN create/configure/handoff and the route/DNS/proxy command phase.
- Execute-mode JSON now separates `tun_handoff` and `sandbox_network` phase status, keeps ordered audit records, and reports `failed_phase` when sandbox command setup fails after a successful TUN handoff.
- Added deterministic tests proving execute mode runs the sandbox command phase after a successful SCM_RIGHTS handoff and fails closed if a sandbox command fails, while preserving the already-handed-off fd evidence.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 18 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo test --all-targets --all-features` — passed, including 18 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- `foxproxsetup --execute-setup` now wires real TUN setup/handoff and the sandbox route/DNS/proxy command phase, but capability drop, setup-fd close, target `exec`, privileged end-to-end test execution, and production runtime/final-drain wiring remain.

## 2026-06-23 — Add foxproxsetup post-setup lifecycle

Commit: 7d1416d

### Review
- Round-136 correctness and validation found no blocker/high issues. Reviewers confirmed execute mode wires real TUN setup/handoff plus sandbox route/DNS/proxy command phase and identified the next gap as close setup-only fds, drop `CAP_NET_ADMIN`, and `exec` the target.

### Fix
- Added `PostSetupLifecycleRunner` and `PostSetupLifecycleReport` for the post-network setup lifecycle.
- Added `run_post_setup_lifecycle_with_runner(...)`, which runs `close_setup_fds`, `drop_setup_capability`, and `exec_target` in order, emits structured `tun_configured` success evidence in deterministic tests, and fails closed with `broker_error` on the first lifecycle failure.
- Extended `CommandSandboxSetupRunner` to implement the production lifecycle runner:
  - setup-control socket ownership is dropped before lifecycle execution;
  - `CAP_NET_ADMIN` is removed from Linux Ambient, Effective, Inheritable, Permitted, and Bounding capability sets via the safe `caps` crate;
  - target execution uses safe `std::os::unix::process::CommandExt::exec`, which only returns on failure.
- Integrated the post-setup lifecycle into `foxproxsetup --execute-setup` after successful TUN handoff and sandbox route/DNS/proxy setup.
- Execute-mode JSON now includes a `post_setup_lifecycle` phase and preserves ordered audit records across TUN handoff, sandbox networking, and lifecycle phases.
- Added deterministic tests proving successful lifecycle ordering and fail-closed lifecycle failure after successful TUN handoff and sandbox networking.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 19 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 19 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- `foxproxsetup --execute-setup` now covers TUN setup/handoff, sandbox route/DNS/proxy commands, setup-control close, `CAP_NET_ADMIN` drop, and target exec boundary. Remaining gaps are privileged end-to-end execution in a real bwrap/TUN environment and production runtime/final-drain wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Add host setup-control handoff evidence

Commit: 7e7ec11

### Review
- Round-137 correctness and validation found no blocker/high issues. Reviewers confirmed `foxproxsetup --execute-setup` now covers TUN setup/handoff, sandbox route/DNS/proxy commands, setup-control close, `CAP_NET_ADMIN` drop, and target exec boundary while leaving privileged bwrap/TUN E2E and production runtime/final-drain wiring open.

### Fix
- Added `accept_setup_control_tun_handoff(...)`, a host-side setup-control listener helper that builds a `BwrapSetupPlan`, accepts one setup-control Unix socket connection, receives the TUN fd through the existing SCM_RIGHTS helper, retains ownership of the received fd, and emits ordered setup-plan, received-handoff, and host-handoff summary audit evidence.
- Added `HostSetupControlHandoffReport` and `HostSetupControlHandoffStatus` to distinguish successful host receipt from fail-closed accept/receive failures.
- Added deterministic coverage proving the host setup-control listener accepts a TUN-like fd, receives ownership, records `setup_plan_created`, records `tun_configured` with `fd_source=scm_rights`, and includes host `setup_phase=host_setup_control_handoff` summary evidence.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 20 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 20 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup-control fd receipt is now represented with retained fd ownership and structured evidence, but it still uses a deterministic sender in CI rather than launching privileged bwrap/foxproxsetup end-to-end. Remaining gaps are privileged bwrap/TUN E2E execution and production runtime/final-drain wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Drain host handoff evidence in local runtime

Commit: 7fe14cd

### Review
- Round-138 correctness and validation found no blocker/high issues. Reviewers confirmed host setup-control fd receipt retains `OwnedFd` ownership and structured audit evidence, while CI still uses a deterministic sender rather than privileged bwrap/foxproxsetup E2E.

### Fix
- Added `foxprox-cli` as an egress dev-dependency so the combined local Tokio runtime proof can exercise the host setup-control handoff helper instead of directly calling `send_tun_fd` / `recv_tun_fd` inside the runtime task.
- Updated `async_local_scheduler_combines_live_io_smoltcp_and_final_drain` so setup-control evidence now flows through `accept_setup_control_tun_handoff(...)`:
  - builds the bwrap/setup plan;
  - accepts a setup-control socket connection;
  - receives the TUN fd through SCM_RIGHTS;
  - retains fd ownership for AsyncFd packet readiness/read dispatch;
  - appends setup-plan, received-handoff, and host handoff summary audits to the setup ledger.
- Extended final JSON drain assertions to require `setup_plan_created`, `fd_source=scm_rights`, and `host_setup_control_handoff` alongside runtime readiness, task cancellation, lifecycle exit, and cleanup evidence.

### Commands run
- `cargo test -p foxprox-egress --all-targets --all-features async_local_scheduler_combines_live_io_smoltcp_and_final_drain` — passed.
- `cargo test --all-targets --all-features` — passed, including 20 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The combined local runtime now drains host setup-control handoff evidence through `RuntimeAuditFanIn` while using the received fd for Tokio packet readiness, but the sender is still deterministic. Remaining gaps are privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production runtime/final-drain wiring outside the test harness.

## 2026-06-23 — Add host setup process session evidence

Commit: 247825a

### Review
- Round-139 correctness and validation found no blocker/high issues. Reviewers confirmed the combined local runtime drains host setup-control handoff evidence through `RuntimeAuditFanIn` while using the received fd for Tokio packet readiness, with the remaining gap being privileged bwrap/foxproxsetup E2E and production runtime/final-drain wiring.

### Fix
- Added `HostSetupProcessRunner`, `CommandHostSetupProcessRunner`, `HostSetupProcessExit`, and `HostSetupSessionReport` for the host launcher side of setup.
- Added `run_host_setup_control_session_with_runner(...)`, which starts a setup process from `BwrapSetupPlan`, accepts and retains the setup-control TUN fd handoff, waits for setup/target process exit status, and records ordered setup-plan, host handoff, and host setup-process audit evidence.
- The production runner starts the plan's `bwrap ... foxproxsetup --execute-setup ...` command and waits for the child/target process status; deterministic tests use an injected runner that sends a TUN-like fd over SCM_RIGHTS.
- Added deterministic coverage proving a successful setup session records setup-plan, host handoff, retained fd ownership, and clean process-exit evidence, plus fail-closed coverage for a nonzero setup/target process exit after fd handoff.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features` — passed, 22 CLI tests and 1 ignored privileged Linux CLI test.
- `cargo test --all-targets --all-features` — passed, including 22 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup process orchestration now has a concrete production runner boundary and fail-closed evidence, but CI still uses an injected deterministic process/sender. Remaining gaps are privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production runtime/final-drain wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Fail closed host setup session accept races

Commit: 6d0cce9

### Review
- Round-140 correctness found a blocker/high issue: `run_host_setup_control_session_with_runner(...)` built and started the setup process before inferring `setup_control_socket_path`, so a default config could start plan-mode `foxproxsetup` and then block forever waiting for a connection.
- Round-140 correctness and validation also found a high issue: the session blocked in `listener.accept()` before checking setup-process exit, so an early setup process failure could hang without fail-closed process-exit evidence.

### Fix
- `run_host_setup_control_session_with_runner(...)` now infers the listener's socket path before building `BwrapSetupPlan`, so the spawned command includes `--execute-setup` and `--setup-control-socket` even when the caller supplies a default config.
- Added `HostSetupProcessRunner::poll_setup_process(...)` and implemented it with `Child::try_wait()` in `CommandHostSetupProcessRunner`.
- Changed host setup session accept to use nonblocking `UnixListener::accept()`, poll setup-process exit while waiting, restore listener blocking mode on exit paths, and emit fail-closed `host_setup_process` evidence if the process exits before fd handoff.
- Added a bounded accept wait and read timeout for the setup-control fd receive so missing/invalid handoff paths fail closed instead of hanging in the host session helper.
- Added deterministic regression tests for missing pre-populated socket path and setup process exit before fd handoff.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session -- --nocapture` — passed, 4 filtered host setup session tests.
- `cargo clippy -p foxprox-cli --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 24 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- The host setup session now avoids the reviewed setup-control accept races and records fail-closed evidence for early setup-process exit, but CI still uses injected deterministic process/sender coverage. Remaining gaps are privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production runtime/final-drain wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Cover host setup handoff timeout evidence

Commit: 1ca912e

### Review
- Round-141 correctness and validation found no blocker/high issues. Reviewers confirmed the setup-control socket path is now inferred before plan/start, nonblocking accept polls setup-process exit, and early setup-process exit records fail-closed evidence.
- The next noted gap was that timeout behavior existed but was not directly regression-tested for accept timeout or read-timeout/no-SCM_RIGHTS cases.

### Fix
- Split the host setup session helper through an internal timeout-parameterized path so tests can prove timeout behavior quickly while production retains five-second accept/read bounds.
- Added deterministic regression coverage for no setup-control connection: the host session times out waiting for fd handoff and records fail-closed `host_setup_process` evidence.
- Added deterministic regression coverage for a setup-control connection that never sends SCM_RIGHTS data: the host session read timeout produces fail-closed `receive_failed` handoff evidence instead of hanging.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session -- --nocapture` — passed, 6 filtered host setup session tests.
- `cargo test --all-targets --all-features` — passed, including 26 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup session timeout and early-exit paths are now deterministic CI evidence, but privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production runtime/final-drain wiring after the host broker receives the real TUN fd remain open.

## 2026-06-23 — Stabilize no-fd handoff timeout test

Commit: 06a93fd

### Review
- Round-142 correctness and validation found no blocker/high issues. Reviewers confirmed production timeout bounds, deterministic timeout tests, progress hash, and honest scope.
- Round-142 noted the connected/no-fd timeout test held the peer connection open with a fixed sleep, which had not reproduced flakiness but could be made less scheduler-sensitive.

### Fix
- Replaced the fixed peer sleep in `CliScriptedHostSetupProcessRunner` with a channel release guard: the no-fd peer connects and stays open until `wait_setup_process()` releases it.
- This keeps the read-timeout/no-SCM_RIGHTS test deterministic without adding privileged setup claims.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session -- --nocapture` — passed, 6 filtered host setup session tests.
- `cargo test --all-targets --all-features` — passed, including 26 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup session deterministic timeout coverage is less scheduler-sensitive, but the remaining major gaps are unchanged: privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production runtime/final-drain wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Drain host setup session audits through fan-in

Commit: 56e02dc

### Review
- Round-143 correctness and validation found no blocker/high issues. Reviewers confirmed the no-fd timeout test no longer relies on a fixed sleep, validation passed, and the remaining highest gap is privileged bwrap/real TUN E2E plus production runtime/final-drain wiring.

### Fix
- Added `HostSetupSessionAuditDrainReport` and `HostSetupSessionAuditDrainError`.
- Added `drain_host_setup_session_audits_to_sink(...)`, a host-side bridge that ingests `HostSetupSessionReport` audit records into `RuntimeAuditFanIn` under a named `host_setup_session` source and drains them to a `JsonLineAuditSink`.
- The helper re-sequences cloned session audit records before fan-in ingestion because host setup session records are accumulated outside a `BoundedAuditLedger` and therefore otherwise carry sequence zero.
- Added deterministic coverage proving host setup session setup-plan, setup-control handoff, and host setup-process exit evidence drain through `RuntimeAuditFanIn` to JSON sink output.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session -- --nocapture` — passed, 7 filtered host setup session tests.
- `cargo test --all-targets --all-features` — passed, including 27 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup session evidence can now drain through the runtime fan-in/sink path, but the runtime still needs privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production packet-loop wiring after the host broker receives the real TUN fd.

## 2026-06-23 — Cover host setup fan-in duplicate and backpressure paths

Commit: fd603d1

### Review
- Round-144 correctness and validation found no blocker/high issues. Reviewers confirmed host setup session audits are re-sequenced, ingested as `host_setup_session`, drained through `RuntimeAuditFanIn`, and scoped honestly as a final-drain bridge rather than privileged bwrap/real TUN E2E.
- The noted remaining bridge-specific gap was direct regression coverage for duplicate re-drain and bridge-level backpressure.

### Fix
- Added deterministic coverage proving repeated `drain_host_setup_session_audits_to_sink(...)` calls skip already-ingested `host_setup_session` records and do not duplicate sink output.
- Added deterministic coverage proving bounded `RuntimeAuditFanIn` backpressure is surfaced as `HostSetupSessionAuditDrainError::Ingest(RuntimeAuditFanInError::AuditBackpressure)` with the expected source and attempted audit kind.

### Commands run
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session_fan_in_bridge -- --nocapture` — passed, 2 filtered host setup fan-in bridge tests.
- `cargo test -p foxprox-cli --all-targets --all-features host_setup_session -- --nocapture` — passed, 9 filtered host setup session tests.
- `cargo test --all-targets --all-features` — passed, including 29 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 99 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Host setup session fan-in duplicate and backpressure behavior is now covered, but privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and production packet-loop/final-drain wiring after the host broker receives the real TUN fd remain open.

## 2026-06-23 — Bridge setup audits with packet-fd runtime read

Commit: 202fe10

### Review
- Round-145 correctness and validation found no blocker/high issues. Reviewers confirmed host setup fan-in duplicate/backpressure edge coverage is clean and the remaining highest gap is privileged runtime/E2E coverage with real bwrap + TUN fd handoff and production final-drain wiring.

### Fix
- Added `AsyncRuntimeSetupPacketDrainReport`, `AsyncRuntimeSetupPacketDrainError`, and `AsyncRuntimePacketFdReadBounds`.
- Added `drain_setup_audits_and_read_packet_fd_once(...)`, a Unix async runtime bridge that ingests setup evidence into `RuntimeAuditFanIn`, waits for packet-fd readiness on an existing `AsyncFd`, reads one ready packet through the existing TUN ready-task path, and drains setup evidence to a `JsonLineAuditSink`.
- The helper is generic over packet fd type and does not depend on test-only device setup; it is intended as a production-side ownership seam after the host broker has received a real configured TUN fd and wrapped it in `AsyncFd`.
- Added deterministic coverage with a UnixStream-backed packet fd proving setup-plan/TUN handoff evidence drains while packet readiness/read dispatch consumes the received packet. This remains a local fd proof, not privileged bwrap/real TUN E2E.

### Commands run
- `cargo test -p foxprox-egress --all-targets --all-features async_runtime_setup_audits_drain_while_reading_packet_fd_once -- --nocapture` — passed.
- `cargo clippy -p foxprox-egress --all-targets --all-features -- -D warnings` — passed.
- `cargo test --all-targets --all-features` — passed, including 29 CLI tests + 1 ignored, 161 core tests, 11 device tests + 1 ignored, 100 egress tests, and 16 stack tests.
- `cargo fmt --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

### Remaining blind spots
- Setup audit fan-in and packet-fd readiness/read can now be driven together by a production-style async helper after fd receipt, but privileged bwrap/foxproxsetup E2E execution with a real Linux TUN device and long-running production packet-loop/final-drain wiring remain open.
