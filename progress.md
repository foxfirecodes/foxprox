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
