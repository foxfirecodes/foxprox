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
- _pending_ — DNS query parser and refused-response foundation.
