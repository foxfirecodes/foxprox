# Learning Ledger

## 2026-06-21 — Alpha implementation starts from core observability contracts

The repository only had a minimal `foxprox-core` marker crate. To keep behavior externally visible before runtime forwarding exists, the first implementation must make policy, flow, packet, setup, and audit contracts testable through structured records and bounded ledgers. Real network namespace/TUN/smoltcp execution remains a later integration surface, but the denial reasons and event schema can be locked down now.

## 2026-06-21 — Audit backpressure must affect decisions, not only storage

A bounded audit buffer alone proves memory cannot grow unbounded, but alpha forwarding should also fail closed when audit-critical decisions cannot be recorded. `BrokerCore` now joins policy evaluation to audit append and returns an `audit_backpressure` fail-closed decision when the ledger is full, while retaining a lossy backpressure record for postmortem visibility. Zero requested capacity is normalized to one slot so the fail-closed evidence remains inspectable.

## 2026-06-21 — Flow lifecycle events must not claim policy decisions they did not make

UDP and QUIC lifecycle records are useful observability, but they should not encode `decision=allow` unless a policy decision actually produced that outcome. The flow manager now emits lifecycle metadata without a decision field, leaving allow/deny authority to `BrokerCore`/`PolicyEngine` audit records.

## 2026-06-21 — DNS returned-address observations are audit-critical

DNS policy allow evidence alone is not enough for transparent hostname attribution. The handler must also record returned addresses before releasing an upstream response; otherwise later DNS-to-flow decisions could rely on invisible cache state. When the observation audit cannot be appended, the DNS path now fails closed and returns REFUSED with audit-backpressure evidence instead of silently allowing an untraceable attribution update.

## 2026-06-21 — Packet write-back must be audit-gated before bytes leave

The ICMP write-back proof is only externally debuggable if outbound packet synthesis is recorded before the reply is written to the device. The in-memory TUN harness now appends `packet_observed` with `direction=to_sandbox` and `write_back=icmp_echo_reply` before writing bytes; audit backpressure prevents the write and leaves `audit_backpressure` evidence.

## 2026-06-21 — UDP egress must wait for lifecycle audit, not just policy audit

For UDP, an allow decision without `udp_flow_created` evidence is insufficient because later expiration and byte-count accounting depend on flow state. The UDP forwarding harness now appends lifecycle records before fake egress sends; if lifecycle audit backpressures, no datagram is sent.

## 2026-06-21 — TCP close evidence is a separate lifecycle contract from connect policy

A TCP connect allow audit proves host egress was authorized, but it does not prove what bytes crossed or how the flow ended. The TCP forwarding harness now emits `tcp_flow_closed` with byte counts and duration. Close audit backpressure is visible, but real async stream integration must preserve this boundary even when close/error happens after bytes have already moved.

## 2026-06-21 — IP-version dispatch changes malformed-packet evidence

Switching the TUN harness from IPv4-only parsing to IP-version dispatch changed all-zero short packets from `short_ipv4_header` to `unsupported_ip_version`. Tests should assert the structured parse detail produced by the dispatch boundary, not assume every malformed packet entered the IPv4 parser.

## 2026-06-21 — Observation and authorization must stay separate at frontend boundaries

The TUN packet harness originally emitted `packet_observed` and then treated successful parsing as allow/write-back. Review caught that this bypassed default-deny and `allow_ping=false`. Frontend harnesses must record packet observation first, then still run normalized policy decisions before any forwarding or write-back.

## 2026-06-21 — Mutable attribution/flow state must commit after audit success

DNS cache updates and UDP flow byte counts are decision-relevant state. Review caught that both could mutate before audit append succeeded, leaving invisible state after fail-closed outcomes. Future state managers should use prepare-audit/commit or rollback patterns when audit is required for correctness.

## 2026-06-21 — Upstream DNS responses must be validated before attribution

Review caught that parsing returned addresses without matching transaction ID, question, rcode, or answer owner can poison DNS attribution. The DNS handler now validates upstream responses against the original query before releasing a response or committing cache observations; mismatch/malformed responses fail closed with `dns_upstream_error=malformed_response`.

## 2026-06-21 — Egress failures need their own audit event after allow

Policy allow and lifecycle creation are not enough when a host egress operation fails. UDP, TCP, and explicit proxy harnesses now append `broker_error` records for send/connect failures so post-allow errors are inspectable instead of only visible as returned Rust errors.

## 2026-06-21 — MSRV-sensitive helpers in validation code

- `Option::is_none_or` is convenient for validation predicates but violates this workspace's Rust 1.80 MSRV; use an explicit `match` for helper predicates that must pass `cargo clippy --all-targets --all-features -- -D warnings` with `clippy::incompatible_msrv` enabled.
