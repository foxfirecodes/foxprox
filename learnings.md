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
