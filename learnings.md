# Learning Ledger

## 2026-06-21 — Alpha implementation starts from core observability contracts

The repository only had a minimal `foxprox-core` marker crate. To keep behavior externally visible before runtime forwarding exists, the first implementation must make policy, flow, packet, setup, and audit contracts testable through structured records and bounded ledgers. Real network namespace/TUN/smoltcp execution remains a later integration surface, but the denial reasons and event schema can be locked down now.

## 2026-06-21 — Audit backpressure must affect decisions, not only storage

A bounded audit buffer alone proves memory cannot grow unbounded, but alpha forwarding should also fail closed when audit-critical decisions cannot be recorded. `BrokerCore` now joins policy evaluation to audit append and returns an `audit_backpressure` fail-closed decision when the ledger is full, while retaining a lossy backpressure record for postmortem visibility. Zero requested capacity is normalized to one slot so the fail-closed evidence remains inspectable.

## 2026-06-21 — Flow lifecycle events must not claim policy decisions they did not make

UDP and QUIC lifecycle records are useful observability, but they should not encode `decision=allow` unless a policy decision actually produced that outcome. The flow manager now emits lifecycle metadata without a decision field, leaving allow/deny authority to `BrokerCore`/`PolicyEngine` audit records.
