# Harness Lab Learnings

## 2026-06-21 — Initial environment

- `/dev/net/tun` and `bwrap` are installed in the local harness worktree environment, so environment-dependent namespace/TUN smoke commands can be offered. Their existence does not prove the current user can create/configure TUN devices inside a bwrap network namespace with `CAP_NET_ADMIN`.

## 2026-06-21 — Harness boundary

- Platform-independent alpha semantics can be verified without namespace privileges by routing normalized events through a shared policy engine, mock egress backend, structured audit records, and deterministic packet/proxy fixtures.
- `foxprox-lab run env-smoke` should remain a capability report, not a success claim for real bwrap/TUN setup, until a setup helper can actually create/configure a TUN device and hand its fd to the broker.
