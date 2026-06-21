# Learning Ledger

## 2026-06-21T16:41:33Z
- The repository currently contains only a minimal `foxprox-core` crate, so the safest alpha path is to build a verified, platform-independent policy/audit/event kernel before adding TUN, bwrap, or forwarding code.

## 2026-06-21T22:44:40Z
- `/dev/net/tun` is present in this environment, but the current user lacks `CAP_NET_ADMIN`; real TUN creation/configuration smoke tests must run under bwrap/setup-helper capability context or be skipped with an explicit ledger note.
