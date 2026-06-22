# Learning Ledger

## 2026-06-21T16:41:33Z
- The repository currently contains only a minimal `foxprox-core` crate, so the safest alpha path is to build a verified, platform-independent policy/audit/event kernel before adding TUN, bwrap, or forwarding code.

## 2026-06-21T22:44:40Z
- `/dev/net/tun` is present in this environment, but the current user lacks `CAP_NET_ADMIN`; real TUN creation/configuration smoke tests must run under bwrap/setup-helper capability context or be skipped with an explicit ledger note.

## 2026-06-21T23:01:35Z
- The bwrap command plan needed an explicit inherited handoff fd; without it, a setup helper could configure the sandbox interface but would have no safe path to transfer the TUN fd back to the host broker before target exec.

## 2026-06-21T23:53:25Z
- IPv4 UDP parsing must validate nonzero UDP checksums before exposing packet metadata; zero remains accepted because IPv4 permits omitted UDP checksums, but invalid present checksums fail closed.

## 2026-06-21T23:02:50Z
- Minimal DNS response caching should use the minimum TTL among accepted A/AAAA records for a hostname so attribution cannot outlive the shortest observed address binding.

## 2026-06-21T23:59:30Z
- Broker-directed DNS tests must configure the same broker DNS IP in `PolicyConfig`; otherwise DNS policy correctly treats even broker-address packets as `RequireBrokerDns` direct-bypass attempts.

## 2026-06-22T00:10:05Z
- UDP host-reply routing must stay address-family explicit: the current packet synthesis boundary supports IPv4 only and should reject IPv6 routes until IPv6 packet synthesis has its own verified checksum tests.
