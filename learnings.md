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

## 2026-06-22T00:27:10Z
- Once protocol 6 became a parsed TCP path, unsupported-protocol tests had to switch to a truly unsupported IPv4 protocol number; otherwise they no longer proved fail-closed unsupported handling.

## 2026-06-22T00:42:45Z
- Transparent HTTP inspection is only safe for complete buffered request headers; one TCP segment with incomplete headers must return `NeedMoreData` and wait for future stream reassembly rather than making a policy guess.

## 2026-06-22T01:11:45Z
- Hidden or absent SNI must not be governed by broad allow rules: only explicit destination rules can intentionally allow no-visible-SNI HTTPS, while SNI/DNS mismatches still fail closed before any allow rule.

## 2026-06-22T01:28:05Z
- Explicit proxy runtime needs a resolution boundary: policy can evaluate hostname/origin metadata, but the current host egress trait still requires an IP endpoint, so this slice accepts a caller-resolved IP until DNS/egress resolution is integrated.

## 2026-06-22T01:27:57Z
- A verified commit is not a stopping point for this goal; after each commit the next progress-ledger step must be executed immediately unless a documented stop condition is hit.

## 2026-06-22T01:33:05Z
- The verification-kernel implementation approach now explicitly forbids user-facing checkpoint summaries after successful commits; a clean commit or verification run is never a stop condition by itself.

## 2026-06-22T21:51:42Z
- `smoltcp` latest 0.13.x requires Rust 1.91, which is above this workspace's Rust 1.80 MSRV; use `smoltcp` 0.12.x for the alpha adapter unless the workspace MSRV changes.

## 2026-06-22T22:03:40Z
- In smoltcp loopback tests, the client socket can become active before the listener-side socket is counted active; reset tests should compare against the pre-reset active count rather than assuming exactly two active sockets.

## 2026-06-22T22:07:08Z
- A smoltcp TCP socket can be active before `send_slice` accepts payload data; adapter tests should poll/retry on `TcpSendRejected` instead of assuming active implies send-ready.

## 2026-06-22T22:20:18Z
- `smoltcp::phy::DeviceCapabilities` is non-exhaustive in 0.12, so custom devices must mutate `DeviceCapabilities::default()` rather than constructing it with struct update syntax.

## 2026-06-22T22:25:10Z
- smoltcp TUN-ingressed TCP connects surface on accepted listener-side sockets, while earlier loopback proofs used active client-side sockets; the adapter needs an explicit connect-report mode so tests do not conflate the two orientations.
