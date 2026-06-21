# Learning Ledger


## 2026-06-21 — Contract-first alpha foundation

- Domain and CIDR policy needed to live in `foxprox-core` as narrow normalized matchers; otherwise `foxprox-policy` would have been tempted to import parser/config helper crates and widen its dependency surface.
- Direct external DNS bypass and unsupported events need hard policy pre-checks before default allow rules; this preserves fail-closed behavior even when a profile later opts into broad allow-by-default forwarding.
- Explicit proxy hostnames and transparent DNS/SNI attribution share a common hostname/confidence model, but explicit proxy destinations should remain high-confidence normalized events rather than frontend-specific request structs.

## 2026-06-21 — Packet proof boundary

- ICMP echo synthesis can be kept completely outside policy: packet code emits `IcmpMessage` plus opaque reply bytes, while policy/audit still see only normalized metadata.
- Unsupported fragmentation should be normalized immediately at the packet boundary because later flow/policy layers should not need raw IPv4 flags or fragment offsets.

## 2026-06-21 — Transparent inspection boundary

- TLS inspection should normalize ECH as an unsupported event rather than a regular no-SNI ClientHello because default policy treats hidden SNI as policy-sensitive and fail-closed.
- The QUIC alpha classifier should stay heuristic and payload-local; full QUIC semantics would be a separate parser/inspection boundary.

## 2026-06-21 — DNS normalization boundary

- DNS bypass detection belongs in normalized DNS metadata (`direct_external`) rather than in policy looking at raw UDP payloads; this keeps direct-external DNS fail-closed without packet leaks.
- A denied DNS response can be synthesized from the original question at the DNS boundary while audit/policy still operate only on `DnsQuery` and decisions.
