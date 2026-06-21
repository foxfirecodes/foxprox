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

## 2026-06-21 — HTTP origin contract widened

- The first `HttpRequest` contract was too narrow because it required `Hostname`; explicit and transparent HTTP requests can target IP literals, so the normalized contract now uses `DestinationHost` to preserve IP/port policy support without frontend leakage.

## 2026-06-21 — HTTP method/path rules

- Plaintext HTTP method and path matching belongs in the shared policy rule contract, not in frontends, so transparent HTTP and proxy HTTP can share enforcement semantics.

## 2026-06-21 — DNS answer attribution boundary

- DNS response parsing should export only hostname/IP/TTL address records; keeping answer offsets, compression pointers, and RR wire details inside `foxprox-dns` lets `foxprox-net` update attribution without giving policy raw DNS parser state.
- CNAME-aware attribution is a separate contract decision: the current answer boundary handles direct A/AAAA owner names and deliberately leaves alias-chain semantics for a later DNS contract expansion.

## 2026-06-21 — Config validation boundary

- Config validation needs its own crate boundary so string/CIDR/hostname/path/timeout validation happens before policy construction; this keeps `foxprox-policy` deterministic over normalized contracts instead of config file shapes.
- HTTP path matchers should reject non-absolute paths during config validation because policy matching should not need to decide whether a user-provided path pattern is syntactically meaningful.

## 2026-06-21 — HTTP egress contract

- Allowed plaintext `HttpRequest` events must dispatch through shared egress; treating them as `UnsupportedAllowedEvent` would make explicit HTTP proxy support incomplete and tempt frontend-local forwarding.
- The egress dispatch outcome type should be aliased as the trait grows so the public contract stays readable and clippy-clean without suppressions.

## 2026-06-21 — Hidden-SNI policy guard

- Default-allow cannot apply blindly to transparent TLS when SNI/hostname attribution is unavailable; policy needs a pre-default guard while still permitting explicit IP/port allow rules for intentional hidden-SNI cases.

## 2026-06-21 — ICMP policy defaults

- ICMP needs explicit policy defaults independent of the broad default allow/deny switch: essential error messages are broker mechanics, ping is user-configurable, and unusual ICMP should fail closed.
