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

## 2026-06-21 — Flow lifecycle audit boundary

- Flow close/expiry audit constructors should accept a normalized input struct, not stack adapter objects or long parameter lists; this keeps lifecycle schema explicit and prevents audit from depending on flow-manager internals.

## 2026-06-21 — Policy timeout override contract

- Timeout overrides belong in the normalized allow decision, not in flow-manager config string handling; this lets UDP/QUIC expiry policy remain a policy output that flow code can cache per flow.

## 2026-06-21 — Per-flow timeout storage

- Flow timeouts need to be stored on `FlowState` at creation time; recomputing from global UDP classification later would ignore per-rule policy overrides and make QUIC/DNS expiry behavior drift from policy decisions.

## 2026-06-21 — CNAME attribution boundary

- CNAME expansion can stay inside DNS normalization by emitting extra hostname/IP records for aliases; downstream attribution cache still does not need DNS RR or compression-pointer details.

## 2026-06-21 — HTTP scheme matcher boundary

- Origin-aware HTTP policy needs scheme as a typed matcher alongside host/port/path; otherwise explicit proxy absolute-form requests could not distinguish `http` and `https` origins without parser-specific shortcuts.

## 2026-06-21 — HTTP audit metadata

- Audit schema must expose method/scheme/path as structured normalized fields for HTTP decisions; otherwise path-aware policy would be enforced but not reviewable from audit output.

## 2026-06-21 — IPv4 TCP/UDP packet normalization

- UDP destination classification is a shared core contract rather than a packet-local or flow-local helper; otherwise QUIC/DNS/multicast behavior could drift between raw packet parsing and stack-adapter flow paths.
- TCP packet normalization should only emit connect attempts for initial SYN packets; later TCP segment handling belongs behind the userspace stack adapter and remains fail-closed in the packet proof parser.
- ICMP denial packet synthesis can remain an opaque packet-boundary helper so policy chooses `Deny(IcmpUnreachable)` without learning raw IPv4/ICMP header shapes.

## 2026-06-21 — Identifiable encrypted-DNS guard

- DNS-over-TLS bypass prevention can be expressed as a normalized destination-port policy guard for TCP/853; policy does not need raw TLS or DNS parser inputs to deny this identifiable case by default.
- The guard must run before default allow but after explicit configured rules are checked for that candidate, preserving a deliberate escape hatch for test resolvers or future broker-owned encrypted DNS endpoints.

## 2026-06-21 — Flow resource limits

- Flow count limits belong in the normalized runtime config, not launcher-specific code, so the network flow table can enforce bounded state for transparent and proxy paths consistently.
- Flow-table replacement of an existing key should remain allowed at capacity; otherwise refreshing byte counts or timeout state could be blocked by the same limit meant to prevent new flow growth.

## 2026-06-21 — Proxy authority IPv6 parsing

- HTTP proxy and CONNECT authority parsing must handle bracketed IPv6 before generic `host:port` splitting; otherwise IPv6 literals can be mis-normalized as host strings or malformed ports.
- Frontend fixes should still emit only `DestinationHost::Ip` plus port, keeping policy and egress independent from request-line syntax.

## 2026-06-21 — Proxy parser size limit

- Parser size limits should map to `UnsupportedReason::ParserLimitExceeded` rather than generic malformed request errors; this preserves audit clarity for robustness failures without exposing raw proxy bytes.
- Enforcing request-head size before UTF-8 conversion keeps malformed/oversized proxy input contained entirely in the frontend boundary.

## 2026-06-21 — SOCKS5 handshake helpers

- SOCKS5 method selection and reply-code bytes are frontend wire concerns; keeping them out of `foxprox-core` preserves the normalized policy contract around only the eventual `SocksConnect` intent.
- The alpha SOCKS helper can advertise no-auth only and synthesize standard CONNECT replies without requiring egress or policy crates to know SOCKS reply codes.

## 2026-06-21 — TLS mismatch audit schema

- SNI/DNS mismatch needs a stable audit field instead of relying on denial reason strings; otherwise reviewers cannot reliably distinguish mismatch, unavailable attribution, and unchecked TLS cases.
- Audit can safely expose the normalized `HostnameMismatch` enum because TLS parser internals and raw ClientHello bytes still terminate in the inspect boundary.

## 2026-06-21 — Policy-driven denial synthesis

- Mapping `Deny(IcmpUnreachable)` to ICMP bytes belongs in the packet crate, not policy or audit; policy should choose only the normalized denial action.
- Drop and reset decisions intentionally produce no packet-level synthetic response from the IPv4 packet helper, preserving explicit denial semantics.

## 2026-06-21 — Standard-library egress backend

- A minimal blocking egress backend can live in `foxprox-egress` and still preserve frontend independence as long as it accepts only normalized core events.
- Plain HTTP forwarding should reject normalized HTTPS-scheme `HttpRequest` values in the std backend; HTTPS traffic should use CONNECT/SOCKS/TCP paths unless a future TLS-aware proxy layer is added.

## 2026-06-21 — Autonomy failure: unnecessary runtime path escalation

- I incorrectly escalated the next runtime implementation path to the user even though the implementation approach explicitly says autonomy means proceed by default and choose the safest documented option for ordinary implementation choices.
- The better path was to select the documented default (`Tokio` unless strong reason otherwise, prove `smoltcp` behind the adapter, and evaluate TUN crates locally) and record assumptions in `progress.md`, only pausing for a truly scope-changing or security-sensitive decision.
- Future autonomous cycles should not ask for permission to pick among documented implementation paths; choose the best path forward, verify, record risks/learnings, and continue until a real stop condition is met.

## 2026-06-21 — IPv4 packet orchestration boundary

- Packet write-back should be gated by policy in `foxprox-net`: the packet crate may discover a possible echo reply, but the orchestrator only returns it after the normalized ICMP event is allowed.
- Policy-driven ICMP unreachable synthesis can use the original packet bytes locally in the net/packet boundary while audit and policy continue to see only normalized events and denial actions.

## 2026-06-21 — Configurable parser limit boundary

- HTTP request-head limits belong in the normalized runtime config so production listeners and tests can share one typed robustness contract instead of relying on a frontend-local constant.
- Frontend parsers should enforce size limits before UTF-8 conversion and request-line parsing, then emit `ParserLimitExceeded` as a normalized unsupported event for policy/audit.

## 2026-06-21 — SOCKS parser limit boundary

- SOCKS greeting and CONNECT request size limits can share the normalized `ParserLimits` contract with HTTP while keeping SOCKS wire negotiation in the frontend crate.
- Oversized SOCKS CONNECT attempts should normalize to `ParserLimitExceeded`; malformed-but-in-limit SOCKS bytes remain `MalformedProxyRequest`.

## 2026-06-21 — SOCKS policy reply mapping

- SOCKS reply-code selection can depend on normalized `PolicyDecision` in the frontend crate, but policy must stay unaware of SOCKS wire values.
- Denied and broker-DNS-required SOCKS CONNECT attempts should map to `ConnectionNotAllowed`; fail-closed parser/runtime cases should map to `GeneralFailure`.

## 2026-06-21 — Audit JSON serialization boundary

- Audit JSON serialization can be implemented in `foxprox-audit` from the stable normalized schema without introducing serde or frontend-specific dependencies.
- Enum values in audit output should use explicit stable snake-case labels rather than Debug formatting so log consumers do not depend on Rust variant spelling.
