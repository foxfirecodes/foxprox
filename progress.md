# Security Invariants Progress

This is an append-only implementation ledger for `docs/implementation-approach-security-invariants.md`.

## 2026-06-21 - Core policy invariants foundation

* Invariant under work: deny-by-default, direct DNS bypass prevention, explicit hostname attribution confidence, attribution mismatch denial, unsupported/malformed fail-closed, multicast/broadcast and unusual ICMP denial, structured audit decisions, bounded audit buffering, and no unsafe code in policy/audit/config/event logic.
* Threat or failure mode addressed: a minimal broker core without executable policy invariants could accidentally allow traffic, accept low-confidence domain attribution, miss DNS bypasses, or grow unbounded audit memory under load.
* Planned verification: add unit/table tests near policy and audit code, then run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Core policy invariants foundation results

* Tests added/updated:
  * deny-by-default TCP behavior with structured `DefaultDeny` reason.
  * malformed input and unsupported protocol fail-closed before allow rules.
  * direct DNS bypass denial for `Protocol::Dns` plus generic TCP/UDP flows to external port 53 and identifiable DoT port 853, even when an allow-all IP rule exists.
  * multicast, limited broadcast, and conservative directed-broadcast denial before allow rules.
  * domain rules require medium/high hostname attribution; low-confidence IP-only attribution cannot satisfy them.
  * DNS/presented-hostname mismatch denial before otherwise matching IP allow rules.
  * hidden-SNI/ECH denial unless an explicit IP/CIDR allow rule matches; domain allow rules are not sufficient.
  * unusual ICMP denied by default; ping configurable; essential ICMP errors allowed.
  * deterministic first-match rule ordering.
  * structured audit events preserve decisions, denial reasons, behavior, frontend, and protocol.
  * bounded audit buffer returns backpressure instead of growing beyond configured capacity.
* Commands run:
  * `cargo fmt && cargo test` — passed: 17 tests passed.
  * Initial `cargo clippy --all-targets --all-features -- -D warnings` found fixable issues: too many audit constructor arguments, MSRV-incompatible `Option::is_none_or`, range-pattern style, and test field reassignment.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 17 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * default network traffic denies without an allow rule.
  * malformed and unsupported events fail closed before policy rules can allow them.
  * external DNS/DoT bypass attempts deny before allow rules.
  * broker DNS destination is not treated as bypass, but still requires normal policy allowance.
  * hidden-SNI/ECH cannot be allowed by domain attribution alone.
* Audit evidence: audit unit tests assert structured deny behavior/reason/rule fields and bounded queue backpressure.
* Residual risk: this is platform-independent core policy/audit scaffolding only; packet parsing, actual TUN setup, DNS resolver enforcement, flow correlation, and egress forwarding still need implementation and integration tests.
* Commit hash: 25f9249 core security policy invariants.

## 2026-06-21 - Packet parsing fail-closed foundation

* Invariant under work: malformed packet and unsupported network protocol inputs fail closed before they can reach policy or forwarding, with normalized protocol/source/destination metadata only for validated IPv4/IPv6 TCP, UDP, and ICMP surfaces.
* Threat or failure mode addressed: truncated IP/TCP/UDP/ICMP headers, unsupported fragmentation/extension headers, invalid lengths, or unknown protocol numbers could otherwise be interpreted permissively or bypass policy classification.
* Planned verification: add table-driven parser tests for valid IPv4/IPv6 TCP/UDP/ICMP metadata extraction and negative tests for malformed lengths, unsupported protocol numbers, IPv4 fragmentation, and IPv6 extension headers; run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Packet parsing fail-closed foundation results

* Tests added/updated:
  * valid IPv4 TCP metadata extraction for source/destination IPs and ports.
  * UDP/53 classification as DNS and UDP/443 classification as QUIC candidate.
  * valid IPv6 ICMPv6 metadata extraction.
  * fail-closed errors for empty packets, truncated IP headers, invalid IPv4 total length, invalid TCP header length, and invalid UDP length.
  * fail-closed errors for unsupported IP protocol numbers, IPv4 fragmentation, and IPv6 extension headers.
  * conversion from validated packet summaries to normalized policy requests.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` found ambiguous test parse type annotations.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 23 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * parser returns structured errors for malformed/unsupported packet inputs rather than inventing permissive metadata.
  * IPv4 fragmentation and IPv6 extension headers are not accepted in the alpha parser.
  * only validated TCP, UDP, DNS-classified, QUIC-candidate, and ICMP metadata is converted into policy requests.
* Audit evidence: not applicable in this commit; parser output feeds policy/audit layers but does not emit audit directly.
* Residual risk: packet checksums are not validated yet; TCP flags/state, IPv4 options semantics, IPv6 extension handling, and MTU/error synthesis remain future packet-core work.
* Commit hash: e75b509 fail closed packet metadata parsing.

## 2026-06-21 - DNS attribution cache bounds and confidence

* Invariant under work: DNS observations used for transparent hostname attribution must be normalized, medium-confidence only, TTL-bound, and capacity-bound so hostile DNS traffic cannot create unbounded memory growth or high-confidence domain authorization.
* Threat or failure mode addressed: DNS cache poisoning/over-attribution, stale hostname-to-IP decisions, and unbounded DNS answer accumulation could cause incorrect domain allows or resource exhaustion.
* Planned verification: add unit tests for hostname normalization, medium-confidence attribution, TTL expiry, capacity eviction, multiple hostnames on shared IPs, and invalid hostname rejection; run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS attribution cache bounds and confidence results

* Tests added/updated:
  * DNS observations normalize hostnames and return only medium-confidence `DnsCache` attribution.
  * invalid hostnames are rejected without storing cache entries.
  * entries expire according to DNS TTL and configured maximum TTL clamp.
  * cache capacity is fixed and evicts oldest entries when full.
  * shared IPs can return multiple medium-confidence hostnames instead of pretending high-confidence uniqueness.
  * zero capacity, zero max TTL, and zero DNS TTL store no attribution.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 29 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * DNS cache never upgrades attribution above medium confidence.
  * stale, invalid, or capacity-exhausted DNS observations are not available for domain policy matching.
  * shared IP attribution remains explicit and ambiguous for later policy review.
* Audit evidence: not applicable in this commit; DNS cache stores attribution state only. DNS query audit emission remains future frontend/DNS-handler work.
* Residual risk: no DNS wire parser or upstream resolver exists yet; CNAME chain semantics, DNSSEC, negative caching, and audit emission for DNS answers are not implemented.
* Commit hash: 54f8f49 bound dns attribution cache.

## 2026-06-21 - Plaintext HTTP host/path attribution parser

* Invariant under work: plaintext HTTP metadata used for policy must be parsed strictly, require unambiguous hostname attribution, reject malformed/conflicting Host information, and bound header scanning.
* Threat or failure mode addressed: permissive HTTP parsing could allow host-header ambiguity, absolute-URI/Host mismatch, invalid hostnames, or unbounded buffering to bypass domain/path policy.
* Planned verification: add parser tests for origin-form and absolute-form requests, hostname normalization, default/explicit ports, duplicate/conflicting Host rejection, missing Host rejection, malformed request-line rejection, invalid hostname rejection, and header scan limit enforcement; run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Plaintext HTTP host/path attribution parser results

* Tests added/updated:
  * origin-form HTTP/1.1 request parsing with normalized high-confidence Host attribution.
  * absolute-form HTTP proxy-style request parsing with explicit port extraction.
  * missing Host, duplicate Host, and absolute-URI/Host mismatch rejection.
  * malformed request-line, lowercase/invalid method, and unsupported HTTP version rejection.
  * invalid host, invalid port, and invalid target rejection.
  * header scan limit and incomplete header enforcement.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 35 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * HTTP Host attribution is high-confidence only after strict Host parsing and normalization.
  * ambiguous or conflicting host sources are rejected instead of falling back to permissive parsing.
  * header scanning is bounded by caller-supplied maximum bytes.
* Audit evidence: not applicable in this commit; parser output feeds future transparent/proxy HTTP policy events.
* Residual risk: parser currently handles HTTP/1.x request-head metadata only; chunking/body semantics, header folding policy, IPv6/IP-literal Host support, HTTPS CONNECT parsing, and actual stream buffering remain future frontend work.
* Commit hash: bed2ddf strict plaintext http attribution parsing.

## 2026-06-21 - TLS ClientHello SNI parser foundation

* Invariant under work: transparent HTTPS hostname attribution must come only from strictly parsed TLS ClientHello SNI, with missing/hidden SNI represented explicitly and malformed ClientHello inputs rejected.
* Threat or failure mode addressed: permissive TLS parsing could allow malformed handshakes, duplicate SNI ambiguity, oversized ClientHello buffering, or ECH/hidden-SNI cases to bypass hostname attribution policy.
* Planned verification: add unit tests for valid SNI extraction, missing SNI, ECH extension detection, duplicate SNI rejection, malformed/truncated record rejection, non-ClientHello rejection, invalid SNI rejection, and configured size-limit enforcement; run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - TLS ClientHello SNI parser foundation results

* Tests added/updated:
  * valid ClientHello SNI extraction with normalized high-confidence TLS SNI attribution.
  * missing SNI represented as explicit hidden-SNI metadata.
  * ECH extension detection marks hidden-SNI even when a plaintext SNI is present.
  * duplicate SNI, invalid hostname SNI, and IP-literal SNI rejection.
  * non-handshake TLS records and non-ClientHello handshakes rejected.
  * truncated, invalid-length, and oversized ClientHello inputs rejected.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` passed tests but clippy flagged test vector initialization style.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 41 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * TLS SNI attribution is high-confidence only after a strict ClientHello parse.
  * missing SNI and ECH are explicit hidden-SNI states for policy denial unless explicit IP/CIDR allow exists.
  * malformed ClientHello data returns structured parse errors rather than falling back to IP-only domain authorization.
* Audit evidence: not applicable in this commit; TLS metadata feeds future transparent HTTPS policy/audit events.
* Residual risk: parser handles single-record ClientHello only; GREASE nuances, fragmented TLS records, QUIC TLS metadata, and stream reassembly remain future frontend/inspection work.
* Commit hash: pending.
