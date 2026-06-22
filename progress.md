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
* Commit hash: a41c021 strict tls clienthello sni parsing.

## 2026-06-21 - HTTPS CONNECT authority parser

* Invariant under work: explicit HTTPS proxy CONNECT destinations must be parsed as unambiguous host/port origins with high-confidence explicit-proxy attribution and malformed/conflicting authority rejected.
* Threat or failure mode addressed: permissive CONNECT parsing could allow missing ports, Host/authority mismatches, duplicate Host ambiguity, invalid hostnames, or unbounded header scans to bypass origin policy.
* Planned verification: add unit tests for valid CONNECT parsing, normalized host and required port, Host header match, missing/invalid port rejection, duplicate Host rejection, Host mismatch rejection, invalid method/target rejection, and scan limit enforcement; run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - HTTPS CONNECT authority parser results

* Tests added/updated:
  * valid CONNECT request parsing with normalized host, required port, and high-confidence explicit-proxy attribution.
  * missing port rejection for CONNECT authority.
  * CONNECT authority/Host mismatch rejection.
  * duplicate CONNECT Host header rejection.
  * invalid method, malformed target, and header scan limit rejection.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` found one overly-specific expected error in a malformed-target test.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 44 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * CONNECT attribution is explicit-proxy/high-confidence only for strict `host:port` authorities.
  * malformed or conflicting CONNECT destinations are rejected before policy matching.
  * CONNECT header scanning remains bounded by caller-supplied maximum bytes.
* Audit evidence: not applicable in this commit; CONNECT parser output feeds future proxy frontend policy/audit events.
* Residual risk: actual proxy accept loop, CONNECT tunneling, SOCKS5 parser, proxy response synthesis, and shared egress backend are not implemented yet.
* Commit hash: 80f7973 strict https connect authority parsing.

## 2026-06-21 - SOCKS5 TCP CONNECT parser fail-closed foundation

* Invariant under work: explicit SOCKS proxy destinations must be parsed as bounded, unambiguous TCP CONNECT requests, reject unsupported commands/address forms/auth modes, and attach high-confidence explicit-proxy attribution only to validated domain destinations.
* Threat or failure mode addressed: permissive SOCKS parsing could allow UDP ASSOCIATE, BIND, malformed address lengths, invalid hostnames, or partial request buffering to bypass origin policy or create ambiguous audit metadata.
* Planned verification: add unit tests for no-auth method negotiation, valid domain/IP TCP CONNECT parsing, unsupported auth/command/address rejection, malformed/truncated length handling, invalid host/port rejection, and bounded request size enforcement; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - SOCKS5 TCP CONNECT parser fail-closed foundation results

* Tests added/updated:
  * SOCKS5 greeting selects only no-auth when offered and rejects unsupported auth, invalid versions, partial messages, trailing bytes, and oversized messages.
  * SOCKS5 TCP CONNECT parser accepts validated domain, IPv4, and IPv6 destinations.
  * domain destinations normalize hostnames and receive high-confidence explicit-proxy attribution; IP destinations remain low-confidence IP-only attribution.
  * BIND/UDP ASSOCIATE, nonzero reserved byte, unknown address types, zero-length domains, invalid hostnames, zero ports, trailing bytes, and oversized requests are rejected.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 50 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * SOCKS proxy metadata is produced only for complete, bounded SOCKS5 CONNECT requests.
  * unsupported SOCKS features are rejected rather than downgraded to permissive TCP metadata.
  * domain-based policy can only use validated SOCKS domain destinations, not IP-only requests.
* Audit evidence: not applicable in this commit; SOCKS metadata feeds future proxy frontend policy/audit events.
* Residual risk: actual SOCKS accept loop, reply synthesis, stream forwarding, and shared egress integration remain future proxy frontend work.
* Commit hash: 73f6f2f strict socks5 connect parsing.

## 2026-06-21 - DNS query wire parser fail-closed foundation

* Invariant under work: broker-controlled DNS handling must extract query hostnames and types only from strict, bounded DNS query messages, rejecting malformed, compressed, multi-question, non-IN, response, or unsupported-message shapes before audit/policy use.
* Threat or failure mode addressed: permissive DNS parsing could misattribute hostnames, accept ambiguous compressed question names, ignore extra questions, or let malformed query packets feed DNS cache/audit state.
* Planned verification: add DNS query parser tests for valid A/AAAA normalization, query type classification, malformed/truncated headers and labels, pointer/compression rejection, multi-question/response/opcode/class rejection, trailing data rejection, root/invalid host rejection, and message-size bounding; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS query wire parser fail-closed foundation results

* Tests added/updated:
  * valid DNS A/AAAA/unknown-type queries parse transaction ID, recursion-desired flag, normalized hostname, and query type.
  * truncated headers/questions, oversized messages, response messages, unsupported opcodes, multi-question messages, and unexpected answer/authority/additional records are rejected.
  * compressed/reserved-label question names, root names, invalid hostnames, unsupported classes, trailing bytes, and incomplete qtype/qclass fields are rejected.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` found one test expectation that treated a reserved high-bit DNS label as invalid length rather than unsupported compression/reserved label encoding.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 54 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * DNS query metadata is produced only for a single standard IN-class question with no extra records.
  * ambiguous compressed/reserved question names are rejected rather than followed or normalized permissively.
  * invalid DNS names never feed hostname attribution or audit metadata.
* Audit evidence: not applicable in this commit; DNS query metadata feeds future DNS handler policy/audit events.
* Residual risk: DNS response parsing, EDNS(0), CNAME answer handling, upstream forwarding, DNS response synthesis, and DNS query audit emission remain future DNS-handler work.
* Commit hash: bdcc7be strict dns query parsing.

## 2026-06-21 - DNS address response parser attribution foundation

* Invariant under work: DNS hostname-to-address attribution must come only from strict, bounded DNS responses whose answer owner names match the validated question, with TTLs captured for cache expiry and malformed/unsupported response shapes rejected.
* Threat or failure mode addressed: permissive DNS response parsing could attribute unrelated owner names, accept poisoned answer sections, miss truncation/trailing data, or store stale/unbounded address observations.
* Planned verification: add DNS response parser tests for valid compressed and uncompressed A/AAAA answers, empty successful/error responses without attribution, answer count bounds, owner-name mismatch rejection, unsupported class/type rejection, malformed RDLENGTH/trailing data rejection, response/opcode/question validation, and min-TTL extraction; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS address response parser attribution foundation results

* Tests added/updated:
  * valid DNS responses with compressed and uncompressed owner names extract A/AAAA addresses and minimum answer TTL.
  * NXDOMAIN/error responses with no answers parse without attribution addresses.
  * answer count bounds, owner-name mismatch, invalid compression pointers, unsupported answer types/classes, invalid A/AAAA record lengths, trailing bytes, and oversized messages are rejected.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 58 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * address attribution is produced only for response answers owned by the validated question hostname.
  * DNS response compression is accepted only for a direct pointer back to the validated question name.
  * unsupported CNAME/other answer semantics fail closed instead of attributing addresses across unimplemented alias chains.
* Audit evidence: not applicable in this commit; parsed DNS responses feed future DNS handler cache/audit events.
* Residual risk: CNAME chain handling, EDNS(0), additional records, response-code audit mapping, upstream forwarding, and DNS response synthesis remain future DNS-handler work.
* Commit hash: dd1ddfa strict dns address response parsing.

## 2026-06-21 - HTTP method/path policy matching foundation

* Invariant under work: plaintext HTTP allow/deny decisions that depend on method or path must require explicit parsed HTTP metadata and must not be satisfied by generic TCP/IP or hostname-only events.
* Threat or failure mode addressed: domain-only HTTP rules could accidentally authorize paths or methods that should be denied, while missing HTTP metadata might be treated as a permissive wildcard.
* Planned verification: add policy tests for method/path-prefix allow rules, mismatch denial by default, missing HTTP metadata not matching HTTP-specific rules, deterministic deny-before-allow ordering, and preservation of existing deny-by-default/domain attribution behavior; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - HTTP method/path policy matching foundation results

* Tests added/updated:
  * HTTP allow rule with exact method and path prefix permits only matching parsed HTTP metadata.
  * method mismatch, path mismatch, and missing HTTP metadata fall through to default deny instead of satisfying HTTP-specific rules.
  * HTTP-specific deny rules preserve first-match ordering before broader domain allows.
  * invalid configured HTTP method/path matchers fail config validation before policy use.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 61 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * path/method policy dimensions are opt-in and only match explicit parsed metadata.
  * hostname/domain attribution requirements remain unchanged for host-based HTTP rules.
  * invalid HTTP request matchers produce `InvalidConfig` fail-closed policy behavior through config validation.
* Audit evidence: not applicable in this commit; policy decisions continue to feed structured audit events, but audit schema does not yet include HTTP method/path fields.
* Residual risk: HTTP audit method/path fields, proxy/transparent stream integration, request body handling, and richer origin tuple policy remain future work.
* Commit hash: b1ccf62 add http method path policy matching.

## 2026-06-21 - HTTP/source audit context preservation

* Invariant under work: audit records for policy decisions must preserve security-relevant request metadata, including source endpoint and HTTP method/path when those dimensions affect allow/deny behavior.
* Threat or failure mode addressed: policy can now decide on HTTP method/path, but audit records without those fields would make path-scoped allows/denies hard to review and could hide bypass attempts.
* Planned verification: add audit tests that build context from normalized policy requests and assert source endpoint, hostname attribution, HTTP method/path, decisions, reasons, and bounded-buffer behavior are preserved; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - HTTP/source audit context preservation results

* Tests added/updated:
  * audit context construction from normalized policy requests preserves source endpoint, destination endpoint, hostname attribution source/confidence, HTTP method, HTTP path/query, decision, reason, and rule ID.
  * existing audit decision and bounded-buffer backpressure tests continue to pass with the expanded schema.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 62 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * HTTP method/path policy decisions can now be audited with the request metadata that influenced the decision.
  * source endpoint is no longer dropped when audit context is derived from a normalized policy request.
* Audit evidence: unit tests assert the expanded audit schema preserves HTTP/source metadata and denial details.
* Residual risk: audit serialization/sink implementation, DNS query type fields, flow byte/duration accounting, and lifecycle/error event builders remain future audit work.
* Commit hash: 380353f preserve http source audit context.

## 2026-06-21 - UDP pseudo-flow timeout and capacity foundation

* Invariant under work: UDP/QUIC/DNS pseudo-flow tracking must use explicit per-class timeouts and fixed capacity so hostile datagram traffic cannot create unbounded memory growth or stale flow state.
* Threat or failure mode addressed: unbounded UDP mapping tables or stale QUIC/DNS flows could exhaust broker memory, retain obsolete policy decisions, or misroute replies after attribution has expired.
* Planned verification: add flow table tests for DNS/generic/QUIC timeout selection, byte counters and last-seen updates, expiry, oldest-flow eviction at capacity, zero-capacity rejection, and deterministic flow keys; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - UDP pseudo-flow timeout and capacity foundation results

* Tests added/updated:
  * DNS, generic UDP, QUIC candidate, and NTP-like flows receive explicit configurable timeout classes.
  * existing flows update last-seen time, expiry, class, and saturating byte counters without resetting creation time.
  * expired flows are purged deterministically before accepting new flows.
  * capacity is fixed, oldest flows are evicted when full, and zero-capacity tables reject new flows without allocation growth.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` found one incorrect test expectation for QUIC expiry after an update.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 67 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * UDP flow state is capacity-bounded and timeout-bounded by class.
  * QUIC candidate state lives longer than generic UDP by default, while DNS/NTP-like flows expire quickly.
  * byte counters saturate instead of overflowing.
* Audit evidence: not applicable in this commit; flow expiration/byte counts feed future UDP audit events.
* Residual risk: actual UDP socket forwarding, reply routing, audit emission for flow creation/expiration, and policy-decision caching are not implemented yet.
* Commit hash: 7aa848b bound udp pseudo flow tracking.

## 2026-06-21 - QUIC candidate header parser foundation

* Invariant under work: QUIC candidate classification must parse only bounded, structurally valid QUIC header metadata and treat malformed UDP/443 payloads as unsupported metadata rather than trusted hostname attribution.
* Threat or failure mode addressed: loose QUIC detection could misclassify arbitrary UDP as QUIC, over-read connection ID lengths, or imply decrypted HTTP/3 visibility that the architecture explicitly forbids.
* Planned verification: add parser tests for valid long-header Initial metadata, short-header candidate classification, malformed fixed-bit/version/connection-ID lengths, oversized packets, unsupported versions being represented explicitly, and absence of hostname attribution; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - QUIC candidate header parser foundation results

* Tests added/updated:
  * valid QUIC long-header Initial metadata extracts packet type, version support status, and bounded connection ID lengths.
  * short-header candidates are classified without claiming version or hostname metadata.
  * unsupported long-header versions are represented explicitly instead of treated as supported v1.
  * empty packets, missing fixed bit, oversized packets, truncated long headers, and invalid connection ID lengths are rejected.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 72 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * QUIC parsing does not infer hostname or HTTP/3 semantics.
  * malformed UDP payloads cannot produce trusted QUIC metadata.
  * unsupported versions stay explicit for future policy/audit review.
* Audit evidence: not applicable in this commit; QUIC metadata feeds future UDP/QUIC inspection and audit events.
* Residual risk: QUIC varint/token/packet number parsing, TLS CRYPTO frame extraction, SNI/ECH visibility, and UDP flow integration remain future work.
* Commit hash: 55bad4b parse bounded quic candidate headers.

## 2026-06-21 - DNS response transaction correlation foundation

* Invariant under work: DNS responses must update hostname attribution only when they match a recent broker-observed DNS query for the same client, upstream, transaction ID, hostname, and query type, with pending state capacity- and TTL-bounded.
* Threat or failure mode addressed: unsolicited, replayed, cross-client, or mismatched DNS responses could poison hostname attribution if parsed address answers were cached without transaction correlation.
* Planned verification: add pending DNS transaction tests for matching query/response removal, transaction ID/hostname/type/client/upstream mismatch rejection, expiry, capacity eviction, zero-capacity rejection, and bounded pending length; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS response transaction correlation foundation results

* Tests added/updated:
  * pending DNS responses match only after a stored query with the same client endpoint, upstream endpoint, transaction ID, hostname, and query type.
  * matched pending queries are removed so replayed responses cannot be reused.
  * cross-client, cross-upstream, hostname-mismatched, and query-type-mismatched responses are rejected.
  * pending query state expires by TTL, evicts oldest entries at capacity, rejects zero-capacity/zero-timeout storage, and replaces reused transaction IDs on the same path.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` found a test that accidentally reused the same DNS transaction ID when exercising capacity eviction.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 76 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * parsed DNS address responses cannot update attribution unless correlated to a pending broker-observed query.
  * mismatched responses fail closed and do not leave ambiguous pending state behind.
  * pending transaction memory remains bounded by both capacity and timeout.
* Audit evidence: not applicable in this commit; transaction outcomes feed future DNS audit events.
* Residual risk: DNS handler wiring to cache insertion, response-code audit mapping, upstream retry behavior, and response synthesis remain future work.
* Commit hash: 16ce278 correlate dns responses before attribution.

## 2026-06-21 - Domain policy port binding for explicit proxy origins

* Invariant under work: hostname/domain allow rules with a port constraint must require the explicit requested port from proxy-origin metadata when no destination IP endpoint exists, and must not treat missing destination endpoints as port matches.
* Threat or failure mode addressed: explicit HTTPS CONNECT or SOCKS domain requests could otherwise satisfy `example.com:443` rules while requesting a different port if policy evaluation only checked hostname attribution and ignored parser-provided authority port.
* Planned verification: add policy tests showing requested-port matches allow, requested-port mismatch denies, missing port metadata denies port-scoped domain rules, and existing transparent destination-port matching still works; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Domain policy port binding for explicit proxy origins results

* Tests added/updated:
  * explicit proxy hostname requests with requested port 443 satisfy a host rule scoped to port 443.
  * explicit proxy hostname requests with requested port 22, or missing requested-port metadata, do not satisfy the port-scoped host rule and default-deny.
  * transparent destination endpoints still populate requested-port metadata and continue to match host rules by destination port.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 77 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * domain rules now bind to `PolicyRequest::requested_port` instead of treating absent IP endpoints as a port match.
  * packet-derived policy requests copy destination port into requested-port metadata.
  * explicit proxy events must carry parser-derived authority/destination port to satisfy port-scoped domain rules.
* Audit evidence: not applicable in this commit; requested port should be added to expanded audit context in a later audit schema cycle.
* Residual risk: parser-to-policy conversion helpers for CONNECT/SOCKS/HTTP and requested-port audit fields remain future work.
* Commit hash: 95d4fbf bind domain policy to requested ports.

## 2026-06-21 - Parser-to-policy normalization helpers

* Invariant under work: HTTP, HTTPS CONNECT, and SOCKS parser outputs must normalize into policy requests with explicit frontend, protocol, hostname attribution, requested port, path/method metadata, and IP destination where available.
* Threat or failure mode addressed: callers hand-building policy requests could omit requested-port or attribution metadata, causing port-scoped domain rules, audit context, or IP-only SOCKS decisions to behave incorrectly.
* Planned verification: add normalization tests for plaintext HTTP method/path/port attribution, HTTPS CONNECT requested-port attribution, SOCKS domain requested-port attribution, SOCKS IP destination/IP-only attribution, and policy allow/deny behavior using normalized requests; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Parser-to-policy normalization helpers results

* Tests added/updated:
  * plaintext HTTP parser metadata normalizes into HTTP policy requests with frontend, high-confidence host attribution, requested port, method, and path/query.
  * HTTPS CONNECT parser metadata normalizes into explicit HTTP proxy policy requests with high-confidence host attribution and requested port.
  * SOCKS5 domain metadata normalizes into SOCKS policy requests with requested port and no premature IP destination; SOCKS5 IP metadata normalizes into an IP destination with IP-only attribution.
  * normalized CONNECT requests enforce port-scoped domain policy for matching and mismatching authority ports.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 79 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * callers can now preserve parser-derived ports and attribution consistently when entering policy.
  * SOCKS IP destinations remain unable to satisfy domain rules.
  * port-scoped explicit proxy domain rules deny normalized requests with the wrong requested port.
* Audit evidence: not applicable in this commit; normalized policy requests feed existing audit context builders, with requested-port audit coverage still pending.
* Residual risk: transparent TLS metadata normalization, DNS metadata normalization, requested-port audit fields, and actual frontend wiring remain future work.
* Commit hash: 61be355 normalize proxy parser metadata for policy.

## 2026-06-21 - Requested-port audit preservation

* Invariant under work: audit records must preserve requested-port metadata for explicit proxy and transparent host/domain decisions so reviewers can distinguish host attribution from the authority/destination port that was authorized or denied.
* Threat or failure mode addressed: after separating requested ports from IP destination endpoints, audit records without requested-port could hide CONNECT/SOCKS port mismatches or make port-scoped domain policy decisions unverifiable.
* Planned verification: extend audit schema/context tests to assert requested-port preservation for requests without IP destinations and existing destination/source fields; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Requested-port audit preservation results

* Tests added/updated:
  * audit context derived from policy requests now preserves requested-port metadata alongside source, destination, hostname attribution, HTTP method/path, decision, reason, and rule ID.
  * existing audit decision and bounded-buffer tests continue to pass with the expanded schema.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 79 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * audit events can now show the explicit authority/destination port used in domain policy decisions even when no IP destination endpoint exists.
  * transparent requests still retain both destination endpoint and requested-port metadata.
* Audit evidence: unit tests assert requested-port preservation in policy-derived audit events.
* Residual risk: audit serialization/sinks and DNS/flow-specific audit builder coverage remain future work.
* Commit hash: 3477db0 preserve requested port in audit context.

## 2026-06-21 - TLS ClientHello policy normalization

* Invariant under work: parsed transparent TLS ClientHello metadata must enter policy with explicit TLS-SNI protocol class, destination/requested port, presented hostname, DNS attribution when available, and hidden-SNI state.
* Threat or failure mode addressed: callers hand-building TLS policy requests could omit hidden-SNI/ECH flags or mismatch metadata, allowing domain rules to bypass documented hidden-SNI and SNI/DNS mismatch denial behavior.
* Planned verification: add normalization tests for visible SNI attribution, SNI/DNS mismatch denial, missing SNI hidden-state denial, and explicit IP-rule exemption for hidden SNI; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - TLS ClientHello policy normalization results

* Tests added/updated:
  * visible TLS SNI metadata normalizes into `Protocol::TlsSni` requests with destination/requested port, high-confidence attribution, presented hostname, and DNS attribution.
  * SNI/DNS mismatch on normalized TLS requests is denied with `AttributionMismatch`.
  * missing SNI normalizes to hidden-SNI state and is denied by default.
  * explicit IP/CIDR allow rules can still exempt hidden-SNI traffic as documented.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 80 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * TLS parser outputs can now enter policy without losing hidden-SNI/ECH or presented-hostname semantics.
  * mismatch and hidden-SNI protections apply to normalized TLS metadata by default.
* Audit evidence: not applicable in this commit; normalized TLS requests feed existing audit context builders.
* Residual risk: transparent stream reassembly before TLS parsing, fragmented ClientHello handling, and QUIC TLS metadata normalization remain future work.
* Commit hash: 987bdad normalize tls clienthello metadata for policy.

## 2026-06-21 - QUIC candidate policy normalization

* Invariant under work: QUIC candidate metadata must normalize into UDP/QUIC policy requests with destination/requested port and optional medium-confidence DNS attribution, without inventing hostname attribution from QUIC headers.
* Threat or failure mode addressed: UDP/443 traffic could be evaluated as generic UDP or receive fabricated hostname confidence if QUIC parser metadata is not normalized through an explicit policy path.
* Planned verification: add tests for normalized QUIC candidate protocol/frontend/port, DNS-attributed domain allow, no-attribution default deny for domain rules, and explicit IP allow behavior; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - QUIC candidate policy normalization results

* Tests added/updated:
  * QUIC parser metadata normalizes into `Protocol::QuicCandidate` requests with frontend, destination, and requested port.
  * QUIC candidate headers do not fabricate hostname attribution; domain rules default-deny without DNS attribution.
  * medium-confidence DNS attribution can satisfy port-scoped domain rules for QUIC candidates.
  * explicit IP/CIDR allow rules can allow unattributed QUIC candidates by destination IP/port.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 81 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * QUIC metadata enters policy as QUIC-specific traffic rather than generic UDP.
  * domain authorization still requires DNS or other explicit hostname attribution; QUIC headers alone do not provide it.
* Audit evidence: not applicable in this commit; normalized QUIC requests feed existing audit context builders.
* Residual risk: QUIC version/type audit fields, visible QUIC TLS SNI/ECH parsing, and UDP frontend integration remain future work.
* Commit hash: 966e79d normalize quic candidate metadata for policy.

## 2026-06-21 - DNS correlated response cache insertion

* Invariant under work: broker DNS responses must update hostname attribution cache only through the pending-query transaction correlation path, preserving TTL/capacity bounds and never caching mismatched or unsolicited responses.
* Threat or failure mode addressed: even with strict DNS parsers and pending transaction checks, callers could accidentally insert parsed responses directly into the DNS attribution cache without validating transaction identity, enabling cache poisoning or stale attribution.
* Planned verification: add DNS state helper tests for correlated response-to-cache insertion, empty successful responses, TTL-zero responses, response replay rejection, and mismatch/no-cache behavior; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS correlated response cache insertion results

* Tests added/updated:
  * correlated DNS responses update the attribution cache only after matching a pending query by client/upstream/transaction/host/type.
  * replayed responses are rejected after the pending transaction is consumed.
  * empty successful responses and zero-TTL answers remove pending state but store no attribution.
  * hostname-mismatched responses do not update the cache and leave no ambiguous pending state.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 84 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * parsed DNS address answers cannot enter the hostname attribution cache without transaction correlation.
  * no-address and zero-TTL responses cannot create stale attribution.
  * response replay and hostname mismatch are rejected without cache mutation.
* Audit evidence: not applicable in this commit; this helper wires correlation to cache mutation, while DNS query/response audit event builders remain future work.
* Residual risk: DNS audit event fields, actual upstream forwarding, response synthesis, retry behavior, and DNS handler socket integration remain future work.

* Commit hash: 6663d5d gate dns attribution cache by transactions.

## 2026-06-21 - DNS audit metadata preservation

* Invariant under work: DNS query audit records must preserve the validated query type and hostname/source endpoints so DNS allow, deny, and fail-closed decisions are reviewable without re-parsing packet bytes.
* Threat or failure mode addressed: DNS policy and cache decisions could be audited only as generic protocol events, hiding whether A/AAAA/unsupported query types were allowed or denied and weakening security review of direct-DNS and attribution behavior.
* Planned verification: extend audit schema and tests to preserve `DnsQueryType` in policy-derived and DNS-metadata-derived audit events; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS audit metadata preservation results

* Tests added/updated:
  * DNS query audit events built from validated query metadata preserve query type, hostname, source endpoint, destination endpoint, requested port, frontend, protocol, and decision.
  * policy-derived audit events explicitly preserve no DNS query type unless DNS metadata is present.
  * bounded audit backpressure remains enforced after schema expansion; backpressured events are returned boxed to keep `PushOutcome` size bounded under clippy.
* Commands run:
  * Initial `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` passed tests but clippy flagged `PushOutcome` as a large enum variant after the audit schema grew.
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 85 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * DNS audit records now distinguish validated query types instead of logging DNS only as a generic protocol.
  * audit backpressure continues to reject the new event without increasing queue capacity.
* Audit evidence: unit tests assert DNS query type/hostname/endpoints and bounded-buffer behavior.
* Residual risk: DNS response audit fields, serialized sink output, audit drain/backpressure policy in async runtime, and actual DNS socket handler integration remain future work.

* Commit hash: 7309f22 preserve dns query metadata in audit.

## 2026-06-21 - Stable audit JSON line serialization

* Invariant under work: audit records for allow, deny, fail-closed, DNS, HTTP, and endpoint-bearing decisions must serialize to a deterministic structured line without dropping security-relevant fields or relying on ad hoc debug formatting.
* Threat or failure mode addressed: if audit sinks receive lossy or unstable text, reviewers and tests can miss denial reasons, query types, attribution source/confidence, or requested ports that explain security decisions.
* Planned verification: add JSON-line serialization helpers and tests for denied HTTP policy events, DNS query events, fail-closed reasons, endpoint objects, null optional fields, and string escaping; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Stable audit JSON line serialization results

* Tests added/updated:
  * denied HTTP policy audit events serialize kind, source/destination endpoints, requested port, hostname attribution, decision, deny behavior, denial reason, rule ID, HTTP path, and null DNS query type.
  * DNS query audit events serialize DNS query type, hostname source, null endpoints, fail-closed decision, and malformed-input reason.
  * unsupported protocol audit serialization preserves the protocol number as `unsupported:<number>`.
  * JSON string escaping covers quotes in rule IDs and HTTP path/query values.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 88 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * allow/deny/fail-closed decisions retain structured fields through audit serialization rather than relying on debug formatting.
  * optional fields serialize as explicit `null`, which makes missing attribution or endpoints auditable.
* Audit evidence: unit tests assert deterministic JSON fragments for denial context, DNS query metadata, fail-closed reason, endpoint objects, and unsupported protocol numbers.
* Residual risk: no async audit drain or file/stdout sink exists yet; lifecycle/flow-specific event constructors and response audit serialization coverage remain future work.

* Commit hash: e9613d8 serialize audit events as structured json.

## 2026-06-21 - UDP flow lifecycle audit builders

* Invariant under work: UDP pseudo-flow creation and expiration audit records must preserve source/destination endpoints, protocol class, byte counts, and bounded lifetime metadata so flow decisions remain reviewable when state expires.
* Threat or failure mode addressed: UDP flow tracking currently bounds memory and counters, but lifecycle audit records could omit byte totals or duration, hiding stale-flow cleanup behavior and QUIC/DNS/generic classification.
* Planned verification: add audit constructors/tests for UDP flow created, QUIC candidate flow created, and UDP flow expired events with byte counts and duration; ensure JSON serialization includes flow duration and byte count; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - UDP flow lifecycle audit builders results

* Tests added/updated:
  * QUIC candidate UDP flow creation audit records preserve source/destination endpoints, requested port, byte count, duration, and QUIC protocol classification.
  * generic UDP expiration audit records preserve saturated byte counts and flow duration.
  * JSON audit serialization includes `byte_count` and `flow_duration_millis` for flow lifecycle records.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 90 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * UDP lifecycle events can now be reviewed after state cleanup without losing counters or timeout-derived lifetime evidence.
  * QUIC candidate flow audit records remain distinguishable from generic UDP records.
* Audit evidence: unit tests assert lifecycle event fields and serialized byte/duration output.
* Residual risk: the flow table still returns only expiration counts rather than expired entries for automatic audit emission; UDP socket forwarding and reply routing remain future work.

* Commit hash: 07c37ac audit udp flow lifecycle metadata.

## 2026-06-21 - UDP expiration returns auditable entries

* Invariant under work: UDP flow expiration must expose the expired flow entries, not only a count, so cleanup can emit complete audit records without retaining stale state or dropping byte/endpoint evidence.
* Threat or failure mode addressed: if expiration only reports counts, a future runtime could either omit expiration audit details or retain expired state longer than necessary to log it, weakening bounded memory behavior.
* Planned verification: add `expire_collect` coverage proving expired entries are removed and returned with byte counts/classification while non-expired flows remain; preserve existing count-based behavior; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - UDP expiration returns auditable entries results

* Tests added/updated:
  * `expire_collect` returns expired UDP flow entries with key, class, and byte count intact while removing them from the table.
  * non-expired flows remain in the table after collection.
  * existing count-based `expire` behavior remains intact for callers that only need counts.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 91 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * cleanup can now emit complete expiration audit events without retaining stale expired flow state.
  * flow memory remains bounded because expired entries are removed during collection.
* Audit evidence: flow tests preserve the data required by `AuditEvent::from_udp_flow_entry` for expiration records.
* Residual risk: UDP forwarding, response routing, and automatic runtime coupling between `expire_collect` and audit sinks remain future work.

* Commit hash: be30b6b return auditable udp expirations.

## 2026-06-21 - Duplicate policy rule ID rejection

* Invariant under work: policy configuration must reject duplicate rule IDs before evaluation so audit `rule_id` fields identify a single deterministic rule and cannot hide ambiguous allow/deny provenance.
* Threat or failure mode addressed: duplicate rule IDs could make audit records ambiguous even when first-match rule ordering is deterministic, weakening review of why traffic was allowed or denied.
* Planned verification: add config validation and policy fail-closed tests for duplicate rule IDs, preserving deterministic first-match behavior for unique IDs; run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Duplicate policy rule ID rejection results

* Tests added/updated:
  * config validation rejects duplicate rule IDs.
  * policy evaluation fail-closes with `InvalidConfig` when duplicate IDs are present, before any allow rule can match.
  * existing deterministic first-match behavior remains covered for unique rule IDs.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 93 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * ambiguous rule provenance is rejected at validation time.
  * invalid policy configuration cannot authorize traffic.
* Audit evidence: rule IDs emitted in audit records now have a validation invariant that they identify at most one configured rule.
* Residual risk: config file parsing/loading and broader normalization of externally supplied configs remain future work.

* Commit hash: 0a8a87f reject duplicate policy rule ids.

## 2026-06-21 - DNS response audit metadata preservation

* Invariant under work: DNS response audit records must preserve response code, query type, answer count, and TTL evidence from strict parsed DNS responses without implying high-confidence hostname authorization.
* Threat or failure mode addressed: DNS responses that create, skip, or deny attribution could otherwise be audited as generic DNS events, hiding NXDOMAIN/error outcomes, empty answers, zero-TTL answers, or the TTL evidence used for bounded cache insertion.
* Planned verification: add parsed response-code metadata to DNS response parsing, add DNS response audit event builders/serialization coverage, and run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - DNS response audit metadata preservation results

* Tests added/updated:
  * DNS address response parser now exposes `DnsResponseCode` and tests assert `NOERROR` and `NXDOMAIN` preservation.
  * DNS response audit builder preserves source/destination endpoints, response hostname, query type, response code, answer count, minimum TTL, and medium-confidence DNS-cache attribution semantics.
  * JSON audit serialization includes `dns_response_code`, `dns_answer_count`, and `dns_min_ttl_seconds` fields.
* Commands run:
  * `cargo fmt && cargo test && cargo clippy --all-targets --all-features -- -D warnings` — passed: 94 tests passed and clippy completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * DNS response metadata remains produced only by the strict DNS response parser.
  * Response audit metadata reports DNS-derived attribution as medium confidence rather than upgrading it to high-confidence domain policy evidence.
  * Empty/error DNS responses can be audited with response code and zero answer evidence instead of disappearing behind generic DNS logs.
* Audit evidence: unit tests assert DNS response audit fields and JSON fragments for response code, answer count, and TTL.
* Residual risk: actual DNS socket handler/upstream forwarding, DNS response synthesis, async audit drain/backpressure policy, and automatic response audit emission remain future work.
* Commit hash: ad00a4b preserve dns response audit metadata.

## 2026-06-21 - Packet checksum fail-closed validation

* Invariant under work: validated packet metadata must reject invalid IPv4 header checksums and invalid TCP, UDP, ICMP, and ICMPv6 transport checksums before policy or forwarding sees the packet.
* Threat or failure mode addressed: malformed packets with corrupted headers or transport metadata could otherwise be normalized into policy requests, causing audit and policy decisions to rely on packet fields that the network stack should have rejected.
* Planned verification: add checksum validation to the IP packet parser, update packet fixtures to carry valid checksums, add negative checksum tests, and run `cargo fmt`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings`.

## 2026-06-21 - Packet checksum fail-closed validation results

* Tests added/updated:
  * packet fixtures now generate valid IPv4 header and TCP/UDP/ICMP/ICMPv6 checksums.
  * invalid IPv4 header checksums fail closed with `InvalidIpv4HeaderChecksum`.
  * invalid TCP and ICMPv6 transport checksums fail closed with `InvalidTransportChecksum`.
  * existing metadata extraction, malformed length, unsupported protocol, fragmentation, and policy normalization tests continue to pass under checksum validation.
* Commands run:
  * `cargo fmt && cargo test` — passed: 95 tests passed.
  * `cargo clippy --all-targets --all-features -- -D warnings` — completed cleanly.
* Observed allow/deny/fail-closed behavior:
  * corrupted IPv4 headers are rejected before fragmentation/protocol metadata can be trusted.
  * corrupted transport payloads are rejected before source/destination ports, DNS/QUIC classification, or ICMP type/code metadata can feed policy.
  * IPv4 UDP checksum zero remains accepted according to protocol semantics; IPv6 UDP checksum zero fails closed.
* Audit evidence: not applicable in this commit; checksum failures surface as parser errors that future runtime code should audit as fail-closed unsupported/malformed packet decisions.
* Residual risk: packet parser still rejects IPv4 fragments and IPv6 extension headers rather than reassembling/processing them; no runtime TUN integration currently couples parser errors to audit sink emission.
