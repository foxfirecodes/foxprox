# Security Invariants Learnings

This is an append-only security learning ledger for `docs/implementation-approach-security-invariants.md`.

## 2026-06-21 - DNS and hidden-SNI bypass ordering

A DNS bypass check that only considers a dedicated DNS event class is insufficient: transparent TCP/UDP flows to external port 53 (and identifiable DoT port 853) must be denied before generic IP allow rules. Hidden-SNI/ECH checks must also run before generic domain allow matching; only explicit IP/CIDR allow rules can exempt hidden-SNI/ECH.

## 2026-06-21 - Packet parser fail-closed scope

The alpha packet parser should reject IPv4 fragments and IPv6 extension headers until the broker has explicit reassembly/extension semantics. Classifying UDP/53 as DNS and UDP/443 as QUIC candidate at the normalized metadata boundary helps policy apply DNS-bypass and QUIC-default invariants consistently.

## 2026-06-21 - DNS attribution confidence

DNS cache correlation must stay medium confidence and may produce multiple hostnames for one IP. A shared IP match should not be collapsed into high-confidence uniqueness; policy code must keep source/confidence explicit when deciding domain rules.

## 2026-06-21 - Plaintext HTTP attribution strictness

Plaintext HTTP Host attribution should reject duplicate Host headers and absolute-URI/Host mismatches rather than choosing one source. Header parsing must have an explicit scan limit before any future stream frontend buffers request data.

## 2026-06-21 - TLS hidden-SNI representation

TLS inspection should distinguish valid SNI attribution from hidden-SNI states. Missing SNI or ECH presence must be surfaced explicitly so policy can apply the documented deny-unless-explicit-IP rule instead of silently falling back to domain rules.

## 2026-06-21 - CONNECT authority strictness

HTTPS CONNECT should require an explicit nonzero port in the request authority and reject Host/authority mismatches. Successful CONNECT parsing can be treated as high-confidence explicit-proxy attribution, but only after duplicate/conflicting host inputs are excluded.

## 2026-06-21 - SOCKS5 explicit proxy strictness

SOCKS5 support should treat only TCP CONNECT as alpha scope. BIND, UDP ASSOCIATE, unsupported authentication, malformed address lengths, and invalid domain names must fail closed. SOCKS domain destinations can be high-confidence explicit-proxy attribution; SOCKS IP destinations remain IP-only and should not satisfy domain rules.

## 2026-06-21 - DNS query parser strictness

The first DNS wire parser is intentionally single-question, IN-class, no-extra-records, and no-compression for query names. That avoids ambiguous hostname attribution, but EDNS(0) and compressed question support will need explicit semantics before enabling for compatibility.

## 2026-06-21 - DNS response attribution owner checks

DNS address attribution should require every stored A/AAAA answer owner to match the validated question hostname. Compression can be handled narrowly for the common pointer-to-question case; CNAME chains and additional records need explicit semantics before they can safely contribute to attribution.

## 2026-06-21 - HTTP request metadata must be explicit for path policy

HTTP path/method rules should not act as wildcards when request metadata is absent. Missing parsed method/path must fail to match HTTP-specific rules so generic TCP/domain events cannot accidentally receive path-scoped authorization.

## 2026-06-21 - Audit schema must follow policy dimensions

Whenever policy gains a new security decision dimension, audit context needs a matching field or builder path. HTTP method/path decisions are not reviewable if audit records only retain host and destination metadata.

## 2026-06-21 - UDP flow state requires independent bounds

UDP pseudo-flow tracking needs both capacity limits and protocol-class timeouts. QUIC, DNS, generic UDP, and NTP-like traffic have materially different safe lifetimes, and byte counters should saturate rather than overflow under hostile traffic.

## 2026-06-21 - QUIC metadata must not imply HTTP/3 visibility

QUIC candidate parsing should be explicit about what is known: header form, packet type, version, and connection ID lengths. It must not imply hostname or HTTP/3 request visibility unless future TLS/QUIC parsing safely extracts that metadata.

## 2026-06-21 - DNS responses need transaction correlation before caching

Strict DNS response parsing is not sufficient for safe attribution. Address answers should only enter the attribution cache after matching a recent pending query by client, upstream, transaction ID, hostname, and query type; mismatched responses should fail closed and not poison or reuse pending state.

## 2026-06-21 - Domain allow rules must bind proxy authority ports

Host/domain policy rules with ports cannot rely only on IP destination endpoints. Explicit proxy requests may have no resolved IP yet, so policy needs a separate requested-port field populated from CONNECT/SOCKS/HTTP authority metadata; missing requested-port must not match port-scoped host rules.

## 2026-06-21 - Normalize parser output before policy decisions

Parser outputs should have first-class conversion paths into normalized policy requests. This avoids hand-built requests that accidentally omit requested ports, frontend source, path/method metadata, or IP-only-vs-hostname attribution distinctions.

## 2026-06-21 - Requested port is audit-relevant metadata

After separating requested authority ports from IP destination endpoints, audit records need the requested-port field too. Otherwise explicit proxy decisions are not independently reviewable when no destination IP endpoint exists yet.

## 2026-06-21 - TLS metadata normalization must carry hidden-SNI state

TLS parser output should normalize into policy with both presented hostname and hidden-SNI/ECH state. If callers only pass attribution when SNI exists, missing SNI can be mistaken for ordinary IP-only traffic instead of receiving the documented hidden-SNI denial behavior.

## 2026-06-21 - QUIC policy normalization must not invent attribution

QUIC header metadata is useful for classifying UDP/443 and timeout/policy defaults, but it is not hostname evidence. Domain authorization for QUIC should come from DNS correlation or future safe QUIC/TLS metadata parsing, not from merely recognizing a QUIC-shaped packet.

## 2026-06-21 - DNS cache mutation must be correlation-gated

DNS response parsing and pending transaction validation need a single helper path into attribution cache insertion. Leaving cache insertion to callers risks bypassing correlation checks with a parsed-but-unsolicited response. Empty and zero-TTL responses should consume pending state but store no attribution.

## 2026-06-21 - DNS query type is audit-critical

DNS audit events need first-class query type metadata. A generic DNS protocol audit record is not enough to review A/AAAA attribution decisions or spot unsupported query-type policy gaps. Growing the audit schema can also trip `large_enum_variant`; keep backpressure return types size-bounded without weakening bounded queue behavior.

## 2026-06-21 - Audit serialization must preserve numeric unsupported protocols

Audit JSON should not collapse `Protocol::Unsupported(n)` to a generic string. The unsupported protocol number is security-relevant evidence for fail-closed packet decisions and must survive structured serialization along with explicit nulls for absent attribution fields.

## 2026-06-21 - UDP expiration needs auditable entry data

A flow table that only reports an expiration count cannot emit complete expiration audit records by itself. Lifecycle audit builders need the expired `UdpFlowEntry` data so byte counts, endpoints, class, and duration survive cleanup.

## 2026-06-21 - Expiration APIs should return consumed state for audit

For bounded state tables, auditability and cleanup should be linked: returning expired entries lets the runtime log exact flow data while removing stale state immediately, instead of choosing between complete audit records and bounded memory.

## 2026-06-21 - Rule IDs are part of audit integrity

Policy rule IDs are not just labels; audit records depend on them for provenance. Duplicate IDs should be invalid configuration, even when first-match evaluation would still be deterministic.

## 2026-06-21 - DNS response audit must distinguish cache confidence

DNS response audit records should preserve response code, answer count, and TTL data, but they must not imply high-confidence domain attribution. Even correlated DNS answers feed the attribution cache at medium confidence, so response audit builders should reflect DNS-cache semantics instead of broker-query or explicit-host semantics.

## 2026-06-21 - Packet checksum validation protects policy metadata

Packet parsing should validate IPv4 header and transport checksums before exposing ports, DNS/QUIC classification, or ICMP type/code to policy. IPv4 UDP checksum zero is a protocol-permitted exception, but IPv6 UDP checksum zero should fail closed.

## 2026-06-21 - DNS bypass exemptions need config validation

Direct-DNS bypass checks are only as safe as the broker DNS server list. Treating multicast, broadcast, directed-broadcast, or unspecified addresses as broker-controlled DNS would weaken bypass prevention, so those addresses should be rejected during policy config validation.

## 2026-06-21 - Audit drain batches need explicit bounds

Bounded audit queues also need bounded drain APIs. Even if queue capacity is fixed, a sink path that serializes every queued event in one unbounded operation can create avoidable latency and allocation spikes under hostile traffic.

## 2026-06-21 - Parser errors need audit mapping before runtime wiring

Packet parser failures should have a single structured audit conversion path before adding TUN runtime loops. This avoids each caller inventing its own malformed-vs-unsupported mapping and preserves numeric unsupported protocol evidence consistently.

## 2026-06-21 - Autonomy should follow documented scope without clarification

I paused to ask which runtime implementation track to take even though the source docs already specify the alpha direction: Rust, TUN, smoltcp-based forwarding proof, broker-controlled DNS, shared policy/audit core, and bwrap-compatible setup boundaries. That was an over-application of the clarification gate. For this workflow, documented architecture choices should be treated as authorization to proceed autonomously; only conflicts, outside-docs choices, irreversible external changes, or security-model changes should stop for user input.

## 2026-06-21 - DNS response synthesis should round trip through strict parsing

DNS response builders should consume already-validated query metadata, preserve transaction IDs and normalized owner names, and produce responses that the strict DNS response parser accepts. Error responses should be empty-answer and bounded; address responses should reject unsupported query types and A/AAAA family mismatches rather than silently dropping or rewriting records.

## 2026-06-21 - Broker DNS query policy requires configured broker destination

Even validated DNS query metadata should be denied by direct-DNS bypass checks unless the destination IP is configured as a broker DNS server. Tests for DNS query policy normalization should include the broker DNS server in policy config so domain-rule behavior is exercised without weakening bypass prevention.

## 2026-06-21 - DNS handler should separate malformed drops from validated denials

Malformed DNS bytes may not contain a trustworthy transaction ID or question, so the safe core behavior is fail-closed audit plus drop. Once a query is strictly parsed, policy denials can synthesize bounded empty error responses such as REFUSED while preserving audit metadata.

## 2026-06-21 - Pending DNS state should be created only after allow decisions

Strict parsing alone is not enough to justify pending DNS transaction state. The core handler should observe pending transactions only for policy-allowed queries that are actually going to be forwarded upstream; denied or malformed queries must not leave state that a later response could match.

## 2026-06-21 - DNS responses should be forwarded only after transaction-gated cache observation

The safe DNS response path is strict parse, pending transaction validation, then cache observation and forward/audit as one operation. Replays or unmatched responses should use fail-closed attribution-mismatch audit and must not mutate the attribution cache.

## 2026-06-21 - DNS forwarding should use audited wire bytes

DNS handler forward outcomes should carry the exact bounded wire bytes that were parsed and audited. Reconstructing wire messages from metadata in the runtime could diverge from the security decision or accidentally mutate transaction IDs, flags, or answer sections.

## 2026-06-21 - Proxy frontends need a pure decision boundary before IO

Explicit HTTP and CONNECT handlers should parse bounded headers, normalize into shared policy requests, build audit records, and synthesize bounded local denial/error responses before any runtime socket forwarding. This keeps malformed requests and policy denials out of egress code and avoids per-listener ad hoc parsing.

## 2026-06-21 - SOCKS helpers must keep IP-only attribution distinct

SOCKS domain CONNECT requests can be high-confidence explicit-proxy hostname evidence, but SOCKS IP CONNECT requests must remain IP-only/low-confidence and should not satisfy domain rules. The handler boundary should preserve that distinction in both policy requests and audit records.

## 2026-06-21 - TUN forwarding should start from a pure parse-policy-audit boundary

A live TUN loop should call a core helper that strictly parses packet bytes, normalizes metadata, decides policy, and builds audit before any forwarding. Malformed and unsupported packets should not return forwardable bytes; bypass denials such as direct DNS should be visible at this boundary.

## 2026-06-21 - ICMP synthesis must follow strict packet validation

Synthetic ICMP replies should be generated only after the packet parser validates IP and transport checksums. The echo-reply proof should reject unusual ICMP types and preserve payload/checksum correctness rather than becoming a generic permissive ICMP responder.

## 2026-06-21 - Lifecycle audit events should not masquerade as policy decisions

Startup/setup/shutdown audit records should preserve sandbox and frontend context with null decision fields, while actual broker errors should use explicit fail-closed decisions and typed denial reasons. This keeps lifecycle review separate from allow/deny policy review.

## 2026-06-21 - TCP flow expiration boundaries should be explicit

TCP flow expiry uses `expires_at_millis <= now` semantics, matching UDP flow cleanup. Tests and runtime cleanup should account for the exact boundary so flow state is not retained past its configured idle timeout.

## 2026-06-21 - TCP lifecycle audit should consume flow state

TCP close/expiration audit records should be built from the `TcpFlowEntry` returned by close or expiration collection. That links bounded cleanup with complete endpoint, counter, and duration evidence instead of requiring stale state retention.

## 2026-06-21 - ICMP write-back must be policy-gated

Synthetic ping replies should be produced only after the TUN packet handler has both parsed the packet and received an allow decision, such as `allow_ping`. Default-denied echo requests should drop with ICMP denial audit and must not reach synthesis.

## 2026-06-21 - Host egress should require an allow-derived permit

Future host socket code should accept an `EgressPermit` built from a shared policy allow decision, not raw parser metadata. This keeps TUN, HTTP, CONNECT, and SOCKS frontends from accidentally bypassing the policy/audit boundary.

## 2026-06-21 - Attribution mismatch audit needs both names

For SNI/DNS mismatch review, logging only the selected hostname and denial reason is insufficient. Audit records should preserve the presented hostname and DNS-correlated hostname together so reviewers can see the conflict without reconstructing flow state.

## 2026-06-21 - Hidden-SNI state is audit-relevant even on allowed flows

When policy explicitly allows hidden-SNI traffic by IP/CIDR, the audit record must still show that SNI/ECH hid hostname attribution. A denial reason alone is not enough because allowed hidden-SNI flows would otherwise lose that evidence.

## 2026-06-21 - QUIC audit should separate header evidence from attribution

QUIC candidate audit records should include bounded header metadata such as form, type, version, support status, and connection-ID lengths, but should keep hostname attribution null unless future QUIC/TLS parsing safely extracts it.

## 2026-06-21 - Transparent TLS inspection should issue egress permits only after SNI policy

Direct HTTPS bytes should pass through strict ClientHello parsing, SNI/DNS mismatch checks, hidden-SNI handling, audit, and allow-derived egress permits before host socket connection. Malformed ClientHello must not fall back to ordinary IP-only authorization.

## 2026-06-21 - QUIC handler must not convert header parsing into hostname trust

The QUIC decision path should use QUIC headers for classification/audit and DNS cache for domain attribution. A QUIC-shaped UDP/443 packet should not satisfy domain rules unless DNS or future safe QUIC/TLS metadata supplies hostname evidence.

## 2026-06-21 - Transparent HTTP must not fall back to generic TCP on parser failure

For direct plaintext HTTP over TUN, malformed or incomplete request-head metadata should fail closed at the HTTP inspection boundary. Otherwise Host/path policy can be bypassed by relying on broader TCP/IP rules after parser failure.

## 2026-06-21 - Packet-level DNS attribution must not weaken DNS bypass checks

DNS cache attribution can safely enrich ordinary transparent TCP/UDP policy requests, but DNS-classified packets must keep direct-bypass denial precedence and ignore supplied attribution. Otherwise resolver traffic could be disguised as domain-authorized application traffic.

## 2026-06-21 - Shared-IP DNS cache lookups need an explicit ambiguity state

DNS cache APIs should not force callers to choose the first hostname for an IP. Returning `Ambiguous` for shared-IP mappings makes the false-deny tradeoff explicit and avoids accidental domain authorization based on cache insertion order.

## 2026-06-21 - UDP lifecycle audit needs reply-side byte accounting

UDP pseudo-flows are bidirectional once a host socket is opened. Expiration audit records should include host-to-sandbox bytes as well as sandbox-to-host bytes, using saturating counters so large flows cannot wrap audit totals.

## 2026-06-21 - bwrap setup argv needs explicit helper-target separation

The setup backend should construct `foxproxsetup -- target...` explicitly and validate empty/NUL argv before launch. This avoids ambiguous command lines where the target could run without the network setup helper or where malformed env/argv reaches process spawning.
