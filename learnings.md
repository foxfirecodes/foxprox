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
