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
