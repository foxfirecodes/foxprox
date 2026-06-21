# Security Invariants Learnings

This is an append-only security learning ledger for `docs/implementation-approach-security-invariants.md`.

## 2026-06-21 - DNS and hidden-SNI bypass ordering

A DNS bypass check that only considers a dedicated DNS event class is insufficient: transparent TCP/UDP flows to external port 53 (and identifiable DoT port 853) must be denied before generic IP allow rules. Hidden-SNI/ECH checks must also run before generic domain allow matching; only explicit IP/CIDR allow rules can exempt hidden-SNI/ECH.

## 2026-06-21 - Packet parser fail-closed scope

The alpha packet parser should reject IPv4 fragments and IPv6 extension headers until the broker has explicit reassembly/extension semantics. Classifying UDP/53 as DNS and UDP/443 as QUIC candidate at the normalized metadata boundary helps policy apply DNS-bypass and QUIC-default invariants consistently.

## 2026-06-21 - DNS attribution confidence

DNS cache correlation must stay medium confidence and may produce multiple hostnames for one IP. A shared IP match should not be collapsed into high-confidence uniqueness; policy code must keep source/confidence explicit when deciding domain rules.
