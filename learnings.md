# Security Invariants Learnings

This is an append-only security learning ledger for `docs/implementation-approach-security-invariants.md`.

## 2026-06-21 - DNS and hidden-SNI bypass ordering

A DNS bypass check that only considers a dedicated DNS event class is insufficient: transparent TCP/UDP flows to external port 53 (and identifiable DoT port 853) must be denied before generic IP allow rules. Hidden-SNI/ECH checks must also run before generic domain allow matching; only explicit IP/CIDR allow rules can exempt hidden-SNI/ECH.
