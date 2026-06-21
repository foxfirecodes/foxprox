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
