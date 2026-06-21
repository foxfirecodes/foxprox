# Learning Ledger


## 2026-06-21 — keep first core slice dependency-free

The initial normalized event → policy → audit proof did not require serde or networking dependencies. Typed audit records plus unit tests were enough evidence for the first platform-independent boundary; external serialization can wait until an audit sink slice needs it.

## 2026-06-21 — parser slice should own raw buffers briefly

Keeping raw IPv4 bytes inside a dedicated packet crate made the architecture boundary explicit: parser tests can use fixtures, but policy/audit only see `foxprox-core` normalized events. Fragmentation is rejected before normalization and converted to fail-closed evidence when needed.

## 2026-06-21 — packet write-back can be proven before TUN privileges

ICMP echo reply synthesis gives useful checksum and source/destination reversal evidence without needing `/dev/net/tun` or bwrap. The remaining risk is connecting this packet builder to real TUN IO and sandbox ping behavior.

## 2026-06-21 — broker orchestration can stay platform-independent

A single-packet broker handler can prove parser → policy/audit → write-back behavior without importing Linux or async IO. This gives the eventual TUN frontend a narrow contract: supply packet bytes and write returned outbound packets.

## 2026-06-21 — stable audit output can map from core records

The audit output crate can avoid coupling serialization derives into `foxprox-core` by mapping `AuditRecord` into a JSON-specific schema. This keeps the core boundary typed and allows audit output format to evolve independently.

## 2026-06-21 — config parsing should terminate in core types

The TOML config layer is safest when it validates strings at the edge and returns `PolicyConfig`; broker code does not need to know whether policy came from tests, TOML, or a future live reload source.

## 2026-06-21 — keep CLI audit stdout separate from packet bytes

The first process-boundary harness should emit JSON Lines audit on stdout and write synthesized packet bytes only to an explicit output target. Mixing binary write-back with audit stdout would make runtime evidence and downstream log collection ambiguous.

## 2026-06-21 — DNS observations need payload fixtures, not just UDP/53

Port-based DNS classification is enough for direct-bypass denial, but hostname attribution requires real DNS question fixtures. Minimal uncompressed QNAME parsing gives useful audit evidence now while leaving compression and response caching for a later DNS subsystem slice.

## 2026-06-21 — DNS attribution should not overwrite stronger metadata

DNS cache correlation is only medium-confidence. The enrichment layer should fill missing transparent flow attribution but preserve higher-confidence metadata from future HTTP Host, TLS SNI, QUIC metadata, or explicit proxy frontends.

## 2026-06-21 — HTTP policy needs audit fields, not just match logic

Adding method/path matching without carrying those fields into structured audit would make policy behavior hard to verify externally. Semantic inspection slices should update both rule evaluation and audit output together.

## 2026-06-21 — TLS metadata parsers must stay length-first

Even a minimal SNI-only ClientHello parser has multiple nested length fields. Keep it isolated in inspection code, fail on truncation, and emit only normalized metadata so policy never depends on TLS parser internals.

## 2026-06-21 — host-only proxy events still need port matching

Policy port rules cannot depend solely on IP endpoints. Explicit proxy events may know host and port before DNS resolution, so core matching should use an event-level destination port abstraction.

## 2026-06-21 — SOCKS5 CONNECT parsing should expose both host string and IP when available

Domain-form SOCKS requests feed hostname policy directly, while IP-form requests should preserve destination IP for audit/IP policy. Do not infer domain attribution from IP-form requests.

## 2026-06-21 — DNS response parsing needs compression loop protection

DNS answer names commonly use compression pointers, so response parsing is necessary for realistic cache population. Pointer following must be bounded and fail closed on loops before using any hostname attribution.
