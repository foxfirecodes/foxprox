# Learning Ledger


## 2026-06-21 — keep first core slice dependency-free

The initial normalized event → policy → audit proof did not require serde or networking dependencies. Typed audit records plus unit tests were enough evidence for the first platform-independent boundary; external serialization can wait until an audit sink slice needs it.

## 2026-06-21 — parser slice should own raw buffers briefly

Keeping raw IPv4 bytes inside a dedicated packet crate made the architecture boundary explicit: parser tests can use fixtures, but policy/audit only see `foxprox-core` normalized events. Fragmentation is rejected before normalization and converted to fail-closed evidence when needed.

## 2026-06-21 — packet write-back can be proven before TUN privileges

ICMP echo reply synthesis gives useful checksum and source/destination reversal evidence without needing `/dev/net/tun` or bwrap. The remaining risk is connecting this packet builder to real TUN IO and sandbox ping behavior.

## 2026-06-21 — broker orchestration can stay platform-independent

A single-packet broker handler can prove parser → policy/audit → write-back behavior without importing Linux or async IO. This gives the eventual TUN frontend a narrow contract: supply packet bytes and write returned outbound packets.
