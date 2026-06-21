# Learning Ledger


## 2026-06-21 — keep first core slice dependency-free

The initial normalized event → policy → audit proof did not require serde or networking dependencies. Typed audit records plus unit tests were enough evidence for the first platform-independent boundary; external serialization can wait until an audit sink slice needs it.
