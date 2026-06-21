# Progress Ledger

## 2026-06-21T16:41:33Z
- Current objective: start verification-kernel session and implement the smallest verified alpha-scope slice from `docs/implementation-approach-verification-kernel.md`.
- Git status summary: clean worktree before ledger creation.
- Intended slice: establish append-only ledgers, inspect source docs, then build platform-independent core verification kernel before any Linux/TUN integration.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` after the first coherent change.
- Files expected to change: `progress.md`, `learnings.md`, core Rust sources.
- Remaining risks: full alpha includes Linux namespace/TUN/proxy integration that must be built outward only after core behavior is typed and tested.
- Exact next step: implement the smallest deterministic broker-core types for normalized events, decisions, audit records, and fail-closed policy evaluation.

## 2026-06-21T16:47:30Z
- Current objective: complete first coherent verification-kernel slice for platform-independent broker core behavior.
- Files changed: `crates/foxprox-core/src/lib.rs`, `types.rs`, `policy.rs`, `audit.rs`, `dns.rs`, `flow.rs`, `origin.rs`, `inspect.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed because new files needed rustfmt; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on test vector initialization; fixed)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 17 unit tests passed. The tests cover default deny, direct DNS bypass denial, malformed fail-closed precedence, domain attribution rules, CIDR matching, audit backpressure, DNS cache expiry, UDP/QUIC classification, HTTP request metadata extraction, CONNECT/HTTP origin parsing, and TLS ClientHello SNI extraction.
- Commit hash when committed: pending.
- Remaining risks: this slice intentionally does not yet create TUN devices, bridge TCP/UDP, run bwrap setup, expose proxy listeners, fuzz parsers, or provide a CLI/config loader.
- Exact next step: commit this verified core slice, then add executable configuration loading and proxy/frontend normalized request handling tests around the same policy engine.

## 2026-06-21T16:51:50Z
- Current objective: add deterministic packet-facing proof for the packet write-back milestone without introducing Linux/TUN dependencies.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/packet.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in new packet tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 20 unit tests passed. New tests prove IPv4 ICMP echo requests parse deterministically, synthetic echo replies reverse source/destination and preserve id/sequence/payload with valid checksums, malformed checksums are rejected, and fragmentation fails closed.
- Commit hash when committed: previous verified core slice committed as `7762592`; packet proof commit pending.
- Remaining risks: packet parsing currently covers only the minimal IPv4/ICMP proof path; TCP/UDP parsing, IPv6, fuzzing, and real TUN write-back are not implemented yet.
- Exact next step: commit packet proof, then add normalized proxy frontend parsers for HTTP CONNECT/SOCKS and config validation around the shared policy engine.

## 2026-06-21T16:55:20Z
- Current objective: add explicit proxy request parsing to feed the same normalized policy/audit kernel.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/frontend.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified rustfmt changes in the new frontend parser; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 25 unit tests passed. New tests prove SOCKS5 no-auth negotiation is explicit, unsupported SOCKS UDP ASSOCIATE is rejected, SOCKS domain destinations produce high-confidence explicit-proxy attribution, HTTP proxy CONNECT is origin-only, and HTTP absolute-form requests preserve plaintext paths for policy.
- Commit hash when committed: previous packet proof committed as `67e6bf2`; proxy parser commit pending.
- Remaining risks: this is parser/kernel behavior only; no listener sockets, proxy forwarding loops, host egress sockets, or malformed-request fuzzing yet.
- Exact next step: commit parser slice, then add config validation and deny-by-default examples that connect parsed proxy/TUN metadata to policy decisions.

## 2026-06-21T16:58:10Z
- Current objective: add explicit policy configuration validation so invalid defaults and ambiguous domain rules fail before runtime.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/config.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 29 unit tests passed. New tests prove duplicate rule IDs, global `RequireBrokerDns` defaults, and domain rules without explicit attribution confidence are rejected, while a valid domain rule with broker DNS passes.
- Commit hash when committed: previous proxy parser slice committed as `ed06d5f`; config validation commit pending.
- Remaining risks: no file-format parser exists yet; callers must construct `PolicyConfig` in memory until a serde-free or serde-backed loader is selected.
- Exact next step: commit config validation, then add end-to-end normalized decision scenarios that combine DNS/TLS/HTTP/SOCKS metadata with policy decisions and audit records.

## 2026-06-21T17:02:05Z
- Current objective: add normalized event conversion so transparent and explicit frontends share one policy/audit path.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/event.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new event module; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 32 unit tests passed. New scenario tests prove transparent HTTP Host/path metadata, TLS SNI/DNS mismatch, and SOCKS explicit-host metadata all evaluate through the same policy engine and fail closed before allow rules where required.
- Commit hash when committed: previous config validation slice committed as `02adb85`; normalized event commit pending.
- Remaining risks: normalized events are in-memory only; packet adapters, proxy listener loops, audit sinks beyond bounded memory, and host egress runtime are still pending.
- Exact next step: commit normalized event slice, then add egress/frontend abstraction types and a minimal CLI/config-facing crate boundary for future runtime wiring.

## 2026-06-21T17:04:35Z
- Current objective: enforce the verification-kernel invariant that every policy decision is appended to bounded audit history or fails closed.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/kernel.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new kernel module; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 34 unit tests passed. New tests prove decisions are recorded in audit events and audit backpressure turns an otherwise allowed decision into fail-closed `AuditBackpressure`.
- Commit hash when committed: previous normalized event slice committed as `99add43`; verification kernel commit pending.
- Remaining risks: only in-memory audit sink exists; durable append-only audit sinks, runtime forwarding, and process lifecycle events are not yet implemented.
- Exact next step: commit kernel slice, then scaffold the runtime crate boundaries for device/integration/egress code without leaking those types into core policy.

## 2026-06-21T17:07:10Z
- Current objective: scaffold runtime egress boundary so host sockets cannot be opened before verified policy/audit decisions.
- Files changed: `Cargo.toml`, `crates/foxprox-runtime/Cargo.toml`, `crates/foxprox-runtime/src/lib.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in the new runtime crate; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 34 core unit tests and 2 runtime unit tests passed. Runtime tests prove denied events do not call host egress and allowed TCP events call egress exactly once after the verification kernel decision/audit path.
- Commit hash when committed: previous audit kernel slice committed as `dc88fa8`; runtime boundary commit pending.
- Remaining risks: host egress trait is not yet backed by real TCP/UDP sockets; there is no smoltcp adapter, device frontend, bwrap setup helper, or network namespace integration.
- Exact next step: commit runtime boundary, then add device/setup backend abstractions and fail-early setup planning types for TUN/bwrap integration.

## 2026-06-21T17:10:05Z
- Current objective: add fail-early integration planning types for bwrap-compatible TUN setup without putting bwrap semantics into core policy.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-integrations/Cargo.toml`, `crates/foxprox-integrations/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially identified formatting in integration code; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 34 core tests, 3 integration tests, and 2 runtime tests passed. Integration tests prove the bwrap command plan includes `--unshare-net`, temporary `CAP_NET_ADMIN`, `/dev/net/tun`, and `foxproxsetup`, and rejects missing targets or invalid MTU before execution.
- Commit hash when committed: previous runtime boundary slice committed as `e94aa21`; integration planning commit pending.
- Remaining risks: the integration crate only plans command/setup shape; it does not execute bwrap, create/configure TUN, pass file descriptors, drop capabilities, or validate kernel features.
- Exact next step: commit integration planning, then add an audit file sink or CLI-facing smoke entry point to make verification outputs durable outside tests.

## 2026-06-21T17:13:00Z
- Current objective: add durable line-oriented audit sink support while preserving fail-closed behavior on write failure.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/audit.rs`, `crates/foxprox-core/src/kernel.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 35 core tests, 3 integration tests, and 2 runtime tests passed. New test proves line audit sink writes appendable structured records with timestamp, event kind, decision, and rule ID; kernel maps write failure to fail-closed audit backpressure.
- Commit hash when committed: previous integration planning slice committed as `3e817e5`; line audit commit pending.
- Remaining risks: audit line format is intentionally simple and not yet a stable JSON schema; no rotating file writer or async backpressure strategy is implemented.
- Exact next step: commit audit sink slice, then run final workspace verification and summarize remaining alpha gaps.

## 2026-06-21T17:14:20Z
- Current objective: final workspace verification after verified alpha-kernel slices.
- Files changed: `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `git status --short`
- Observed result: all verification passed; 35 core tests, 3 integration tests, and 2 runtime tests passed. `git status --short` was clean before this final progress entry.
- Commit hash when committed: previous audit sink slice committed as `7ebe3f0`; final ledger commit pending.
- Remaining risks: alpha is not complete end-to-end. Missing pieces include real TUN creation/configuration, fd handoff, `foxproxsetup`, smoltcp TCP bridging, real UDP/DNS egress, HTTP/SOCKS listener loops, bwrap execution, namespace integration tests, fuzz targets, and runtime network smoke tests.
- Exact next step: implement the first real OS-facing integration slice: `foxproxsetup`/device crate that can create/configure a TUN in a controlled namespace, then verify with a sandbox-visible packet log or ICMP ping proof.

## 2026-06-21T22:36:06Z
- Current objective: continue autonomous verification-kernel work toward the next alpha gap after final kernel verification.
- Git status summary: clean worktree at session start.
- Intended slice: implement the first OS-facing device/setup boundary for Linux TUN creation/configuration while keeping policy core free of Linux and bwrap semantics.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; privileged TUN smoke will be recorded as unavailable unless `/dev/net/tun` and required capabilities are present.
- Files expected to change: `Cargo.toml`, `Cargo.lock`, a new device/setup crate, and ledgers.
- Remaining risks: actual namespace/TUN smoke may require unavailable kernel capabilities in this worktree environment, so unit tests must prove fail-early planning and command behavior first.
- Exact next step: add a `foxprox-device` crate with validated TUN setup execution boundaries and deterministic tests for fail-early setup behavior.

## 2026-06-21T22:44:40Z
- Current objective: add first OS-facing TUN device setup boundary while preserving verified core isolation.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-device/Cargo.toml`, `crates/foxprox-device/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in the new device crate; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed because a test compared `Result<TunDevice, _>` without `TunDevice: PartialEq`; fixed by asserting the error)
  - `cargo test --all-targets --all-features`
  - `/dev/net/tun`/capability probe: `/dev/net/tun` exists, but the current user lacks `CAP_NET_ADMIN`, so privileged TUN creation smoke was not attempted.
- Observed result: final verification passed; 35 core tests, 5 device tests, 3 integration tests, and 2 runtime tests passed. The device crate validates Linux TUN names, wraps `TUNSETIFF` in a small documented unsafe boundary, and deterministically tests point-to-point `ip` setup command ordering and fail-early behavior.
- Commit hash when committed: pending.
- Remaining risks: no `foxproxsetup` executable, fd handoff, namespace execution, DNS file configuration, or real ping/TUN smoke exists yet; TUN creation requires capabilities unavailable in this session.
- Exact next step: commit the device setup boundary, then add a `foxproxsetup` CLI/helper crate that parses the bwrap-planned arguments, creates/configures the TUN through `foxprox-device`, and fails before target exec on setup errors.

## 2026-06-21T23:01:35Z
- Current objective: add a bwrap-compatible `foxproxsetup` helper path that fails before target exec unless setup completes.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-integrations/src/lib.rs`, `crates/foxprox-setup/Cargo.toml`, `crates/foxprox-setup/src/lib.rs`, `crates/foxprox-setup/src/main.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in the new setup crate; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on an unused import; fixed)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 35 core tests, 5 device tests, 3 integration tests, 2 runtime tests, and 4 setup tests passed. The bwrap command plan now passes `--handoff-fd`; `foxproxsetup` parses planned arguments, validates a `SetupPlan`, sequences TUN create/configure/fd handoff before target exec, and tests that handoff failure prevents exec.
- Commit hash when committed: pending.
- Remaining risks: fd handoff uses a small Linux/Unix `sendmsg(SCM_RIGHTS)` boundary but does not yet have a receiver-side round-trip test; setup does not yet drop `CAP_NET_ADMIN`, write resolver config, or perform an end-to-end bwrap smoke.
- Exact next step: commit the setup helper slice, then add deterministic fd-handoff verification and/or setup privilege-drop behavior before attempting namespace smoke tests.

## 2026-06-21T23:07:20Z
- Current objective: verify the Unix fd-handoff boundary used by `foxproxsetup` before relying on it for TUN transfer.
- Files changed: `crates/foxprox-setup/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 35 core tests, 5 device tests, 3 integration tests, 2 runtime tests, and 5 setup tests passed. New setup test proves `sendmsg(SCM_RIGHTS)` fd handoff round-trips over a Unix socket by sending one UnixStream fd and writing through the received descriptor.
- Commit hash when committed: pending.
- Remaining risks: fd handoff is verified in-process but not yet through an inherited bwrap control socket; `foxproxsetup` still does not drop setup capabilities or write DNS resolver configuration.
- Exact next step: commit fd-handoff verification, then add fail-closed capability-drop/resolver setup sequencing in `foxproxsetup` before target exec.

## 2026-06-21T23:17:15Z
- Current objective: add fail-closed DNS resolver setup and CAP_NET_ADMIN drop sequencing before `foxproxsetup` target exec.
- Files changed: `crates/foxprox-setup/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 35 core tests, 5 device tests, 3 integration tests, 2 runtime tests, and 7 setup tests passed. New tests prove resolver config contents are deterministic and setup sequencing is TUN create/configure, DNS config, fd handoff, capability drop, then exec; pure capability-bit tests prove CAP_NET_ADMIN is removed from effective/permitted/inheritable sets before the Linux `capset` call.
- Commit hash when committed: pending.
- Remaining risks: capability drop is compiled and bit-tested but not exercised with real elevated capabilities in this worktree; bwrap invocation and inherited control socket are still not smoke-tested end-to-end.
- Exact next step: commit setup hardening, then implement host-side setup control socket receiving the TUN fd so the broker side can pair with `foxproxsetup` handoff.

## 2026-06-21T23:25:10Z
- Current objective: add host-side setup control socket support so the broker side can receive the TUN fd handed off by `foxproxsetup`.
- Files changed: `crates/foxprox-device/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 35 core tests, 6 device tests, 3 integration tests, 2 runtime tests, and 7 setup tests passed. New device test proves a setup control socket pair can receive an fd via `SCM_RIGHTS` and use the received descriptor to write bytes through the original peer.
- Commit hash when committed: pending.
- Remaining risks: host-side bwrap launch does not yet keep/pass the helper fd through process creation, and the received fd is not yet connected to a packet log or ICMP echo loop.
- Exact next step: commit setup control socket support, then add a minimal broker-side TUN packet loop that reads handed-off IP packets and writes synthetic ICMP echo replies through the existing packet kernel.
