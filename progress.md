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

## 2026-06-21T23:32:50Z
- Current objective: add a minimal broker-side TUN packet proof loop using the existing packet kernel.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting for the new runtime outcome enum; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 35 core tests, 6 device tests, 3 integration tests, 5 runtime tests, and 7 setup tests passed. New runtime tests prove one TUN packet read can synthesize/write an ICMP echo reply with valid checksums, while unsupported IPv4 protocols and malformed packets are dropped without write-back.
- Commit hash when committed: pending.
- Remaining risks: the proof loop operates on generic `Read`/`Write` and is not yet wired to a received real TUN fd; TCP/UDP/smoltcp forwarding still absent.
- Exact next step: commit the ICMP proof loop, then add a host launcher/control abstraction that pairs bwrap command construction, setup control socket creation, and received TUN fd handoff into one fail-early setup flow.

## 2026-06-21T23:38:35Z
- Current objective: pair host-side bwrap launch preparation with setup control socket creation and live handoff fd injection.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in launcher tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 35 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 5 runtime tests, and 7 setup tests passed. New launcher tests prove bwrap command preparation injects the live helper fd from a setup control socket, preserves required network isolation arguments, and rejects invalid plans before command construction.
- Commit hash when committed: pending.
- Remaining risks: the launcher still does not spawn bwrap with fd-preservation semantics, and the received TUN file is not yet connected to the ICMP proof loop.
- Exact next step: commit launcher preparation, then add a broker session type that accepts a received TUN file and runs the ICMP proof loop for one packet with deterministic IO tests.

## 2026-06-21T23:44:05Z
- Current objective: wrap the ICMP packet proof in a broker-side session type that can own received TUN-like IO.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 35 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 6 runtime tests, and 7 setup tests passed. New runtime test proves `TunIcmpProofSession` can own a TUN-like read/write object, process one packet, and write a valid synthetic ICMP reply.
- Commit hash when committed: pending.
- Remaining risks: session is still tested against fake IO, not a real received TUN fd; forwarding beyond ICMP proof is still absent.
- Exact next step: commit the session wrapper, then add minimal IPv4 UDP parsing/classification in the packet/runtime path to start Milestone 4 without bypassing policy.

## 2026-06-21T23:53:25Z
- Current objective: start UDP foundation by adding verified IPv4 UDP packet parsing/classification without enabling forwarding bypass.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/packet.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 38 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 7 runtime tests, and 7 setup tests passed. New tests prove IPv4 UDP packets expose source/destination ports and payload, invalid UDP lengths fail closed, nonzero invalid UDP checksums fail closed, and runtime observes UDP packets without writing a response or forwarding until policy/forwarder wiring exists.
- Commit hash when committed: pending.
- Remaining risks: UDP forwarding, DNS resolver behavior, pseudo-flow tracking integration, and direct-DNS denial at packet runtime are still absent.
- Exact next step: commit UDP parsing/classification, then wire UDP observations into normalized policy events so DNS/direct-DNS decisions can be audited before any UDP egress is introduced.

## 2026-06-22T00:01:05Z
- Current objective: wire UDP packet observations into normalized policy events before any UDP egress exists.
- Files changed: `crates/foxprox-core/src/event.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 38 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 9 runtime tests, and 7 setup tests passed. New runtime tests prove UDP/53 packets become DNS policy events that trigger `RequireBrokerDns` for non-broker resolvers, and UDP/443 packets become QUIC-candidate UDP flow events.
- Commit hash when committed: pending.
- Remaining risks: DNS payload parsing, DNS cache population, UDP pseudo-flow state, and actual UDP egress are still not implemented.
- Exact next step: commit UDP policy event wiring, then add minimal DNS query parsing/caching for broker-directed DNS packets.

## 2026-06-21T22:53:56Z
- Current objective: continue autonomous verification-kernel cycles from the UDP policy event wiring checkpoint.
- Git status summary: clean worktree at session start.
- Intended slice: add minimal broker-directed DNS packet parsing/caching so DNS observations can feed hostname attribution before UDP egress is introduced.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; record any parser misconceptions in `learnings.md`.
- Files expected to change: `crates/foxprox-core/src/dns.rs`, runtime/core exports as needed, and ledgers.
- Remaining risks: DNS parsing must stay minimal and fail closed; no UDP forwarding should be added until DNS policy/audit behavior is verified.
- Exact next step: implement deterministic DNS query parsing for one-question UDP DNS packets and cache broker-observed A/AAAA answers only when structurally valid.

## 2026-06-21T23:02:50Z
- Current objective: add minimal broker-directed DNS parsing and cache population for hostname attribution.
- Files changed: `crates/foxprox-core/src/dns.rs`, `crates/foxprox-core/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in the expanded DNS parser; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 43 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 9 runtime tests, and 7 setup tests passed. New DNS tests prove one-question query parsing, query/response distinction, A/AAAA response observation with minimum TTL, cache record/lookup for DNS attribution, and fail-closed truncation handling.
- Commit hash when committed: pending.
- Remaining risks: DNS parser is intentionally minimal; it does not yet parse DNS response codes, CNAME chains, multiple-question queries, EDNS, TCP DNS, or synthesize/forward DNS responses.
- Exact next step: commit DNS parser/cache slice, then wire broker-directed UDP/53 packets to parse DNS questions into `DnsQuery` policy/audit events before resolver forwarding exists.

## 2026-06-21T23:10:15Z
- Current objective: wire broker-directed UDP/53 packets to parsed DNS query policy/audit events.
- Files changed: `crates/foxprox-core/src/event.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on one long runtime assertion line; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 43 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 11 runtime tests, and 7 setup tests passed. New tests prove broker DNS UDP packets parse into `DnsQuery` events with hostname metadata, while malformed broker DNS payloads become malformed network events and fail closed with `MalformedInput`.
- Commit hash when committed: pending.
- Remaining risks: DNS responses are parsed/cached only through explicit cache APIs, not yet connected to UDP response handling; resolver forwarding is still absent.
- Exact next step: commit DNS query event wiring, then add UDP flow table integration for DNS/QUIC/generic packet attempts before adding egress.

## 2026-06-21T23:17:35Z
- Current objective: integrate UDP packet observations with flow tracking before adding any host UDP egress.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 43 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 13 runtime tests, and 7 setup tests passed. New runtime tests prove UDP packet flow recording classifies broker DNS, counts sandbox datagram bytes across repeated packets, and assigns QUIC candidate flows the longer timeout class.
- Commit hash when committed: pending.
- Remaining risks: flow recording is not yet invoked by a continuous TUN loop; UDP host egress and DNS response routing remain absent.
- Exact next step: commit UDP flow tracking integration, then add a minimal broker DNS resolver abstraction that handles parsed DNS query events without opening arbitrary UDP egress.

## 2026-06-21T23:24:45Z
- Current objective: add minimal DNS response synthesis for broker-controlled resolver behavior without arbitrary UDP egress.
- Files changed: `crates/foxprox-core/src/dns.rs`, `crates/foxprox-core/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting for new DNS synthesis tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 45 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 13 runtime tests, and 7 setup tests passed. New DNS tests prove query-type-filtered response synthesis for A records, empty successful responses when no address matches the requested type, and parseability/cacheability of synthesized responses.
- Commit hash when committed: pending.
- Remaining risks: resolver backing data is not yet configured, denied DNS answers are not represented, and synthesized DNS packets are not yet written back through TUN/UDP packet synthesis.
- Exact next step: commit DNS response synthesis, then add a static broker DNS resolver component that maps parsed DNS queries to synthesized allowed/empty responses and cache observations.

## 2026-06-21T23:31:20Z
- Current objective: add a static broker DNS resolver component that maps parsed queries to synthesized responses without arbitrary UDP egress.
- Files changed: `crates/foxprox-core/src/dns.rs`, `crates/foxprox-core/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in new resolver tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 47 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 13 runtime tests, and 7 setup tests passed. New tests prove a static broker DNS resolver preserves query IDs, returns type-filtered synthesized answers with observations, and returns empty no-observation responses for unknown hosts.
- Commit hash when committed: pending.
- Remaining risks: static resolver records are in-memory only; DNS response packets are not yet wrapped in UDP/IPv4 and written back through the TUN session.
- Exact next step: commit static DNS resolver, then add IPv4 UDP response synthesis so broker DNS answers can be written back through TUN with valid IP/UDP checksums.

## 2026-06-21T23:37:40Z
- Current objective: add IPv4 UDP response synthesis so broker DNS answers can eventually be written back through TUN.
- Files changed: `crates/foxprox-core/src/packet.rs`, `crates/foxprox-core/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 48 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 13 runtime tests, and 7 setup tests passed. New packet test proves synthesized UDP responses reverse IPv4 addresses and UDP ports, preserve payload, and include a nonzero UDP checksum that the packet parser validates.
- Commit hash when committed: pending.
- Remaining risks: DNS response synthesis and UDP packet synthesis are not yet joined in runtime; no continuous TUN write-back for DNS exists.
- Exact next step: commit UDP response synthesis, then wire broker DNS query handling to synthesize a DNS UDP response packet in runtime without host egress.

## 2026-06-21T23:43:50Z
- Current objective: join static DNS resolution with UDP packet synthesis in runtime without opening host UDP egress.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 48 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 15 runtime tests, and 7 setup tests passed. New runtime tests prove broker DNS UDP handling synthesizes a reversed UDP response packet, caches successful observations for later attribution, and rejects malformed DNS queries without cache mutation.
- Commit hash when committed: pending.
- Remaining risks: broker DNS handling is not yet integrated into the `TunIcmpProofSession` loop, and DNS records are still static in-memory configuration only.
- Exact next step: commit broker DNS UDP response handling, then extend the TUN proof session to handle broker DNS UDP packets in addition to ICMP echo replies.

## 2026-06-21T23:50:15Z
- Current objective: extend TUN packet handling to answer broker DNS UDP packets in addition to ICMP echo proof packets.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 48 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 17 runtime tests, and 7 setup tests passed. New runtime tests prove a TUN-read broker DNS query is answered with a valid UDP response packet and DNS cache attribution, while malformed broker DNS queries are dropped without write-back or cache mutation.
- Commit hash when committed: pending.
- Remaining risks: the TUN session still does not perform policy/audit before DNS write-back, and DNS records remain static; no host upstream resolver exists.
- Exact next step: commit DNS TUN write-back, then gate broker DNS write-back through the verification kernel so malformed/denied DNS events are audited before any response is emitted.

## 2026-06-21T23:59:30Z
- Current objective: gate broker DNS TUN write-back through the verification kernel so policy/audit decisions happen before responses are emitted.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on too many function arguments; fixed by introducing `BrokerDnsRuntime` context)
  - `cargo test --all-targets --all-features` (initially failed because the deny-by-default test omitted broker DNS config and hit `RequireBrokerDns`; fixed the test config to model broker DNS plus default deny)
- Observed result: final verification passed; 48 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 19 runtime tests, and 7 setup tests passed. New tests prove broker DNS TUN packets are audited/denied before write-back by default and only synthesize/cache responses after an explicit DNS allow rule passes.
- Commit hash when committed: pending.
- Remaining risks: the policy-gated DNS handler uses a placeholder sandbox ID and is not yet part of a full session context; static DNS records still lack config loading.
- Exact next step: commit policy-gated DNS write-back, then add a session context carrying sandbox ID/broker DNS/resolver/cache so packet handlers do not use placeholder identity.

## 2026-06-22T00:06:35Z
- Current objective: remove placeholder identity from policy-gated DNS packet handling by carrying session context into runtime DNS handling.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 48 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 19 runtime tests, and 7 setup tests passed. `BrokerDnsRuntime` now carries sandbox ID, resolver, cache, broker DNS addresses, and verification kernel; tests assert audit records use the configured sandbox IDs for allowed and denied DNS packets.
- Commit hash when committed: pending.
- Remaining risks: session context currently covers DNS runtime only; broader TUN packet sessions still need policy/audit identity for ICMP, unsupported packets, and future TCP/UDP forwarding.
- Exact next step: commit DNS session identity, then add policy/audit gating for ICMP echo handling so ping behavior follows `allow_ping`/rules instead of unconditional write-back.

## 2026-06-22T00:13:40Z
- Current objective: gate ICMP echo write-back through policy/audit instead of unconditional ping replies.
- Files changed: `crates/foxprox-core/src/policy.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 21 runtime tests, and 7 setup tests passed. New tests prove ping is denied/audited by default, `allow_ping` permits ICMP echo replies, and audit records carry the configured sandbox identity.
- Commit hash when committed: pending.
- Remaining risks: ICMP handling is still echo-only; essential ICMP errors, unusual ICMP denial classification, and a unified policy-gated TUN session remain to be implemented.
- Exact next step: commit ICMP policy gating, then add unified packet handling that routes ICMP, broker DNS, unsupported packets, and malformed packets through one session context.

## 2026-06-22T00:20:30Z
- Current objective: add one unified policy-gated TUN packet handler for ICMP, UDP/DNS, malformed packets, and unsupported protocols.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 23 runtime tests, and 7 setup tests passed. New runtime tests prove unsupported IPv4 protocols and malformed packets are converted to normalized policy/audit events and fail closed without write-back, alongside the existing DNS and ICMP gated paths.
- Commit hash when committed: pending.
- Remaining risks: unified handler does not yet own a real TUN fd session loop or TCP/smoltcp forwarding; UDP non-DNS allow still only observes flow metadata and does not egress.
- Exact next step: commit unified TUN policy handler, then introduce an explicit host UDP egress trait/path gated by policy for allowed non-DNS UDP datagrams.

## 2026-06-22T00:27:20Z
- Current objective: add explicit policy-gated host UDP egress path without sending empty datagrams from generic event handling.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 26 runtime tests, and 7 setup tests passed. New runtime tests prove denied UDP datagrams never reach host egress, allowed UDP datagrams carry their original payload to host egress, and generic event handling no longer sends empty UDP payloads accidentally.
- Commit hash when committed: pending.
- Remaining risks: UDP egress is still trait-backed only; no real host UDP socket implementation or response routing to TUN exists.
- Exact next step: commit UDP egress gating, then implement a minimal real host UDP socket backend or response-routing abstraction for allowed UDP datagrams.

## 2026-06-22T00:02:29Z
- Current objective: continue autonomous verification-kernel cycles from the policy-gated UDP egress checkpoint.
- Git status summary: clean worktree at session start.
- Intended slice: implement the minimal real host UDP socket backend or response-routing boundary for allowed non-DNS UDP datagrams without bypassing the verification kernel.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; keep tests deterministic with loopback sockets only.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` only if the socket boundary reveals a new assumption.
- Remaining risks: UDP response routing back to TUN and long-lived socket lifecycle management are still outside this smallest slice.
- Exact next step: add a standard-library host UDP egress implementation and verify an allowed datagram reaches a loopback UDP listener only after policy/audit approval.

## 2026-06-22T00:05:20Z
- Current objective: add a minimal real host UDP socket backend behind the verified egress boundary.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on one long test line; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 27 runtime tests, and 7 setup tests passed. New runtime test proves `StdHostEgress` sends an allowed UDP payload to a loopback UDP listener only after policy/audit approval.
- Commit hash when committed: pending.
- Remaining risks: `StdHostEgress` opens a one-shot UDP socket per datagram and does not yet route host UDP responses back into TUN packets; TCP forwarding remains connect-only.
- Exact next step: commit the standard UDP egress backend, then add a UDP response routing abstraction that can synthesize TUN UDP response packets from host replies.

## 2026-06-22T00:07:10Z
- Current objective: continue from the real UDP host egress checkpoint with the smallest response-routing proof.
- Git status summary: clean worktree after commit `4f66dfe`.
- Intended slice: add a deterministic UDP host-reply-to-TUN packet synthesis boundary keyed by the recorded UDP flow, without adding a long-running socket loop yet.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if route constraints reveal a new invariant.
- Remaining risks: this will still be a synchronous synthesis proof, not a continuous UDP socket receive loop.
- Exact next step: implement flow-keyed UDP response synthesis that rejects non-UDP and unsupported address-family routes fail-closed.

## 2026-06-22T00:10:05Z
- Current objective: add a deterministic UDP host-reply-to-TUN response synthesis boundary.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on `let else` formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 29 runtime tests, and 7 setup tests passed. New tests prove a recorded IPv4 UDP flow can synthesize a valid reverse-direction TUN packet for host replies, and non-UDP or non-IPv4 routes are rejected instead of producing ambiguous packets.
- Commit hash when committed: pending.
- Remaining risks: response synthesis is not yet driven by a continuous host UDP receive loop or written through a live TUN session; IPv6 UDP synthesis remains unsupported and explicit fail-closed.
- Exact next step: commit UDP response routing synthesis, then add a TUN session wrapper that records allowed UDP flows, sends allowed datagrams through host egress, and can write synthesized host replies back through its TUN writer.

## 2026-06-22T00:12:10Z
- Current objective: continue from UDP response synthesis toward a minimal UDP TUN session boundary.
- Git status summary: clean worktree after commit `048175d`.
- Intended slice: add a TUN-like UDP session wrapper that records allowed UDP flows, sends allowed datagrams through host egress, and can write synthesized host replies back through its TUN writer.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with fake TUN IO and fake egress.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this will still use fake IO; a real asynchronous UDP receive loop and live TUN fd wiring remain later work.
- Exact next step: implement the session wrapper and deterministic tests for allow/deny/send/reply behavior.

## 2026-06-22T00:17:00Z
- Current objective: add a minimal policy-gated UDP TUN egress session wrapper.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on one formatted call; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 49 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 32 runtime tests, and 7 setup tests passed. New tests prove the UDP TUN session denies before host egress by default, records allowed UDP flows, sends allowed payloads to host egress, and writes synthesized host replies back to a TUN-like device.
- Commit hash when committed: pending.
- Remaining risks: the session is fake-IO and one-packet-at-a-time; it does not yet poll a real host UDP socket for replies, integrate with DNS/ICMP in one session type, or run against a live TUN fd.
- Exact next step: commit the UDP TUN egress session, then add TCP packet parsing/normalized connect attempt handling as the next step toward the smoltcp TCP forwarding gate.

## 2026-06-22T00:20:00Z
- Current objective: continue toward the smoltcp TCP gate by adding the smallest TCP packet parsing and normalized connect-attempt event slice.
- Git status summary: clean worktree after commit `9a3c818`.
- Intended slice: parse validated IPv4 TCP headers well enough to recognize sandbox SYN connect attempts and convert them into shared `TcpConnectAttempt` policy events, without implementing TCP forwarding or state transitions.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; record any existing tests that assumed TCP was unsupported and update them to an actually unsupported protocol.
- Files expected to change: `crates/foxprox-core/src/packet.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if TCP checksum/header constraints change the approach.
- Remaining risks: parsing SYN packets is not TCP stream forwarding; smoltcp or a stack adapter is still required for Milestone 2.
- Exact next step: implement checksum-checked TCP header parsing and a runtime event conversion for SYN connect attempts.

## 2026-06-22T00:27:10Z
- Current objective: add checksum-checked IPv4 TCP SYN parsing and normalized connect-attempt event handling.
- Files changed: `crates/foxprox-core/src/lib.rs`, `crates/foxprox-core/src/packet.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed due rustfmt changes after new enum variants/tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because an old unsupported-protocol test still expected protocol 6 after TCP became parsed; fixed to use protocol 99)
- Observed result: final verification passed; 52 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 35 runtime tests, and 7 setup tests passed. New tests prove TCP SYN packets parse with mandatory checksum validation, invalid TCP header lengths fail closed, SYN packets become `TcpConnectAttempt` events, non-SYN TCP is unsupported/fail-closed for now, and unified TUN policy handling audits TCP connect attempts.
- Commit hash when committed: pending.
- Remaining risks: this does not implement TCP stream state, SYN/ACK synthesis, smoltcp integration, host TCP bridging, or close/error lifecycle logging.
- Exact next step: commit TCP connect-attempt parsing, then add a TCP stack adapter trait boundary for future smoltcp integration so TCP forwarding cannot bypass policy/audit.

## 2026-06-22T00:30:00Z
- Current objective: continue from TCP connect-attempt parsing by adding a replaceable TCP stack adapter boundary.
- Git status summary: clean worktree after commit `afeff3e`.
- Intended slice: define a minimal stack-adapter contract for userspace TCP connect attempts and prove policy/audit gates host TCP egress before a future smoltcp adapter can open sockets.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this adapter boundary will not yet bridge stream bytes or synthesize TCP stack packets.
- Exact next step: implement fake-stack tests for denied reset and allowed host connect sequencing.

## 2026-06-22T00:35:35Z
- Current objective: add a replaceable TCP stack adapter boundary gated by policy/audit.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 52 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 37 runtime tests, and 7 setup tests passed. New tests prove a fake userspace TCP stack connect attempt is reset before host egress when policy denies, and allowed connects open host egress only after policy/audit approval and then notify the stack.
- Commit hash when committed: pending.
- Remaining risks: no smoltcp implementation, byte bridging, backpressure, TCP close/reset packet synthesis, or real stream lifecycle audit exists yet.
- Exact next step: commit TCP stack adapter boundary, then add minimal plaintext HTTP inspection wiring from TCP payload metadata into policy events before stream forwarding is implemented.

## 2026-06-22T00:38:00Z
- Current objective: continue from TCP adapter boundary with the first transparent plaintext HTTP metadata wiring.
- Git status summary: clean worktree after commit `fe8dd58`.
- Intended slice: convert validated TCP payload bytes on HTTP-like traffic into normalized `HttpRequest` policy events using the existing parser, without adding TCP stream reassembly.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and possibly `learnings.md` if one-packet HTTP parsing reveals a constraint.
- Remaining risks: this slice only handles a complete request in one segment; stream buffering/reassembly remains future TCP adapter work.
- Exact next step: add a runtime conversion function and tests for parsed HTTP metadata and incomplete request fail-closed/no-event behavior.

## 2026-06-22T00:42:45Z
- Current objective: wire complete TCP plaintext HTTP payloads into normalized HTTP policy events.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed due import/call formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 52 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 39 runtime tests, and 7 setup tests passed. New tests prove a complete HTTP request in a validated TCP segment becomes a normalized `HttpRequest` with host/method/path metadata, while incomplete HTTP data returns `NeedMoreData` instead of guessing.
- Commit hash when committed: pending.
- Remaining risks: no TCP stream reassembly exists, so split HTTP requests cannot be classified yet; this helper must remain metadata-only until the stack adapter can buffer stream bytes safely.
- Exact next step: commit TCP HTTP metadata wiring, then add TLS ClientHello SNI wiring from TCP payloads into TCP connect policy metadata.

## 2026-06-22T00:45:00Z
- Current objective: continue transparent TCP metadata wiring with TLS ClientHello SNI attribution.
- Git status summary: clean worktree after commit `9fc408f`.
- Intended slice: convert visible TLS ClientHello SNI in validated TCP payloads into a normalized TCP connect policy event with high-confidence TLS attribution, without decrypting TLS or guessing when SNI is absent.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: ECH/hidden-SNI detection remains parser/policy metadata only; no TLS stream buffering exists yet.
- Exact next step: add TLS SNI conversion helper and deterministic tests for visible SNI and missing-SNI behavior.

## 2026-06-22T00:49:25Z
- Current objective: wire visible TLS ClientHello SNI from TCP payloads into normalized TCP connect policy metadata.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed due import formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 52 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 41 runtime tests, and 7 setup tests passed. New tests prove a visible TLS ClientHello SNI becomes a high-confidence `TlsSni` hostname attribution on a `TcpConnectAttempt`, while a TLS ClientHello without SNI returns `MissingSni` instead of inventing hostname metadata.
- Commit hash when committed: pending.
- Remaining risks: ECH/hidden-SNI policy is represented but not specifically detected beyond missing visible SNI; stream buffering/reassembly is still absent.
- Exact next step: commit TLS SNI wiring, then add explicit policy tests for SNI/DNS mismatch and hidden-SNI denial using the TCP metadata conversion path.

## 2026-06-22T01:02:57Z
- Current objective: continue autonomous verification-kernel work from the TLS SNI wiring checkpoint toward transparent policy and attribution alpha gaps.
- Git status summary: clean worktree at session start.
- Intended slice: add explicit policy/runtime verification for SNI/DNS mismatch and hidden-SNI/ECH denial using the TCP metadata conversion path before any TCP forwarding can rely on hostname attribution.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` after the smallest coherent change.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-core/src/policy.rs` if additional policy coverage is needed, and ledgers.
- Remaining risks: this will still be metadata/policy verification only; stream buffering, smoltcp byte bridging, and real TCP forwarding remain pending.
- Exact next step: add deterministic tests/helpers proving TLS SNI metadata with DNS mismatch fails closed before allow rules, and missing/hidden SNI is denied when hostname attribution is required.

## 2026-06-22T01:11:45Z
- Current objective: verify transparent TLS attribution denial behavior before forwarding can rely on SNI/DNS metadata.
- Files changed: `crates/foxprox-core/src/policy.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt line wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 43 runtime tests, and 7 setup tests passed. New tests prove TLS SNI/DNS mismatch produced by the TCP metadata conversion path fails closed before broad allow rules, missing SNI on direct HTTPS requires hostname attribution unless an explicit destination rule allows it, and hidden/ECH-like SNI metadata is not allowed by broad rules.
- Commit hash when committed: pending.
- Remaining risks: SNI metadata is still per-segment without stream buffering/reassembly; ECH detection is represented by explicit metadata status rather than a real parser signal; smoltcp byte bridging remains absent.
- Exact next step: commit TLS attribution policy hardening, then add QUIC metadata policy coverage beyond UDP/443 classification, including disabled-QUIC denial and DNS-attributed QUIC allow behavior.

## 2026-06-22T01:14:10Z
- Current objective: continue after TLS attribution policy hardening commit toward QUIC transparent policy coverage.
- Git status summary: clean worktree after commit `97479ce`.
- Intended slice: add deterministic QUIC policy/event coverage for disabled QUIC denial and DNS-attributed UDP/443 allow behavior before adding any QUIC forwarding metadata parser.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-core/src/policy.rs` if policy gaps appear, and ledgers.
- Remaining risks: QUIC metadata remains candidate classification only; this slice should not introduce decrypted HTTP/3 semantics or host forwarding changes.
- Exact next step: prove UDP/443 candidate events are denied when QUIC is disabled and can be allowed by DNS-attributed domain policy when QUIC is enabled.

## 2026-06-22T01:18:35Z
- Current objective: add deterministic QUIC candidate policy coverage before richer UDP/QUIC metadata parsing.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 54 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 45 runtime tests, and 7 setup tests passed. New runtime tests prove UDP/443 QUIC-candidate events are denied when QUIC is disabled and DNS-attributed QUIC candidates can share the domain policy engine when QUIC is enabled.
- Commit hash when committed: pending.
- Remaining risks: QUIC classification is still UDP/443 candidate-only; no visible QUIC/TLS metadata parser, host reply receive loop, or HTTP/3 semantic inspection exists.
- Exact next step: commit QUIC policy coverage, then add a minimal explicit HTTP proxy frontend runtime path that gates parsed HTTP/CONNECT requests through the shared policy and host egress boundary.

## 2026-06-22T01:19:20Z
- Current objective: continue after QUIC policy coverage toward explicit proxy networking alpha gaps.
- Git status summary: clean worktree after commit `45f2a62`.
- Intended slice: add a minimal explicit HTTP proxy runtime path that converts already-parsed HTTP absolute-form and HTTPS CONNECT request lines into normalized policy events and opens host TCP egress only after verification-kernel approval.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with deterministic fake egress.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` only if proxy parser/runtime boundaries reveal a new invariant.
- Remaining risks: this slice should not add socket listener loops, HTTP body forwarding, CONNECT byte bridging, or proxy authentication.
- Exact next step: implement policy-gated HTTP proxy request-line handling for plaintext HTTP and CONNECT using the shared host egress trait.

## 2026-06-22T01:28:05Z
- Current objective: add minimal explicit HTTP proxy runtime gating through the shared policy/audit and host egress boundary.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 48 runtime tests, and 7 setup tests passed. New runtime tests prove parsed explicit HTTP proxy request lines are denied before host egress by default, plaintext HTTP origin/path rules can open host TCP egress, and HTTPS CONNECT origin rules can open host TCP egress through the same verification kernel.
- Commit hash when committed: pending.
- Remaining risks: the runtime accepts a caller-resolved IP for now; it does not yet run a listener, resolve proxy hostnames, forward request bytes, bridge CONNECT streams, or support SOCKS runtime handling.
- Exact next step: commit the HTTP proxy runtime slice, then add SOCKS5 CONNECT runtime gating through the shared policy and host egress boundary.

## 2026-06-22T01:29:10Z
- Current objective: continue after HTTP proxy runtime gating toward SOCKS5 explicit proxy alpha behavior.
- Git status summary: clean worktree after commit `75e27d0`.
- Intended slice: add minimal SOCKS5 CONNECT runtime gating that parses CONNECT requests into normalized policy events and opens host TCP egress only after audit-backed policy approval.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with deterministic fake egress.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this slice should not add a full SOCKS listener, greeting response IO, stream bridging, UDP ASSOCIATE, or proxy authentication.
- Exact next step: implement SOCKS CONNECT policy/eager parse handling for IP and hostname destinations behind the existing host egress trait.

## 2026-06-22T01:36:50Z
- Current objective: add minimal SOCKS5 CONNECT runtime gating through the shared policy/audit and host egress boundary.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 51 runtime tests, and 7 setup tests passed. New runtime tests prove SOCKS5 CONNECT requests are denied before host egress by default, domain CONNECT requests can open host TCP egress only after domain policy approval, and unresolved domain CONNECT requests fail before audit or egress.
- Commit hash when committed: pending.
- Remaining risks: SOCKS runtime does not yet include greeting response IO, listener loops, stream bridging, UDP ASSOCIATE support, or integrated DNS resolution for hostnames.
- Exact next step: commit SOCKS runtime gating, then add minimal config-to-runtime construction so static DNS records/proxy/runtime policy can be loaded from validated configuration rather than only in-memory tests.

## 2026-06-22T01:37:35Z
- Current objective: continue after SOCKS runtime gating toward configuration-backed runtime construction.
- Git status summary: clean worktree after commit `524543a`.
- Intended slice: add a minimal validated runtime configuration builder for sandbox identity, policy, broker DNS addresses, and static DNS resolver records so DNS/proxy/runtime tests no longer require ad hoc construction only.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and possibly `learnings.md` if config validation uncovers a new invariant.
- Remaining risks: this is still an in-memory configuration schema, not a serde/file-format loader or CLI parser.
- Exact next step: implement validated runtime config construction for `StaticDnsResolver`, `DnsCache`, and `PolicyEngine` inputs.

## 2026-06-22T01:44:15Z
- Current objective: add validated in-memory runtime configuration construction for policy and static DNS components.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on import wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 3 launcher tests, 53 runtime tests, and 7 setup tests passed. New runtime tests prove `BrokerRuntimeConfig` validates policy before construction, rejects zero DNS TTL, builds a policy engine, carries broker DNS addresses, and seeds a static DNS resolver with configured records.
- Commit hash when committed: pending.
- Remaining risks: runtime configuration is still in-memory only; no serde/file-format loader, CLI config path, upstream DNS resolver config, or listener binding config exists.
- Exact next step: commit runtime configuration builder, then add a small launcher/session assembly path that combines prepared bwrap launch, runtime config, and setup control handoff into a fail-early broker session plan.

## 2026-06-22T01:45:00Z
- Current objective: continue after runtime configuration construction toward fail-early launcher/session assembly.
- Git status summary: clean worktree after commit `71c073b`.
- Intended slice: add a small host-side broker session preparation API that validates runtime config before preparing bwrap/setup handoff, tying setup planning and runtime components together without spawning bwrap yet.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/lib.rs`, `Cargo.lock`, and `progress.md`.
- Remaining risks: this will still not spawn bwrap, preserve fds across exec, or run a live broker loop.
- Exact next step: implement a prepared broker session type combining `PreparedBwrapLaunch` and validated runtime components with deterministic fail-early tests.

## 2026-06-22T01:50:20Z
- Current objective: add fail-early launcher/session assembly that combines setup planning with validated runtime components.
- Files changed: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 5 launcher tests, 53 runtime tests, and 7 setup tests passed. New launcher tests prove a prepared broker session combines bwrap setup handoff with validated runtime components and rejects invalid runtime config before preparing launch state.
- Commit hash when committed: pending.
- Remaining risks: prepared sessions still do not spawn bwrap, preserve fds through exec, wait for TUN handoff, or start a live broker runtime loop.
- Exact next step: commit broker session preparation, then add a process-spawn command descriptor that records fd-preservation requirements without executing bwrap.

## 2026-06-22T01:51:05Z
- Current objective: continue after broker session preparation toward explicit spawn requirements for bwrap fd preservation.
- Git status summary: clean worktree after commit `581581b`.
- Intended slice: add a deterministic process-spawn descriptor that records the bwrap program/args and the helper fd that must be preserved into `foxproxsetup`, without executing bwrap.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Remaining risks: this still does not spawn bwrap or enforce fd flags in a child process; it only makes requirements auditable and testable.
- Exact next step: implement a spawn descriptor from `PreparedBwrapLaunch` and prove it carries the helper fd referenced in command args.

## 2026-06-22T01:54:25Z
- Current objective: make bwrap spawn fd-preservation requirements explicit and testable without executing bwrap.
- Files changed: `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 53 runtime tests, and 7 setup tests passed. New launcher test proves `PreparedBwrapLaunch` emits a `BwrapSpawnSpec` containing the bwrap program/args and the live helper fd that must be preserved and is referenced by `--handoff-fd`.
- Commit hash when committed: pending.
- Remaining risks: no actual process spawning, fd flag manipulation, or bwrap smoke execution exists yet.
- Exact next step: commit spawn descriptor, then add a bounded packet-processing session that combines DNS/ICMP/UDP handling into one reusable runtime object for live TUN fd ownership.

## 2026-06-22T01:55:10Z
- Current objective: continue after spawn descriptor toward a reusable live-TUN packet processing session boundary.
- Git status summary: clean worktree after commit `e433270`.
- Intended slice: add a bounded `TunBrokerSession` that owns a TUN-like IO object plus DNS resolver/cache and verification kernel, and runs the unified policy-gated packet handler for one packet at a time.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with fake TUN IO.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this session still uses fake IO in tests and does not poll host UDP/TCP sockets or integrate smoltcp stream bridging.
- Exact next step: refactor unified packet handling into a reusable helper and wrap it in an owning TUN broker session.

## 2026-06-22T02:02:20Z
- Current objective: add an owning TUN broker session for unified policy-gated packet processing.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 55 runtime tests, and 7 setup tests passed. New runtime tests prove `TunBrokerSession` owns fake TUN IO plus resolver/cache/kernel, answers broker DNS while updating cache, and applies ICMP policy through its owned verification kernel.
- Commit hash when committed: pending.
- Remaining risks: the session still processes one packet at a time with fake IO; generic UDP host egress and TCP stack handling remain separate session types, and no real TUN fd smoke has run.
- Exact next step: commit TUN broker session, then add DNS-cache hostname attribution lookup into UDP/TCP event conversion for TUN flows.

## 2026-06-22T02:03:05Z
- Current objective: continue after owning TUN broker session toward transparent DNS-to-flow hostname attribution.
- Git status summary: clean worktree after commit `416bf9d`.
- Intended slice: enrich TUN-derived TCP and UDP policy events with live DNS-cache hostname attribution when destination IPs match broker-observed DNS results.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` only if cache lifetime assumptions change.
- Remaining risks: attribution remains medium-confidence DNS correlation; SNI/HTTP Host mismatch logic and stream buffering are separate paths.
- Exact next step: add DNS-cache enrichment helper and tests proving cached hostnames allow domain policy for TUN TCP/UDP flows.

## 2026-06-22T02:11:45Z
- Current objective: enrich TUN-derived TCP/UDP policy events with broker DNS cache attribution.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on rustfmt wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 57 runtime tests, and 7 setup tests passed. New tests prove live DNS-cache observations enrich TUN TCP and UDP/QUIC policy events with medium-confidence hostname attribution so domain policies can allow matching flows.
- Commit hash when committed: pending.
- Remaining risks: DNS attribution is IP-based and medium-confidence only; HTTP Host and TLS SNI stream reassembly/mismatch handling still need integration with full TCP forwarding.
- Exact next step: commit DNS-cache flow attribution, then add policy/audit coverage for expired DNS attribution failing closed instead of allowing stale domain decisions.

## 2026-06-22T02:12:25Z
- Current objective: continue after DNS-cache flow attribution by proving stale DNS attribution cannot allow domain policy.
- Git status summary: clean worktree after commit `dd6437c`.
- Intended slice: add deterministic regression coverage that expired DNS observations are ignored for TUN domain decisions and therefore stale hostnames cannot open flows.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this is verification coverage only; it does not add DNS cache eviction scheduling or richer attribution conflict handling.
- Exact next step: add expired-cache TUN TCP/UDP domain-policy tests.

## 2026-06-22T02:17:55Z
- Current objective: prove stale DNS attribution cannot allow TUN domain policy.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 58 runtime tests, and 7 setup tests passed. New runtime regression test proves expired DNS cache observations are ignored and do not satisfy domain policy for TUN TCP flows.
- Commit hash when committed: pending.
- Remaining risks: cache expiry is checked during lookup but there is no background cache pruning in the owning session; DNS/SNI mismatch integration still depends on future TCP stream metadata plumbing.
- Exact next step: commit expired-attribution coverage, then add TCP metadata precedence tests that SNI mismatch overrides cached DNS allow decisions in the TUN path.

## 2026-06-22T02:18:35Z
- Current objective: continue after expired DNS attribution coverage toward TCP metadata precedence for DNS/SNI conflicts.
- Git status summary: clean worktree after commit `cb1ca3f`.
- Intended slice: add a TCP TLS metadata helper that compares visible SNI against live DNS-cache attribution and marks mismatches so policy fails closed before cached-domain allow rules.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this still operates on complete TLS ClientHello payloads supplied by tests; stream buffering/reassembly remains future work.
- Exact next step: implement DNS-cache-aware TLS ClientHello event conversion and tests for match/mismatch precedence.

## 2026-06-22T02:24:10Z
- Current objective: add DNS-cache-aware TLS ClientHello event conversion for SNI/DNS precedence checks.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 60 runtime tests, and 7 setup tests passed. New runtime tests prove visible TLS SNI compared against live DNS-cache attribution fails closed on mismatch before broad allows, and matching SNI/DNS cache attribution can use high-confidence SNI domain policy.
- Commit hash when committed: pending.
- Remaining risks: TLS metadata conversion still requires complete ClientHello bytes from future stream buffering; no smoltcp byte bridge feeds this helper yet.
- Exact next step: commit TLS DNS-cache precedence, then add minimal HTTP/TLS stream metadata buffering state that waits for complete headers/ClientHello instead of evaluating partial TCP payloads.

## 2026-06-22T02:24:50Z
- Current objective: continue after TLS/DNS precedence toward bounded TCP metadata buffering for future stream forwarding.
- Git status summary: clean worktree after commit `241a3f6`.
- Intended slice: add a small bounded TCP metadata buffer that accumulates payload bytes until plaintext HTTP headers or TLS ClientHello SNI are complete, returning `NeedMoreData` instead of guessing on partial input.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this buffer is not yet wired to smoltcp streams or backpressure; it is a deterministic metadata boundary only.
- Exact next step: implement bounded HTTP/TLS metadata buffering helpers and split-payload tests.

## 2026-06-22T02:33:15Z
- Current objective: add bounded TCP metadata buffering for complete HTTP headers and TLS ClientHello SNI extraction.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on a large `Result` error variant in the private buffer extender; fixed by returning `Option<TcpMetadataBufferOutcome>`)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 63 runtime tests, and 7 setup tests passed. New tests prove split HTTP headers and split TLS ClientHello payloads return `NeedMoreData` until complete metadata is available, and the buffer enforces a configured size limit before parsing.
- Commit hash when committed: pending.
- Remaining risks: buffering is not yet attached to a real smoltcp stream adapter, has no per-flow lifecycle, and does not bridge bytes.
- Exact next step: commit TCP metadata buffering, then add per-flow TCP metadata buffer management keyed by flow so future stream adapters can feed ordered bytes safely.

## 2026-06-22T02:34:00Z
- Current objective: continue after bounded TCP metadata buffering toward per-flow metadata state for future stream adapters.
- Git status summary: clean worktree after commit `f8d51ec`.
- Intended slice: add a small per-flow TCP metadata buffer table keyed by normalized `FlowKey`, so future TCP stack adapters can feed ordered bytes without sharing metadata state across flows.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this remains deterministic in-memory state only; no TCP sequence reordering, retransmission handling, or smoltcp byte bridge is implemented.
- Exact next step: implement per-flow buffer storage and tests for flow isolation/removal.

## 2026-06-22T02:39:10Z
- Current objective: add per-flow TCP metadata buffer storage for future stream adapters.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 54 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 64 runtime tests, and 7 setup tests passed. New runtime test proves `TcpMetadataBufferTable` isolates metadata state by `FlowKey` and supports explicit removal on flow cleanup.
- Commit hash when committed: pending.
- Remaining risks: no TCP sequence/retransmit handling, stream lifecycle hook, or smoltcp byte bridge feeds these per-flow buffers yet.
- Exact next step: commit per-flow metadata buffers, then add TCP flow lifecycle audit outcomes for opened/closed/error events from the stack adapter boundary.

## 2026-06-22T01:27:57Z
- Current objective: resume immediately after mistakenly final-answering at a commit checkpoint.
- Git status summary: clean worktree at resume.
- Intended slice: add TCP flow lifecycle audit outcomes for opened/closed/error events from the stack adapter boundary, as recorded in the prior next step.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-core/src/kernel.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if the stop/resume mistake is recorded.
- Remaining risks: this does not implement smoltcp byte bridging; it only makes lifecycle audit emission explicit and bounded by audit sink behavior.
- Exact next step: add an audit emission method and runtime TCP lifecycle event handling tests.

## 2026-06-22T01:33:05Z
- Current objective: update implementation approach documentation to prevent stopping after commit checkpoints.
- Files changed: `docs/implementation-approach-verification-kernel.md`, `learnings.md`, `progress.md`.
- Verification commands run:
  - Documentation-only change; no code verification required.
- Observed result: implementation approach now explicitly says to immediately begin the next cycle after each successful commit and that a successful commit, clean verification run, or progress summary is never a stop condition by itself.
- Commit hash when committed: pending.
- Remaining risks: none for this documentation clarification.
- Exact next step: commit this documentation clarification and wait for further instruction as requested.

## 2026-06-22T01:30:55Z
- Current objective: continue autonomous verification-kernel cycles from the checkpoint protocol clarification.
- Git status summary: clean worktree at session start.
- Intended slice: add TCP flow lifecycle audit outcomes for opened/closed/error events from the stack adapter boundary, as recorded before the documentation-only checkpoint.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-core/src/audit.rs`, `crates/foxprox-core/src/kernel.rs`, `crates/foxprox-runtime/src/lib.rs`, and `progress.md`.
- Remaining risks: this will not implement smoltcp byte bridging; it only makes lifecycle audit emission explicit and bounded by audit sink behavior.
- Exact next step: add an audit emission method and runtime TCP lifecycle event handling tests.

## 2026-06-22T01:34:45Z
- Current objective: add TCP flow lifecycle audit outcomes from the stack adapter boundary.
- Files changed: `crates/foxprox-core/src/audit.rs`, `crates/foxprox-core/src/kernel.rs`, `crates/foxprox-core/src/lib.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting in kernel/runtime; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo fmt --check && cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 67 runtime tests, and 7 setup tests passed. New tests prove TCP lifecycle close/error events are emitted through the audit sink, audit backpressure becomes fail-closed, and non-TCP lifecycle events from a TCP adapter are rejected.
- Commit hash when committed: pending.
- Remaining risks: lifecycle events are still fake-stack driven; no smoltcp byte bridge, live stream close/error capture, or socket backpressure handling exists.
- Exact next step: commit TCP lifecycle audit outcomes, then add a minimal stream-bridge trait boundary that can transfer bytes only after a verified opened TCP flow.

## 2026-06-22T01:35:22Z
- Current objective: continue after TCP lifecycle audit commit toward the smoltcp TCP forwarding gate.
- Git status summary: clean worktree after commit `68b534f`.
- Intended slice: add a minimal stream-bridge trait/state boundary that transfers TCP bytes only for flows marked opened after policy/audit approval.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with fake bridge implementations.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if the bridge state reveals a new invariant.
- Remaining risks: this remains an in-memory/fake bridge boundary; no smoltcp stream or real host socket byte loop is implemented in this slice.
- Exact next step: implement opened-flow tracking and deterministic tests that deny bridging before a flow is opened and count bytes after bridging.

## 2026-06-22T01:36:46Z
- Current objective: add a minimal TCP stream-bridge state boundary for future smoltcp byte forwarding.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 70 runtime tests, and 7 setup tests passed. New tests prove TCP bytes cannot be bridged before a flow is marked open, opened flows transfer bytes to fake host/sandbox sides while counting byte totals, and non-TCP flow keys are rejected at open time.
- Commit hash when committed: pending.
- Remaining risks: this is not a live TCP stream bridge; no smoltcp stream, real host socket splitting, backpressure, half-close handling, or lifecycle audit integration is wired to this bridge yet.
- Exact next step: commit TCP stream-bridge boundary, then connect bridge close accounting to TCP lifecycle audit events so byte counts can be logged when a verified open flow is closed.

## 2026-06-22T21:28:54Z
- Current objective: continue after TCP stream-bridge boundary commit toward auditable TCP close accounting.
- Git status summary: clean worktree after commit `13e852a`.
- Intended slice: connect verified TCP stream bridge byte counters to TCP lifecycle audit event construction when a flow closes.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if close accounting reveals a lifecycle invariant.
- Remaining risks: this remains fake-bridge/lifecycle wiring; no live smoltcp stream or host socket bridge exists yet.
- Exact next step: add a helper that closes an opened bridge flow into a `TcpStackLifecycleEvent::FlowClosed` carrying byte counts and duration, then verify the existing lifecycle audit path records those counts.

## 2026-06-22T21:30:18Z
- Current objective: connect TCP stream bridge close accounting to lifecycle audit event construction.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on formatting for the new close-accounting test; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 72 runtime tests, and 7 setup tests passed. New tests prove closing an opened TCP bridge flow produces a `TcpStackLifecycleEvent::FlowClosed` with byte counts and duration that the audit path records, and unknown flow close attempts fail before lifecycle emission.
- Commit hash when committed: pending.
- Remaining risks: close accounting is still driven by fake bridge state; live smoltcp streams and host TCP socket half-close/error handling are not implemented.
- Exact next step: commit TCP bridge close accounting, then add real host TCP stream bridge boundary tests using loopback sockets and in-memory sandbox-side IO.

## 2026-06-22T21:31:06Z
- Current objective: continue after TCP bridge close-accounting commit toward a real host TCP bridge boundary.
- Git status summary: clean worktree after commit `12ce595`.
- Intended slice: add a standard-library TCP stream bridge implementation that writes sandbox bytes to a loopback `TcpStream` and writes host bytes into sandbox-side IO, behind the existing opened-flow bridge gate.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; keep network verification loopback-only and deterministic.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`, and `learnings.md` if socket behavior requires a new invariant.
- Remaining risks: this still will not integrate smoltcp or continuously poll sockets; it only proves the concrete stream bridge boundary can move bytes after verification gates open the flow.
- Exact next step: implement `StdTcpStreamBridge` and a loopback test through `TcpStreamBridgeRuntime`.

## 2026-06-22T21:32:23Z
- Current objective: add a concrete standard-library TCP stream bridge behind the opened-flow gate.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 73 runtime tests, and 7 setup tests passed. New loopback test proves `StdTcpStreamBridge` writes sandbox bytes to a real localhost `TcpStream` and writes host bytes to sandbox-side in-memory IO only after the bridge runtime marks the TCP flow open.
- Commit hash when committed: pending.
- Remaining risks: the concrete bridge still performs explicit writes only; no host socket read polling, smoltcp stream integration, backpressure, or half-close behavior exists.
- Exact next step: commit the standard TCP stream bridge, then add a bounded host-read helper that reads from a real TCP stream and writes the bytes through the sandbox side with EOF/error outcomes.

## 2026-06-22T21:32:59Z
- Current objective: continue after standard TCP stream bridge commit toward host-to-sandbox read routing.
- Git status summary: clean worktree after commit `535b004`.
- Intended slice: add a bounded helper that reads bytes from a real host `TcpStream`, writes them to sandbox-side IO through the bridge, and reports EOF/error explicitly.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` using a loopback listener that writes and closes deterministically.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this still will not poll continuously or integrate with smoltcp; it proves one bounded read/write operation for the bridge boundary.
- Exact next step: implement host-read outcome types and loopback tests for bytes and EOF.

## 2026-06-22T21:33:52Z
- Current objective: add bounded host-to-sandbox reads for the standard TCP stream bridge.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 75 runtime tests, and 7 setup tests passed. New loopback tests prove `StdTcpStreamBridge` can read bounded host bytes into sandbox-side IO and reports host EOF without writing bogus sandbox bytes.
- Commit hash when committed: pending.
- Remaining risks: reads are one-shot and blocking; there is no event loop, readiness polling, smoltcp stream source, or timeout configuration on the bridge runtime yet.
- Exact next step: commit bounded TCP host-read support, then add a nonblocking/readiness-safe outcome so the future event loop can avoid blocking when no host bytes are available.

## 2026-06-22T21:34:47Z
- Current objective: continue after bounded TCP host-read commit toward event-loop-safe bridge reads.
- Git status summary: clean worktree after commit `b417796`.
- Intended slice: add an explicit nonblocking/no-data outcome for `StdTcpStreamBridge` host reads so future runtime loops do not treat readiness absence as an IO failure.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with a loopback nonblocking socket.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this still does not add a poller or async event loop; it only makes no-data behavior typed and testable.
- Exact next step: add a `WouldBlock` read outcome and deterministic nonblocking loopback coverage.

## 2026-06-22T21:35:26Z
- Current objective: make TCP host-read no-data behavior typed for future nonblocking event loops.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 76 runtime tests, and 7 setup tests passed. New loopback test proves a nonblocking host TCP stream with no available data returns `TcpHostReadOutcome::WouldBlock` without mutating sandbox output or treating readiness absence as an IO failure.
- Commit hash when committed: pending.
- Remaining risks: no poller/async runtime exists yet; the bridge only exposes a typed one-shot no-data outcome for a future loop.
- Exact next step: commit nonblocking host-read outcome, then add a bridge pump helper that combines sandbox-to-host writes and host-to-sandbox reads for one opened flow with explicit outcomes.

## 2026-06-22T21:36:12Z
- Current objective: continue after typed nonblocking TCP reads toward a one-flow bridge pump helper.
- Git status summary: clean worktree after commit `7e63efb`.
- Intended slice: add a one-shot TCP bridge pump helper that writes available sandbox bytes to the host and then reads bounded host bytes back to sandbox IO for an already-opened flow.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with loopback TCP.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this remains synchronous and one-flow-at-a-time; no smoltcp integration or readiness poller yet.
- Exact next step: implement the pump outcome and a loopback request/response test with byte accounting.

## 2026-06-22T21:37:48Z
- Current objective: add a one-shot TCP bridge pump for an opened flow.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on one chained host-read call; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 78 runtime tests, and 7 setup tests passed. New loopback tests prove the pump writes one sandbox request to a host TCP stream, reads one host response into sandbox IO, updates byte accounting, and rejects unopened flows before IO.
- Commit hash when committed: pending.
- Remaining risks: pump is synchronous and one-flow-at-a-time; it does not yet consume smoltcp stream buffers, poll readiness, or enforce resource limits beyond opened-flow gating.
- Exact next step: commit TCP bridge pump, then add TCP bridge resource limits for maximum open flows to prevent unbounded state growth.

## 2026-06-22T21:38:10Z
- Current objective: continue after TCP bridge pump commit toward TCP bridge resource limits.
- Git status summary: clean worktree after commit `2ecdb1d`.
- Intended slice: add a deterministic maximum-open-flow limit to `TcpStreamBridgeRuntime` so future stream adapters cannot grow bridge state without bound.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this only bounds in-memory bridge flow records; it does not yet enforce byte-buffer or socket-fd limits globally.
- Exact next step: add a limited constructor and fail-closed tests for opening beyond capacity.

## 2026-06-22T21:38:55Z
- Current objective: add TCP bridge resource limits for maximum open flows.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 80 runtime tests, and 7 setup tests passed. New tests prove `TcpStreamBridgeRuntime::with_max_open_flows` rejects new flows beyond capacity while allowing an existing flow key to be refreshed at capacity.
- Commit hash when committed: pending.
- Remaining risks: only open-flow map cardinality is bounded; per-flow buffers, socket fd counts, and total byte buffering limits still need runtime-level enforcement.
- Exact next step: commit TCP bridge open-flow limits, then add runtime configuration for TCP bridge limits so limits are not hardcoded by callers.

## 2026-06-22T21:39:20Z
- Current objective: continue after TCP bridge open-flow limits toward configuration-backed resource limits.
- Git status summary: clean worktree after commit `3d26f00`.
- Intended slice: add a validated TCP max-open-flow limit to `BrokerRuntimeConfig` and carry it into runtime components so bridge capacity is configured centrally.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this only configures open-flow count; byte-buffer, audit, and fd limits still need separate settings.
- Exact next step: extend runtime config/components and update validation tests for zero/nonzero TCP flow limits.

## 2026-06-22T21:40:43Z
- Current objective: add configuration-backed TCP open-flow limits.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 80 runtime tests, and 7 setup tests passed. Runtime config now validates nonzero `tcp_max_open_flows`, carries it into runtime components, and launcher session tests assert the configured limit is preserved.
- Commit hash when committed: pending.
- Remaining risks: no config file parser exists, and the limit is not yet automatically applied to a constructed TCP bridge runtime by session assembly.
- Exact next step: commit runtime TCP limit config, then add a helper that constructs `TcpStreamBridgeRuntime` from `BrokerRuntimeComponents` so configured limits are applied consistently.

## 2026-06-22T21:41:02Z
- Current objective: continue after runtime TCP limit config toward applying configured limits in bridge construction.
- Git status summary: clean worktree after commit `48ed78d`.
- Intended slice: add a helper that constructs `TcpStreamBridgeRuntime` from `BrokerRuntimeComponents` so the validated `tcp_max_open_flows` limit is not forgotten by callers.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this still does not assemble a full TCP session with smoltcp; it only applies validated limits to bridge runtime construction.
- Exact next step: implement the construction helper and a regression test that the configured limit rejects the second opened flow.

## 2026-06-22T21:42:12Z
- Current objective: apply configured TCP limits when constructing bridge runtimes.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 81 runtime tests, and 7 setup tests passed. New test proves `build_tcp_stream_bridge_runtime` applies `BrokerRuntimeComponents::tcp_max_open_flows`, causing the second flow open to fail at a configured limit of 1.
- Commit hash when committed: pending.
- Remaining risks: full session assembly still does not create a TCP bridge runtime from a real accepted smoltcp stream and host socket pair.
- Exact next step: commit configured bridge construction, then add explicit TCP metadata buffer size configuration and validation so stream inspection buffers are bounded by runtime config.

## 2026-06-22T21:42:52Z
- Current objective: continue after configured TCP bridge construction toward bounded TCP metadata inspection configuration.
- Git status summary: clean worktree after commit `f547d58`.
- Intended slice: add a validated TCP metadata buffer byte limit to runtime config/components so future stream inspection buffers are centrally bounded.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Remaining risks: this config value will not yet be wired into a smoltcp stream adapter; it makes the limit validated and available to callers.
- Exact next step: extend runtime config/components with `tcp_metadata_buffer_bytes` and zero-limit tests.

## 2026-06-22T21:43:49Z
- Current objective: add validated TCP metadata buffer size configuration.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 81 runtime tests, and 7 setup tests passed. Runtime config now validates nonzero `tcp_metadata_buffer_bytes`, preserves it in runtime components, and rejects zero-sized metadata buffers before construction.
- Commit hash when committed: pending.
- Remaining risks: the configured metadata buffer size is not yet applied by a helper that creates per-flow TCP metadata buffers.
- Exact next step: commit TCP metadata buffer configuration, then add a helper that fetches per-flow metadata buffers using `BrokerRuntimeComponents::tcp_metadata_buffer_bytes`.

## 2026-06-22T21:44:21Z
- Current objective: continue after TCP metadata buffer config toward applying configured inspection buffer limits.
- Git status summary: clean worktree after commit `8145f65`.
- Intended slice: add a helper that creates/fetches per-flow TCP metadata buffers using `BrokerRuntimeComponents::tcp_metadata_buffer_bytes` so callers do not accidentally bypass the configured limit.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this still does not attach metadata buffers to a live TCP adapter; it applies config to the existing deterministic buffer table.
- Exact next step: implement the configured-buffer helper and a regression test for limit enforcement.

## 2026-06-22T21:45:16Z
- Current objective: apply configured TCP metadata buffer limits to per-flow buffer creation.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on a long assertion; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 82 runtime tests, and 7 setup tests passed. New test proves `configured_tcp_metadata_buffer` creates a flow buffer using `BrokerRuntimeComponents::tcp_metadata_buffer_bytes` and enforces that configured limit during HTTP metadata accumulation.
- Commit hash when committed: pending.
- Remaining risks: per-flow metadata buffers are still not automatically pruned by a live TCP lifecycle manager.
- Exact next step: commit configured metadata buffer helper, then prune TCP metadata buffers when TCP bridge flows close to prevent stale inspection state.

## 2026-06-22T21:45:37Z
- Current objective: continue after configured metadata buffer helper toward TCP metadata lifecycle cleanup.
- Git status summary: clean worktree after commit `c545eb1`.
- Intended slice: prune per-flow TCP metadata buffers when the corresponding TCP bridge flow closes so stale inspection state cannot be reused.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: cleanup remains helper-driven; a live stack adapter must call it from real close events later.
- Exact next step: add a close-and-prune helper plus regression coverage.

## 2026-06-22T21:46:24Z
- Current objective: prune TCP metadata buffers when bridge flows close.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on match formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 83 runtime tests, and 7 setup tests passed. New helper closes a TCP bridge flow and removes its matching metadata buffer; regression test proves partial HTTP inspection state is pruned at close.
- Commit hash when committed: pending.
- Remaining risks: cleanup is helper-driven and must be called by the future live TCP lifecycle manager.
- Exact next step: commit TCP metadata close pruning, then add an integrated TCP flow state object that owns bridge runtime plus metadata table so close cleanup is harder to forget.

## 2026-06-22T21:46:42Z
- Current objective: continue after TCP metadata close pruning toward integrated TCP flow state ownership.
- Git status summary: clean worktree after commit `8edf294`.
- Intended slice: add a small `TcpFlowRuntime` that owns both TCP bridge runtime and metadata table so open/metadata/close cleanup use one state object.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this state object will still be driven by tests/fake bridge rather than a real smoltcp adapter.
- Exact next step: implement `TcpFlowRuntime` with configured limits and close-prune behavior.

## 2026-06-22T21:47:30Z
- Current objective: add integrated TCP flow runtime state for bridge and metadata cleanup.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, and 7 setup tests passed. New `TcpFlowRuntime` owns the bridge runtime and metadata table, applies configured open-flow limits, and closes flows while pruning partial metadata state.
- Commit hash when committed: pending.
- Remaining risks: integrated state is still not driven by smoltcp or a live TUN event loop.
- Exact next step: commit integrated TCP flow runtime, then add initial smoltcp adapter crate boundary or dependency-gated adapter scaffold for future TUN TCP forwarding.

## 2026-06-22T21:50:02Z
- Current objective: continue after integrated TCP flow runtime toward the documented smoltcp TCP forwarding gate.
- Git status summary: clean worktree after commit `8edf294` plus subsequent verified runtime-state commits through `c545eb1`; current worktree clean before this cycle.
- Intended slice: add a small `foxprox-smoltcp` adapter crate with a deterministic IP-medium loopback interface proof, keeping smoltcp types out of core policy.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`; dependency version must respect the workspace Rust 1.80 requirement.
- Files expected to change: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-smoltcp/*`, `progress.md`, and `learnings.md` if smoltcp API constraints affect the adapter plan.
- Remaining risks: this is an adapter proof, not TCP forwarding; real TUN fd feeding and stream bridging remain later work.
- Exact next step: add smoltcp 0.12 with IP-medium loopback construction tests.

## 2026-06-22T21:51:42Z
- Current objective: add the initial smoltcp adapter crate boundary.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-smoltcp/Cargo.toml`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially passed after formatting; later one test assertion needed `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed because `unwrap_err` required `SmoltcpIpLoopback: Debug`; fixed with `matches!`)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 2 smoltcp adapter tests passed. New crate uses `smoltcp` 0.12 with IP medium loopback, validates IPv4 prefix length fail-early, constructs an IP-medium interface, and polls once without exposing smoltcp types to core policy.
- Commit hash when committed: pending.
- Remaining risks: this is only an adapter construction proof; it does not feed TUN packets into smoltcp sockets, detect TCP connect attempts, or bridge streams.
- Exact next step: commit the smoltcp adapter boundary, then add a smoltcp TCP socket proof that a socket can be allocated/listened without unsafe code and with explicit buffer sizing.

## 2026-06-22T21:52:14Z
- Current objective: continue after smoltcp adapter boundary toward the TCP socket proof for the forwarding gate.
- Git status summary: clean worktree after commit `5db2c41`.
- Intended slice: add a smoltcp TCP listener socket allocation proof with explicit RX/TX buffer sizes and no unsafe code.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: listening socket proof still does not accept a TUN-origin connection or bridge bytes.
- Exact next step: implement `listen_tcp` on the smoltcp loopback adapter and deterministic validation tests.

## 2026-06-22T21:53:06Z
- Current objective: add smoltcp TCP listener socket proof.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 4 smoltcp adapter tests passed. New adapter method allocates a smoltcp TCP listener with explicit RX/TX buffers, rejects port 0 and zero-sized buffers, and polls the loopback stack without unsafe code.
- Commit hash when committed: pending.
- Remaining risks: the listener is not yet connected to a peer or surfaced as a normalized `TcpConnectAttempt`.
- Exact next step: commit smoltcp TCP listener proof, then add a loopback client-to-listener connection proof that can detect the listener socket becoming active.

## 2026-06-22T21:53:42Z
- Current objective: continue after smoltcp TCP listener proof toward TCP connect detection.
- Git status summary: clean worktree after commit `3af4cd2`.
- Intended slice: add a smoltcp loopback client-to-listener connection proof and expose only adapter-level active socket counts, not smoltcp types to core policy.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this remains smoltcp-internal loopback, not TUN-origin SYN handling or host egress bridging.
- Exact next step: track TCP socket handles inside the adapter and test listener/client active state after polling.

## 2026-06-22T21:54:38Z
- Current objective: add smoltcp loopback client-to-listener connection proof.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 6 smoltcp adapter tests passed. New tests prove the adapter can allocate listener and client TCP sockets, poll the smoltcp IP loopback until both sockets are active, and reject invalid client ports/buffers.
- Commit hash when committed: pending.
- Remaining risks: active smoltcp sockets are not yet translated into foxprox runtime connect attempts or bridged to host sockets.
- Exact next step: commit smoltcp loopback connection proof, then translate active smoltcp TCP endpoints into a `TcpStackConnectAttempt` without leaking smoltcp endpoint types.

## 2026-06-22T21:56:10Z
- Current objective: continue after smoltcp loopback connect proof by translating active smoltcp TCP endpoints into normalized runtime connect attempts.
- Git status summary: clean worktree before edits after commit `9c0f895`.
- Intended slice: expose active client-side smoltcp TCP endpoints as `TcpStackConnectAttempt` while filtering listener sockets and keeping smoltcp endpoint types inside the adapter crate.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/Cargo.toml`, `crates/foxprox-smoltcp/src/lib.rs`, `Cargo.lock`, `progress.md`.
- Remaining risks: normalized attempts are observed from smoltcp loopback only; policy/audit gating and host bridge integration remain separate runtime paths.
- Exact next step: add endpoint conversion and loopback assertion for source/destination ports.

## 2026-06-22T21:59:35Z
- Current objective: expose smoltcp active endpoints through the normalized TCP stack adapter boundary.
- Files changed: `crates/foxprox-smoltcp/Cargo.toml`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on one long assertion; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 7 smoltcp adapter tests passed. The smoltcp adapter now filters listener sockets and exports active client endpoints as normalized `TcpStackConnectAttempt` values with source/destination `Endpoint`s.
- Commit hash when committed: pending.
- Remaining risks: exported connect attempts are not yet consumed by `TcpStackRuntime`, and duplicate reporting suppression/reset semantics are not implemented.
- Exact next step: commit smoltcp connect-attempt export, then implement `TcpStackAdapter` for the smoltcp adapter and verify policy-gated host egress with a fake egress.

## 2026-06-22T21:59:33Z
- Current objective: continue after smoltcp connect-attempt export toward runtime policy gating.
- Git status summary: `Cargo.lock` still has the smoltcp crate's new `foxprox-core` dependency recorded after commit `6939ae9`; include it with this integration slice.
- Intended slice: implement `TcpStackAdapter` for `SmoltcpIpLoopback` and verify `TcpStackRuntime` can policy-gate a smoltcp-observed connect attempt before fake host egress.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `Cargo.lock`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: adapter reset/open callbacks will be minimal state hooks, not full smoltcp socket reset/bridge behavior.
- Exact next step: add the trait impl and a policy-gated fake-egress test.

## 2026-06-22T22:01:12Z
- Current objective: implement `TcpStackAdapter` for smoltcp loopback adapter.
- Files changed: `Cargo.lock`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on a long import; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 8 smoltcp adapter tests passed. New test proves a smoltcp-observed connect attempt can be consumed by `TcpStackRuntime`, audited by the verification kernel, and reach fake host TCP egress only after an allow rule.
- Commit hash when committed: pending.
- Remaining risks: smoltcp adapter callbacks do not yet suppress duplicate connect reports or reset smoltcp sockets on denial.
- Exact next step: commit smoltcp runtime gating, then add duplicate connect-attempt suppression after `mark_connect_opened` or `reset_connect` callbacks.

## 2026-06-22T22:00:56Z
- Current objective: continue after smoltcp runtime gating toward stable adapter event semantics.
- Git status summary: clean worktree after commit `ea834b8`.
- Intended slice: suppress duplicate smoltcp connect-attempt reports after runtime callbacks mark a connect opened or reset.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: suppression is adapter-state based; it still does not actively close/reset smoltcp sockets.
- Exact next step: track reported attempts and add callback regression tests.

## 2026-06-22T22:02:42Z
- Current objective: suppress duplicate smoltcp connect-attempt reports after runtime callbacks.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 10 smoltcp adapter tests passed. New tests prove `mark_connect_opened` and `reset_connect` callbacks remember reported smoltcp attempts so `next_connect_attempt` does not repeatedly emit the same active socket.
- Commit hash when committed: pending.
- Remaining risks: `reset_connect` only suppresses reporting; it does not yet abort/close matching smoltcp sockets.
- Exact next step: commit duplicate suppression, then make smoltcp `reset_connect` abort the matching socket and verify the active socket count drops after polling.

## 2026-06-22T22:02:17Z
- Current objective: continue after smoltcp duplicate suppression toward denial/reset behavior.
- Git status summary: clean worktree after commit `29c8431`.
- Intended slice: make smoltcp `reset_connect` abort the matching active socket instead of only suppressing duplicate reports.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: aborting the client socket is still an adapter-local reset proof, not full TCP reset packet synthesis for a TUN peer.
- Exact next step: match attempts to smoltcp socket endpoints and abort on reset.

## 2026-06-22T22:04:36Z
- Current objective: abort matching smoltcp sockets on denied/reset connect callbacks.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because the reset test assumed exactly two active loopback sockets; fixed to assert the matching client socket is no longer active)
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 11 smoltcp adapter tests passed. `reset_connect` now records the attempt and aborts the matching smoltcp socket; regression checks the matching active socket disappears and no duplicate connect attempt is emitted.
- Commit hash when committed: pending.
- Remaining risks: aborting the smoltcp socket is not yet connected to writing a TCP reset packet back to a real TUN peer.
- Exact next step: commit smoltcp reset abort behavior, then add smoltcp socket byte send/receive proof to prepare for bridging accepted streams.

## 2026-06-22T22:05:04Z
- Current objective: continue after smoltcp reset abort behavior toward stream byte bridging proof.
- Git status summary: clean worktree after commit `d2380f1`.
- Intended slice: prove bytes can be sent from the smoltcp client socket and received by the smoltcp listener-side socket inside the adapter, with typed errors for missing sockets or smoltcp send/recv rejection.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this is still internal smoltcp loopback byte movement, not host socket bridge integration.
- Exact next step: add send/receive helpers and a deterministic loopback payload test.

## 2026-06-22T22:07:08Z
- Current objective: prove smoltcp loopback TCP payload movement.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on a wrapped `is_some_and` expression; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because active did not imply send-ready; fixed by polling/retrying typed `TcpSendRejected`)
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 12 smoltcp adapter tests passed. New helpers send bytes on a normalized connect attempt and receive them on the listener port, proving internal smoltcp loopback payload movement with typed send/recv/no-socket errors.
- Commit hash when committed: pending.
- Remaining risks: payload movement is still inside smoltcp loopback; host socket bridging and TUN packet IO are not joined to it.
- Exact next step: commit smoltcp byte movement proof, then add an adapter-level receive helper that exports listener bytes alongside the normalized connect attempt flow key for bridge integration.

## 2026-06-22T22:07:30Z
- Current objective: continue after smoltcp payload movement toward bridge-ready payload events.
- Git status summary: clean worktree after commit `7d5d07b`.
- Intended slice: export received smoltcp listener bytes with a normalized TCP `FlowKey` so runtime bridge code can associate payloads with opened flows without smoltcp endpoint types.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will still not write payloads into the host bridge automatically.
- Exact next step: add `SmoltcpTcpPayload` and listener receive-with-flow tests.

## 2026-06-22T22:09:10Z
- Current objective: export smoltcp listener payloads with normalized flow keys.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 12 smoltcp adapter tests passed. `recv_on_listener_port_with_flow` now returns `SmoltcpTcpPayload` with a normalized TCP `FlowKey` and payload bytes, and the loopback payload test asserts the flow matches the exported connect attempt.
- Commit hash when committed: pending.
- Remaining risks: payloads are not yet handed to `TcpFlowRuntime` or a host bridge automatically.
- Exact next step: commit smoltcp payload flow export, then add a runtime integration test that feeds a smoltcp payload event into `TcpFlowRuntime` with a fake bridge.

## 2026-06-22T22:09:35Z
- Current objective: continue after smoltcp payload flow export toward bridge integration.
- Git status summary: clean worktree after commit `1a34d4d`.
- Intended slice: add a `TcpFlowRuntime` forwarding method and verify a smoltcp-exported payload flow can be handed to a fake runtime bridge with byte accounting.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: fake bridge only; no real host socket bridge or TUN packet source is joined yet.
- Exact next step: expose a safe TCP flow runtime send method and add cross-crate smoltcp payload handoff coverage.

## 2026-06-22T22:10:06Z
- Current objective: hand smoltcp payload flows to `TcpFlowRuntime`.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on fake bridge method formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 13 smoltcp adapter tests passed. `TcpFlowRuntime` now exposes a safe sandbox-payload-to-host method, and smoltcp tests prove a loopback payload with normalized flow key can be marked open and forwarded into a fake host bridge with byte accounting.
- Commit hash when committed: pending.
- Remaining risks: bridge integration remains fake-host; real `StdTcpStreamBridge` and TUN/smoltcp packet IO are not joined.
- Exact next step: commit smoltcp payload-to-runtime handoff, then add a real `StdTcpStreamBridge` loopback handoff using a smoltcp-exported payload flow.

## 2026-06-22T22:10:28Z
- Current objective: continue after smoltcp payload-to-runtime handoff toward a concrete host TCP bridge proof.
- Git status summary: clean worktree after commit `5471b5f`.
- Intended slice: use a smoltcp-exported payload flow to drive `TcpFlowRuntime<StdTcpStreamBridge<_>>` and verify bytes reach a real loopback host TCP listener.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: the smoltcp and host sockets are still test-loopback objects, not a live TUN session.
- Exact next step: add the concrete bridge handoff test.

## 2026-06-22T22:11:20Z
- Current objective: bridge smoltcp-exported payload flows to a real loopback host TCP stream.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on a wrapped `StdTcpStreamBridge::new` call; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 14 smoltcp adapter tests passed. New test proves a smoltcp-exported payload flow can be opened in `TcpFlowRuntime<StdTcpStreamBridge<_>>` and delivered to a real localhost TCP listener.
- Commit hash when committed: pending.
- Remaining risks: this still uses loopback test sockets and an in-memory smoltcp loopback adapter; no live TUN fd is feeding smoltcp yet.
- Exact next step: commit concrete smoltcp-to-host bridge proof, then add an adapter-facing IP packet ingress queue so tests can feed raw IP packets toward smoltcp without exposing smoltcp device types to policy.

## 2026-06-22T22:12:05Z
- Current objective: continue after concrete smoltcp-to-host bridge proof toward adapter packet ingress.
- Git status summary: clean worktree after commit `aa29e36`.
- Intended slice: replace the smoltcp loopback-only device boundary with an adapter-owned IP packet queue that can ingest raw IP packets and expose emitted outbound IP packets without leaking smoltcp device types to policy/runtime code.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with deterministic in-process packet queue tests.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, and `learnings.md` only if replacing `Loopback` changes a test invariant.
- Remaining risks: packet ingress will still be test-fed bytes, not a live TUN fd; TCP host bridging remains separate from continuous stack polling.
- Exact next step: add an adapter-owned IP packet device with `ingest_ip_packet` and `next_outbound_ip_packet` helpers plus a raw packet ingress/emission proof.

## 2026-06-22T22:20:18Z
- Current objective: add adapter-owned raw IP packet ingress/egress queues for smoltcp.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on associated type formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed because `DeviceCapabilities` is non-exhaustive; fixed by mutating `DeviceCapabilities::default()`)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 16 smoltcp adapter tests passed. `SmoltcpIpLoopback` now owns a queue-backed IP device, exposes `ingest_ip_packet` and `next_outbound_ip_packet`, rejects empty ingress packets, and proves a raw IPv4 TCP SYN fed into the adapter causes smoltcp to emit a parseable SYN/ACK without leaking smoltcp device types.
- Commit hash when committed: pending.
- Remaining risks: ingress packets are still test-fed bytes, not read from a live TUN fd; outbound packets are captured in memory and not written to TUN.
- Exact next step: commit smoltcp packet queue ingress, then add a runtime-facing one-poll packet pump that reads one IP packet from a TUN-like object, feeds smoltcp, and writes emitted outbound IP packets back to the TUN-like writer.

## 2026-06-22T22:21:05Z
- Current objective: continue after smoltcp packet queue ingress toward a TUN-like packet pump.
- Git status summary: clean worktree after commit `0567306`.
- Intended slice: add a runtime-facing one-packet pump that reads one IP packet from a TUN-like reader, feeds `SmoltcpIpLoopback`, polls once, and writes emitted outbound IP packets to a TUN-like writer.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with deterministic in-memory reader/writer tests.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will still be a one-packet synchronous proof, not a continuous broker loop or live fd integration.
- Exact next step: add the pump helper and prove a raw SYN read from fake TUN writes a smoltcp SYN/ACK response packet.

## 2026-06-22T22:22:25Z
- Current objective: add one-packet TUN-like pump for smoltcp packet ingress/egress.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on wrapped pump calls in tests; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 18 smoltcp adapter tests passed. New `pump_one_tun_packet` reads one TUN-like IP packet, feeds the adapter queue, polls smoltcp once, drains emitted outbound packets to a writer, and reports no-packet reads without polling; tests prove a raw TCP SYN read from fake TUN writes a parseable smoltcp SYN/ACK packet.
- Commit hash when committed: pending.
- Remaining risks: one-packet pump is synchronous and test-only so far; it does not integrate policy-gated connect handling, host socket opening, or continuous TUN fd operation.
- Exact next step: commit smoltcp TUN packet pump, then connect packet-pumped smoltcp connect attempts to `TcpStackRuntime` so an ingress SYN can be policy-gated after the smoltcp poll.

## 2026-06-22T22:23:05Z
- Current objective: continue after smoltcp TUN packet pump toward policy-gated TCP connect handling from packet ingress.
- Git status summary: clean worktree after commit `391d668`.
- Intended slice: let the smoltcp adapter report accepted listener-side TCP sockets as normalized connect attempts for TUN-ingressed SYN packets, while preserving the existing internal client-socket reporting mode for loopback tests.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: accepted listener reporting will prove policy gating but still not complete the ACK/data/host bridge lifecycle from a live TUN fd.
- Exact next step: add an explicit connect-report mode and a pump+runtime test for a raw SYN.

## 2026-06-22T22:25:10Z
- Current objective: policy-gate smoltcp connects that originate from packet-pumped TUN ingress.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on long assertions; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 20 smoltcp adapter tests passed. The adapter now has explicit `TcpConnectReportMode` values for internal active-client proofs versus TUN accepted-listener sockets, exports accepted listener attempts with sandbox source and destination endpoints, and proves a raw SYN pumped through smoltcp is consumed by `TcpStackRuntime` and audited/allowed before fake host egress.
- Commit hash when committed: pending.
- Remaining risks: denied accepted-listener reset is only indirectly supported, and accepted payloads are not yet linked to host bridges in the same packet-pumped session.
- Exact next step: commit packet-pumped connect gating, then add a denied TUN-ingressed SYN regression proving `TcpStackRuntime` reset callbacks suppress and abort accepted listener sockets.

## 2026-06-22T22:25:45Z
- Current objective: continue after packet-pumped connect gating by proving denied TUN-ingressed connects are reset/suppressed.
- Git status summary: clean worktree after commit `4e03ea5`.
- Intended slice: add a denied raw-SYN regression showing `TcpStackRuntime` invokes the smoltcp reset callback for accepted listener sockets, suppresses duplicate reporting, and aborts the matching socket.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: reset is still adapter-local; no verified TCP RST packet synthesis to the sandbox peer yet.
- Exact next step: add an orientation-agnostic active-socket check and denied packet-pumped SYN test.

## 2026-06-22T22:27:04Z
- Current objective: prove denied TUN-ingressed smoltcp connects are reset/suppressed.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because the test expected audited `DenyReset` instead of the default policy's `DenyDrop`; fixed to assert runtime cleanup separately from policy action)
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 21 smoltcp adapter tests passed. New regression proves a default-denied raw SYN reaches `TcpStackRuntime`, emits no host egress, records one audit event, aborts the accepted smoltcp socket, and suppresses duplicate reporting.
- Commit hash when committed: pending.
- Remaining risks: reset is still adapter-local and not asserted as a specific outbound TCP RST packet to the sandbox; full ACK/data bridge from a TUN peer remains unimplemented.
- Exact next step: commit denied packet-pumped SYN reset proof, then add a helper/test for completing the packet-pumped TCP handshake so sandbox-to-host payload can flow through the same accepted listener socket path.

## 2026-06-22T22:27:30Z
- Current objective: continue after denied packet-pumped SYN reset proof toward packet-pumped TCP payload flow.
- Git status summary: clean worktree after commit `8e2fc33`.
- Intended slice: complete a deterministic raw-packet TCP handshake against smoltcp and prove payload bytes from a TUN-like peer are received as a normalized `SmoltcpTcpPayload` on the accepted listener path.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, and `learnings.md` if TUN-mode device behavior needs an explicit invariant.
- Remaining risks: payload will still stop at the smoltcp accepted socket; host bridge handoff from this exact packet-pumped session remains next.
- Exact next step: add non-loopback packet-device mode for TUN-style tests and craft ACK/data packets from the emitted SYN/ACK.

## 2026-06-22T22:29:05Z
- Current objective: complete a packet-pumped TCP handshake and receive listener payload bytes.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 22 smoltcp adapter tests passed. New test disables packet self-loopback, feeds raw SYN/ACK/data packets through the TUN pump, derives the client ACK from the emitted SYN/ACK, and proves listener-side bytes are exported as `SmoltcpTcpPayload` with the expected flow key.
- Commit hash when committed: pending.
- Remaining risks: payload handoff from this exact packet-pumped accepted socket to `TcpFlowRuntime<StdTcpStreamBridge<_>>` remains unjoined; outbound host-to-sandbox bytes are still not packetized back through smoltcp.
- Exact next step: commit packet-pumped TCP payload proof, then hand that packet-pumped payload flow to a real host bridge in the same test path.

## 2026-06-22T22:29:25Z
- Current objective: continue after packet-pumped TCP payload proof toward host bridge handoff on the same TUN-style path.
- Git status summary: clean worktree after commit `4f5ced9`.
- Intended slice: feed raw TCP handshake/data packets through smoltcp, export the accepted listener payload, open the normalized flow in `TcpFlowRuntime<StdTcpStreamBridge<_>>`, and verify bytes reach a real localhost TCP listener.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: host-to-sandbox reverse bytes and continuous polling remain outside this slice.
- Exact next step: add a packet-pumped smoltcp-to-host bridge regression.

## 2026-06-22T22:30:10Z
- Current objective: hand packet-pumped smoltcp payloads to a real host TCP bridge.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on helper call wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 23 smoltcp adapter tests passed. New regression feeds raw TCP handshake/data packets through the smoltcp TUN pump, exports the accepted listener payload flow, opens that flow in `TcpFlowRuntime<StdTcpStreamBridge<_>>`, and verifies the bytes reach a real localhost TCP listener.
- Commit hash when committed: pending.
- Remaining risks: reverse host-to-sandbox bytes are still not packetized through smoltcp; no continuous live TUN fd loop exists.
- Exact next step: commit packet-pumped host bridge handoff, then add an adapter helper that writes host bytes into the accepted smoltcp socket and emits outbound IP packets for sandbox delivery.

## 2026-06-22T22:30:35Z
- Current objective: continue after packet-pumped host bridge handoff toward reverse host-to-sandbox packet emission.
- Git status summary: clean worktree after commit `ff23c06`.
- Intended slice: add a smoltcp adapter helper that writes host-side bytes into an accepted TCP flow and verify smoltcp emits a valid outbound IP packet back toward the sandbox endpoint.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will prove packet emission from a test-established flow, not a continuous host-read/TUN-write loop.
- Exact next step: add reverse-flow send helper and outbound packet assertion.

## 2026-06-22T22:31:05Z
- Current objective: emit sandbox-bound IP packets for host bytes on packet-pumped smoltcp flows.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on helper signature formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 24 smoltcp adapter tests passed. New helper sends host-side bytes into the accepted smoltcp flow and a regression proves polling emits a checksum-validated TCP payload packet from broker/listener endpoint back to the sandbox endpoint.
- Commit hash when committed: pending.
- Remaining risks: host bytes are injected by a test helper rather than a real `TcpFlowRuntime` host-read pump; no continuous TUN writer loop or TCP close packet lifecycle exists.
- Exact next step: commit host-to-sandbox smoltcp packet emission, then add a small integrated pump that combines host-read bytes from `TcpFlowRuntime` with `send_to_sandbox_on_flow` and writes emitted packets to a TUN-like writer.

## 2026-06-22T22:32:20Z
- Current objective: combine host-read bridge bytes with smoltcp sandbox packet emission.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on wrapped `StdTcpStreamBridge::new` and chained access; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 25 smoltcp adapter tests passed. `TcpFlowRuntime<StdTcpStreamBridge<_>>` now exposes a host-read pump into its sandbox writer, and the smoltcp regression verifies those host bytes can be injected into the accepted flow and emitted as a sandbox-bound TCP/IP packet.
- Commit hash when committed: pending.
- Remaining risks: the sandbox writer is still an intermediate buffer in the test path; a continuous session type must join TUN reads, policy gating, host bridge reads/writes, smoltcp polling, and lifecycle auditing.
- Exact next step: commit host-read-to-smoltcp packet emission, then introduce a small TCP transparent session harness that owns smoltcp adapter + TCP flow runtime and executes one sandbox-to-host pump step after policy-open.

## 2026-06-22T22:33:05Z
- Current objective: continue after host-read smoltcp packet emission toward a small transparent TCP bridge session harness.
- Git status summary: clean worktree after commit `9a14e54`.
- Intended slice: add a smoltcp TCP bridge session object that owns an adapter plus `TcpFlowRuntime`, reads one accepted listener payload, and forwards it to the already-open host bridge with typed adapter/bridge errors.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will be one-direction/one-step and assume policy already opened the flow.
- Exact next step: add the session harness and a packet-pumped payload-to-real-host regression through it.

## 2026-06-22T22:34:25Z
- Current objective: introduce a one-step transparent TCP bridge session harness.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 26 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession` now owns a smoltcp adapter and `TcpFlowRuntime`, reads one accepted listener payload, forwards it to an already-open bridge, and returns typed adapter/bridge errors; the regression proves packet-pumped payload bytes reach a real localhost TCP listener through the session harness.
- Commit hash when committed: pending.
- Remaining risks: session assumes policy already opened the flow; it does not yet own `TcpStackRuntime`, host-read reverse pumping, TUN writer draining, or lifecycle close auditing.
- Exact next step: commit one-step TCP bridge session, then add a complementary session method that pumps host bytes from `TcpFlowRuntime` back into smoltcp and drains emitted IP packets to a TUN-like writer.

## 2026-06-22T22:34:50Z
- Current objective: continue after one-step TCP bridge session by adding host-to-sandbox session pumping.
- Git status summary: clean worktree after commit `41305ca`.
- Intended slice: add a session method that pumps host bytes from `TcpFlowRuntime<StdTcpStreamBridge<Vec<u8>>>`, injects them into the smoltcp accepted flow, polls, and drains emitted IP packets to a TUN-like writer.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will still use a Vec-backed bridge writer and in-memory TUN writer rather than a continuous live fd loop.
- Exact next step: add typed host-to-sandbox pump outcome and regression with localhost host bytes.

## 2026-06-22T22:36:05Z
- Current objective: add host-to-sandbox pumping to the smoltcp TCP bridge session.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on chained formatting and bridge constructor wrapping; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially failed on an unnecessary `mut`; fixed)
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 27 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession` can now pump host bytes from `TcpFlowRuntime<StdTcpStreamBridge<Vec<u8>>>`, inject them into the accepted smoltcp flow, poll, and drain emitted IP packets to a TUN-like writer with typed write errors.
- Commit hash when committed: pending.
- Remaining risks: session still depends on callers to establish/open flows and uses Vec-backed host-read staging; continuous event loop, real TUN fd, and lifecycle close auditing remain.
- Exact next step: commit host-to-sandbox session pump, then add flow close accounting for the session path so packet-pumped bridge byte counts can become audited lifecycle events.

## 2026-06-22T22:36:50Z
- Current objective: continue after bidirectional smoltcp session pumping by adding close accounting for the session path.
- Git status summary: clean worktree after commit `5f54fb4`.
- Intended slice: expose session flow close through `TcpFlowRuntime` and verify packet-pumped sandbox bytes plus host-read bytes produce an auditable `TcpStackLifecycleEvent::FlowClosed` with byte counts and duration.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: lifecycle event emission to audit sink is still handled by runtime kernel code outside this session harness.
- Exact next step: add `close_flow` on the session and a bidirectional close-count regression.

## 2026-06-22T22:38:05Z
- Current objective: add close accounting to the smoltcp TCP bridge session path.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 28 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession::close_flow` now delegates to `TcpFlowRuntime` close accounting, and the regression proves packet-pumped sandbox bytes plus host-read bytes produce a `TcpStackLifecycleEvent::FlowClosed` with expected byte counts and duration.
- Commit hash when committed: pending.
- Remaining risks: the lifecycle event is returned but not emitted through `VerificationKernel::emit_audit_event` by the session harness; continuous live fd loop remains.
- Exact next step: commit session close accounting, then add a policy-open helper that marks the `TcpFlowRuntime` flow opened when `TcpStackRuntime` allows an accepted smoltcp connect, eliminating manual `mark_opened` in packet-pumped bridge tests.

## 2026-06-22T22:38:25Z
- Current objective: continue after session close accounting by joining policy-open attempts to flow-runtime open state.
- Git status summary: clean worktree after commit `3dc7b41`.
- Intended slice: add a session helper that converts an allowed `TcpStackConnectAttempt` into an open `FlowKey` in `TcpFlowRuntime`, and verify a packet-pumped accepted connect can be policy-gated before session bridge forwarding without manual `mark_opened` calls.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: host egress opened by `TcpStackRuntime` is still fake in this slice; real host stream creation remains test-provided.
- Exact next step: add the helper and policy-open-to-session regression.

## 2026-06-22T22:40:05Z
- Current objective: join policy-allowed smoltcp connect attempts to session flow-open state.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 29 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession::mark_opened_connect` converts an allowed `TcpStackConnectAttempt` into the matching TCP `FlowKey` and opens it in `TcpFlowRuntime`; regression proves packet-pumped accepted connects can be policy-gated, marked open through the session helper, and forwarded to a real host listener without manual flow-open calls.
- Commit hash when committed: pending.
- Remaining risks: `TcpStackRuntime` still uses fake host egress in this proof; production host stream creation is not yet unified with policy-open handling.
- Exact next step: commit policy-open session helper, then add audit emission for session close lifecycle events through `VerificationKernel::emit_audit_event`.

## 2026-06-22T22:40:25Z
- Current objective: continue after policy-open session helper by auditing session close lifecycle events.
- Git status summary: clean worktree after commit `421326c`.
- Intended slice: expose the runtime TCP lifecycle audit-event formatter and add a smoltcp session helper that closes a flow and emits the resulting lifecycle event through `VerificationKernel::emit_audit_event`.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will audit explicit session close calls, not yet automatically detect FIN/RST close from live packet streams.
- Exact next step: make lifecycle audit formatting reusable and add close-and-audit regression.

## 2026-06-22T22:41:15Z
- Current objective: emit audit records for smoltcp session close lifecycle events.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on wrapped lifecycle audit call and assertions; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 30 smoltcp adapter tests passed. Runtime lifecycle audit formatting is now reusable, and `SmoltcpTcpBridgeSession::close_and_audit_flow` closes a flow, formats the lifecycle audit event, emits it through `VerificationKernel::emit_audit_event`, and returns typed audit/bridge/session errors.
- Commit hash when committed: pending.
- Remaining risks: close auditing is explicit-call based; automatic FIN/RST close detection and continuous live TUN session orchestration are still absent.
- Exact next step: commit session close audit emission, then assess the remaining Milestone 2 gap: replacing fake host egress in policy-open with real host stream construction inside a unified TCP session factory.

## 2026-06-22T22:41:35Z
- Current objective: continue after session close audit emission toward a unified TCP session factory.
- Git status summary: clean worktree after commit `a463438`.
- Intended slice: replace fake host egress in the packet-pumped policy-open proof with a small factory boundary that creates `StdTcpStreamBridge` for an allowed `TcpStackConnectAttempt` using a caller-provided host `TcpStream`.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this remains caller-provided host stream construction; address resolution and real outbound connect dialing are still separate.
- Exact next step: add the factory/helper and a regression that builds an open `SmoltcpTcpBridgeSession<StdTcpStreamBridge<Vec<u8>>>` directly from the allowed attempt.

## 2026-06-22T22:43:10Z
- Current objective: add a factory boundary for allowed smoltcp TCP bridge sessions.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on wrapped `StdTcpStreamBridge::new`; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 31 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession::from_allowed_connect` now constructs a `StdTcpStreamBridge<Vec<u8>>`, opens the matching flow in `TcpFlowRuntime`, and returns the session plus `FlowKey`; regression proves a policy-allowed packet-pumped connect can build the open session and forward payload to a real localhost host stream.
- Commit hash when committed: pending.
- Remaining risks: the host `TcpStream` is still caller-provided; dialing/resolution and live TUN loop ownership remain to be unified.
- Exact next step: commit the allowed-connect session factory, then add an explicit stop-gap note or next slice for real host dialing once address resolution policy is ready.

## 2026-06-22T22:43:45Z
- Current objective: continue with explicit permission to add real host integration for allowed transparent TCP connects.
- Git status summary: clean worktree after commit `b8c695b`.
- Intended slice: add a fail-explicit host TCP dialing boundary for allowed `TcpStackConnectAttempt` values and verify it builds an open smoltcp bridge session only after policy has allowed the packet-pumped connect.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` using loopback TCP sockets only.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, and `learnings.md` only if real dialing reveals a new invariant.
- Remaining risks: this will dial loopback in tests and keep DNS/name resolution out of scope; continuous live TUN fd orchestration remains later work.
- Exact next step: add a `connect_allowed_host_session` helper around `TcpStream::connect` plus a regression that policy-gated packet-pumped TCP reaches a real loopback host without caller-provided `TcpStream`.

## 2026-06-25T02:59:10Z
- Current objective: add real host TCP dialing boundary for allowed smoltcp connects.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 32 smoltcp adapter tests passed. `SmoltcpTcpBridgeSession::connect_allowed_host_session` now dials a real `SocketAddr`, converts connection failure into a typed session error, builds the open `StdTcpStreamBridge<Vec<u8>>` session, and the regression proves a policy-allowed packet-pumped connect forwards sandbox bytes to a real loopback host listener without a caller-provided `TcpStream`.
- Commit hash when committed: pending.
- Remaining risks: host address is still provided as an IP socket address; hostname resolution and DNS attribution decisions remain separate, and no live continuous TUN fd loop owns the full session yet.
- Exact next step: commit real host dialing boundary, then add a higher-level allowed-connect orchestration helper that runs policy handling, real dialing, and session creation in one call.

## 2026-06-25T02:59:35Z
- Current objective: continue after real host TCP dialing boundary toward one-call allowed-connect session orchestration.
- Git status summary: clean worktree after commit `3c68a26`.
- Intended slice: add a helper that consumes a smoltcp adapter, evaluates the next accepted connect through `VerificationKernel`, resets denied attempts, dials a real host socket only on allow, marks the adapter connect opened, and returns an open bridge session.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with loopback-only host sockets.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: helper still accepts an IP socket address and does not perform hostname resolution or spawn a continuous session loop.
- Exact next step: implement `connect_next_allowed_host_session` and allowed/denied regression coverage.

## 2026-06-25T03:01:20Z
- Current objective: add one-call orchestration for policy-gated real host TCP session creation.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on wrapped `from_allowed_connect`; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 34 smoltcp adapter tests passed. `connect_next_allowed_host_session` now consumes a smoltcp adapter, evaluates the next accepted connect through `VerificationKernel`, resets denied attempts before dialing, dials a real host `SocketAddr` only on allow, marks the adapter attempt opened, and returns an open bridge session plus `FlowKey` and `Decision`.
- Commit hash when committed: pending.
- Remaining risks: host connect failure coverage is not yet explicit, hostname resolution is still out of scope, and no continuous live TUN fd loop owns sessions.
- Exact next step: commit one-call allowed host session orchestration, then add explicit host-connect-failure coverage proving failed dialing resets the smoltcp attempt and emits the allow audit before returning a typed host-connect error.

## 2026-06-25T03:02:40Z
- Current objective: continue after one-call host session orchestration toward a TUN-read open-session step.
- Git status summary: clean worktree after commit `85b56ad`.
- Intended slice: add a helper that reads one TUN-like packet into smoltcp, writes emitted packets back to the TUN-like writer, then policy-gates and dials the next accepted TCP connect into an open host bridge session.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with loopback-only host sockets and in-memory TUN IO.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this will open a session from a SYN packet but will not yet own subsequent ACK/data packets inside a continuous loop.
- Exact next step: add `pump_tun_and_open_next_allowed_host_session` and a SYN-to-open-session regression.

## 2026-06-25T03:04:05Z
- Current objective: open a real host TCP bridge session from one TUN-like SYN packet.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially failed on tuple return and open-flow assertion formatting; fixed with `cargo fmt`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 35 smoltcp adapter tests passed. `pump_tun_and_open_next_allowed_host_session` now reads one TUN-like packet, feeds/polls smoltcp, writes the emitted SYN/ACK to a TUN-like writer, evaluates the accepted connect through policy/audit, dials a real loopback host socket, and returns an open bridge session with the flow recorded.
- Commit hash when committed: pending.
- Remaining risks: subsequent ACK/data packets still require direct access to the adapter/session plumbing; the helper opens from SYN but does not yet provide a session method for later TUN packet ingestion and sandbox payload forwarding.
- Exact next step: commit TUN-pump open-session helper, then add a session method that ingests a subsequent TUN packet, polls smoltcp, and forwards any resulting listener payload to host.

## 2026-06-25T03:05:30Z
- Current objective: continue after TUN-pump open-session helper by adding subsequent sandbox packet forwarding on the open session.
- Git status summary: clean worktree after commit `cd94f61`.
- Intended slice: add a session method that ingests one subsequent TUN-like packet, drains smoltcp outbound packets to a writer, and forwards any newly received listener payload to the already-open host bridge.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with raw ACK/data packets and a loopback host listener.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: host-to-sandbox reverse pumping and loop scheduling are still separate session methods rather than one event loop.
- Exact next step: add the session packet-step method and an open-SYN then ACK/data forwarding regression.

## 2026-06-25T03:06:35Z
- Current objective: forward subsequent sandbox TUN packets through an opened real host TCP session.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 36 smoltcp adapter tests passed. `pump_tun_packet_and_forward_sandbox_payload` now lets an opened `SmoltcpTcpBridgeSession` ingest a later TUN-like ACK/data packet, drain smoltcp outbound packets, and forward newly received listener payload bytes into the already-open host bridge; regression proves SYN opens a real host session and subsequent raw ACK/data packets deliver `step-data` to a real loopback host listener.
- Commit hash when committed: pending.
- Remaining risks: host-to-sandbox reverse pumping is still a separate call rather than one duplex event-loop tick; live TUN fd smoke remains blocked by missing `CAP_NET_ADMIN` in this environment.
- Exact next step: commit subsequent TUN packet forwarding, then add a single bidirectional session tick that combines optional sandbox packet ingestion with host-read-to-TUN packet emission.

## 2026-06-25T03:08:15Z
- Current objective: continue after subsequent TUN packet forwarding by composing a bidirectional session tick.
- Git status summary: clean worktree after commit `55f3b32`.
- Intended slice: add one session method that ingests one sandbox/TUN packet, forwards any sandbox payload to host, then reads available host bytes, injects them into smoltcp, and drains sandbox-bound packets to a TUN-like writer.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with in-memory packet IO and loopback host sockets.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: still synchronous one-tick behavior; a production loop must schedule repeated ticks and handle WouldBlock without blocking.
- Exact next step: add bidirectional tick outcome/method and a request-response regression.

## 2026-06-25T03:10:05Z
- Current objective: add one bidirectional transparent TCP session tick.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 37 smoltcp adapter tests passed. `pump_bidirectional_once` now composes sandbox packet ingestion, smoltcp outbound draining, sandbox payload forwarding to host, host read, host-byte injection back into smoltcp, and sandbox-bound packet draining; regression proves raw data after an opened SYN session reaches a real host listener and a real host reply is emitted as a TCP/IP packet to the TUN-like writer.
- Commit hash when committed: pending.
- Remaining risks: host streams are still blocking by default when created via `connect_next_allowed_host_session`; production loop should use nonblocking host streams to avoid stalls.
- Exact next step: commit bidirectional tick, then make real host dialing set host streams nonblocking and update tick tests to handle `WouldBlock` explicitly.

## 2026-06-25T03:11:20Z
- Current objective: continue after bidirectional bridge tick by making real host dialing nonblocking.
- Git status summary: clean worktree after commit `a18cef9`.
- Intended slice: set real host `TcpStream`s created by smoltcp session helpers to nonblocking mode and make bidirectional tick verification explicitly tolerate `WouldBlock` before host bytes arrive.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Remaining risks: one-tick scheduling is still test-driven; production needs repeated polling around `WouldBlock`.
- Exact next step: update host dialing and retry the bidirectional host-read assertion deterministically.

## 2026-06-25T03:13:05Z
- Current objective: make real host dialing nonblocking and verify bidirectional ticks tolerate `WouldBlock`.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because the bidirectional tick test assumed the nonblocking host socket would return reply bytes immediately; fixed by bounded retry on `WouldBlock`)
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 37 smoltcp adapter tests passed. Real host streams created by smoltcp session helpers are now set nonblocking, and the bidirectional regression explicitly retries until host bytes are available while still proving the host reply is emitted as a sandbox-bound TCP/IP packet.
- Commit hash when committed: pending.
- Remaining risks: repeated polling is still test-local rather than an owned production event loop; live TUN fd smoke remains blocked by missing `CAP_NET_ADMIN` in this environment.
- Exact next step: commit nonblocking host dialing, then introduce a small session-loop state type that can repeat bidirectional ticks and report `WouldBlock`/progress outcomes without blocking.

## 2026-06-25T03:14:20Z
- Current objective: continue toward complete alpha scope by turning one-shot bidirectional smoltcp ticks into a repeatable nonblocking session-loop step.
- Git status summary: clean worktree after commit `8c1cac0`.
- Intended slice: add a small session-loop outcome/state helper that runs one bidirectional tick, reports whether sandbox bytes, host bytes, or outbound packets made progress, and treats nonblocking `WouldBlock` as a normal no-progress host-read outcome.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with in-memory TUN IO and loopback host sockets.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this is still deterministic in-process IO, not a live TUN fd smoke; live TUN remains blocked by missing CAP_NET_ADMIN in this environment.
- Exact next step: implement a progress-classified bidirectional session step and regression tests for WouldBlock and eventual reply progress.

## 2026-06-25T03:18:10Z
- Current objective: add progress-classified session loop ticks for transparent TCP smoltcp sessions.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features` (initially failed because the loop-state test assumed exactly one idle tick before progress; fixed to allow bounded nonblocking retries)
- Observed result: final verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 38 smoltcp adapter tests passed. Added `SmoltcpTcpBridgeLoopState`, `SmoltcpTcpBridgeLoopStep`, and progress classification on bidirectional tick outcomes; regression proves an idle `WouldBlock` tick increments idle state and a later host reply increments progress while emitting a sandbox-bound TCP/IP packet.
- Commit hash when committed: pending.
- Remaining risks: the loop state is still driven by tests/callers rather than a broker-owned continuous fd loop; live TUN smoke remains unavailable without CAP_NET_ADMIN.
- Exact next step: commit loop tick state, then add a live-session wrapper that owns the TUN-like IO buffer and session state so repeated ticks do not require callers to pass all plumbing each time.

## 2026-06-25T03:19:45Z
- Current objective: continue after loop progress tracking by owning TUN-like IO and loop state in a live-session wrapper.
- Git status summary: clean worktree after commit `25633ce`.
- Intended slice: add a `SmoltcpTcpBridgeIoSession` wrapper that owns the bridge session, TUN-like IO object, buffer, flow, listener port, byte limits, and loop state, plus a one-call tick method for repeated nonblocking operation.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` with a deterministic in-memory TUN object and loopback host socket.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this remains in-memory TUN-like IO; real fd smoke requires CAP_NET_ADMIN.
- Exact next step: implement the IO-session wrapper and request/reply regression.

## 2026-06-25T03:24:10Z
- Current objective: wrap transparent TCP bridge state with owned TUN-like IO and reusable loop state.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 85 runtime tests, 7 setup tests, and 39 smoltcp adapter tests passed. Added `SmoltcpTcpBridgeIoSession`, which owns the smoltcp bridge session, TUN-like IO, buffer, flow key, listener/byte limits, and loop state; regression proves repeated ticks consume scripted ACK/data packets, forward sandbox bytes to a real loopback host, read a host reply nonblocking, emit a sandbox-bound TCP/IP packet into owned TUN-like writes, and update progress state.
- Commit hash when committed: pending.
- Remaining risks: live TUN fd smoke remains unavailable without CAP_NET_ADMIN; TCP close/FIN detection from packets is not automatic; UDP/QUIC still need equivalent real forwarding loops.
- Exact next step: commit owned TCP IO session wrapper, then advance UDP alpha by adding a real nonblocking UDP socket flow session that sends allowed datagrams and receives host replies into synthesized TUN packets.

## 2026-06-25T03:24:40Z
- Current objective: advance UDP alpha by adding a real nonblocking UDP host flow session with reply-to-TUN synthesis.
- Git status summary: clean worktree after commit `a9de605`.
- Intended slice: add a runtime `StdUdpFlowSession` that validates UDP/IPv4 flow keys, sends sandbox payloads to a real host UDP endpoint through a nonblocking socket, receives host replies, and synthesizes valid TUN-bound IPv4/UDP response packets.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` using loopback UDP sockets only.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: policy-gated creation from TUN packets and flow table ownership remain separate until the next slice.
- Exact next step: implement `StdUdpFlowSession` and loopback echo regression.

## 2026-06-25T03:27:15Z
- Current objective: complete real nonblocking UDP host flow primitive.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt` after `cargo fmt --check` identified formatting-only drift in the new UDP session code.
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 87 runtime tests, 7 setup tests, and 39 smoltcp adapter tests passed. Added `StdUdpFlowSession`, `UdpFlowSessionError`, and `UdpHostReplyOutcome`; loopback UDP regression proves sandbox bytes are sent to a real nonblocking host UDP socket and host replies are synthesized into valid sandbox-bound IPv4/UDP packets.
- Commit hash when committed: pending.
- Remaining risks: the real UDP primitive is not yet wired to policy-gated TUN packet handling; live TUN fd smoke remains unavailable without CAP_NET_ADMIN.
- Exact next step: commit real UDP flow primitive, then add a policy-gated TUN UDP host session wrapper that owns TUN-like IO, records allowed flow state, sends allowed datagrams with `StdUdpFlowSession`, polls for replies, and writes synthesized packets back to TUN-like IO.

## 2026-06-25T03:28:25Z
- Current objective: wire the real UDP primitive into a policy-gated TUN-like UDP host session.
- Git status summary: clean worktree after commit `4f0099f`.
- Intended slice: add a deterministic `TunUdpHostSession` that owns TUN-like IO, kernel, flow table, live UDP sessions, and an MTU buffer; a tick should read at most one TUN packet, fail closed on denied/malformed traffic, send allowed payloads to real loopback UDP, poll nonblocking replies, and write synthesized response packets back to the TUN-like IO.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: live TUN fd smoke and UDP session cleanup/expiry are still separate follow-up work.
- Exact next step: implement wrapper and loopback regression.

## 2026-06-25T03:33:45Z
- Current objective: complete policy-gated real UDP host session from TUN-like packets.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift in new tests)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 89 runtime tests, 7 setup tests, and 39 smoltcp adapter tests passed. Added `TunUdpHostSession` with typed ingress/reply tick outcomes; regression proves allowed TUN-like UDP packets are audited/policy-gated, sent to a real loopback UDP socket, tracked in the flow table/open session map, nonblocking host replies are synthesized into valid TUN-bound IPv4/UDP packets, and denied packets record flow/audit state without opening host sockets.
- Commit hash when committed: pending.
- Remaining risks: UDP flow expiry/cleanup is not wired to close live sockets; live TUN fd smoke remains unavailable without CAP_NET_ADMIN; DNS hostname attribution for real host dialing still needs a cohesive path.
- Exact next step: commit policy-gated UDP host session, then add deterministic cleanup/expiry for owned UDP host sessions keyed to `FlowTable::expire_udp` so long-running sessions do not leak host sockets.

## 2026-06-25T03:34:20Z
- Current objective: add deterministic UDP host session accounting and cleanup.
- Git status summary: clean worktree after commit `cecdcf8`.
- Intended slice: record host-to-sandbox UDP bytes in flow state when replies are written, and add an explicit `expire_idle_flows` method that removes expired flow-table entries and closes matching live `StdUdpFlowSession`s.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-core/src/flow.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: live TUN fd smoke remains unavailable without CAP_NET_ADMIN.
- Exact next step: implement flow host-byte accounting and expiration regression.

## 2026-06-25T03:37:35Z
- Current objective: complete deterministic UDP host session accounting and cleanup.
- Files changed: `crates/foxprox-core/src/flow.rs`, `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift in new runtime accounting/test code)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 6 device tests, 3 integration tests, 6 launcher tests, 90 runtime tests, 7 setup tests, and 39 smoltcp adapter tests passed. Added `FlowTable::record_udp_host_datagram`, made `TunUdpHostSession` account host-to-sandbox bytes on reply writes, and added `expire_idle_flows` to remove expired flow-table entries and close matching live UDP sockets; regression proves socket count and flow table drop together at the configured timeout boundary.
- Commit hash when committed: pending.
- Remaining risks: live TUN fd smoke remains unavailable without CAP_NET_ADMIN; DNS hostname attribution for real host dialing is still socket-address only for TCP and IP-only for UDP.
- Exact next step: commit UDP cleanup/accounting, then assess remaining alpha scope against docs and add an explicit live-TUN capability-gated smoke/skip path if no code path already records the CAP_NET_ADMIN blocker.

## 2026-06-25T03:40:05Z
- Current objective: add an explicit live-TUN smoke/skip verification path for the known CAP_NET_ADMIN boundary.
- Files changed: `crates/foxprox-device/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo test -p foxprox-device live_tun_create_smoke_runs_only_when_cap_net_admin_is_available -- --nocapture`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 90 runtime tests, 7 setup tests, and 39 smoltcp adapter tests passed. The focused live-TUN smoke test passed by explicitly skipping because `/dev/net/tun` exists but `CAP_NET_ADMIN` is not effective in this environment (`skipping live TUN smoke: CAP_NET_ADMIN is not effective`). If run with the capability, the same test attempts real `create_tun("fpxsmoke0")`.
- Commit hash when committed: pending.
- Remaining risks: no privileged end-to-end bwrap/TUN smoke has executed in this unprivileged worktree; TCP/UDP real host tests remain loopback-only and deterministic.
- Exact next step: commit live-TUN smoke/skip harness, then reassess docs for any remaining alpha feature gap that can be advanced without privileged namespace execution.

## 2026-06-25T03:42:30Z
- Current objective: close the remaining DNS-attribution gap for packet-pumped real TCP host sessions.
- Git status summary: clean worktree after commit `b003121`.
- Intended slice: add DNS-cache-aware smoltcp TCP host session opening so policy decisions can use broker DNS attribution while still dialing the real destination socket, preserving the existing no-attribution helper as a wrapper.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Remaining risks: this still uses loopback-only host sockets in tests; live TUN/bwrap smoke remains capability-gated.
- Exact next step: implement DNS-cache-aware connect helper and regression.

## 2026-06-25T03:46:20Z
- Current objective: close DNS-attributed policy for packet-pumped real TCP host sessions.
- Files changed: `crates/foxprox-smoltcp/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift in the new DNS-aware helper/test)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 90 runtime tests, 7 setup tests, and 40 smoltcp adapter tests passed. Added DNS-cache-aware `connect_next_allowed_host_session_with_dns_cache` and `pump_tun_and_open_next_allowed_host_session_with_dns_cache`; regression proves packet-pumped SYNs can be allowed by broker-DNS hostname attribution, audit the hostname, and still dial a real loopback host socket.
- Commit hash when committed: pending.
- Remaining risks: live privileged TUN/bwrap smoke is still capability-gated; explicit proxy listener sockets are represented by runtimes/parsers but not by a long-running listener loop.
- Exact next step: commit DNS-aware TCP host session helper, then either add deterministic explicit proxy listener-step harnesses or conclude alpha if listener loops are intentionally out of scope for the verified kernel slice.

## 2026-06-25T03:47:25Z
- Current objective: add deterministic explicit HTTP proxy connection-step IO coverage around the existing proxy runtime.
- Git status summary: clean worktree after commit `4498c28`.
- Intended slice: provide a one-connection HTTP proxy handler that reads a request line from a stream, runs shared policy/audit/egress logic, and writes explicit HTTP status responses for malformed, denied, failed, and CONNECT-open outcomes.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this is a deterministic stream-step harness, not a full long-running async listener or byte relay.
- Exact next step: implement the HTTP proxy connection-step helper and tests.

## 2026-06-25T03:51:20Z
- Current objective: add deterministic explicit HTTP proxy connection-step IO coverage.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings` (initially caught `large_enum_variant`; fixed by boxing the large runtime outcome)
  - `cargo test --all-targets --all-features` (initially caught an invalid malformed-line assumption; fixed the test to use an actually malformed request line)
  - final `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 92 runtime tests, 7 setup tests, and 40 smoltcp adapter tests passed. Added `handle_http_proxy_connection_once` and typed connection outcomes; tests prove CONNECT success writes `200 Connection Established`, policy denial writes fail-closed `403`, and malformed request lines write `400` without host egress.
- Commit hash when committed: pending.
- Remaining risks: the helper is a stream-step harness, not a full async listener/relay; SOCKS has runtime/parser support but not a similar stream-step response helper yet.
- Exact next step: commit HTTP proxy connection-step harness, then add a deterministic SOCKS5 connection-step helper for greeting/connect response behavior.

## 2026-06-25T03:52:05Z
- Current objective: add deterministic SOCKS5 connection-step IO coverage around the existing SOCKS runtime.
- Git status summary: clean worktree after commit `067eca4`.
- Intended slice: provide a one-connection SOCKS5 helper that performs no-auth greeting negotiation, parses one CONNECT request, runs shared policy/audit/egress logic, and writes explicit SOCKS success/denial/failure replies.
- Verification plan: run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- Files expected to change: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Remaining risks: this remains a deterministic connection-step harness, not a full relay loop.
- Exact next step: implement SOCKS5 connection-step helper and tests.

## 2026-06-25T03:56:35Z
- Current objective: add deterministic SOCKS5 connection-step IO coverage.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 94 runtime tests, 7 setup tests, and 40 smoltcp adapter tests passed. Added `handle_socks5_connection_once` and typed SOCKS connection outcomes; tests prove no-auth greeting negotiation, domain CONNECT policy success with SOCKS success reply, policy denial with fail-closed SOCKS reply, and rejected auth methods without host egress.
- Commit hash when committed: pending.
- Remaining risks: SOCKS helper is a deterministic connection-step harness, not a full long-running relay loop; live privileged TUN/bwrap smoke remains unavailable in this worktree.
- Exact next step: commit SOCKS5 connection-step harness, then perform a final alpha-scope audit and either add the last missing verified boundary or record completion criteria.

## 2026-06-25T03:59:55Z
- Current objective: complete deterministic SOCKS5 connection-step IO coverage.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 94 runtime tests, 7 setup tests, and 40 smoltcp adapter tests passed. Added `handle_socks5_connection_once`, SOCKS reply helpers, and typed connection outcomes; tests prove no-auth greeting, domain CONNECT success, policy denial, and rejected auth methods have explicit protocol replies and no undefined host egress.
- Commit hash when committed: pending.
- Remaining risks: full async listener/relay loops remain outside the deterministic step harness; live privileged TUN/bwrap smoke remains gated on CAP_NET_ADMIN.
- Exact next step: commit SOCKS5 connection-step helper, then run final alpha-scope verification/audit and stop only if remaining work is blocked by live privilege or out-of-scope async listener orchestration.

## 2026-06-25T04:02:30Z
- Current objective: strengthen SOCKS5 connection-step coverage before final audit.
- Files changed: `crates/foxprox-runtime/src/lib.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check` (initially reported formatting drift)
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `cargo fmt --check`
- Observed result: verification passed; 55 core tests, 7 device tests, 3 integration tests, 6 launcher tests, 95 runtime tests, 7 setup tests, and 40 smoltcp adapter tests passed. Added a SOCKS5 connection-step regression for unresolved domain CONNECT requests, proving it replies with host-unreachable status, opens no host connection, and emits no audit event before resolution exists.
- Commit hash when committed: amended into `88a500e`.
- Remaining risks: same as previous entry: full async listener/relay loops and privileged end-to-end TUN/bwrap smoke are outside what this unprivileged deterministic harness can execute.
- Exact next step: amend the prior checkpoint with this verification, then run final git status and scope audit.

## 2026-06-25T04:05:00Z
- Current objective: run rootless bwrap live tests and patch gaps until the alpha prototype works end-to-end.
- Git status summary: clean worktree at start of live-test cycle.
- User correction: bwrap is rootless here and should be used for live tests; missing host effective CAP_NET_ADMIN is not by itself a blocker for bwrap-based setup.
- Intended slice: inspect launcher/setup/device paths, run the smallest live bwrap/TUN smoke, capture failures, and patch the repo toward a full working alpha prototype.
- Verification plan: use deterministic cargo checks plus focused live bwrap commands; record any environment-specific skip/failure precisely.
- Files expected to change: likely setup/launcher/device/runtime integration plus `progress.md` and `learnings.md` for the corrected bwrap assumption.
- Exact next step: inspect bwrap/setup command paths and run rootless bwrap capability/TUN probes.

## 2026-06-25T14:45:00Z
- Current objective: make rootless bwrap live TUN setup work and patch setup gaps.
- Files changed: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-integrations/src/lib.rs`, `crates/foxprox-setup/src/lib.rs`, `progress.md`, `learnings.md`.
- Live failures observed and fixed:
  - Initial bwrap live setup with `--dev-bind /dev/net/tun` only failed opening `/dev/net/tun` with `Permission denied`; rootless bwrap needs `--dev /dev` plus the TUN bind.
  - Running as uid 1000 in the user namespace failed `TUNSETIFF` with `Operation not permitted`; adding bwrap `--uid 0 --gid 0` gives namespace-scoped CAP_NET_ADMIN for setup.
  - Inherited fd handoff is not viable through the current bwrap command shape; added `--handoff-socket` and Unix socket fd transfer for rootless bwrap.
  - Capability drop failed on rootless bounding/ambient `prctl`; patched setup to enforce and verify CAP_NET_ADMIN removal from effective/permitted/inheritable sets after `capset`, while treating rootless-only bounding/ambient prctl failures as best-effort.
- Verification commands run:
  - `cargo fmt`
  - `cargo clippy -p foxprox-device -p foxprox-integrations -p foxprox-setup --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-device -p foxprox-integrations -p foxprox-setup --all-targets --all-features`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - Manual live bwrap smoke with `foxproxsetup --handoff-socket`: passed with one TUN fd received over SCM_RIGHTS; sandbox target saw `fpxlive1` configured with `10.66.0.2 peer 10.66.0.1`, default route via `fpxlive1`, generated resolver config, and `CapEff: 0000000000000000` after setup exec.
- Observed result: final deterministic verification passed; 55 core tests, 8 device tests, 4 integration tests, 6 launcher tests, 95 runtime tests, 10 setup tests, and 40 smoltcp adapter tests passed. Rootless bwrap live setup now creates/configures TUN, hands its fd to the host over a Unix socket, drops CAP_NET_ADMIN before target exec, and proves the target namespace sees the configured interface while the host holds the fd.
- Commit hash when committed: pending.
- Remaining risks: launcher still lacks a high-level socket-handoff execution helper; live setup smoke proves TUN setup but does not yet run the broker loop against the handed-off fd.
- Exact next step: commit rootless bwrap setup fixes, then add launcher support for socket-handoff bwrap execution and a live smoke that receives the TUN fd via launcher-owned path.

## 2026-06-25T14:47:30Z
- Current objective: expose socket-handoff bwrap setup through launcher preparation so the live rootless path is not only manual.
- Git status summary: clean worktree after commit `b8f0f74`.
- Intended slice: add launcher-owned socket control path preparation, bwrap command generation with `--handoff-socket`, and tests proving no inherited fd preservation is needed for rootless bwrap.
- Verification plan: run focused launcher/integration/device checks plus full workspace verification if the slice passes.
- Files expected to change: `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Exact next step: implement socket-handoff launcher preparation and regression.

## 2026-06-25T14:52:30Z
- Current objective: expose rootless socket handoff through launcher APIs and verify a live sandbox-visible packet path.
- Files changed: `crates/foxprox-launcher/src/lib.rs`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check`
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - Manual live bwrap UDP/TUN smoke: sandbox Python sent UDP `ping` to broker TUN IP `10.66.0.1:9999`; host received the packet on the handed-off TUN fd, wrote a synthesized UDP reply, and sandbox received `pong` with process exit code 0.
- Observed result: launcher now prepares socket-handoff bwrap commands without preserved fds; live manual UDP/TUN smoke proves traffic crosses the rootless bwrap-created TUN fd bidirectionally when the host keeps the handed-off fd open.
- Remaining risks: the live UDP reply smoke used a small Python packet responder rather than a checked-in Rust broker loop; next slice should move this into Rust product/test code using existing packet synthesis/runtime boundaries.
- Exact next step: run full workspace verification, commit launcher socket handoff, then add a checked-in Rust live smoke harness or broker loop for the same UDP/TUN path.

## 2026-06-25T14:57:30Z
- Current objective: make the live rootless bwrap UDP/TUN smoke checked in and Rust-backed.
- Files changed: `crates/foxprox-launcher/examples/live_bwrap_udp_smoke.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo build -p foxprox-setup --bin foxproxsetup`
  - `cargo run -p foxprox-launcher --example live_bwrap_udp_smoke` (passed: `live bwrap UDP smoke passed: pong`)
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - final `cargo run -p foxprox-launcher --example live_bwrap_udp_smoke` (passed again)
- Observed result: full deterministic verification passed; 55 core tests, 8 device tests, 4 integration tests, 7 launcher tests, 95 runtime tests, 10 setup tests, and 40 smoltcp adapter tests passed. The checked-in live example launches rootless bwrap, runs `foxproxsetup`, receives the real TUN fd through launcher socket handoff, reads a real UDP packet from the sandbox namespace, writes a Rust-synthesized UDP reply via the TUN fd, and verifies the sandbox process receives `pong`.
- Commit hash when committed: pending.
- Remaining risks: the checked-in live smoke proves UDP packet write-back but does not yet run the full TCP smoltcp bridge against a live bwrap TUN fd; TCP remains verified with deterministic raw-packet/TUN-like tests and real loopback host sockets.
- Exact next step: commit live Rust bwrap UDP smoke, then attempt a live bwrap TCP smoke through the smoltcp bridge session or identify the minimal missing API for wiring live TUN fd to smoltcp session startup.

## 2026-06-25T15:05:30Z
- Current objective: add live rootless bwrap TCP smoke through the Rust smoltcp bridge.
- Files changed: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-smoltcp/Cargo.toml`, `crates/foxprox-smoltcp/src/lib.rs`, `crates/foxprox-smoltcp/examples/live_bwrap_tcp_smoke.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo run -p foxprox-smoltcp --example live_bwrap_tcp_smoke` (initially failed with `NoConnectAttempt` because live TUN first emitted non-TCP/early packets; fixed the example to pump until an accepted connect is visible before consuming the adapter into a session)
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - final `cargo run -p foxprox-smoltcp --example live_bwrap_tcp_smoke` (passed: `live bwrap TCP smoke passed: live-reply`)
- Observed result: full deterministic verification passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher tests, 95 runtime tests, 10 setup tests, and 40 smoltcp adapter tests passed. The live TCP example launches rootless bwrap, configures a real TUN with `foxproxsetup`, receives the fd over socket handoff, uses smoltcp to accept the sandbox TCP SYN, policy-gates it, opens a real localhost TCP host connection, forwards sandbox bytes to the host, reads the host reply, injects it through smoltcp, and the sandbox process receives `live-reply`.
- Commit hash when committed: pending.
- Remaining risks: examples are smoke harnesses rather than a polished CLI; however the alpha forwarding paths now have both deterministic tests and rootless bwrap live proof for UDP/TUN and TCP/smoltcp/TUN.
- Exact next step: commit live TCP smoke, run both live examples once more, and perform a final alpha-scope audit.

## 2026-06-25T15:08:30Z
- Current objective: final alpha live-smoke audit after rootless bwrap UDP and TCP proof harnesses.
- Files changed: `progress.md` only, amended into prior live TCP smoke checkpoint.
- Verification commands run:
  - `cargo run -p foxprox-launcher --example live_bwrap_udp_smoke`
  - `cargo run -p foxprox-smoltcp --example live_bwrap_tcp_smoke`
- Observed result: both live rootless bwrap examples passed (`pong` for UDP/TUN write-back and `live-reply` for TCP/smoltcp/host bridge). Worktree was clean before this ledger amendment. At this point the alpha prototype has deterministic and live coverage for rootless bwrap TUN setup, fd handoff, capability drop, DNS resolver config, UDP TUN packet reply, TCP smoltcp TUN forwarding to real localhost host sockets, policy/audit gates, explicit HTTP/SOCKS connection-step fail-closed behavior, and setup/launcher planning.
- Commit hash when committed: amended into `c35a10b`.
- Remaining risks/deferred beyond alpha prototype: examples are smoke harnesses rather than a polished long-running CLI daemon; live tests use loopback host sockets and synthetic sandbox clients; additional production work should package the broker event loop and broaden live DNS/proxy scenarios.
- Exact next step: stop and report completion, with commands and commit hash, because documented alpha prototype criteria now have deterministic tests plus rootless bwrap live proof for the critical forwarding paths.

## 2026-06-27T02:36:10Z
- Current objective: build a dedicated production CLI/daemon wrapper for alpha, not just examples.
- Git status summary: clean worktree at start of CLI cycle.
- User requirement: production launcher is part of alpha scope; wrapper must run rootless bwrap, setup TUN, receive fd, and run the broker loop.
- Intended slice: add a `foxprox` CLI binary that launches a sandbox target through rootless bwrap/foxproxsetup with socket handoff and runs an alpha broker loop for transparent TCP port mapping via smoltcp to a configured host socket.
- Verification plan: run formatting, clippy, tests, and a live bwrap CLI smoke using a sandbox Python TCP client against a localhost host TCP server.
- Files expected to change: `crates/foxprox-launcher/Cargo.toml`, new launcher binary source, possibly launcher library helpers, `progress.md`.
- Exact next step: implement manual-arg CLI and live TCP smoke through the binary.

## 2026-06-27T02:44:30Z
- Current objective: add a dedicated production alpha `foxprox` CLI launcher.
- Files changed: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/bin/foxprox.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (initially reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings` (initially caught unused import and useless `format\!`; fixed)
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - Live CLI smoke: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-live --tun-name fpxcli0 --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`; result exit code 0, sandbox printed `cli-reply`, host server received `cli-live`.
- Observed result: added `foxprox run` production alpha wrapper that launches rootless bwrap with `foxproxsetup`, receives the TUN fd through launcher socket handoff, policy-gates one transparent TCP port via smoltcp, bridges sandbox TCP to a configured host `SocketAddr`, and exits with the sandbox target status.
- Remaining risks: current production CLI supports one transparent TCP mapping per invocation and no config file yet; UDP forwarding and proxy listeners remain in runtime/proof harnesses but are not exposed by this first CLI slice.
- Exact next step: run full workspace verification, commit the CLI slice, then extend CLI surface for UDP/proxy or document alpha usage.

## 2026-06-27T02:44:30Z
- Current objective: add a dedicated production alpha `foxprox` CLI launcher.
- Files changed: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/bin/foxprox.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (initially reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings` (initially caught unused import and useless `format!`; fixed)
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - Live CLI smoke: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-live --tun-name fpxcli0 --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`; result exit code 0, sandbox printed `cli-reply`, host server received `cli-live`.
- Observed result: added `foxprox run` production alpha wrapper that launches rootless bwrap with `foxproxsetup`, receives the TUN fd through launcher socket handoff, policy-gates one transparent TCP port via smoltcp, bridges sandbox TCP to a configured host `SocketAddr`, and exits with the sandbox target status.
- Remaining risks: current production CLI supports one transparent TCP mapping per invocation and no config file yet; UDP forwarding and proxy listeners remain in runtime/proof harnesses but are not exposed by this first CLI slice.
- Exact next step: run full workspace verification, commit the CLI slice, then extend CLI surface for UDP/proxy or document alpha usage.

## 2026-06-27T02:47:30Z
- Current objective: finalize dedicated production alpha CLI launcher.
- Files changed: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/bin/foxprox.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-live --tun-name fpxcli0 --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`: passed; sandbox printed `cli-reply`, host received `cli-live`.
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 3 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - final live CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-final --tun-name fpxclif --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`: passed; sandbox printed `cli-final`, host received `cli-final-request`.
- Observed result: production alpha now has a dedicated `foxprox run` binary. It launches rootless bwrap, runs `foxproxsetup`, receives the TUN fd by socket handoff, configures a smoltcp TCP listener on the broker IP, policy-gates the first accepted sandbox TCP connect, opens the configured host TCP endpoint, bridges bytes bidirectionally, and exits with the sandbox target status.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond this CLI slice: the CLI currently exposes one transparent TCP port mapping per invocation and no config file; UDP/proxy runtime pieces exist but are not yet surfaced through `foxprox run` flags. A future daemon iteration should support multiple mappings and configuration files.
- Exact next step: commit the CLI slice, then report usage and remaining limits.

## 2026-06-27T02:47:30Z
- Current objective: finalize dedicated production alpha CLI launcher.
- Files changed: `crates/foxprox-launcher/Cargo.toml`, `crates/foxprox-launcher/src/bin/foxprox.rs`, `Cargo.lock`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-live --tun-name fpxcli0 --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`: passed; sandbox printed `cli-reply`, host received `cli-live`.
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 3 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - final live CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id cli-final --tun-name fpxclif --tcp-listen 8080 --tcp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox tcp client>`: passed; sandbox printed `cli-final`, host received `cli-final-request`.
- Observed result: production alpha now has a dedicated `foxprox run` binary. It launches rootless bwrap, runs `foxproxsetup`, receives the TUN fd by socket handoff, configures a smoltcp TCP listener on the broker IP, policy-gates the first accepted sandbox TCP connect, opens the configured host TCP endpoint, bridges bytes bidirectionally, and exits with the sandbox target status.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond this CLI slice: the CLI currently exposes one transparent TCP port mapping per invocation and no config file; UDP/proxy runtime pieces exist but are not yet surfaced through `foxprox run` flags. A future daemon iteration should support multiple mappings and configuration files.
- Exact next step: commit the CLI slice, then report usage and remaining limits.

## 2026-06-27T02:50:30Z
- Current objective: extend `foxprox run` beyond TCP-only so the production alpha launcher exposes a minimal UDP forwarding path too.
- Git status summary: clean worktree after commit `4ed919a`.
- Intended slice: add `--udp-listen PORT --udp-host HOST:PORT` mode that launches the same rootless bwrap/TUN setup, accepts sandbox UDP addressed to broker-ip:port, forwards it to the configured host UDP socket, and writes a TUN UDP reply back to the sandbox.
- Verification plan: parser tests, launcher package clippy/tests, full workspace checks, and live CLI UDP smoke with a sandbox Python UDP client and localhost UDP host server.
- Files expected to change: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Exact next step: implement mutually exclusive TCP/UDP modes in the CLI.

## 2026-06-27T02:55:30Z
- Current objective: expose a minimal UDP forwarding mode in the production `foxprox run` CLI.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live UDP CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id udp-cli --tun-name fpxudpc --udp-listen 5353 --udp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox udp client>`: passed; sandbox printed `udp-cli-reply`, host UDP server received `udp-cli-live`.
- Observed result: `foxprox run` now supports mutually exclusive TCP and UDP alpha modes. UDP mode launches the same rootless bwrap/TUN setup, accepts sandbox UDP datagrams addressed to broker-ip:listen-port, forwards payloads to the configured host UDP socket, and writes a synthesized IPv4/UDP response back to the sandbox.
- Remaining risks: TCP and UDP modes are still one mapping per invocation; config-file and multi-flow daemon orchestration are future work.
- Exact next step: run full workspace verification, run live TCP and UDP CLI smokes, then commit the UDP CLI mode.

## 2026-06-27T02:55:30Z
- Current objective: expose a minimal UDP forwarding mode in the production `foxprox run` CLI.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live UDP CLI smoke with `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id udp-cli --tun-name fpxudpc --udp-listen 5353 --udp-host 127.0.0.1:<host-port> -- /usr/bin/python3 -c <sandbox udp client>`: passed; sandbox printed `udp-cli-reply`, host UDP server received `udp-cli-live`.
- Observed result: `foxprox run` now supports mutually exclusive TCP and UDP alpha modes. UDP mode launches the same rootless bwrap/TUN setup, accepts sandbox UDP datagrams addressed to broker-ip:listen-port, forwards payloads to the configured host UDP socket, and writes a synthesized IPv4/UDP response back to the sandbox.
- Remaining risks: TCP and UDP modes are still one mapping per invocation; config-file and multi-flow daemon orchestration are future work.
- Exact next step: run full workspace verification, run live TCP and UDP CLI smokes, then commit the UDP CLI mode.

## 2026-06-27T02:59:00Z
- Current objective: finalize TCP+UDP production alpha CLI modes.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live UDP CLI smoke: sandbox sent `udp-cli-live` to `10.66.0.1:5353`, host UDP server received it and replied `udp-cli-reply`, sandbox printed `udp-cli-reply`.
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 5 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - final live TCP CLI smoke: sandbox printed `tcp-again`, host received `tcp-again-request`.
  - final live UDP CLI smoke: sandbox printed `udp-again`, host received `udp-again-request`.
- Observed result: production alpha `foxprox run` supports both TCP and UDP rootless-bwrap/TUN modes. TCP mode bridges one transparent sandbox TCP port through smoltcp to a configured host TCP socket. UDP mode forwards sandbox UDP datagrams addressed to broker-ip:listen-port to a configured host UDP socket and writes synthesized UDP responses back to the sandbox.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond alpha CLI: one mapping per invocation; no config file or multi-flow/multi-mapping daemon orchestration yet; explicit HTTP/SOCKS proxy listener runtimes are still not surfaced as listener flags.
- Exact next step: commit UDP CLI mode, then provide concise usage and limits.

## 2026-06-27T02:59:00Z
- Current objective: finalize TCP+UDP production alpha CLI modes.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run:
  - `cargo fmt --check`
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - live UDP CLI smoke: sandbox sent `udp-cli-live` to `10.66.0.1:5353`, host UDP server received it and replied `udp-cli-reply`, sandbox printed `udp-cli-reply`.
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 5 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - final live TCP CLI smoke: sandbox printed `tcp-again`, host received `tcp-again-request`.
  - final live UDP CLI smoke: sandbox printed `udp-again`, host received `udp-again-request`.
- Observed result: production alpha `foxprox run` supports both TCP and UDP rootless-bwrap/TUN modes. TCP mode bridges one transparent sandbox TCP port through smoltcp to a configured host TCP socket. UDP mode forwards sandbox UDP datagrams addressed to broker-ip:listen-port to a configured host UDP socket and writes synthesized UDP responses back to the sandbox.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond alpha CLI: one mapping per invocation; no config file or multi-flow/multi-mapping daemon orchestration yet; explicit HTTP/SOCKS proxy listener runtimes are still not surfaced as listener flags.
- Exact next step: commit UDP CLI mode, then provide concise usage and limits.

## 2026-06-27T03:04:30Z
- Current objective: support `curl http://example.com` through the production CLI.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - Live real-site CLI smoke: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id curl-example --tun-name fpxcurl --tcp-domain example.com:80 -- /usr/bin/curl -fsS --max-time 10 http://example.com/`; passed and returned the Example Domain HTML. This exercises broker DNS aliasing for `example.com` to the broker TUN IP, smoltcp TCP accept on port 80, host DNS resolution of `example.com:80`, host TCP connect, and bidirectional bridge back to curl.
- Observed result: `foxprox run --tcp-domain example.com:80 -- curl http://example.com/` now works for real HTTP sites. `--tcp-domain HOST:PORT` automatically adds a broker DNS alias for HOST and maps sandbox traffic for that port to the host-resolved real endpoint.
- Remaining risks: domain mode currently aliases DNS to the broker IP for the specified hostname and maps a single TCP port; HTTPS/SNI and multiple domains need later config-file support.
- Exact next step: run full workspace verification and live TCP/UDP/domain smokes, then amend/commit CLI updates.

## 2026-06-27T03:04:30Z
- Current objective: support `curl http://example.com` through the production CLI.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`.
- Verification commands run so far:
  - `cargo fmt --check` (reported formatting drift; fixed with `cargo fmt`)
  - `cargo clippy -p foxprox-launcher --all-targets --all-features -- -D warnings`
  - `cargo test -p foxprox-launcher --all-targets --all-features`
  - `cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-launcher --bin foxprox`
  - Live real-site CLI smoke: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id curl-example --tun-name fpxcurl --tcp-domain example.com:80 -- /usr/bin/curl -fsS --max-time 10 http://example.com/`; passed and returned the Example Domain HTML. This exercises broker DNS aliasing for `example.com` to the broker TUN IP, smoltcp TCP accept on port 80, host DNS resolution of `example.com:80`, host TCP connect, and bidirectional bridge back to curl.
- Observed result: `foxprox run --tcp-domain example.com:80 -- curl http://example.com/` now works for real HTTP sites. `--tcp-domain HOST:PORT` automatically adds a broker DNS alias for HOST and maps sandbox traffic for that port to the host-resolved real endpoint.
- Remaining risks: domain mode currently aliases DNS to the broker IP for the specified hostname and maps a single TCP port; HTTPS/SNI and multiple domains need later config-file support.
- Exact next step: run full workspace verification and live TCP/UDP/domain smokes, then amend/commit CLI updates.

## 2026-06-27T03:08:00Z
- Current objective: finalize real-site curl support.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 6 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - Live real-site CLI smoke re-run unsandboxed: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id curl-example2 --tun-name fpxcur2 --tcp-domain example.com:80 -- /usr/bin/curl -fsS --max-time 10 http://example.com/`; passed and returned the Example Domain HTML.
- Observed result: user can now curl a real HTTP website by using `--tcp-domain example.com:80` and running curl against `http://example.com/` inside the launched sandbox.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond this slice: HTTPS support needs `--tcp-domain example.com:443` and policy/SNI hardening; arbitrary multiple-domain/multiple-port routing still needs config-file driven daemon mode.

## 2026-06-27T03:08:00Z
- Current objective: finalize real-site curl support.
- Files changed: `crates/foxprox-launcher/src/bin/foxprox.rs`, `progress.md`, `learnings.md`.
- Verification commands run:
  - full workspace `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`: passed; 55 core tests, 9 device tests, 4 integration tests, 7 launcher library tests, 6 `foxprox` CLI tests, 95 runtime tests, 10 setup tests, and 40 smoltcp tests passed.
  - Live real-site CLI smoke re-run unsandboxed: `target/debug/foxprox run --setup-bin target/debug/foxproxsetup --sandbox-id curl-example2 --tun-name fpxcur2 --tcp-domain example.com:80 -- /usr/bin/curl -fsS --max-time 10 http://example.com/`; passed and returned the Example Domain HTML.
- Observed result: user can now curl a real HTTP website by using `--tcp-domain example.com:80` and running curl against `http://example.com/` inside the launched sandbox.
- Commit hash when committed: pending.
- Remaining risks/deferred beyond this slice: HTTPS support needs `--tcp-domain example.com:443` and policy/SNI hardening; arbitrary multiple-domain/multiple-port routing still needs config-file driven daemon mode.
