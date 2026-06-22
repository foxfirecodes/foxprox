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
