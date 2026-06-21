# Progress Ledger

## 2026-06-21T16:42:34Z — Session start

- Current objective: implement the autonomous-crew alpha scope from `docs/implementation-approach-autonomous-crew.md`, beginning with Rust broker foundations that respect `docs/arch.md` and `docs/initial-impl.md`.
- Source docs read: `docs/implementation-approach-autonomous-crew.md`, `docs/arch.md`, `docs/initial-impl.md`, `docs/bubblewrap-fork.md`.
- Current state: workspace contains `foxprox-core` only, with a minimal crate marker and no alpha broker model yet.
- Verification plan for first commit boundary: add platform-independent core/policy/audit/config types with unit tests; run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Expected commit boundary: coherent foundation commit for normalized events, audit schema, policy decisions/rules, config defaults, and fail-closed packet classification types in `foxprox-core`.
- Subagents/reviews requested: none yet.
- Commands run and outcomes: `git status --short --branch` showed clean `autonomous-crew`; source docs and initial crate files read successfully.
- Files changed: `progress.md` created.
- Current git status summary: clean before ledger creation.
- Next exact action: implement core foundation modules in `crates/foxprox-core` and add tests.

## 2026-06-21T16:54:22Z — Core foundation implemented and reviewed

- Current objective: finish and commit the first platform-independent `foxprox-core` foundation before moving to Milestone 0/1 TUN setup proof.
- Changes implemented:
  - Added normalized event model in `crates/foxprox-core/src/event.rs` for TCP, UDP, DNS, HTTP, HTTPS CONNECT, TLS ClientHello, SOCKS CONNECT, ICMP, setup/session, and unsupported fail-closed events.
  - Added flow keys and UDP timeout classes in `crates/foxprox-core/src/flow.rs`.
  - Added deterministic policy model in `crates/foxprox-core/src/policy.rs` with default deny, direct DNS bypass guard, multicast/broadcast guard, TLS SNI/DNS mismatch and hidden-SNI guards, IP/CIDR/port/hostname/domain rules, and fail-closed unsupported handling.
  - Added structured audit schema in `crates/foxprox-core/src/audit.rs` with policy decision, endpoint, attribution, byte count, flow duration, and HTTP metadata fields.
  - Added platform-independent config data in `crates/foxprox-core/src/config.rs` for TUN, DNS, proxy env, UDP timeouts, policy, and audit defaults.
  - Kept `foxprox-core` dependency-free and `#![forbid(unsafe_code)]`/`#![deny(missing_docs)]`.
- Subagents/reviews requested:
  - `context-builder` wrote `context-build/core-foundation.md`; key recommendation was a no-dependency core foundation with normalized events, policy, audit, config, and flow types before Linux/TUN work.
  - Rust correctness reviewer found required fixes: semantic HTTP/SOCKS port matching, direct DNS bypass too narrow, audit missing HTTP metadata, contradictory SOCKS port representation.
  - Architecture reviewer found required fixes: direct DNS bypass too narrow, directed broadcast configuration gap, TLS mismatch/hidden-SNI not enforced, invalid port ranges accepted.
- Accepted findings and fixes:
  - Accepted HTTP/SOCKS port matching: added event port extraction independent of IP endpoint and added regression tests.
  - Accepted SOCKS contradiction risk: replaced separate SOCKS host/destination/port fields with `SocksDestination` enum.
  - Accepted direct DNS bypass issue: TCP/UDP destination port 53 now requires broker DNS before allow rules, regardless of UDP classification; regression test covers broad UDP allow.
  - Accepted audit HTTP metadata issue: added structured `origin`, `http_method`, and `path_and_query` audit fields and builder.
  - Accepted directed broadcast issue: policy now has configured broadcast addresses; default broker config adds the default TUN `/24` directed broadcast.
  - Accepted TLS mismatch/hidden-SNI issue: added default guards and tests; hidden SNI requires explicit IP/CIDR allow.
  - Accepted invalid port range issue: `PortRange::new` is now fallible; `PortRange::single` remains infallible.
- Rejected/deferred findings: no rejected reviewer findings for this commit; concrete egress traits are deferred to a later commit because first boundary is core schema/policy only.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 22 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed after replacing Rust 1.82-only `Option::is_none_or` with `map_or` for MSRV 1.80 compatibility.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` showed `foxprox-core` only, confirming no new dependencies.
- Files changed: `crates/foxprox-core/src/lib.rs`, new `audit.rs`, `config.rs`, `event.rs`, `flow.rs`, `policy.rs`, `progress.md`, `learnings.md`.
- Current git status summary: modified `crates/foxprox-core/src/lib.rs`; new core module files and ledgers; temporary subagent artifact dirs still untracked pending cleanup/summarization.
- Next exact action: read final blocker review, apply any required fix, re-run verification, remove transient subagent artifact directories from the worktree, then commit the verified core foundation.

## 2026-06-21T16:58:18Z — Final core blocker fixed

- Current objective: commit verified `foxprox-core` foundation.
- Final blocker review: `core-final-blockers` found one required fix: TLS SNI/DNS mismatch was represented by a caller-supplied boolean and could be bypassed by inconsistent event construction.
- Accepted finding and fix: policy now derives mismatch from `sni` and `dns_hostname` inside core policy, treating the caller boolean only as additional evidence; added regression `tls_mismatch_is_derived_even_if_caller_flag_is_false`.
- Verification commands and outcomes after final fix:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 23 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` showed only `foxprox-core`.
- Environment prerequisites checked for next milestone: `/dev/net/tun` exists, `bwrap` is `/usr/bin/bwrap`, and unprivileged user namespaces are enabled (`/proc/sys/kernel/unprivileged_userns_clone` = `1`).
- Files changed: core module files plus `progress.md` and `learnings.md`.
- Current git status summary: source and ledgers changed; subagent artifact directories removed from worktree.
- Next exact action: commit core foundation, then start Milestone 0/1 TUN setup and ICMP write-back proof using one writer thread.

## 2026-06-21T16:59:10Z — Core foundation committed; next objective selected

- Commit created: `1dcd576` (`add core broker foundation`).
- Current objective: start Milestone 1-safe packet proof code before wiring Linux setup: implement dependency-free IPv4/ICMPv4 parsing and synthetic echo-reply generation in a new device/packet crate.
- Rationale: this advances Packet Write-Back Proof mechanics while keeping Linux TUN/bwrap setup separate and preserving the core crate boundary.
- Verification plan: add focused unit tests for valid echo request reply, checksum correctness, unsupported fragmentation/protocol/type drops, and malformed packet rejection; run full workspace fmt/check/test/clippy/doc.
- Expected commit boundary: `foxprox-device` packet proof library plus progress update.
- Next exact action: add `crates/foxprox-device` and implement ICMPv4 echo reply synthesis without adding dependencies to `foxprox-core`.

## 2026-06-21T17:04:49Z — Device packet proof verified

- Current objective: commit dependency-free `foxprox-device` IPv4/ICMPv4 packet proof helpers.
- Changes implemented:
  - Added workspace crate `crates/foxprox-device` depending only on `foxprox-core`.
  - Added fail-closed IPv4 packet metadata parsing with validation for version, IHL, total length, unsupported options, unsupported fragmentation, and IPv4 header checksum.
  - Added ICMPv4 metadata parsing and echo-reply synthesis for valid echo requests addressed to the configured broker/gateway IP.
  - Echo replies swap IPv4 source/destination, set TTL, preserve identifier/sequence/payload, and recompute IPv4 and ICMP checksums.
  - Added conversion helpers from packet drop reasons to normalized `NetworkEvent::Unsupported` and ICMP messages to `NetworkEvent::IcmpMessage`.
- Subagents/reviews requested:
  - `device-packet-proof-blockers` reviewer found one blocker: incoming ICMPv4 checksums were not validated before reply synthesis.
- Accepted finding and fix:
  - Added `PacketDropReason::InvalidIcmpv4Checksum`, fail-closed checksum validation before echo reply synthesis, and regression test `drops_invalid_icmp_checksum`.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 23 core tests and 8 device tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still showed only `foxprox-core`, confirming no dependency creep into core.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-device/Cargo.toml`, `crates/foxprox-device/src/lib.rs`, `progress.md`.
- Current git status summary: uncommitted packet proof crate and progress update; review artifacts removed.
- Next exact action: commit packet proof, then start Linux setup/broker proof crates to create/configure TUN and write synthesized ICMP replies through an actual fd.

## 2026-06-21T17:10:50Z — Linux setup/broker proof implemented pending review

- Current objective: verify and commit initial Linux `foxproxsetup` and `foxprox proof-icmp` binaries for Milestone 0/1 wiring.
- Changes implemented:
  - Added workspace crates `foxprox-setup` (binary `foxproxsetup`) and `foxprox-cli` (binary `foxprox`).
  - `foxproxsetup` parses setup options, creates `IFF_TUN | IFF_NO_PI` via `/dev/net/tun` and `TUNSETIFF`, configures loopback/interface/address/MTU/default route using `ip`, sends the TUN fd over a Unix socket with `SCM_RIGHTS`, drops `CAP_NET_ADMIN`, closes setup fds, then `exec`s the target.
  - `foxprox proof-icmp` listens on a Unix setup socket, receives the TUN fd, logs IPv4/ICMP metadata, synthesizes ICMP echo replies using `foxprox-device`, and drops/logs unsupported packets.
  - Interface names are validated to avoid silent truncation, and existing socket paths are not unlinked automatically.
- Subagents/reviews requested: parallel setup/broker proof review and security review are running.
- Verification commands and outcomes so far:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` showed no dependency creep; setup/CLI dependency trees are limited to `caps`, `libc`, `nix`, and existing foxprox crates.
- Files changed: `Cargo.toml`, `Cargo.lock`, new `crates/foxprox-setup`, new `crates/foxprox-cli`, `progress.md`.
- Current git status summary: uncommitted setup/broker proof crates and progress update.
- Next exact action: read reviewer blockers, apply required fixes, re-run verification, then commit.

## 2026-06-21T17:14:20Z — Setup/broker proof review fixes and live validation

- Current objective: commit initial Linux setup/broker proof for Milestone 0/1.
- Review findings accepted and fixed:
  - Bounding-set `CAP_NET_ADMIN` drop failed under documented bwrap `CAP_NET_ADMIN`-only model: changed bounding-set drops to best-effort while required effective/permitted/inheritable/ambient drops remain enforced and `PR_SET_NO_NEW_PRIVS` is set.
  - `ip` lookup used `PATH` with setup privileges: changed to trusted absolute `/usr/bin/ip` with `env_clear()` for each setup command. Full in-process netlink remains a later hardening improvement.
  - Setup fd handoff had no broker-ready acknowledgment: `foxproxsetup` now waits for `ready\n` from broker before dropping setup fds/caps and execing target; broker sends ack after receiving and validating one fd.
  - Broker accepted first fd too loosely: receive side now requires exactly one SCM_RIGHTS fd and verifies peer uid via `SO_PEERCRED`.
  - Target fd/cap inheritance: setup now clears all effective/permitted/inheritable/ambient capabilities by default, can intentionally keep `CAP_NET_RAW` only for ping proof via `--keep-cap-net-raw-for-ping`, sets `no_new_privs`, and closes fds 3..1023 before exec.
  - Existing socket path is no longer unlinked by broker; socket permissions are set to `0600` after bind.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 23 core tests and 8 device tests; CLI/setup compile test binaries have 0 unit tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo build --workspace --bins` passed.
  - Live bwrap/TUN validation passed with command shape: broker `foxprox proof-icmp --setup-socket $sock`; bwrap with `--unshare-user --unshare-net --cap-add CAP_NET_ADMIN --cap-add CAP_NET_RAW --bind / / --dev-bind /dev/net/tun /dev/net/tun --proc /proc -- foxproxsetup --setup-socket $sock --keep-cap-net-raw-for-ping -- /bin/ping -n -c 1 -W 1 10.255.0.1`. Ping received one synthetic reply; broker logged inbound IPv4 ICMP echo request and outbound echo reply.
- Rejected/deferred findings: replacing `/usr/bin/ip` shellout with in-process netlink is deferred; current proof uses absolute trusted path plus scrubbed environment. Production setup should move to netlink.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-setup`, `crates/foxprox-cli`, `progress.md`.
- Current git status summary: uncommitted setup/broker proof and progress update; review artifacts removed.
- Next exact action: commit setup/broker proof, then continue toward alpha Milestone 2 smoltcp TCP forwarding gate.

## 2026-06-21T17:29:00Z — Milestone 2 smoltcp TCP proof implemented pending review

- Current objective: verify and commit Milestone 2 smoltcp TCP forwarding gate.
- Context used: `context-build/smoltcp-gate.md` recommended smoltcp `0.12.0` for MSRV 1.80, a separate `foxprox-net` crate, `Medium::Ip`, nonblocking TUN fd, AnyIP, and TCP validation with curl `--resolve` to avoid the DNS/UDP gap.
- Changes implemented:
  - Added workspace crate `crates/foxprox-net` with smoltcp `=0.12.0` and features `std`, `medium-ip`, `phy-tuntap_interface`, `proto-ipv4`, `socket-tcp`.
  - Added `TcpProofConfig` and `run_tcp_proof()` that consumes a received TUN fd, sets it nonblocking, wraps it with `smoltcp::phy::TunTapInterface::from_fd(..., Medium::Ip, mtu)`, configures broker IP, AnyIP, and a default IPv4 route.
  - Added a narrow TCP bridge proof for one configured destination port (default 80): a smoltcp listening TCP socket accepts sandbox connections, logs a normalized `TcpConnectAttempt`, opens a host `TcpStream` to the original destination, and bridges bytes in both directions with bounded pending buffers.
  - Added `foxprox proof-tcp` CLI command reusing the setup-socket peer credential check, exact-one-fd receive, and broker-ready ack before handing the fd to `foxprox-net`.
- Verification commands and outcomes so far:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - Live validation passed: with broker `foxprox proof-tcp --setup-socket $sock --tcp-port 80`, bwrap+`foxproxsetup`, and sandbox `/usr/bin/curl --noproxy '*' --max-time 10 -v --resolve example.com:80:<resolved-ip> http://example.com/`, curl received an HTTP 200 response. Broker logged TCP connect from `10.255.0.2:<port>` to `<resolved-ip>:80` and an allow `TcpConnectAttempt`.
- Subagents/reviews requested: parallel smoltcp proof blocker review and security/correctness review are running.
- Current limitations intentionally accepted for proof: only one configured TCP port/listening socket; DNS/UDP is not implemented, so validation uses pre-resolved curl `--resolve`; connect is blocking with timeout; full arbitrary-port transparent forwarding is deferred.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-net`, `crates/foxprox-cli`, `progress.md`; `context-build/smoltcp-gate.md` is an untracked subagent artifact to remove before commit.
- Current git status summary: uncommitted smoltcp proof plus context/review artifacts.
- Next exact action: read reviewer blockers, apply required fixes, re-run validation, remove artifacts, and commit Milestone 2 proof.

## 2026-06-21T17:37:55Z — smoltcp proof blocker fixes applied

- Current objective: finish review/commit for the smoltcp TCP forwarding proof.
- Review findings accepted and fixed:
  - Listener/ready race: `foxprox-net` now installs the smoltcp TCP listener before the first `iface.poll()`, and `foxprox proof-tcp` sends broker `ready\n` through a callback only after stack/listener initialization succeeds.
  - Flow I/O errors killing broker: per-flow pump/connect errors are now logged, the smoltcp socket is aborted, the flow is dropped, and the broker resumes listening instead of returning from `run_tcp_proof`.
  - Blocking host connect: host `TcpStream::connect_timeout` now runs in a connector worker while the main loop continues polling smoltcp; sandbox bytes received while connecting are buffered up to the configured cap.
  - Idle/half-close pinning: active flows now track `last_activity`, enforce `idle_timeout`, and propagate sandbox receive-half close to host with `shutdown(Write)` once pending sandbox->host bytes are drained.
  - Negative validation gap: added a `foxprox-net` config unit test and ran a live negative port smoke where broker listened on port 80 and sandbox curl to resolved example.com:81 failed (curl status 7) with no forwarded connection logged.
- Verification commands and outcomes after fixes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 23 core tests, 8 device tests, 1 net test.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows only `foxprox-core`.
  - `cargo tree -p foxprox-net -e features` confirms smoltcp 0.12.0 with `medium-ip`, `phy-tuntap_interface`, `proto-ipv4`, and `socket-tcp`.
  - Positive live validation re-run passed: sandbox curl with `--resolve example.com:80:<ip>` received a 559-byte HTTP response; broker logged host connected and flow closed with byte counts.
  - Negative live validation passed: sandbox curl to `example.com:81` while proof listens on 80 failed with curl status 7 and no forwarded connection.
- Remaining known limitation: literal `curl http://example.com` still depends on UDP/DNS support and is deferred to Milestone 4; this commit is the TCP forwarding gate, not the DNS foundation.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-net`, `crates/foxprox-cli`, `progress.md`; review/context artifacts still untracked pending final blocker review.
- Next exact action: read final blocker review, apply any remaining required fix, remove artifacts, and commit.

## 2026-06-21T17:48:30Z — Milestone 2 smoltcp TCP proof verified

- Current objective: commit Milestone 2 smoltcp TCP forwarding gate.
- Final blocker review: found one remaining blocker where host connect failures still propagated via `connecting.try_finish()?` and could terminate `run_tcp_proof`.
- Accepted finding and fix: host connect errors are now caught in the connecting-flow state, logged as `host connect failed`, the smoltcp socket is aborted, the flow is cleared, and the listener resumes without terminating the broker.
- Additional validation after final fix:
  - Positive TCP forwarding: sandbox curl with `--resolve example.com:80:<ip>` returned a 559-byte HTTP response through `foxprox proof-tcp`; broker logged host connected and flow closed with byte counts.
  - Non-configured port negative: broker listening on 80 did not forward sandbox curl to `example.com:81`.
  - Configured-port host-connect failure recovery: sandbox first tried `http://10.255.0.1/` on configured port 80, broker logged `host connect failed: connection timed out`, resumed listening, then a second sandbox curl to resolved `example.com:80` succeeded with a 559-byte response.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 23 core tests, 8 device tests, 1 net test.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows no smoltcp dependency.
  - `cargo tree -p foxprox-net -e features` confirms smoltcp 0.12.0 with `medium-ip`, `phy-tuntap_interface`, `proto-ipv4`, and `socket-tcp`.
- Commit scope: `foxprox-net` smoltcp TCP proof, `foxprox proof-tcp` CLI, workspace dependency updates, and this progress ledger.
- Known limitation: this is the TCP forwarding gate with pre-resolved addresses. Literal `curl http://example.com` remains deferred until UDP/DNS foundation work.
- Current git status summary: uncommitted Milestone 2 proof; context/review artifacts removed.
- Next exact action: commit, then begin Milestone 3 minimal broker core / Milestone 4 UDP-DNS foundation planning depending on safest serial order.

## 2026-06-21T17:50:30Z — smoltcp proof committed; next objective selected

- Commit created: `15dafce` (`add smoltcp tcp proof`).
- Current objective: close remaining Minimal Broker Core gaps before deeper UDP/DNS work.
- Rationale: `foxprox-core` already has normalized events, config schema, audit schema, flow keys, and minimal policy. The remaining Milestone 3-shaped foundation is shared egress/frontend abstraction so future TCP, UDP, DNS, proxy, and TUN adapters can share typed boundaries without leaking implementation details.
- Verification plan: add dependency-free core traits/types for frontend sources and egress requests/outcomes, unit-test conversion from normalized events where useful, and run full fmt/check/test/clippy/doc plus `cargo tree -p foxprox-core`.
- Expected commit boundary: small `foxprox-core` abstraction commit and progress update.
- Subagents/reviews requested: `context-builder` is building next-milestone context to validate/de-risk this choice.
- Next exact action: add core frontend/egress modules without adding dependencies or touching Linux/smoltcp crates.

## 2026-06-21T18:02:00Z — core frontend/egress abstraction verified

- Current objective: commit the remaining Minimal Broker Core boundary types.
- Context-builder recommendation: finish and commit Milestone 3 before UDP/DNS; current core already satisfies normalized events, audit schema, config schema, and policy model, leaving shared egress traits and frontend abstraction.
- Reviewer result: no blockers. Notes addressed before commit:
  - Removed `FrontendEvent` wrapper so frontend normalization returns plain `NetworkEvent` values and avoids duplicated/mismatched sandbox/frontend identity.
  - Clarified `EgressContext.decision` semantics and added `EgressContext::is_allowed()` so host egress implementations can fail closed unless policy allowed the request.
- Added dependency-free `foxprox-core` modules:
  - `frontend.rs`: `FrontendContext`, `FrontendError`, `FrontendErrorKind`, `NetworkFrontend`.
  - `egress.rs`: `EgressContext`, TCP/UDP/DNS egress request types, `EgressOutcome`, `EgressError`, `EgressErrorKind`, and TCP/UDP/DNS egress traits.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 27 core tests, 8 device tests, 1 net test.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows only `foxprox-core`, confirming no dependency creep.
- Next exact action: remove context/review artifacts and commit `add core frontend and egress abstractions`.

## 2026-06-21T18:09:00Z — UDP/DNS data foundation verified

- Current objective: start Milestone 4 with platform-independent data types before live UDP/DNS forwarding.
- Added `foxprox-core::dns` data model:
  - `DnsQueryType` with normalized `A`/`AAAA`/other labels.
  - `DnsObservation` for broker-controlled query observations.
  - `DnsCacheEntry` with TTL/expiry and medium-confidence DNS-cache attribution.
  - `DnsCache` with hostname lookup, reverse address lookup, and expiry.
- Extended `foxprox-core::flow` with UDP pseudo-flow runtime state:
  - `UdpFlowRecord` with key, timeout class, attribution, activity timestamps, and byte counters.
  - `UdpFlowTable` with sandbox/host datagram accounting and deterministic expiry.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 31 core tests, 8 device tests, 1 net test.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows only `foxprox-core`, confirming no dependency creep.
- Commit boundary: core UDP pseudo-flow and DNS cache shape only; no live smoltcp UDP/DNS proof yet.
- Next exact action: commit, then implement broker-reachable DNS/UDP proof in `foxprox-net` and CLI.
