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

## 2026-06-21T18:18:00Z — DNS parser and audit metadata verified

- Current objective: complete the core-only half of Milestone 4 before live UDP/DNS proof.
- Planner recommendation received: add dependency-free DNS wire parsing and DNS audit metadata before `foxprox-net` UDP socket work.
- Added core DNS wire parsing:
  - `parse_dns_query` for single-question UDP DNS queries.
  - `parse_dns_response` for UDP DNS responses with bounded compressed-name parsing and A/AAAA answer extraction.
  - `DnsQuestion`, `DnsResponseObservation`, `DnsAddressRecord`, and `DnsParseError`.
  - Tests for A query parsing, compressed A response parsing, malformed/truncated packet rejection, and compression-pointer loop rejection.
- Extended audit schema with DNS metadata fields and `with_dns_metadata` builder:
  - `dns_query_type`, `dns_rcode`, and `dns_answers`.
- Updated `DnsQueryType` to retain unknown wire types by numeric RR type code.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 35 core tests, 8 device tests, 1 net test.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows only `foxprox-core`, confirming no dependency creep.
- Commit boundary: core DNS parser/audit metadata only; no smoltcp UDP changes.
- Next exact action: commit, then implement `foxprox-net` UDP/DNS proof with `socket-udp` and CLI command.

## 2026-06-21T18:36:00Z — UDP/DNS proof implemented and validated pending review

- Current objective: commit Milestone 4 live UDP/DNS proof after final blocker review.
- Added `foxprox-net` UDP/DNS proof:
  - Enabled smoltcp `socket-udp` feature.
  - Added `UdpDnsProofConfig` and `run_udp_dns_proof_with_ready`.
  - Bound a broker DNS UDP socket on port 53 after stack setup and sends `ready\n` only after sockets are installed.
  - Broker DNS path parses sandbox DNS queries, forwards raw UDP DNS to configured upstream, parses/cache-logs A/AAAA responses, and sends the unmodified response back to the sandbox from `10.255.0.1:53`.
  - Direct external DNS attempts to non-broker destination IPs on port 53 are logged as direct DNS bypass and dropped (no host UDP socket opened).
  - Added configured generic UDP proof ports via repeatable `--udp-forward-port`; each configured port forwards datagrams to the original destination and returns one host response, recording UDP pseudo-flow bytes.
- Added CLI command: `foxprox proof-udp-dns --setup-socket PATH [--upstream-dns IP:PORT] [--udp-forward-port PORT]...`.
- Deterministic validation:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 35 core tests, 8 device tests, 2 net tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-net -e features` confirms smoltcp `socket-udp` alongside `socket-tcp`, `medium-ip`, and `proto-ipv4`.
- Live validation:
  - Broker DNS positive: sandbox Python UDP DNS client queried `@10.255.0.1 example.com A`; received a DNS response from `10.255.0.1:53` with `ANCOUNT=2`; broker logged query, cached A answers, and response.
  - Direct external DNS negative: sandbox Python UDP DNS client queried `@1.1.1.1 example.com A`; client timed out as expected; broker logged `deny direct DNS bypass` for destination `1.1.1.1:53`.
  - Generic UDP forwarding positive: host Python UDP echo on host IP port 12345 plus broker `--udp-forward-port 12345`; sandbox Python UDP client received `echo:hello` from the original host IP/port; broker logged UDP forward and response byte counts.
- Known limitations:
  - DNS live validation uses a small Python UDP client because `dig`/`nslookup` abort inside this bwrap environment (`uv.c` fd runtime check) and installed libcurl lacks usable `--dns-servers` support.
  - Generic UDP proof is one-response-per-datagram and proof-scoped, not a production async UDP socket manager yet.
- Final review requested: `reviews/udp-dns-final-blockers.md`.

## 2026-06-21T21:57:00Z — UDP/DNS final review blockers fixed

- Reviewer retry was run with `gpt-5.5` after provider/auth failures with other model overrides.
- Final reviewer blockers accepted and fixed:
  - Host UDP/DNS forwarding no longer blocks the smoltcp poll loop. DNS upstream forwarding and generic UDP host forwarding now run in per-datagram worker threads and return results over an `mpsc` channel while the broker continues polling the TUN/smoltcp stack.
  - Per-datagram errors no longer terminate the proof broker. Datagram handler errors, host UDP/DNS errors, oversized/full smoltcp UDP send failures, and unsupported response-address cases are logged and dropped; the broker loop continues.
- Re-validation after fixes:
  - Broker DNS positive: sandbox Python UDP DNS client queried `@10.255.0.1 example.com A`, received a DNS response from `10.255.0.1:53` with `ANCOUNT=2`, and broker logged DNS cache answers.
  - Direct external DNS negative: sandbox Python UDP DNS client queried `@1.1.1.1 example.com A`, timed out as expected, and broker logged `deny direct DNS bypass` without opening host UDP forwarding.
  - Generic UDP forwarding positive: host Python UDP echo on host IP port 12345 plus broker `--udp-forward-port 12345`; sandbox Python UDP client received `echo:hello` from original host IP/port and broker logged UDP forward/response.
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 35 core tests, 8 device tests, 2 net tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-net -e features` confirms smoltcp `socket-udp` alongside existing TCP/TUN/IP features.
- Remaining known limitation: UDP worker concurrency is proof-scoped and unbounded; production resource limits are Milestone 7 work.

## 2026-06-21T22:01:00Z — UDP/DNS proof rereview passed

- Final rereview result: no blockers.
- Reviewer confirmed:
  - Host UDP/DNS blocking I/O is isolated in worker threads, not the smoltcp poll loop.
  - Per-datagram host/send errors are logged/dropped and do not terminate the broker.
  - smoltcp UDP metadata/source handling is correct for broker DNS and generic UDP responses.
  - Direct external DNS fails closed before host UDP forwarding.
  - Readiness is signaled only after UDP sockets are bound/added.
  - `cargo +1.80.0 check -p foxprox-net`, workspace check/test/clippy, and net dependency review passed.
- Next exact action: remove review artifacts and commit the Milestone 4 UDP/DNS proof.

## 2026-06-21T22:09:00Z — transparent inspection core verified

- Current objective: start Milestone 5 Transparent Policy and Attribution with dependency-free inspection helpers.
- Added `foxprox-core::inspection`:
  - `parse_http_request_head` extracts HTTP method, Host-origin, path/query, and high-confidence Host-header attribution.
  - `parse_tls_client_hello` extracts visible TLS SNI and detects ECH extension presence for hidden-SNI policy paths.
  - `TlsClientHelloInspection::mismatches_dns` supports SNI/DNS mismatch decisions.
  - `classify_udp_candidate` classifies UDP/443 as a QUIC candidate.
- Added tests for HTTP Host/method/path parsing, missing Host fail-closed behavior, TLS SNI/ECH parsing, SNI/DNS mismatch comparison, and QUIC candidate classification.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test --workspace` passed: 40 core tests, 8 device tests, 2 net tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still shows only `foxprox-core`, confirming no dependency creep.
- Commit boundary: core transparent inspection helpers only; no dataplane integration yet.

## 2026-06-21T22:20:17Z — Session continuation

- Current objective: continue autonomous alpha implementation after committed transparent inspection helpers, starting with the next Milestone 5/6-safe core boundary before deeper dataplane/proxy work.
- Source docs/steering read: `docs/implementation-approach-autonomous-crew.md`, `docs/arch.md`, `docs/initial-impl.md`, `docs/bubblewrap-fork.md`, `progress.md`, and `learnings.md`.
- Current state: git status is clean on branch `autonomous-crew`; latest commits include UDP/DNS proof and transparent inspection helpers. Implemented milestone coverage includes core policy/audit/config/events, TUN setup/ICMP proof, smoltcp TCP proof, UDP/DNS proof, DNS cache/parser, and standalone HTTP/TLS/QUIC inspection helpers.
- Active objective for this slice: add missing policy expressiveness for HTTP method/path/origin matching and TLS/QUIC attribution decisions so Milestone 5 policy can evaluate metadata that inspection already extracts.
- Verification plan: focused unit tests for HTTP method/path/origin policy, SNI/domain rules, and QUIC classification rules; then run `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps`, and `cargo tree -p foxprox-core`.
- Expected commit boundary: dependency-free `foxprox-core` policy/config improvements only; no Linux/TUN/smoltcp/proxy dataplane changes in this slice.
- Subagents/reviews requested: async read-only `context-builder` (`context-build/alpha-gap-next-slice.md`) and `reviewer` (`reviews/m5-m6-gap-review.md`) to validate remaining alpha gaps and next slice.
- Commands run and outcomes: `git status --short --branch` showed clean `autonomous-crew`; source files in `crates/foxprox-core`, `foxprox-net`, and `foxprox-cli` inspected.
- Files changed: `progress.md` updated for session continuation.
- Current git status summary: clean before this ledger update.
- Next exact action: implement the core policy metadata match fields and tests while read-only subagents run.

## 2026-06-21T22:26:48Z — core policy metadata slice verified

- Current objective: commit the Milestone 5 policy metadata vocabulary slice before wiring dataplane inspection.
- Changes implemented:
  - Added `ech_present` to `NetworkEvent::TlsClientHello` so ECH is represented explicitly in normalized TLS metadata.
  - Extended `PolicyRule` with origin scheme, HTTP method allow-list, and HTTP path/query prefix match fields plus builder methods.
  - Policy matching now evaluates HTTP origin scheme, method, and path prefix in addition to existing host/domain/port/protocol rules.
  - Hidden-SNI fail-closed precheck now treats either missing SNI or ECH-present TLS as hidden unless an explicit unconstrained IP/CIDR/port TLS allow rule exists.
  - Added regression coverage for HTTP method/path matching, visible SNI domain allow, QUIC domain attribution rule matching, ECH fail-closed and explicit-IP allow override, and an HTTP-constrained IP allow not bypassing hidden-SNI.
- Subagents/reviews requested and findings:
  - `context-builder` wrote `context-build/alpha-gap-next-slice.md`; recommendation matched the selected policy metadata slice and identified UDP/DNS attribution + QUIC classification as the next likely slice after commit.
  - `m5-m6-gap-review` found initial WIP compile/test gaps from the new `ech_present` field and broader remaining M5/M6 dataplane/proxy gaps. The compile/test blocker was fixed by updating all TLS test initializers and adding ECH regression coverage. Runtime policy/DNS/proxy gaps are accepted as follow-on slices.
  - `core-policy-metadata-final` found a blocker where HTTP/origin-constrained IP allow rules could incorrectly suppress hidden-SNI/ECH fail-closed. Fixed `has_explicit_ip_allow` to require no hostname/domain/origin/method/path constraints and added a regression test.
- Accepted findings and fixes: all concrete blockers from reviewers were accepted and fixed in this slice.
- Rejected/deferred findings: transparent runtime policy enforcement, DNS-to-flow attribution, HTTP/TLS dataplane inspection, QUIC dataplane classification, explicit proxy networking, and concrete std egress wrappers are deferred to subsequent milestone slices because this commit is dependency-free core policy vocabulary only.
- Verification commands and outcomes:
  - `cargo fmt --all` applied formatting; `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-core policy::tests -- --nocapture` passed: 18 policy tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 2 net tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still showed only `foxprox-core`, confirming no dependency creep.
  - `cargo +1.80.0 check -p foxprox-core` passed.
- Files changed: `crates/foxprox-core/src/event.rs`, `crates/foxprox-core/src/policy.rs`, `progress.md`, `learnings.md`.
- Learning ledger updated: recorded the fail-closed bypass-helper review lesson for future policy slices.
- Current git status summary: source and ledgers modified; review/context artifacts summarized and ready for removal before commit.
- Next exact action: remove transient `context-build/` and `reviews/` artifacts, commit core policy metadata slice, then start UDP/DNS attribution + QUIC classification in the UDP proof.

## 2026-06-21T22:28:21Z — core policy metadata committed; next objective selected

- Commit created: `b55dd82` (`add core policy metadata matching`).
- Current objective: start the next Milestone 5 dataplane slice by wiring UDP/DNS proof events to existing DNS cache attribution and QUIC classification.
- Rationale: context-builder identified this as the smallest follow-on slice because `foxprox-net` UDP/DNS proof already owns a `DnsCache` and UDP flow table in one process, unlike TCP inspection which needs a larger combined runtime and stream buffering gate.
- Verification plan: update `crates/foxprox-net/src/udp.rs` to use `classify_udp_candidate(destination.port)`, attach medium-confidence DNS-cache attribution on generic UDP flows when `DnsCache::lookup_address` matches, log QUIC candidate distinctions, add focused unit coverage where possible, then run full workspace fmt/check/test/clippy/doc and a live UDP/DNS smoke if practical.
- Expected commit boundary: `foxprox-net` UDP proof attribution/classification changes plus progress update; no HTTP/TLS TCP inspection or proxy listener work in this slice.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: inspect `UdpDnsProofConfig`/`handle_udp_forward_datagram` and implement cache-backed attribution + QUIC classification.

## 2026-06-21T22:36:51Z — UDP DNS attribution and QUIC policy gate verified

- Current objective: commit the Milestone 5 UDP/DNS attribution + QUIC classification slice.
- Changes implemented:
  - `UdpDnsProofConfig` now carries a `PolicyRuleSet`; default proof runtime remains fail-closed because the default policy denies UDP host forwarding.
  - `foxprox proof-udp-dns --udp-forward-port PORT` now installs an explicit proof allow rule for that port, using `Protocol::Quic` for UDP/443 and `Protocol::Udp` otherwise.
  - Generic UDP forwarding now reverse-lookups destination IPs in the broker DNS cache and attaches medium-confidence `DnsCache` attribution when available.
  - UDP/443 forwarding events now classify as QUIC candidates, use `FlowTimeoutClass::Quic`, and log a distinct QUIC candidate flow line.
  - Host UDP forwarding now evaluates `PolicyEngine` on the attributed `UdpFlowAttempt` before recording the flow or spawning host forwarding, and drops non-allow decisions.
  - DNS cache expiry is now run in the UDP proof loop alongside UDP flow expiry.
- Subagents/reviews requested and findings:
  - `udp-attribution-quic-final` accepted DNS-cache attribution and QUIC classification but found a blocker: UDP forwarding still bypassed policy enforcement. Fixed by adding policy to config/runtime, installing explicit CLI proof allow rules, evaluating before forwarding, and adding a default-deny regression.
  - `udp-attribution-quic-rereview` found no blockers and confirmed the prior policy-bypass blocker was resolved.
- Accepted findings and fixes: all concrete reviewer blockers were accepted and fixed.
- Rejected/deferred findings: full audit sink emission/backpressure, TCP DNS attribution, transparent HTTP/TLS inspection, and explicit proxy frontends remain deferred to later alpha slices.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-net` passed: 5 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 5 net tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still showed only `foxprox-core`.
  - `cargo tree -p foxprox-net -e features` confirmed the existing smoltcp TCP/UDP/TUN feature set.
  - Live bwrap/TUN smoke passed: sandbox Python queried broker DNS for `example.com`, then sent UDP to the returned address on port 443; broker logged `quic candidate flow`, `classification=Quic`, DNS-cache medium attribution, and `decision=Allow` via rule `proof-allow-udp-443`.
- Files changed: `crates/foxprox-net/src/udp.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`, `learnings.md`.
- Learning ledger updated: recorded the proof-runtime policy gate lesson.
- Current git status summary: source and ledgers modified; review artifact directory summarized and ready for removal before commit.
- Next exact action: remove transient `reviews/`, commit UDP attribution/QUIC policy gate, then start the next smallest Milestone 5 slice: likely TCP-side policy enforcement/DNS attribution or transparent HTTP/TLS inspection planning.

## 2026-06-21T22:38:00Z — UDP attribution/QUIC policy gate committed; next objective selected

- Commit created: `183026c` (`gate udp proof with policy attribution`).
- Current objective: add an equivalent policy gate to the TCP proof before host connect, preserving proof usability by installing an explicit CLI allow rule for `--tcp-port`.
- Rationale: transparent TCP currently logs an allow without evaluating `PolicyEngine`; adding a default-deny policy gate is the smallest follow-on Milestone 5 runtime enforcement slice before larger DNS-to-TCP attribution and HTTP/TLS stream inspection work.
- Verification plan: add `PolicyRuleSet` to `TcpProofConfig`, evaluate `TcpConnectAttempt` before spawning host connect, abort denied sockets, add focused config/default-deny tests, run full workspace fmt/check/test/clippy/doc, and run a live proof TCP smoke if practical.
- Expected commit boundary: TCP proof policy enforcement and CLI proof allow rule only; no stream HTTP/TLS inspection or DNS attribution in this slice.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: implement TCP proof policy gate in `crates/foxprox-net/src/lib.rs` and `crates/foxprox-cli/src/main.rs`.

## 2026-06-21T22:41:24Z — TCP proof policy gate verified

- Current objective: commit TCP proof policy enforcement before larger transparent HTTP/TLS inspection work.
- Changes implemented:
  - `TcpProofConfig` now carries a `PolicyRuleSet` that defaults to fail-closed/default-deny.
  - TCP proof runtime now builds a `TcpConnectAttempt`, evaluates `PolicyEngine` before constructing `ConnectingFlow`/spawning host connect, logs the decision, and aborts denied smoltcp sockets.
  - `foxprox proof-tcp` installs an explicit proof allow rule for the configured `--tcp-port` so proof CLI behavior remains usable while default runtime config remains deny-by-default.
  - Added focused net test proving default TCP proof policy denies host-connect events.
- Subagents/reviews requested and findings:
  - `tcp-policy-gate-final` found no blockers and confirmed policy is evaluated before host connect, default config is fail-closed, and CLI installs the explicit proof allow rule.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-net` passed: 6 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 6 net tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still showed only `foxprox-core`; `cargo tree -p foxprox-net -e features` showed the existing smoltcp TCP/UDP/TUN feature set.
  - Live bwrap/TUN TCP smoke passed with sandbox Python HTTP client to resolved `example.com:80`; broker logged `tcp policy decision=Decision { action: Allow, rule_id: Some("proof-allow-tcp-80"), reason: None }` before host connect and the response started `HTTP/1.1 200 OK`.
- Files changed: `crates/foxprox-net/src/lib.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Current git status summary: source and progress ledger modified; review artifact directory summarized and ready for removal before commit.
- Next exact action: remove transient `reviews/`, commit TCP proof policy gate, then select the next Milestone 5 slice (DNS-to-TCP attribution or transparent HTTP/TLS first-byte inspection).

## 2026-06-21T22:42:21Z — TCP policy gate committed; next objective selected

- Commit created: `0fa8c0d` (`gate tcp proof with policy`).
- Current objective: begin transparent TCP first-bytes inspection planning/implementation for plaintext HTTP before host connect.
- Rationale: TCP proof now has a policy gate for connect attempts, but Milestone 5 still requires transparent plaintext HTTP Host/method/path inspection. DNS-to-TCP attribution requires a combined TCP+DNS runtime, while HTTP first-byte inspection can be added locally to the TCP proof path.
- Verification plan: add bounded HTTP request-head inspection before host connect on configured TCP port 80, evaluate `HttpRequest` policy before forwarding buffered bytes, preserve proof CLI behavior with an explicit HTTP allow rule for proof port 80, add focused tests for HTTP inspection policy decisions, run full workspace verification and live bwrap/TUN HTTP smoke.
- Expected commit boundary: TCP proof plaintext HTTP inspection gate only; TLS ClientHello inspection and combined DNS attribution remain follow-on slices.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: inspect `ConnectingFlow` and refactor TCP proof to buffer/evaluate HTTP request metadata before host connect.

## 2026-06-21T22:46:46Z — transparent HTTP inspection proof verified

- Current objective: commit the transparent plaintext HTTP inspection gate for the TCP proof.
- Changes implemented:
  - TCP proof now routes allowed port-80 TCP connects through an `InspectingHttpFlow` state before opening the host socket.
  - The inspection state buffers sandbox bytes up to the existing pending buffer limit, parses a complete HTTP request head with `parse_http_request_head`, evaluates a normalized `HttpRequest` with `PolicyEngine`, and only then creates `ConnectingFlow` with the buffered request bytes preserved for host forwarding.
  - Malformed, unsupported, missing-Host, denied, timed-out, or closed inspection cases abort the smoltcp socket before host connect.
  - `foxprox proof-tcp` now installs an explicit `Protocol::Http` proof allow rule for `--tcp-port 80` in addition to the TCP connect proof allow rule.
  - Added focused test coverage that transparent HTTP inspection is limited to default HTTP port 80.
- Subagents/reviews requested and findings:
  - `http-inspection-final` found no blockers and confirmed the diff buffers first bytes before host connect, aborts malformed/missing-Host cases through parser errors, installs the proof CLI HTTP allow rule, and keeps buffers/timeouts bounded.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-net` passed: 7 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 7 net tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - Live bwrap/TUN HTTP smoke passed with sandbox Python client to resolved `example.com:80`; broker logged both `tcp policy decision=Decision { action: Allow, rule_id: Some("proof-allow-tcp-80"), reason: None }` and `transparent HTTP policy decision=Decision { action: Allow, rule_id: Some("proof-allow-http-80"), reason: None }` before host connect; response started `HTTP/1.1 200 OK`.
- Files changed: `crates/foxprox-net/src/lib.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Current git status summary: source and progress ledger modified; review artifact directory summarized and ready for removal before commit.
- Next exact action: remove transient `reviews/`, commit transparent HTTP inspection proof, then start the next alpha slice: TLS ClientHello inspection on transparent TCP port 443 or explicit proxy frontend planning.

## 2026-06-21T22:47:28Z — HTTP inspection committed; next objective selected

- Commit created: `55e2061` (`inspect transparent http before tcp egress`).
- Current objective: add transparent TLS ClientHello inspection before host connect for TCP port 443.
- Rationale: Milestone 5 requires direct HTTPS evaluation by TLS SNI and hidden-SNI/ECH handling. HTTP first-byte inspection established the state-machine pattern; TLS ClientHello inspection can reuse that bounded pre-egress gate before larger DNS-to-TCP attribution or proxy frontend work.
- Verification plan: add a TLS inspection state for port 443, emit `TlsClientHello` with visible SNI/ECH metadata, evaluate policy before host connect, preserve proof CLI usability with an explicit TLS allow rule for `--tcp-port 443`, add focused tests for the port selector/default policy where possible, run full workspace verification and a live TLS smoke if practical.
- Expected commit boundary: TCP proof TLS ClientHello inspection gate only; no TLS MITM, no full HTTPS URL/path visibility, and no DNS attribution integration yet.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: implement bounded TLS ClientHello inspection in `crates/foxprox-net/src/lib.rs` and proof CLI TLS allow rule wiring.

## 2026-06-21T22:51:29Z — transparent TLS inspection proof verified

- Current objective: commit transparent TLS ClientHello inspection for the TCP proof.
- Changes implemented:
  - TCP proof now routes allowed port-443 TCP connects through an `InspectingTlsFlow` state before opening the host socket.
  - The inspection state buffers sandbox bytes up to the existing pending buffer limit, parses a complete TLS ClientHello with `parse_tls_client_hello`, emits a normalized `TlsClientHello` event with SNI/ECH metadata, evaluates `PolicyEngine`, and only then creates `ConnectingFlow` with buffered ClientHello bytes preserved.
  - Malformed, unsupported, denied, timed-out, or closed TLS inspection cases abort before host connect.
  - `foxprox proof-tcp` now installs an explicit `Protocol::Tls` proof allow rule for `--tcp-port 443` in addition to the TCP connect proof allow rule.
  - Added focused test coverage that transparent TLS inspection is limited to default HTTPS port 443.
- Subagents/reviews requested and findings:
  - `tls-inspection-final` found no blockers after inspecting the diff and running targeted tests.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-net` passed: 8 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - Live bwrap/TUN TLS smoke passed with sandbox Python `ssl` client to resolved `example.com:443`; broker logged both `tcp policy decision=Decision { action: Allow, rule_id: Some("proof-allow-tcp-443"), reason: None }` and `transparent TLS policy decision=Decision { action: Allow, rule_id: Some("proof-allow-tls-443"), reason: None }` with `sni: Some(Hostname("example.com"))`; client negotiated TLSv1.3.
- Files changed: `crates/foxprox-net/src/lib.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Current git status summary: source and progress ledger modified; review artifact directory summarized and ready for removal before commit.
- Next exact action: remove transient `reviews/`, commit transparent TLS inspection proof, then select the next alpha slice: combined DNS-to-TCP attribution or explicit proxy frontend foundation.

## 2026-06-21T22:52:03Z — TLS inspection committed; next objective selected

- Commit created: `dd7ceb0` (`inspect transparent tls before tcp egress`).
- Current objective: start Milestone 6 explicit proxy frontend foundation with dependency-light parsing and policy event generation for HTTP proxy requests, HTTPS CONNECT, and SOCKS5 CONNECT.
- Rationale: Milestone 5 now has transparent HTTP/TLS proof gates and UDP/QUIC attribution policy gates. The largest remaining alpha gap is Milestone 6 explicit proxy networking; the smallest safe slice is parser/frontend normalization before live listener/egress wiring.
- Verification plan: add a new proxy/frontend module or crate with tests for HTTP absolute-form requests, CONNECT targets, malformed requests, SOCKS5 greeting/connect parsing for host and IP destinations, and normalized `NetworkEvent` output; run workspace fmt/check/test/clippy/doc.
- Expected commit boundary: explicit proxy parser/normalization foundation only; live proxy listener and host egress forwarding to follow.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: inspect workspace layout and implement `foxprox-proxy` foundation with tests.

## 2026-06-21T22:57:38Z — explicit proxy parser foundation verified pending rereview

- Current objective: commit Milestone 6 explicit proxy parsing/normalization foundation after rereview.
- Changes implemented:
  - Added workspace crate `foxprox-proxy`, depending only on `foxprox-core`.
  - Added dependency-light parsing of HTTP proxy absolute-form `http://host[:port]/path` requests into `NetworkEvent::HttpRequest` with `Frontend::HttpProxy`.
  - Added HTTP `CONNECT host:port HTTP/1.x` parsing into `NetworkEvent::HttpsConnect`.
  - Added SOCKS5 no-auth TCP CONNECT parsing for hostname, IPv4, and IPv6 destinations into `NetworkEvent::SocksConnect`.
  - Unsupported proxy paths fail closed as parser errors: relative HTTP targets, malformed CONNECT targets, UDP ASSOCIATE/BIND, unsupported SOCKS auth methods, unsupported SOCKS address types, HTTP proxy IP-literal authorities, and non-HTTP/1.0/1.1 request versions.
  - Added focused tests for HTTP absolute-form, HTTPS CONNECT, malformed HTTP proxy requests, IP literal rejection, unsupported HTTP versions, SOCKS5 host/IP CONNECT, SOCKS UDP ASSOCIATE rejection, and normalized protocol classes.
- Subagents/reviews requested and findings:
  - `proxy-parser-final` found two blockers: IP-literal HTTP/CONNECT authorities were accepted as hostnames, and unsupported HTTP versions were accepted. Both were fixed with fail-closed checks and regressions.
  - `proxy-parser-rereview` requested and running to confirm blocker fixes before commit.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-proxy` passed: 9 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, 9 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` still showed only `foxprox-core`; `cargo tree -p foxprox-proxy` showed only `foxprox-core` as a dependency.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-proxy/Cargo.toml`, `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy crate and workspace files modified; review artifacts pending rereview/removal.
- Next exact action: read proxy parser rereview, fix any blockers, remove transient `reviews/`, commit parser foundation, then start live explicit proxy listener/egress proof slice.

## 2026-06-21T22:59:37Z — proxy parser foundation committed; next objective selected

- Commit created: `a3ebc58` (`add explicit proxy parser foundation`).
- Current objective: add a live explicit HTTP/HTTPS proxy listener proof using the parser foundation, shared policy evaluation, and host TCP egress.
- Rationale: Milestone 6 requires HTTP proxy frontend, HTTPS CONNECT support, shared policy engine integration, shared audit logging, and origin-aware allow/deny rules. Parser normalization is complete; the next smallest live slice is an HTTP proxy/CONNECT proof listener with policy-gated host TCP forwarding.
- Verification plan: implement a std-threaded proof listener in `foxprox-proxy` for absolute-form HTTP and CONNECT, resolve proxy hostnames through host DNS for proof egress, evaluate `PolicyEngine` before connect, fail closed by default, add local loopback tests with a tiny origin server, run full workspace fmt/check/test/clippy/doc, and then commit.
- Expected commit boundary: HTTP proxy and HTTPS CONNECT live proof only; SOCKS5 live listener remains a follow-on slice.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: extend `foxprox-proxy` with a policy-gated std TCP listener proof for HTTP proxy and CONNECT.

## 2026-06-21T23:04:12Z — live HTTP proxy/CONNECT proof implemented pending review

- Current objective: verify and commit Milestone 6 live HTTP proxy/CONNECT proof.
- Changes implemented:
  - Added `HttpProxyProofConfig` and `run_http_proxy_proof`, a std-threaded explicit proxy proof listener.
  - Proxy proof reads bounded request heads, parses with the existing HTTP proxy parser, evaluates `PolicyEngine`, and fails closed with `403` for non-allow decisions before host connect.
  - Added host TCP connect through a `TcpEgressRequest`/`EgressContext` proof boundary that refuses non-allowed decisions before opening a socket.
  - Plain HTTP proxy requests are rewritten from absolute-form to origin-form before forwarding to the host.
  - HTTPS CONNECT requests receive `200 Connection Established` only after policy allow and successful host connect, then tunnel bytes bidirectionally.
  - Added local loopback tests proving policy-allowed absolute-form HTTP GET forwarding and CONNECT tunneling.
- Subagents/reviews requested: `proxy-live-final` is running as a read-only blocker review.
- Verification commands and outcomes so far:
  - `cargo fmt --all -- --check` passed after formatting.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-proxy -- --nocapture` passed: 11 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, 11 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed after fixing `sliced_string_as_bytes`.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-proxy` showed only `foxprox-core` as a dependency.
- Known proof limitations: blocking/thread-per-connection proof only; no SOCKS live listener yet; no audit sink/backpressure beyond structured decision logs; HTTP request body streaming is minimal proof behavior.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy proof source and progress modified; no commit yet pending final review.
- Next exact action: read proxy live review, fix blockers if any, then commit.

## 2026-06-21T23:09:50Z — live HTTP proxy/CONNECT blocker fixes verified pending rereview

- Current objective: commit live HTTP proxy/CONNECT proof after rereview.
- Review findings accepted and fixed:
  - Buffered bytes after `\r\n\r\n` were not preserved safely. Fixed by splitting the initial read buffer into header and tail; parsing/rewriting only the header; forwarding tail to upstream for both HTTP and CONNECT.
  - Plain HTTP forwarded only upstream-to-client after the initial rewritten request. Fixed by using the bidirectional tunnel after sending the rewritten header and buffered tail, allowing request bodies to continue from client to upstream.
  - Incomplete request heads could pin handler threads indefinitely. Fixed by adding `request_head_timeout` to `HttpProxyProofConfig` and setting a client read timeout before the bounded header read.
  - CONNECT tunnel teardown could hang on join when upstream closed first. Reworked tunnel copy to half-close upstream write after client->upstream finishes and shut down the client socket after upstream->client finishes to wake the other copy path.
- Additional tests added/updated:
  - Plain HTTP proxy proof now uses a coalesced POST body and verifies the origin receives `POST /proof` with `hello-body`.
  - CONNECT proof now coalesces `ping` immediately after the CONNECT header and verifies it reaches the upstream after the proxy sends `200 Connection Established`.
- Verification commands and outcomes after fixes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-proxy -- --nocapture` passed: 11 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, 11 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-proxy` showed only `foxprox-core` as a dependency.
- Subagents/reviews requested: `proxy-live-rereview` is running to confirm blocker fixes.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy proof source and progress modified; review artifacts pending rereview/removal.
- Next exact action: read proxy live rereview, fix any blockers, remove `reviews/`, and commit live proxy proof.

## 2026-06-21T23:10:44Z — live HTTP proxy/CONNECT rereview passed

- Current objective: commit the live explicit HTTP proxy/CONNECT proof.
- Rereview result: `proxy-live-rereview` found no blockers after the buffered-tail, HTTP body forwarding, read-timeout, and CONNECT tunnel teardown fixes.
- Verification evidence remains valid from prior entry: full workspace fmt/check/test/clippy/doc passed and `foxprox-proxy` has 11 tests including live loopback HTTP POST/body forwarding and CONNECT coalesced-tail tunneling.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy proof source and progress modified; review artifacts summarized and ready for removal.
- Next exact action: remove transient `reviews/`, commit live HTTP proxy/CONNECT proof, then start SOCKS5 live CONNECT proof or audit/backpressure slice based on remaining alpha scope.

## 2026-06-21T23:11:33Z — live HTTP proxy committed; next objective selected

- Commit created: `6365a25` (`add live http proxy proof`).
- Current objective: add live SOCKS5 TCP CONNECT proof using the existing SOCKS parser, policy evaluation, and host TCP egress boundary.
- Rationale: Milestone 6 requires SOCKS5 TCP CONNECT support in addition to HTTP proxy and HTTPS CONNECT. Parser support exists; the next smallest slice is a live no-auth SOCKS5 CONNECT proof listener with policy-before-egress.
- Verification plan: implement SOCKS5 no-auth greeting/request handling, evaluate `SocksConnect` before host connect, return SOCKS failure on deny/error, tunnel bytes on allow, add loopback tests for allowed host CONNECT and denied/default policy, then run full workspace fmt/check/test/clippy/doc.
- Expected commit boundary: SOCKS5 TCP CONNECT live proof only; SOCKS UDP ASSOCIATE remains out of alpha scope.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: extend `foxprox-proxy` with `Socks5ProxyProofConfig` and `run_socks5_proxy_proof`.

## 2026-06-21T23:14:24Z — live SOCKS5 CONNECT proof implemented pending review

- Current objective: verify and commit Milestone 6 live SOCKS5 TCP CONNECT proof.
- Changes implemented:
  - Added `Socks5ProxyProofConfig` and `run_socks5_proxy_proof`, a blocking std/threaded SOCKS5 proof listener.
  - Live SOCKS path handles no-auth method negotiation, rejects unsupported methods, reads CONNECT requests for IPv4/IPv6/domain destinations, reuses parser normalization, evaluates `PolicyEngine`, and only opens host TCP egress after allow.
  - Denied SOCKS requests receive a SOCKS failure reply before close; allowed requests receive success reply then tunnel bytes bidirectionally through the same half-close-aware tunnel helper.
  - Added loopback tests proving allowed SOCKS5 hostname CONNECT tunneling and default-deny SOCKS failure behavior.
- Subagents/reviews requested: `socks-live-final` is running as read-only blocker review.
- Verification commands and outcomes so far:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-proxy -- --nocapture` passed: 13 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, 13 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-proxy` showed only `foxprox-core` as dependency.
- Known proof limitations: thread-per-connection and no final audit sink/backpressure; SOCKS UDP ASSOCIATE remains explicitly unsupported.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy source and progress modified; no commit yet pending final review.
- Next exact action: read SOCKS live review, fix blockers if any, then commit.

## 2026-06-21T23:17:52Z — SOCKS5 failure replies fixed pending rereview

- Current objective: commit live SOCKS5 TCP CONNECT proof after rereview.
- Review findings accepted and fixed:
  - Unsupported SOCKS commands/address types after no-auth method selection could close without a SOCKS failure reply. Fixed by mapping parser/request errors to SOCKS reply statuses (`0x07` unsupported command, `0x08` unsupported address type, `0x01` general failure) before returning.
  - Policy-allowed but resolution/connect-failed destinations could close without a SOCKS failure reply. Fixed by wrapping resolution/connect errors and sending host-unreachable/connection-refused/general failure replies before returning.
- Additional tests added:
  - Live SOCKS UDP ASSOCIATE request receives unsupported command reply `0x07`.
  - Policy-allowed but unreachable loopback CONNECT receives a non-success SOCKS failure reply.
- Verification commands and outcomes after fixes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-proxy -- --nocapture` passed: 15 tests.
  - `cargo test --workspace` passed: 45 core tests, 8 device tests, 8 net tests, 15 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
- Subagents/reviews requested: `socks-live-rereview` is running to confirm blocker fixes.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: source and progress modified; review artifacts pending rereview/removal.
- Next exact action: read SOCKS rereview, fix any blockers, remove `reviews/`, and commit.

## 2026-06-21T23:18:42Z — live SOCKS5 rereview passed

- Current objective: commit live SOCKS5 TCP CONNECT proof.
- Rereview result: `socks-live-rereview` found no blockers after SOCKS failure reply fixes.
- Verification evidence remains valid from prior entry: full workspace fmt/check/test/clippy/doc passed and `foxprox-proxy` has 15 focused tests including default-deny, allowed CONNECT tunneling, unsupported UDP ASSOCIATE reply, and allowed-but-unreachable failure reply.
- Files changed: `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: source and progress modified; review artifacts summarized and ready for removal.
- Next exact action: remove transient `reviews/`, commit live SOCKS5 proof, then compare remaining alpha scope and start robustness/audit/backpressure work.

## 2026-06-21T23:19:08Z — SOCKS5 proof committed; next objective selected

- Commit created: `23fa6e6` (`add live socks5 connect proof`).
- Current objective: begin Milestone 7 robustness by adding dependency-free bounded audit buffering/backpressure primitives to `foxprox-core`.
- Rationale: transparent TCP/UDP/DNS and explicit HTTP/CONNECT/SOCKS proof paths now exist, but alpha robustness requires audit backpressure so forwarding cannot grow memory unbounded when audit output is slow. The smallest safe slice is a core audit buffer type with explicit overflow behavior and tests.
- Verification plan: add bounded `AuditBuffer`/error/outcome types in `crates/foxprox-core/src/audit.rs`, test FIFO drain, capacity limits, zero-capacity rejection, and no dependency creep; run full workspace fmt/check/test/clippy/doc and `cargo tree -p foxprox-core`.
- Expected commit boundary: core audit backpressure primitives only; runtime integration into proof paths can follow.
- Current git status summary after commit: clean `autonomous-crew` branch.
- Next exact action: implement bounded audit buffer in `foxprox-core`.

## 2026-06-21T23:22:07Z — core audit backpressure verified

- Current objective: commit dependency-free audit backpressure primitives for Milestone 7.
- Changes implemented:
  - Added `AuditBuffer`, a bounded FIFO audit event queue using `VecDeque` only.
  - Added explicit `AuditBackpressure` errors for full queues and zero-capacity buffers.
  - `try_push` never grows beyond capacity and increments a visible dropped-event counter on rejection.
  - Added FIFO, full-buffer, and zero-capacity tests; exported `AuditBuffer` and `AuditBackpressure` from `foxprox-core`.
- Subagents/reviews requested and findings:
  - `audit-backpressure-final` found no blockers and confirmed bounded memory behavior, explicit backpressure semantics, FIFO behavior, zero-capacity behavior, public exports, and no dependency creep.
- Verification commands and outcomes:
  - `cargo fmt --all -- --check` passed.
  - `cargo check --workspace` passed.
  - `cargo test -p foxprox-core` passed: 48 core tests.
  - `cargo test --workspace` passed: 48 core tests, 8 device tests, 8 net tests, 15 proxy tests, CLI/setup 0 tests.
  - `cargo clippy --workspace --all-targets -- -D warnings` passed.
  - `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` passed.
  - `cargo tree -p foxprox-core` showed no dependencies.
- Files changed: `crates/foxprox-core/src/audit.rs`, `crates/foxprox-core/src/lib.rs`, `progress.md`.
- Current git status summary: core audit source and progress modified; review artifacts summarized and ready for removal.
- Next exact action: remove transient `reviews/`, commit audit backpressure primitives, then start runtime integration of audit buffer or resource-limit robustness work.

## 2026-06-21T22:58:44Z — explicit proxy parser foundation rereview passed

- Current objective: commit Milestone 6 explicit proxy parsing/normalization foundation.
- Rereview result: `proxy-parser-rereview` found no blockers after IP-literal authority and HTTP-version fixes.
- Verification evidence remains valid from prior entry: workspace fmt/check/test/clippy/doc passed; `foxprox-proxy` has 9 focused parser tests; dependency trees confirm `foxprox-core` remains dependency-free and `foxprox-proxy` depends only on `foxprox-core`.
- Files changed: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-proxy/Cargo.toml`, `crates/foxprox-proxy/src/lib.rs`, `progress.md`.
- Current git status summary: proxy crate/workspace/progress modified; review artifacts summarized and ready for removal.
- Next exact action: remove transient `reviews/`, commit proxy parser foundation, then start live explicit proxy listener/egress proof slice.
