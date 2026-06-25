# Harness Lab Progress

## 2026-06-21T00:00:00Z — Initial harness-lab scope checkpoint

- Command executed: `pwd && git status --short && ls`; `cargo --version && rustc --version && uname -a && test -e /dev/net/tun && echo tun=yes || echo tun=no && command -v bwrap || true`
- Environment assumptions: Linux worktree at `/home/foxfire/code/foxprox/.tmp/worktrees/harness-lab`; Rust workspace with only `foxprox-core`; `/dev/net/tun` and `bwrap` are present, but no privilege/capability proof has been run yet.
- Expected result: identify current repo shape and whether local namespace/TUN smoke checks are even plausible.
- Observed result: repo is a skeleton (`Cargo.toml`, `crates/foxprox-core`, docs); `cargo 1.96.0`, `rustc 1.96.0`, Linux 7.0.12, `/dev/net/tun` exists, `bwrap` at `/usr/bin/bwrap`.
- Relevant output excerpt: `tun=yes`; `/usr/bin/bwrap`.
- Changed files: `progress.md` created.
- Interpretation: alpha implementation must start by making the harness and core model executable before any real netns/TUN forwarding proof can be trusted.
- Next verification gap: add deterministic unit/fixture/mock harness checks for policy, audit, packet handling, DNS, proxy parsing, and fail-closed behavior; add environment-sensitive smoke reporting for bwrap/TUN separately.
- Commit hash after commit: pending.

## 2026-06-21T00:10:00Z — Deterministic alpha harness foundation

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: std-only Rust workspace; no external network or namespace privilege required for unit/harness checks.
- Expected result: all core parser, policy, audit, DNS, flow, integration-plan, and CLI tests pass.
- Observed result: pass. `foxprox-core` ran 30 tests; `foxprox-cli` ran 2 tests; doc tests passed.
- Relevant output excerpt: `test result: ok. 30 passed; 0 failed`; `test result: ok. 2 passed; 0 failed`.
- Changed files: `Cargo.toml`, `README.md`, `crates/foxprox-core/src/{lib.rs,audit.rs,dns.rs,egress.rs,flow.rs,integration.rs,origin.rs,packet.rs,policy.rs,scenario.rs}`, `crates/foxprox-cli/{Cargo.toml,src/main.rs}`, `progress.md`, `learnings.md`.
- Interpretation: the lab now proves the platform-independent alpha semantics: structured audit records, default deny/fail-closed policy, direct DNS bypass denial, DNS attribution cache, plaintext HTTP/CONNECT/SOCKS parsing, TLS SNI parsing, QUIC candidate classification, IPv4/UDP/TCP/ICMP parsing, synthetic ICMP echo reply write-back proof, UDP pseudo-flow expiry, shared policy-before-egress boundary, and bwrap/foxwrap command-shape invariants.
- Next verification gap: replace mock egress/packet proofs with environment-dependent real namespace/TUN checks and later smoltcp-backed TCP forwarding.
- Commit hash after commit: pending.

## 2026-06-21T00:12:00Z — Lab command output captured

- Command executed: `cargo run -p foxprox-cli --bin foxprox-lab -- run all | tee /tmp/foxprox-lab-all.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run env-smoke`
- Environment assumptions: deterministic `run all` is local-only; `env-smoke` checks executable/device availability without creating a namespace.
- Expected result: JSON Lines audit records demonstrate alpha behavior and local environment capabilities.
- Observed result: pass. `run all` emitted records for TCP allow, external DNS deny, unsupported fail-closed, broker DNS attribution, HTTP proxy, HTTPS CONNECT, SOCKS CONNECT, ICMP echo reply, QUIC candidate, IPv4 fragment fail-closed, UDP flow create/expire. `env-smoke` reported `/dev/net/tun` exists and `bwrap` responds.
- Relevant output excerpt: `"event":"unsupported_network_event","decision":"fail_closed","reason":"IPv4 fragmentation is unsupported in alpha"`; `"event":"tun_configured","decision":"allow","reason":"/dev/net/tun exists"`; `"bwrap_version":"bubblewrap 0.11.2"`.
- Changed files: no additional source changes from command execution.
- Interpretation: the harness has a reproducible CLI proof path suitable for future comparison fixtures.
- Next verification gap: make privileged namespace/TUN setup a separate smoke command once the setup helper exists.
- Commit hash after commit: pending.

## 2026-06-21T00:14:00Z — Commit recorded

- Command executed: `git add Cargo.lock Cargo.toml README.md crates progress.md learnings.md && git commit -m "Build deterministic alpha harness foundation"`
- Environment assumptions: harness-backed behavior was verified before commit.
- Expected result: commit includes harness foundation and ledgers.
- Observed result: commit `9f0a657` created with 17 files changed.
- Relevant output excerpt: `[harness-lab 9f0a657] Build deterministic alpha harness foundation`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: the foundation checkpoint is preserved; this follow-up ledger note records the actual commit hash.
- Next verification gap: real namespace/TUN setup helper and smoltcp-backed forwarding proof.
- Commit hash after commit: 9f0a657.

## 2026-06-21T00:25:00Z — Environment-dependent bwrap/TUN smoke command

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run tun-smoke`
- Environment assumptions: local system has `bwrap`, `/dev/net/tun`, `/usr/bin/ip`, and user-namespace-compatible temporary `CAP_NET_ADMIN` inside `bwrap --unshare-net`.
- Expected result: deterministic tests still pass; `tun-smoke` attempts real TUN creation/configuration inside a throwaway bwrap network namespace and reports structured audit output.
- Observed result: pass. Tests remained green (`foxprox-core` 30 tests, `foxprox-cli` 2 tests). `tun-smoke` returned `decision":"allow"` and `status":"exit status: 0"`.
- Relevant output excerpt: `"reason":"bwrap namespace TUN setup command succeeded"`; `"stdout":"2: foxprox0    inet 10.0.2.2/24 scope global foxprox0..."`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: Milestone 0 environment capability is now reproducible by a local harness command, although it uses shell/ip as the setup action rather than the future `foxproxsetup` binary and does not perform fd handoff.
- Next verification gap: implement a real setup-helper binary or integration crate that performs TUN setup and fd handoff without shelling out to `ip`.
- Commit hash after commit: pending.

## 2026-06-21T00:27:00Z — TUN smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add bwrap TUN smoke harness command"`
- Environment assumptions: smoke command and test output above were verified before commit.
- Expected result: commit captures the environment-dependent smoke command.
- Observed result: commit `5307d0d` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 5307d0d] Add bwrap TUN smoke harness command`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: the bwrap/TUN smoke checkpoint is preserved.
- Next verification gap: real setup helper and TUN fd handoff.
- Commit hash after commit: 5307d0d.

## 2026-06-21T00:45:00Z — foxproxsetup plan/parser scaffold and bwrap spawning discovery

- Command executed: `cargo fmt --all && cargo test --all`; `cargo run -p foxprox-setup --bin foxproxsetup -- --print-plan`; `cargo build -p foxprox-setup --bin foxproxsetup && HELPER="$PWD/target/debug/foxproxsetup"; bwrap --unshare-user --unshare-net --cap-add CAP_NET_ADMIN --dev-bind /dev/net/tun /dev/net/tun --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind "$PWD/target" "$PWD/target" --proc /proc -- "$HELPER" --configure-only`
- Environment assumptions: local tests do not require privileges; bwrap helper configure run is environment-dependent.
- Expected result: setup helper parser/plan tests pass; print-plan emits deterministic setup/proxy configuration; configure-only ideally creates a TUN inside bwrap.
- Observed result: tests passed (`foxprox-core` 30, `foxprox-cli` 2, `foxproxsetup` 4). `--print-plan` emitted the default TUN/proxy JSON. `bwrap ... foxproxsetup --configure-only` failed when the helper attempted to spawn `/bin/sh`/`/usr/bin/ip` from Rust with ENOENT.
- Relevant output excerpt: `"tun_name":"foxprox0","sandbox_ip":"10.0.2.2/24"`; `foxproxsetup: failed to execute /bin/sh for /usr/bin/ip: No such file or directory (os error 2)`.
- Changed files: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-setup/{Cargo.toml,src/main.rs}`, `README.md`, `learnings.md`, `progress.md`.
- Interpretation: helper command-line contract and plan output are now harnessed, but actual TUN setup from the Rust helper cannot safely rely on shelling out inside bwrap in this environment. This validates the implementation approach directive to turn unknowns into runnable checks and record limitations.
- Next verification gap: implement setup helper TUN configuration using direct syscalls/netlink/ioctl instead of child process spawning, then rerun the bwrap configure-only smoke.
- Commit hash after commit: pending.

## 2026-06-21T00:48:00Z — foxproxsetup scaffold commit recorded

- Command executed: `git add Cargo.lock Cargo.toml README.md crates/foxprox-setup learnings.md progress.md && git commit -m "Add foxproxsetup planning scaffold"`
- Environment assumptions: helper parser/plan behavior was verified; bwrap configure failure is intentionally recorded as a limitation.
- Expected result: commit captures the setup-helper scaffold and the observed bwrap spawning limitation.
- Observed result: commit `2bb815f` created with 7 files changed.
- Relevant output excerpt: `[harness-lab 2bb815f] Add foxproxsetup planning scaffold`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: setup-helper planning checkpoint is preserved.
- Next verification gap: direct syscall/netlink/ioctl TUN setup from helper.
- Commit hash after commit: 2bb815f.

## 2026-06-21T13:15:00Z — Direct ioctl foxproxsetup TUN configuration

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run setup-smoke`
- Environment assumptions: Linux bwrap environment has `/dev/net/tun`, temporary `CAP_NET_ADMIN`, and dynamic runtime bind mounts for the locally built Rust helper; `setup-smoke` uses direct Rust ioctl/syscall setup rather than spawning `/bin/sh` or `/usr/bin/ip` from the helper.
- Expected result: deterministic tests stay green; `foxproxsetup --configure-only` can create/configure a TUN device, assign IPv4/netmask/MTU, bring it up, install a default dev route, and emit sandbox proxy/DNS environment from inside `bwrap --unshare-net`.
- Observed result: pass. `foxprox-core` ran 30 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `setup-smoke` emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"foxproxsetup direct TUN setup succeeded inside bwrap"`; `"stdout":"export HTTP_PROXY='http://10.0.2.1:8080'...export FOXPROX_DNS='10.0.2.1:53'"`.
- Changed files: `crates/foxprox-setup/src/main.rs`, `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`, `learnings.md`.
- Interpretation: the setup helper no longer relies on the previously failing child-process path for TUN setup. It now has direct Linux ioctl coverage plus a reusable harness smoke. The helper also parses the launch-plan `--handoff-env` option, sends the TUN fd over that socket when provided, drops `CAP_NET_ADMIN` before target exec, and fails closed before target exec if no fd handoff socket is provided.
- Next verification gap: add a broker-side handoff harness that receives the TUN fd over a Unix socket and proves the fd remains usable after `foxproxsetup` exits, then use that fd for packet write-back from outside the sandbox namespace.
- Commit hash after commit: pending.

## 2026-06-21T13:25:00Z — Direct setup commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs crates/foxprox-setup/src/main.rs learnings.md progress.md && git commit -m "Implement direct foxproxsetup TUN configuration"`
- Environment assumptions: direct helper setup and test output above were verified before commit.
- Expected result: commit captures direct ioctl TUN setup, setup-smoke harness, fd handoff send path, and capability drop before target exec.
- Observed result: commit `02069d7` created with 5 files changed.
- Relevant output excerpt: `[harness-lab 02069d7] Implement direct foxproxsetup TUN configuration`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: Milestone 0 setup-helper behavior is closer to product shape; the shell-based `tun-smoke` remains as a comparison harness, while `setup-smoke` exercises the Rust helper path.
- Next verification gap: broker-side handoff harness that receives the TUN fd and proves it remains usable after helper exit.
- Commit hash after commit: 02069d7.

## 2026-06-21T13:45:00Z — TUN fd handoff smoke harness

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke`
- Environment assumptions: host harness can create a Unix socket under `target/`; bwrap can bind that socket directory into the sandbox; `foxproxsetup` receives `FOXPROX_SETUP_SOCKET`, creates/configures the sandbox TUN, sends the fd with `SCM_RIGHTS`, drops `CAP_NET_ADMIN`, closes its local fd, and execs `/usr/bin/true`.
- Expected result: deterministic tests remain green; `handoff-smoke` receives a live TUN fd, waits for the helper/target to exit, and confirms the received fd remains valid on the host side.
- Observed result: pass. `foxprox-core` ran 30 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `handoff-smoke` emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"foxproxsetup handed off a live TUN fd and target exited"`; `"fd_valid_after_helper_exit":"true"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`, `learnings.md`.
- Interpretation: the bwrap-compatible setup helper now has a reproducible host-side fd handoff proof. This closes the previous gap between configure-only TUN setup and the broker-owned fd model required by the architecture.
- Next verification gap: use the received TUN fd for an external packet write-back proof, ideally by running a sandbox ping target and having the host harness synthesize ICMP echo replies through the handed-off fd.
- Commit hash after commit: pending.

## 2026-06-21T13:50:00Z — Handoff smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs learnings.md progress.md && git commit -m "Add TUN fd handoff smoke harness"`
- Environment assumptions: handoff smoke and workspace tests above were verified before commit.
- Expected result: commit captures host-side `SCM_RIGHTS` fd receive harness and documentation.
- Observed result: commit `a0a3b30` created with 4 files changed.
- Relevant output excerpt: `[harness-lab a0a3b30] Add TUN fd handoff smoke harness`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: fd handoff proof checkpoint is preserved.
- Next verification gap: packet write-back through the handed-off fd from a host-side harness.
- Commit hash after commit: a0a3b30.

## 2026-06-21T14:20:00Z — Host-side TUN packet write-back smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run writeback-smoke`
- Environment assumptions: `python3` is available inside the bwrap namespace through the `/usr` bind; unprivileged UDP sockets are allowed in the sandbox; the host harness owns the TUN fd received from `foxproxsetup` via `SCM_RIGHTS`.
- Expected result: deterministic tests remain green; sandbox target sends a UDP probe to `10.0.2.1:5353`; host harness reads the IPv4/UDP packet from the handed-off TUN fd, writes a synthetic UDP reply, and the sandbox target exits successfully after receiving it.
- Observed result: pass. `foxprox-core` ran 30 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `writeback-smoke` emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"sandbox UDP probe received synthetic reply through handed-off TUN fd"`; `"packets_read":"2"`; `"reply_written":"true"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`, `learnings.md`.
- Interpretation: the harness now proves real bidirectional packet movement over a bwrap-created TUN fd owned by the host harness. This is a stronger environment-dependent packet write-back proof than the earlier pure unit ICMP synthesis fixture.
- Next verification gap: introduce an actual broker/runtime abstraction around the handoff fd instead of keeping write-back logic inside the CLI harness; then move toward TCP stack/forwarding proof.
- Commit hash after commit: pending.

## 2026-06-21T14:25:00Z — Write-back smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs learnings.md progress.md && git commit -m "Add TUN writeback smoke harness"`
- Environment assumptions: write-back smoke and workspace tests above were verified before commit.
- Expected result: commit captures host-side packet read/write proof over the handed-off TUN fd.
- Observed result: commit `d0658b1` created with 4 files changed.
- Relevant output excerpt: `[harness-lab d0658b1] Add TUN writeback smoke harness`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: packet write-back proof checkpoint is preserved.
- Next verification gap: factor repeated bwrap/handoff harness code into reusable helpers or a broker-device/runtime boundary before adding richer forwarding behavior.
- Commit hash after commit: d0658b1.

## 2026-06-21T14:45:00Z — Local UDP forwarding proof over handed-off TUN

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-forward-smoke`
- Environment assumptions: local-only UDP echo fixture is available on `127.0.0.1`; sandbox target can run Python and send UDP to an arbitrary routed IP through the TUN; host harness can translate the TUN packet to host UDP egress and synthesize the return packet to the sandbox source.
- Expected result: deterministic tests remain green; `udp-forward-smoke` reads the sandbox UDP packet from TUN, forwards the payload through a host `UdpSocket`, receives the echo fixture response, writes it back to TUN, and the sandbox target exits successfully.
- Observed result: pass. `foxprox-core` ran 30 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `udp-forward-smoke` emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"sandbox UDP probe was forwarded through host UDP egress and returned over TUN"`; `"forwarded":"true"`; `"egress_fixture":"127.0.0.1:48603"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: Milestone 4 has a first local UDP forwarding proof: not just synthetic write-back, but a sandbox datagram bridged through a host UDP socket and returned over the broker-owned TUN fd. This is still harness code, not the final broker runtime abstraction.
- Next verification gap: move the repeated TUN fd read/UDP reply logic into a reusable broker runtime/helper boundary and add policy/audit decisions around the environment smoke forwarding path.
- Commit hash after commit: pending.

## 2026-06-21T14:50:00Z — UDP forwarding smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add local UDP forwarding smoke"`
- Environment assumptions: UDP forwarding smoke and workspace tests above were verified before commit.
- Expected result: commit captures local UDP forwarding proof over the handed-off TUN fd.
- Observed result: commit `d7e8d3b` created with 3 files changed.
- Relevant output excerpt: `[harness-lab d7e8d3b] Add local UDP forwarding smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: UDP forwarding proof checkpoint is preserved.
- Next verification gap: reusable broker runtime/helper boundary plus policy/audit around environment smoke forwarding.
- Commit hash after commit: d7e8d3b.

## 2026-06-21T15:20:00Z — Reusable transparent UDP runtime boundary

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-forward-smoke`; `target/debug/foxprox-lab run writeback-smoke`
- Environment assumptions: deterministic runtime tests do not require privileges; environment smoke still requires bwrap, `/dev/net/tun`, local Python, and Unix fd handoff support.
- Expected result: introduce a platform-independent runtime boundary for one TUN IPv4/UDP packet that evaluates policy, calls egress only when allowed, emits structured audit, and returns an optional TUN reply packet; preserve the existing environment UDP forwarding and write-back smoke behavior.
- Observed result: pass. `foxprox-core` increased to 33 tests; `foxprox-cli` remained 2 tests; `foxproxsetup` remained 7 tests. `udp-forward-smoke` emitted `decision":"allow"` with `policy_decision":"allow"`, `policy_reason":"matched allow rule"`, and `rule_id":"allow-udp-forward-smoke"`. `writeback-smoke` still emitted `decision":"allow"`.
- Relevant output excerpt: `runtime::tests::allowed_udp_packet_reaches_egress_and_returns_tun_reply ... ok`; `"runtime_audit":"{...\"frontend\":\"tun\",\"protocol\":\"udp\",\"source\":\"10.0.2.2:58140\",\"destination\":\"203.0.113.10:5354\",...}"`.
- Changed files: `crates/foxprox-core/src/{lib.rs,packet.rs,egress.rs,runtime.rs}`, `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`, `learnings.md`.
- Interpretation: UDP forwarding is no longer just ad hoc CLI harness logic. The core now has a reusable transparent UDP runtime that proves policy-before-egress, denied-no-egress, audit emission, and packet reply synthesis without Linux dependencies; the bwrap smoke uses that runtime for the environment proof.
- Next verification gap: add a negative environment smoke that proves denied UDP traffic from the sandbox does not reach the host egress fixture and times out/fails closed with an audit denial.
- Commit hash after commit: pending.

## 2026-06-21T15:25:00Z — Transparent UDP runtime commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs crates/foxprox-core/src/egress.rs crates/foxprox-core/src/lib.rs crates/foxprox-core/src/packet.rs crates/foxprox-core/src/runtime.rs learnings.md progress.md && git commit -m "Add transparent UDP runtime boundary"`
- Environment assumptions: runtime tests and environment smokes above were verified before commit.
- Expected result: commit captures reusable core UDP runtime plus CLI smoke integration.
- Observed result: commit `3ef2b20` created with 8 files changed.
- Relevant output excerpt: `[harness-lab 3ef2b20] Add transparent UDP runtime boundary`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: reusable transparent UDP runtime checkpoint is preserved.
- Next verification gap: negative denied UDP environment smoke.
- Commit hash after commit: 3ef2b20.

## 2026-06-21T15:50:00Z — Denied UDP environment smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-deny-smoke && target/debug/foxprox-lab run udp-forward-smoke`
- Environment assumptions: sandbox Python UDP target treats receive timeout as success for the negative path; transparent UDP runtime default-deny policy should deny the packet before egress; the local egress adapter counts calls.
- Expected result: deterministic tests remain green; `udp-deny-smoke` observes a sandbox UDP packet, emits a deny audit record from the runtime, performs zero egress calls, sends no reply, and the sandbox target exits successfully after timing out. Existing allow/forward smoke should still pass.
- Observed result: pass. `foxprox-core` ran 33 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests. `udp-deny-smoke` emitted `decision":"deny_drop"`, `egress_calls":"0"`, and `policy_reason":"default deny"`; `udp-forward-smoke` still emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"sandbox UDP probe was denied, no egress call occurred, and target timed out"`; `"runtime_audit":"{...\"destination\":\"203.0.113.11:5354\",...\"decision\":\"deny_drop\",\"reason\":\"default deny\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: the environment harness now proves both positive and negative UDP behavior over the bwrap-created TUN fd with the same core runtime: allowed traffic reaches host egress, denied traffic does not.
- Next verification gap: DNS broker foundation on the transparent UDP runtime path: handle sandbox UDP/53 locally, audit DNS query, and cache/attribute returned addresses without host egress.
- Commit hash after commit: pending.

## 2026-06-21T15:55:00Z — Denied UDP smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add denied UDP environment smoke"`
- Environment assumptions: denied UDP smoke and existing allow UDP smoke were verified before commit.
- Expected result: commit captures negative environment proof for default-deny UDP behavior over TUN.
- Observed result: commit `87fc161` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 87fc161] Add denied UDP environment smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: negative UDP environment checkpoint is preserved.
- Next verification gap: transparent DNS broker foundation using the UDP runtime path.
- Commit hash after commit: 87fc161.

## 2026-06-21T16:25:00Z — Transparent DNS smoke foundation

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-smoke`
- Environment assumptions: sandbox Python can send a raw DNS UDP query to the broker address `10.0.2.1:53`; host harness owns the handed-off TUN fd and can synthesize a minimal DNS A response locally without external DNS.
- Expected result: deterministic DNS wire parser/synthesizer tests pass; `dns-smoke` observes a sandbox DNS A query over TUN, writes a local A response, updates DNS cache attribution, and the sandbox target validates the answer.
- Observed result: pass. `foxprox-core` increased to 35 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. `dns-smoke` emitted `decision":"allow"`, `hostname":"lab.example"`, and `attribution_cached":"true"`.
- Relevant output excerpt: `dns::tests::parses_and_synthesizes_a_query_wire ... ok`; `"reason":"sandbox DNS A query was answered locally and cached for attribution"`; `"answer":"203.0.113.77"`.
- Changed files: `crates/foxprox-core/src/dns.rs`, `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: the harness now has a local DNS broker proof on the same bwrap/TUN fd path: DNS can be answered without external network access and results can feed attribution cache state.
- Next verification gap: use the DNS cache result to attribute a subsequent transparent UDP/TCP flow in an environment smoke, or begin TCP stack/forwarding proof scaffolding.
- Commit hash after commit: pending.

## 2026-06-21T16:30:00Z — DNS smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs crates/foxprox-core/src/dns.rs learnings.md progress.md && git commit -m "Add transparent DNS smoke harness"`
- Environment assumptions: DNS smoke and deterministic DNS tests above were verified before commit.
- Expected result: commit captures DNS wire parser/synthesizer and bwrap/TUN DNS smoke.
- Observed result: commit `9c03387` created with 5 files changed.
- Relevant output excerpt: `[harness-lab 9c03387] Add transparent DNS smoke harness`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: transparent DNS broker foundation checkpoint is preserved.
- Next verification gap: DNS cache attribution applied to subsequent transparent flows.
- Commit hash after commit: 9c03387.

## 2026-06-21T16:45:00Z — DNS cache attribution in transparent UDP runtime

- Command executed: `cargo fmt --all && cargo test --all`; `target/debug/foxprox-lab run dns-smoke && target/debug/foxprox-lab run udp-forward-smoke`
- Environment assumptions: deterministic runtime attribution test uses tick-based DNS cache time; environment smokes reused existing built binaries from the prior DNS cycle.
- Expected result: transparent UDP runtime can consult DNS cache for destination attribution before policy evaluation, allowing domain-suffix rules that require hostname attribution. Existing DNS and UDP environment smokes continue to pass.
- Observed result: pass. `foxprox-core` increased to 36 tests. Runtime test `dns_cache_attribution_can_allow_domain_udp_rule` passed, and both `dns-smoke` and `udp-forward-smoke` emitted `decision":"allow"`.
- Relevant output excerpt: `runtime::tests::dns_cache_attribution_can_allow_domain_udp_rule ... ok`; DNS smoke `"attribution_cached":"true"`; UDP forward smoke `"policy_decision":"allow"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: the core transparent UDP runtime now supports DNS-cache hostname attribution for subsequent flow policy decisions. This provides the deterministic foundation needed for transparent hostname-aware UDP/QUIC policy.
- Next verification gap: environment smoke that performs DNS query and attributed UDP flow in one sandbox session, or begin TCP forwarding gate scaffolding.
- Commit hash after commit: pending.

## 2026-06-21T16:50:00Z — DNS attribution runtime commit recorded

- Command executed: `git add crates/foxprox-core/src/runtime.rs progress.md && git commit -m "Add DNS cache attribution to UDP runtime"`
- Environment assumptions: deterministic runtime attribution test and existing smokes above were verified before commit.
- Expected result: commit captures DNS cache attribution support in the transparent UDP runtime.
- Observed result: commit `174a447` created with 2 files changed.
- Relevant output excerpt: `[harness-lab 174a447] Add DNS cache attribution to UDP runtime`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: DNS attribution in core runtime checkpoint is preserved.
- Next verification gap: one-session environment smoke for DNS query followed by attributed UDP allow.
- Commit hash after commit: 174a447.

## 2026-06-21T17:10:00Z — One-session DNS attribution environment smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke`; rerun after shortening the handoff socket path: `cargo fmt --all && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke`; final check: `cargo test --all`.
- Environment assumptions: Unix domain socket paths have a length limit; the DNS-attribution smoke uses a short `target/debug/fxdns-*/s` socket path. Sandbox Python performs a raw DNS A query, then sends UDP to the returned IP in the same bwrap/TUN session.
- Expected result: DNS query is answered locally, runtime cache is populated, subsequent UDP packet to `203.0.113.77:5354` is allowed only because the DNS cache attributes it to `lab.example`, and host egress receives the datagram.
- Observed result: pass after shortening socket path. Initial run failed with `path must be shorter than SUN_LEN`; after using a short path, `dns-attribution-smoke` emitted `decision":"allow"`. Final `cargo test --all` passed (`foxprox-core` 36, `foxprox-cli` 2, `foxproxsetup` 7).
- Relevant output excerpt: `"reason":"DNS cache attribution allowed subsequent sandbox UDP flow"`; `"attributed_hostname":"lab.example"`; `"rule_id":"allow-dns-attributed-example"`; `"dns_answered":"true"`; `"forwarded":"true"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`, `learnings.md`.
- Interpretation: hostname attribution is now proven end-to-end in an environment-dependent bwrap/TUN session: DNS observation in the harness changes the policy outcome for a later transparent UDP flow.
- Next verification gap: TCP forwarding gate scaffolding, likely starting with deterministic TCP SYN parsing/policy/audit and then a userspace stack or minimal local smoke path.
- Commit hash after commit: pending.

## 2026-06-21T17:15:00Z — DNS attribution smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs learnings.md progress.md && git commit -m "Add DNS attribution environment smoke"`
- Environment assumptions: DNS attribution smoke and deterministic tests above were verified before commit.
- Expected result: commit captures one-session DNS attribution environment proof.
- Observed result: commit `de1897d` created with 4 files changed.
- Relevant output excerpt: `[harness-lab de1897d] Add DNS attribution environment smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: DNS-attributed transparent flow checkpoint is preserved.
- Next verification gap: TCP forwarding gate scaffolding.
- Commit hash after commit: de1897d.

## 2026-06-21T17:30:00Z — Deterministic TCP connect runtime scaffold

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: this is a deterministic scaffold only; it parses synthetic IPv4/TCP SYN packets and does not attempt real TCP stream forwarding or smoltcp integration.
- Expected result: add a platform-independent transparent TCP runtime boundary that evaluates TCP SYN connect attempts through policy, uses DNS cache attribution when available, calls egress only for allowed connects, and audits allowed/denied decisions.
- Observed result: pass. `foxprox-core` increased to 38 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests.
- Relevant output excerpt: `runtime::tests::tcp_syn_connect_attempt_uses_policy_before_egress ... ok`; `runtime::tests::denied_tcp_syn_never_reaches_egress ... ok`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: this does not satisfy the smoltcp TCP forwarding gate, but it creates a verified policy/audit/egress boundary for TCP connect attempts that the future stack adapter can call when it emits stream events.
- Next verification gap: real TCP stack/forwarding proof with smoltcp or another userspace stack, or a smaller harness that demonstrates TCP SYN packets arriving from the bwrap TUN fd.
- Commit hash after commit: pending.

## 2026-06-21T17:35:00Z — TCP scaffold commit recorded

- Command executed: `git add crates/foxprox-core/src/runtime.rs progress.md && git commit -m "Add TCP connect runtime scaffold"`
- Environment assumptions: deterministic TCP runtime tests above were verified before commit.
- Expected result: commit captures transparent TCP connect policy/audit/egress scaffold.
- Observed result: commit `f1f5e6b` created with 2 files changed.
- Relevant output excerpt: `[harness-lab f1f5e6b] Add TCP connect runtime scaffold`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: TCP connect scaffold checkpoint is preserved.
- Next verification gap: real TCP stack/forwarding proof or smaller bwrap/TUN TCP SYN arrival smoke.
- Commit hash after commit: f1f5e6b.

## 2026-06-22T00:05:00Z — TCP SYN arrival environment smoke

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-syn-smoke`
- Environment assumptions: bwrap, `/dev/net/tun`, Python, and Unix fd handoff are available; the sandbox TCP connect attempt is expected to time out because the harness observes only the SYN and does not yet synthesize TCP stack responses back to the sandbox.
- Expected result: deterministic tests remain green; a sandbox TCP connect attempt emits a TCP SYN on the handed-off TUN fd; the transparent TCP runtime evaluates an allow rule, records audit output, and invokes a host TCP egress fixture exactly once.
- Observed result: pass. `foxprox-core` ran 38 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `tcp-syn-smoke` emitted `decision":"allow"`, `syn_observed":"true"`, and `egress_calls":"1"`.
- Relevant output excerpt: `"reason":"sandbox TCP SYN reached the handed-off TUN fd and invoked policy-gated egress"`; `"runtime_audit":"{...\"event\":\"tcp_connect_attempt\",...\"destination\":\"203.0.113.20:8080\",...\"rule_id\":\"allow-tcp-syn-smoke\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: the harness now proves real TCP connect attempts reach the broker-owned TUN fd and enter the policy/audit/egress boundary. This is still not the smoltcp TCP forwarding gate because no SYN-ACK, stream lifecycle, or byte bridging is implemented.
- Next verification gap: implement a userspace TCP stack/forwarding proof (smoltcp or equivalent) that responds to the sandbox TCP handshake and bridges bytes to a local host TCP fixture.
- Commit hash after commit: pending.

## 2026-06-22T00:08:00Z — TCP SYN smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add TCP SYN environment smoke"`
- Environment assumptions: TCP SYN smoke and deterministic tests above were verified before commit.
- Expected result: commit captures the environment proof that sandbox TCP SYN packets reach the handed-off TUN fd and invoke the transparent TCP policy/audit/egress boundary.
- Observed result: commit `3cfd9dd` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 3cfd9dd] Add TCP SYN environment smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: TCP SYN arrival and policy-gated egress checkpoint is preserved.
- Next verification gap: userspace TCP stack/forwarding proof that completes the sandbox handshake and bridges bytes to a host TCP fixture.
- Commit hash after commit: 3cfd9dd.

## 2026-06-22T00:25:00Z — Deterministic smoltcp TCP gate

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run stack`
- Environment assumptions: deterministic in-memory smoltcp IP-medium device; no Linux namespace, TUN fd, or external network required. The fixture uses a valid IPv4/TCP SYN with TCP pseudo-header checksum.
- Expected result: smoltcp consumes a TUN-shaped IPv4/TCP SYN, a listening TCP socket becomes active, and smoltcp emits a SYN-ACK IP packet that the future TUN frontend can write back.
- Observed result: pass. `foxprox-core` ran 40 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests. `foxprox-lab run stack` emitted a `tcp_connect_attempt` audit record with `decision":"allow"`, `socket_active_after_poll":"true"`, and `emitted_packets":"1"`.
- Relevant output excerpt: `smoltcp_gate::tests::smoltcp_consumes_tun_shaped_tcp_syn_and_emits_syn_ack ... ok`; `"reason":"smoltcp consumed a TUN-shaped TCP SYN and emitted a SYN-ACK"`.
- Changed files: `Cargo.toml`, `Cargo.lock`, `crates/foxprox-core/src/{lib.rs,packet.rs,scenario.rs,smoltcp_gate.rs}`, `README.md`, `progress.md`.
- Interpretation: the project now has a reusable deterministic smoltcp gate proving that the selected userspace TCP/IP stack can operate on IP-medium/TUN-shaped packets. This still needs to be wired to the handed-off TUN fd and host TCP byte bridging for the full Milestone 2 forwarding proof.
- Next verification gap: build a TUN-fd smoltcp smoke that writes the emitted SYN-ACK back to the sandbox, then extend it into local TCP byte bridging.
- Commit hash after commit: pending.

## 2026-06-22T00:30:00Z — smoltcp gate commit recorded

- Command executed: `git add Cargo.lock README.md crates/foxprox-core/Cargo.toml crates/foxprox-core/src/lib.rs crates/foxprox-core/src/packet.rs crates/foxprox-core/src/scenario.rs crates/foxprox-core/src/smoltcp_gate.rs learnings.md progress.md && git commit -m "Add deterministic smoltcp TCP gate"`
- Environment assumptions: deterministic smoltcp gate and `foxprox-lab run stack` output above were verified before commit.
- Expected result: commit captures smoltcp dependency, in-memory IP-medium device gate, SYN/SYN-ACK fixture tests, and harness documentation.
- Observed result: commit `cf79595` created with 9 files changed.
- Relevant output excerpt: `[harness-lab cf79595] Add deterministic smoltcp TCP gate`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: deterministic smoltcp stack-gate checkpoint is preserved.
- Next verification gap: TUN-fd smoltcp smoke that writes smoltcp's emitted SYN-ACK back to the sandbox.
- Commit hash after commit: cf79595.

## 2026-06-22T00:45:00Z — smoltcp SYN-ACK write-back smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-synack-smoke`
- Environment assumptions: bwrap, `/dev/net/tun`, Python, and Unix fd handoff are available. The smoke handles only the TCP handshake proof: a sandbox connect succeeds after smoltcp emits a SYN-ACK, but no application bytes are bridged yet.
- Expected result: tests remain green; sandbox TCP SYN is read from the handed-off TUN fd, fed into the smoltcp IP-medium gate, emitted SYN-ACK is written back to TUN, and sandbox `connect()` exits successfully.
- Observed result: pass. `foxprox-core` ran 40 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `tcp-synack-smoke` emitted `decision":"allow"`, `syn_ack_written":"true"`, `emitted_packets":"1"`, and `status":"exit status: 0"`.
- Relevant output excerpt: `"reason":"smoltcp SYN-ACK written to TUN completed the sandbox TCP connect"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: the smoltcp gate is now proven against a real sandbox SYN and real TUN write-back, closing part of the gap between deterministic stack proof and environment integration. It is still not full TCP forwarding because smoltcp state is one-shot and there is no host stream byte bridge.
- Next verification gap: maintain smoltcp interface/socket state across ACK and data packets and bridge received sandbox bytes to a local host TCP fixture.
- Commit hash after commit: pending.

## 2026-06-22T00:50:00Z — SYN-ACK smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add smoltcp SYN-ACK TUN smoke"`
- Environment assumptions: TCP SYN-ACK smoke and deterministic tests above were verified before commit.
- Expected result: commit captures environment smoke that feeds a real sandbox SYN into smoltcp and writes the emitted SYN-ACK back to TUN.
- Observed result: commit `8101a9e` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 8101a9e] Add smoltcp SYN-ACK TUN smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: smoltcp handshake write-back checkpoint is preserved.
- Next verification gap: stateful smoltcp byte bridging to a host TCP fixture.
- Commit hash after commit: 8101a9e.

## 2026-06-22T01:15:00Z — Stateful smoltcp TCP bridge smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: bwrap, `/dev/net/tun`, Python, and Unix fd handoff are available; a local host TCP fixture is used instead of external network. The smoke bridges one request/response and is not yet a production multi-flow TCP runtime.
- Expected result: tests remain green; sandbox connects to a routed TCP destination, smoltcp completes the handshake, smoltcp receives sandbox payload bytes, host egress fixture receives those bytes, fixture response is sent back through smoltcp, and sandbox validates the response.
- Observed result: pass. `foxprox-core` ran 40 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `tcp-bridge-smoke` emitted `decision":"allow"`, `bridged_bytes":"5"`, `response_written":"true"`, and `status":"exit status: 0"`.
- Relevant output excerpt: `"reason":"sandbox TCP bytes were bridged through smoltcp to a host TCP fixture and back"`; `"emitted_packets":"2"`; `"packets_read":"5"`.
- Changed files: `crates/foxprox-core/src/smoltcp_gate.rs`, `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: this is the first local Milestone 2 TCP forwarding proof over the bwrap-created, handed-off TUN fd: bytes from an unmodified sandbox TCP socket are mediated by smoltcp and bridged through a host-owned TCP socket. Remaining work is to turn the smoke path into reusable broker runtime code with policy/audit integration and multi-flow lifecycle handling.
- Next verification gap: integrate policy/audit decisions into the smoltcp TCP bridge smoke and fail closed before host egress on a denied TCP bridge attempt.
- Commit hash after commit: pending.

## 2026-06-22T01:20:00Z — TCP bridge smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs crates/foxprox-core/src/smoltcp_gate.rs learnings.md progress.md && git commit -m "Add stateful smoltcp TCP bridge smoke"`
- Environment assumptions: TCP bridge smoke and deterministic tests above were verified before commit.
- Expected result: commit captures stateful smoltcp server harness and local TCP byte-bridging environment smoke.
- Observed result: commit `554aad2` created with 5 files changed.
- Relevant output excerpt: `[harness-lab 554aad2] Add stateful smoltcp TCP bridge smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: local TCP forwarding proof checkpoint is preserved.
- Next verification gap: policy/audit-gated TCP bridge allow/deny behavior.
- Commit hash after commit: 554aad2.

## 2026-06-22T01:35:00Z — TCP bridge deny smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-deny-smoke && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: the denied-path target treats TCP connect timeout/error as success; default policy denies TCP with reset semantics, but this harness currently observes fail-closed timeout rather than synthesizing an RST packet.
- Expected result: tests remain green; denied sandbox TCP SYN is audited before smoltcp or host egress; no host egress occurs; target exits after observing no connection; existing allow bridge smoke still passes.
- Observed result: pass. `foxprox-core` ran 40 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests. `tcp-bridge-deny-smoke` emitted `decision":"deny_reset"`, `egress_calls":"0"`, `policy_reason":"default deny"`, and `status":"exit status: 0"`; `tcp-bridge-smoke` still emitted `decision":"allow"`.
- Relevant output excerpt: `"reason":"sandbox TCP SYN was denied before smoltcp or host egress and the target timed out"`; `"runtime_audit":"{...\"decision\":\"deny_reset\",\"reason\":\"default deny\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: TCP forwarding has a positive and negative environment proof. The denial path is policy/audit gated and prevents smoltcp/host egress, but reset synthesis remains a correctness gap because the target observes timeout, not an active TCP RST.
- Next verification gap: synthesize TCP RST for denied TCP connects or factor TCP bridge smoke into a reusable broker runtime with policy-before-egress built into the positive path.
- Commit hash after commit: pending.

## 2026-06-22T01:40:00Z — denied TCP bridge smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs learnings.md progress.md && git commit -m "Add denied TCP bridge smoke"`
- Environment assumptions: denied TCP bridge smoke and existing allow bridge smoke above were verified before commit.
- Expected result: commit captures policy/audit-gated negative TCP bridge proof.
- Observed result: commit `feec414` created with 4 files changed.
- Relevant output excerpt: `[harness-lab feec414] Add denied TCP bridge smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: denied TCP bridge checkpoint is preserved.
- Next verification gap: synthesize TCP RST for denied TCP connects.
- Commit hash after commit: feec414.

## 2026-06-22T01:55:00Z — TCP deny reset synthesis

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-deny-smoke`
- Environment assumptions: denied TCP connect should receive a broker-synthesized TCP RST+ACK over the handed-off TUN fd; no smoltcp socket or host egress fixture should be used for denied traffic.
- Expected result: packet helper tests validate TCP RST shape/checksum; denied environment smoke audits default deny, writes RST, performs zero egress, and sandbox target exits successfully.
- Observed result: pass. `foxprox-core` increased to 41 tests; `tcp-bridge-deny-smoke` emitted `decision":"deny_reset"`, `rst_written":"true"`, `egress_calls":"0"`, and `status":"exit status: 0"`.
- Relevant output excerpt: `packet::tests::synthesizes_tcp_rst_for_denied_syn ... ok`; `"reason":"sandbox TCP SYN was denied before smoltcp or host egress and reset"`.
- Changed files: `crates/foxprox-core/src/packet.rs`, `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: denied TCP connects now match the architecture's reset-denial behavior instead of relying on timeout-only fail-closed behavior. This improves the TCP negative path while keeping host egress blocked.
- Next verification gap: factor the positive TCP bridge path into a reusable broker runtime boundary with policy-before-egress built in, instead of keeping bridge orchestration inside the CLI harness.
- Commit hash after commit: pending.

## 2026-06-22T02:00:00Z — TCP reset synthesis commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs crates/foxprox-core/src/packet.rs learnings.md progress.md && git commit -m "Synthesize TCP resets for denied connects"`
- Environment assumptions: TCP RST helper tests and denied bridge reset smoke above were verified before commit.
- Expected result: commit captures TCP RST synthesis and reset-based denied TCP bridge behavior.
- Observed result: commit `f12f830` created with 5 files changed.
- Relevant output excerpt: `[harness-lab f12f830] Synthesize TCP resets for denied connects`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: TCP reset denial checkpoint is preserved.
- Next verification gap: reusable TCP bridge runtime boundary with policy-before-egress in the positive path.
- Commit hash after commit: f12f830.

## 2026-06-22T02:15:00Z — Policy-gated TCP bridge allow path

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke && target/debug/foxprox-lab run tcp-bridge-deny-smoke`
- Environment assumptions: positive TCP bridge smoke uses an explicit allow rule before smoltcp accepts the SYN or host egress receives bytes; denied smoke continues to prove reset/no-egress behavior.
- Expected result: tests remain green; TCP bridge allow path records policy allow metadata before forwarding; TCP bridge deny path still resets and performs zero egress.
- Observed result: pass. `tcp-bridge-smoke` emitted `policy_allowed":"true"`, `policy_decision":"allow"`, `rule_id":"allow-tcp-bridge-smoke"`, and `response_written":"true"`; `tcp-bridge-deny-smoke` still emitted `decision":"deny_reset"` and `rst_written":"true"`.
- Relevant output excerpt: `"runtime_audit":"{...\"event\":\"tcp_connect_attempt\",...\"decision\":\"allow\",\"rule_id\":\"allow-tcp-bridge-smoke\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: both positive and negative TCP bridge environment proofs now include policy-before-smoltcp/egress enforcement evidence. The remaining quality gap is factoring this orchestration out of the CLI harness into a reusable broker runtime boundary.
- Next verification gap: reusable TCP bridge runtime boundary or explicit proxy networking smoke.
- Commit hash after commit: pending.

## 2026-06-22T02:20:00Z — policy-gated TCP bridge commit recorded

- Command executed: `git add crates/foxprox-cli/src/main.rs progress.md && git commit -m "Gate TCP bridge smoke with policy"`
- Environment assumptions: policy-gated allow bridge and reset-based deny bridge smokes above were verified before commit.
- Expected result: commit captures policy-before-smoltcp/egress evidence for the positive TCP bridge path.
- Observed result: commit `0b1bd0d` created with 2 files changed.
- Relevant output excerpt: `[harness-lab 0b1bd0d] Gate TCP bridge smoke with policy`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: policy-gated TCP bridge checkpoint is preserved.
- Next verification gap: explicit proxy networking smoke or reusable TCP bridge runtime boundary.
- Commit hash after commit: 0b1bd0d.

## 2026-06-22T02:40:00Z — Explicit HTTP proxy forwarding smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke`
- Environment assumptions: local-only TCP sockets are available; the smoke uses an in-process client, explicit HTTP proxy listener, and origin fixture with no external network dependency.
- Expected result: tests remain green; proxy parses an absolute-form HTTP request, evaluates host/path policy, forwards an origin-form request to a local host-owned origin socket, returns the response to the client, and emits structured audit metadata.
- Observed result: pass. `foxprox-core` ran 41 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests, and `http-proxy-smoke` emitted `decision":"allow"`, `rule_id":"allow-http-proxy-example"`, `method":"GET"`, and `path":"/ok"`.
- Relevant output excerpt: `"reason":"HTTP proxy request was policy-allowed and forwarded to a local origin fixture"`; `"frontend":"http_proxy"`; `"hostname":"example.com"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: explicit HTTP proxy networking now has a local forwarding proof, not just parser fixtures. Remaining explicit proxy gaps are denied HTTP proxy behavior, HTTPS CONNECT tunneling, and SOCKS5 TCP CONNECT forwarding.
- Next verification gap: add an explicit HTTP proxy deny smoke or HTTPS CONNECT/SOCKS TCP CONNECT forwarding smoke.
- Commit hash after commit: pending.

## 2026-06-22T02:45:00Z — HTTP proxy smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add explicit HTTP proxy smoke"`
- Environment assumptions: local HTTP proxy smoke and workspace tests above were verified before commit.
- Expected result: commit captures explicit HTTP proxy forwarding smoke and ledger updates.
- Observed result: commit `a1401ce` created with 3 files changed.
- Relevant output excerpt: `[harness-lab a1401ce] Add explicit HTTP proxy smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: explicit HTTP proxy allow checkpoint is preserved.
- Next verification gap: denied HTTP proxy behavior, HTTPS CONNECT forwarding, or SOCKS TCP CONNECT forwarding.
- Commit hash after commit: a1401ce.

## 2026-06-22T01:08:00Z — Explicit HTTPS CONNECT and SOCKS5 forwarding smokes

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke`
- Environment assumptions: local-only TCP sockets are available; both smokes use in-process client/proxy/origin fixtures and no external network.
- Expected result: workspace tests remain green; HTTPS CONNECT and SOCKS5 TCP CONNECT requests are parsed, evaluated by policy, tunneled through host-owned TCP sockets, and audited with explicit-proxy attribution.
- Observed result: pass. `foxprox-core` ran 41 tests, `foxprox-cli` ran 2 tests, `foxproxsetup` ran 7 tests. `https-connect-smoke` and `socks5-smoke` each emitted `decision":"allow"`, `policy_decision":"allow"`, and exchanged `ping`/`pong` through a local TCP fixture.
- Relevant output excerpt: `"event":"https_connect","frontend":"http_proxy","hostname":"example.com","rule_id":"allow-https-connect-example"`; `"event":"socks_connect","frontend":"socks5","rule_id":"allow-socks5-example"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: Milestone 6 now has local forwarding proofs for all explicit proxy modes in scope: HTTP proxy, HTTPS CONNECT, and SOCKS5 TCP CONNECT. Denied/malformed explicit proxy paths still need runnable smoke coverage beyond parser/unit tests.
- Next verification gap: add denied/malformed explicit proxy smokes, then improve transparent inspection/audit coverage for plaintext HTTP, TLS SNI mismatch, hidden SNI, and QUIC candidate decisions.
- Commit hash after commit: pending.

## 2026-06-22T01:12:00Z — explicit proxy smokes commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add CONNECT and SOCKS5 proxy smokes"`
- Environment assumptions: HTTPS CONNECT/SOCKS5 smoke commands and workspace tests above were verified before commit.
- Expected result: commit captures explicit HTTPS CONNECT and SOCKS5 TCP CONNECT forwarding smokes plus documentation.
- Observed result: commit `92d14a1` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 92d14a1] Add CONNECT and SOCKS5 proxy smokes`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: explicit proxy forwarding checkpoint is preserved.
- Next verification gap: denied/malformed explicit proxy smokes, then transparent inspection/audit coverage for plaintext HTTP, TLS SNI mismatch, hidden SNI, and QUIC candidate decisions.
- Commit hash after commit: 92d14a1.

## 2026-06-22T01:25:00Z — Transparent inspection runtime and scenario

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run inspect`
- Environment assumptions: deterministic in-memory TCP payload fixtures; no Linux namespace or external network required. TCP stream reassembly remains the responsibility of the smoltcp/flow adapter before calling this inspection boundary.
- Expected result: transparent plaintext HTTP Host/method/path inspection, TLS SNI/DNS mismatch handling, and hidden-SNI fail-closed behavior are modeled as reusable policy/audit behavior and visible through a harness command.
- Observed result: pass. `foxprox-core` increased to 44 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. `foxprox-lab run inspect` emitted transparent `http_request` allow, `tls_client_hello` SNI/DNS mismatch fail-closed, and `tls_client_hello` hidden-SNI fail-closed records.
- Relevant output excerpt: `"event":"http_request","frontend":"tun","attribution_source":"http_host","rule_id":"allow-transparent-http-public"`; `"reason":"SNI/DNS attribution mismatch"`; `"reason":"hidden SNI requires explicit IP allow"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `crates/foxprox-core/src/scenario.rs`, `README.md`, `progress.md`.
- Interpretation: Milestone 5 has stronger deterministic harness coverage for transparent HTTP and TLS attribution decisions. The remaining quality gap is end-to-end environment smoke coverage for transparent HTTP/TLS bytes through the smoltcp bridge, plus explicit denied/malformed proxy smokes.
- Next verification gap: add denied/malformed explicit proxy smoke or wire transparent HTTP inspection into the TCP bridge environment smoke.
- Commit hash after commit: pending.

## 2026-06-22T01:28:00Z — transparent inspection commit recorded

- Command executed: `git add README.md crates/foxprox-core/src/runtime.rs crates/foxprox-core/src/scenario.rs progress.md && git commit -m "Add transparent inspection runtime"`
- Environment assumptions: deterministic inspection tests and `inspect` scenario above were verified before commit.
- Expected result: commit captures transparent HTTP/TLS inspection runtime, scenario output, README update, and prior explicit-proxy commit ledger note.
- Observed result: commit `52eef84` created with 4 files changed.
- Relevant output excerpt: `[harness-lab 52eef84] Add transparent inspection runtime`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: transparent inspection checkpoint is preserved.
- Next verification gap: denied/malformed explicit proxy smoke or environment smoke that feeds transparent HTTP bytes through the TCP bridge into the inspection runtime.
- Commit hash after commit: 52eef84.

## 2026-06-22T01:40:00Z — Denied and malformed explicit proxy smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke`
- Environment assumptions: local-only TCP socket for the HTTP deny path; malformed CONNECT and unsupported SOCKS fixtures are deterministic parser checks with no host egress.
- Expected result: denied HTTP proxy request receives a local 403/reset-style policy decision before egress; malformed CONNECT and unsupported SOCKS requests fail closed with zero egress calls.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 44, `foxprox-cli` 2, `foxproxsetup` 7). `proxy-deny-smoke` emitted `deny_reset` for `/admin` HTTP and `fail_closed` records for malformed CONNECT and SOCKS UDP ASSOCIATE.
- Relevant output excerpt: `"event":"http_request","decision":"deny_reset","rule_id":"deny-http-admin","egress_calls":"0"`; `"reason":"malformed CONNECT request denied before egress: request is not CONNECT"`; `"reason":"unsupported SOCKS request denied before egress: only SOCKS5 TCP CONNECT is supported"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: explicit proxy networking now has allow, deny, and malformed/unsupported smoke coverage across HTTP, HTTPS CONNECT, and SOCKS5 TCP CONNECT scope.
- Next verification gap: wire transparent HTTP inspection into an environment smoke through the smoltcp TCP bridge, or add audit backpressure/resource-limit modeling for robustness.
- Commit hash after commit: pending.

## 2026-06-22T01:43:00Z — denied proxy smoke commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Add denied proxy smoke"`
- Environment assumptions: denied/malformed proxy smoke and workspace tests above were verified before commit.
- Expected result: commit captures explicit proxy deny/fail-closed smoke and README update, plus prior transparent-inspection commit ledger note.
- Observed result: commit `d3d84bd` created with 3 files changed.
- Relevant output excerpt: `[harness-lab d3d84bd] Add denied proxy smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: explicit proxy negative-path checkpoint is preserved.
- Next verification gap: transparent HTTP environment smoke through smoltcp bridge or robustness/resource-limit modeling.
- Commit hash after commit: d3d84bd.

## 2026-06-22T02:00:00Z — Transparent HTTP inspection in TCP bridge smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; sandbox Python sends a plaintext HTTP request to a routed TCP destination; smoltcp bridge receives application bytes and calls the transparent inspection runtime before host egress.
- Expected result: existing tests remain green; TCP bridge smoke still forwards bytes through host-owned TCP egress and now records a transparent HTTP inspection allow audit for Host/path metadata before egress response.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 44, `foxprox-cli` 2, `foxproxsetup` 7). `tcp-bridge-smoke` emitted `decision":"allow"`, `inspection_decision":"allow"`, `inspection_rule_id":"allow-transparent-http-bridge"`, and a nested `http_request` inspection audit with `attribution_source":"http_host"`.
- Relevant output excerpt: `"destination":"203.0.113.22:80","hostname":"example.com","rule_id":"allow-transparent-http-bridge"`; `"bridged_bytes":"43"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `README.md`, `progress.md`.
- Interpretation: transparent plaintext HTTP Host/path inspection is now proven in an environment-dependent bwrap/TUN TCP bridge, not only deterministic unit/scenario fixtures.
- Next verification gap: robustness/resource-limit modeling such as audit backpressure, or UDP/QUIC policy smoke with DNS attribution and configurable timeout evidence.
- Commit hash after commit: pending.

## 2026-06-22T02:03:00Z — TCP bridge inspection commit recorded

- Command executed: `git add README.md crates/foxprox-cli/src/main.rs progress.md && git commit -m "Inspect HTTP in TCP bridge smoke"`
- Environment assumptions: transparent HTTP TCP bridge smoke and workspace tests above were verified before commit.
- Expected result: commit captures environment-backed transparent HTTP inspection in the smoltcp bridge and prior denied-proxy ledger note.
- Observed result: commit `4b4cbe2` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 4b4cbe2] Inspect HTTP in TCP bridge smoke`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: environment transparent HTTP inspection checkpoint is preserved.
- Next verification gap: robustness/resource-limit modeling such as audit backpressure, or UDP/QUIC policy smoke with DNS attribution and configurable timeout evidence.
- Commit hash after commit: 4b4cbe2.

## 2026-06-22T02:15:00Z — Bounded audit backpressure harness

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness`
- Environment assumptions: deterministic in-memory audit buffer; no Linux namespace or external network required.
- Expected result: audit output has a bounded queue model that reports backpressure instead of implying unbounded memory growth; harness scenario emits a fail-closed broker error when capacity is exhausted.
- Observed result: pass. `foxprox-core` increased to 45 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. `foxprox-lab run robustness` emitted `broker_error` with `decision":"fail_closed"` and `backpressure_observed":"true"`.
- Relevant output excerpt: `"reason":"audit buffer full; forwarding must fail closed or apply explicit overflow policy"`; `"capacity":"1"`; `"queued":"1"`.
- Changed files: `crates/foxprox-core/src/audit.rs`, `crates/foxprox-core/src/scenario.rs`, `README.md`, `progress.md`.
- Interpretation: Milestone 7 audit-backpressure behavior is now represented by a reusable core type and deterministic harness evidence. Production forwarding code still needs to wire this bounded sink into all hot paths.
- Next verification gap: final alpha coverage review and any missing documented success criteria that can be reduced to local harness checks.
- Commit hash after commit: pending.

## 2026-06-22T02:18:00Z — audit backpressure commit recorded

- Command executed: `git add README.md crates/foxprox-core/src/audit.rs crates/foxprox-core/src/scenario.rs progress.md && git commit -m "Model audit backpressure"`
- Environment assumptions: bounded audit buffer tests and robustness scenario above were verified before commit.
- Expected result: commit captures audit backpressure model and prior TCP bridge inspection ledger note.
- Observed result: commit `25601ec` created with 4 files changed.
- Relevant output excerpt: `[harness-lab 25601ec] Model audit backpressure`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: audit robustness checkpoint is preserved.
- Next verification gap: final alpha coverage review and any missing documented success criteria that can be reduced to local harness checks.
- Commit hash after commit: 25601ec.

## 2026-06-22T02:28:00Z — QUIC candidate policy/audit path in UDP runtime

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all | rg 'quic_candidate|broker_error'`
- Environment assumptions: deterministic in-memory UDP packet fixtures; no Linux namespace or external network required.
- Expected result: UDP/443 long-header payloads are treated as QUIC candidate policy events rather than generic UDP-only audit records, and existing workspace/harness checks remain green.
- Observed result: pass. `foxprox-core` increased to 46 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. The new runtime test proves DNS-attributed QUIC candidate traffic uses `Protocol::Quic`, `EventKind::QuicCandidateFlow`, `allow_quic(true)`, and a domain rule before egress.
- Relevant output excerpt: `runtime::tests::quic_candidate_uses_quic_policy_and_audit_event ... ok`; `"event":"quic_candidate_flow","frontend":"tun","protocol":"quic"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: transparent QUIC candidate handling now has a reusable policy/audit/egress boundary in the UDP runtime instead of being only a standalone classifier fixture.
- Next verification gap: optional end-to-end bwrap/TUN QUIC smoke, or final alpha coverage review if no more local gaps are high-value.
- Commit hash after commit: pending.

## 2026-06-22T02:31:00Z — QUIC runtime commit recorded

- Command executed: `git add crates/foxprox-core/src/runtime.rs progress.md && git commit -m "Classify QUIC in UDP runtime"`
- Environment assumptions: QUIC runtime test and full workspace checks above were verified before commit.
- Expected result: commit captures QUIC candidate policy/audit handling and prior audit-backpressure commit ledger note.
- Observed result: commit `eca2940` created with 2 files changed.
- Relevant output excerpt: `[harness-lab eca2940] Classify QUIC in UDP runtime`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: QUIC runtime checkpoint is preserved.
- Next verification gap: deterministic ICMP policy/write-back runtime or optional end-to-end bwrap/TUN QUIC smoke.
- Commit hash after commit: eca2940.

## 2026-06-22T02:45:00Z — Deterministic ICMP policy/write-back runtime

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: deterministic IPv4/ICMP echo fixtures; real sandbox `ping` remains environment-blocked by missing `CAP_NET_RAW` after capability drop, so this cycle avoids requiring privileged ping.
- Expected result: ICMP echo requests are policy-gated by `allow_ping`, allowed requests synthesize a valid echo reply, and default-denied requests do not produce a reply.
- Observed result: pass. `foxprox-core` increased to 48 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests.
- Relevant output excerpt: `runtime::tests::icmp_echo_reply_requires_ping_policy ... ok`; `runtime::tests::icmp_echo_denied_without_ping_policy ... ok`.
- Changed files: `crates/foxprox-core/src/policy.rs`, `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: ICMP basics now have a reusable core runtime boundary for ping allow/deny and packet write-back, while the environment limitation for invoking system ping remains recorded in `learnings.md`.
- Next verification gap: final alpha coverage review; remaining gaps are productionization/refactoring rather than additional small harness proofs.
- Commit hash after commit: pending.

## 2026-06-22T02:48:00Z — ICMP runtime commit recorded

- Command executed: `git add crates/foxprox-core/src/policy.rs crates/foxprox-core/src/runtime.rs progress.md && git commit -m "Add ICMP policy runtime"`
- Environment assumptions: deterministic ICMP runtime tests above were verified before commit.
- Expected result: commit captures policy-gated ICMP echo reply/deny runtime and prior QUIC runtime ledger note.
- Observed result: commit `34d5edf` created with 3 files changed.
- Relevant output excerpt: `[harness-lab 34d5edf] Add ICMP policy runtime`.
- Changed files: `progress.md` appended with commit record after the commit.
- Interpretation: ICMP runtime checkpoint is preserved.
- Next verification gap: final alpha coverage review; remaining gaps are productionization/refactoring rather than additional small harness proofs.
- Commit hash after commit: 34d5edf.

## 2026-06-22T03:05:00Z — Final alpha harness verification sweep

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all >/tmp/foxprox-all.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run inspect >/tmp/foxprox-inspect.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness >/tmp/foxprox-robustness.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke >/tmp/foxprox-http-proxy.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke >/tmp/foxprox-connect.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke >/tmp/foxprox-socks.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke >/tmp/foxprox-proxy-deny.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-deny.jsonl`
- Environment assumptions: local Linux supports bwrap, `/dev/net/tun`, Unix fd handoff, and sandbox Python; all network-dependent smokes use local fixtures, not external services.
- Expected result: deterministic unit/scenario coverage, explicit proxy smokes, DNS attribution, TCP bridge allow with transparent HTTP inspection, and TCP bridge deny/reset all pass.
- Observed result: pass. `foxprox-core` ran 48 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. All listed deterministic and environment-dependent commands completed successfully.
- Relevant output excerpt: `OK`; tcp bridge smoke `"decision":"allow"`, `"inspection_decision":"allow"`, `"inspection_rule_id":"allow-transparent-http-bridge"`, `"status":"exit status: 0"`; deny smoke `"decision":"deny_reset"`, `"rst_written":"true"`, `"egress_calls":"0"`.
- Changed files: `progress.md`.
- Interpretation: the harness now covers the documented alpha behavior with local evidence: setup/fd handoff, packet write-back, TCP bridge through smoltcp, UDP/DNS/attribution, transparent HTTP/TLS/QUIC decisions, explicit HTTP/CONNECT/SOCKS proxy allow and deny, ICMP policy/write-back, fail-closed malformed/unsupported paths, and audit backpressure modeling.
- Next verification gap: outside this harness-lab alpha, production hardening remains: factor CLI smoke orchestration into long-lived broker runtime crates, wire bounded audit buffers into all forwarding paths, support real upstream DNS forwarding, and define a safe ping capability strategy if real system `ping` smoke is required.
- Commit hash after commit: pending.

## 2026-06-22T03:08:00Z — final verification commit recorded

- Command executed: `git add progress.md && git commit -m "Record final alpha harness verification"`
- Environment assumptions: final verification sweep above passed before commit.
- Expected result: commit preserves final alpha harness verification evidence and ICMP runtime commit ledger note.
- Observed result: commit `7afd6a8` created with 1 file changed.
- Relevant output excerpt: `[harness-lab 7afd6a8] Record final alpha harness verification`.
- Changed files: `progress.md` appended with this commit record.
- Interpretation: final verification evidence is preserved in git history.
- Next verification gap: production hardening outside the current harness-lab alpha: long-lived broker runtime factoring, bounded audit sink wiring in hot paths, real upstream DNS forwarding, and optional real `ping` capability strategy.
- Commit hash after commit: 7afd6a8.

## 2026-06-22T03:25:00Z — Reusable TCP bridge runtime boundary

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: deterministic core tests do not require privileges; `tcp-bridge-smoke` requires local bwrap/TUN fd handoff and sandbox Python, with host egress as a local TCP fixture.
- Expected result: move the positive TCP bridge orchestration out of the CLI smoke into a reusable, platform-independent core runtime that owns policy-before-smoltcp, optional inspection, smoltcp state, audit records, and emitted TUN packets. Existing bridge smoke should continue to pass using the new runtime boundary.
- Observed result: pass. `foxprox-core` increased to 50 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. The environment `tcp-bridge-smoke` emitted `decision":"allow"`, `policy_decision":"allow"`, `inspection_decision":"allow"`, and `status":"exit status: 0"` through the refactored runtime.
- Relevant output excerpt: `runtime::tests::tcp_bridge_runtime_allowed_syn_enters_smoltcp ... ok`; `runtime::tests::tcp_bridge_runtime_denied_syn_emits_rst_before_stack ... ok`; `"inspection_rule_id":"allow-transparent-http-bridge"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: the highest-priority reviewer gap is partly closed: the core now contains a reusable TCP bridge runtime boundary rather than keeping all positive bridge orchestration in `foxprox-lab`. Host fd IO and host socket egress remain in the CLI/future device-egress crates by design.
- Next verification gap: factor the denied TCP bridge smoke onto the same reusable runtime, then begin wiring bounded audit buffers into runtime paths instead of storing audit in unbounded `Vec`s.
- Commit hash after commit: pending.

## 2026-06-22T03:40:00Z — Denied TCP bridge smoke on reusable runtime

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-deny-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; denied sandbox TCP connect should receive a runtime-synthesized RST with no host egress.
- Expected result: denied environment smoke uses the same reusable `TransparentTcpBridgeRuntime` as the allow bridge path, emits a deny audit record, writes a TCP RST, and performs zero host egress calls.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 50, `foxprox-cli` 2, `foxproxsetup` 7). `tcp-bridge-deny-smoke` emitted `decision":"deny_reset"`, `rst_written":"true"`, and `egress_calls":"0"`.
- Relevant output excerpt: `"runtime_audit":"{...\"event\":\"tcp_connect_attempt\"...\"decision\":\"deny_reset\"...}"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: both allow and deny TCP bridge environment paths now exercise the reusable core bridge runtime; CLI smoke code is reduced to fd IO, child process management, and host fixture egress.
- Next verification gap: wire bounded audit buffers into reusable runtime paths instead of keeping `Vec<AuditRecord>` as the only sink.
- Commit hash after commit: pending.

## 2026-06-22T03:55:00Z — Bounded audit flush for reusable runtimes

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: deterministic core tests; bounded sink behavior is in-memory and independent of Linux/TUN.
- Expected result: reusable runtimes can flush pending audit records into a bounded audit buffer, preserving records and reporting failure when the sink is full.
- Observed result: pass. `foxprox-core` increased to 52 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests.
- Relevant output excerpt: `runtime::tests::audit_flush_preserves_record_when_bounded_sink_is_full ... ok`; `runtime::tests::tcp_bridge_runtime_flushes_audit_to_bounded_sink ... ok`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: audit backpressure is now wired into the reusable TCP bridge runtime boundary via `flush_audit_to`, not just modeled as a standalone buffer. Other runtime paths can use the same helper and should be migrated before production forwarding.
- Next verification gap: add a small reusable host egress abstraction for TCP byte bridging so CLI smokes no longer hand-roll host TCP egress around the core bridge runtime.
- Commit hash after commit: pending.

## 2026-06-22T04:10:00Z — TCP stream data egress abstraction in bridge smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: local host TCP fixture is available; environment smoke still owns fd IO and process lifecycle, while host egress is now routed through the shared egress abstraction.
- Expected result: add a TCP stream-data egress request variant and use an `EgressBackend` implementation for the TCP bridge smoke instead of hand-rolled host socket bridging inline.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 52, `foxprox-cli` 2, `foxproxsetup` 7). `tcp-bridge-smoke` emitted `decision":"allow"`, `inspection_decision":"allow"`, and `egress_calls":"1"`.
- Relevant output excerpt: `"egress_calls":"1"`; `"inspection_rule_id":"allow-transparent-http-bridge"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-core/src/egress.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: TCP byte bridging now uses the shared host egress request model, reducing another piece of product behavior previously embedded only in CLI smoke code.
- Next verification gap: broader production factoring into dedicated broker-device/broker-egress crates, or final review of remaining gaps before stopping.
- Commit hash after commit: pending.

## 2026-06-22T04:25:00Z — Reusable DNS runtime boundary

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-smoke`; final warning cleanup check: `cargo fmt --all && cargo test --all`
- Environment assumptions: deterministic DNS runtime tests are local-only; `dns-smoke` requires bwrap/TUN fd handoff and sandbox Python but answers DNS locally without external network.
- Expected result: move DNS UDP/53 parse/answer/cache/audit behavior into a reusable core runtime and have `dns-smoke` use it.
- Observed result: pass. `foxprox-core` increased to 54 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. `dns-smoke` emitted `decision":"allow"`, `hostname":"lab.example"`, and `attribution_cached":"true"` through `TransparentDnsRuntime`.
- Relevant output excerpt: `runtime::tests::dns_runtime_answers_and_caches_local_a_record ... ok`; `runtime::tests::dns_runtime_denies_unknown_local_name_without_reply ... ok`; `"event":"dns_query","frontend":"tun","hostname":"lab.example"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: DNS broker-local behavior is now factored out of CLI smoke code into the reusable runtime layer, leaving fd IO and process lifecycle in the harness.
- Next verification gap: migrate DNS attribution smoke to the DNS runtime or begin dedicated crate decomposition.
- Commit hash after commit: pending.

## 2026-06-22T04:40:00Z — DNS attribution smoke uses DNS runtime

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; sandbox Python performs a raw DNS A query followed by a UDP datagram to the returned IP; all egress is local fixture traffic.
- Expected result: one-session DNS attribution smoke should use `TransparentDnsRuntime` for the DNS packet, transfer its cache into `TransparentUdpRuntime`, and still allow the subsequent domain-attributed UDP flow.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 54, `foxprox-cli` 2, `foxproxsetup` 7). `dns-attribution-smoke` emitted `decision":"allow"`, `dns_answered":"true"`, `forwarded":"true"`, and `attributed_hostname":"lab.example"`.
- Relevant output excerpt: `"rule_id":"allow-dns-attributed-example"`; `"destination":"203.0.113.77:5354","hostname":"lab.example"`; `"status":"exit status: 0"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: both standalone DNS and DNS-attribution smokes now use the reusable DNS runtime boundary, further reducing CLI-only broker behavior.
- Next verification gap: final review after runtime factoring; remaining work is likely crate decomposition and production async/resource hardening.
- Commit hash after commit: pending.

## 2026-06-22T04:43:00Z — DNS attribution runtime commit recorded

- Command executed: `git add crates/foxprox-cli/src/main.rs progress.md && git commit -m "Use DNS runtime in attribution smoke"`
- Environment assumptions: DNS attribution smoke and workspace tests above were verified before commit.
- Expected result: commit captures DNS attribution smoke migration to the reusable DNS runtime plus prior TCP/egress/runtime commit ledger notes.
- Observed result: commit `10d0d28` created with 2 files changed.
- Relevant output excerpt: `[harness-lab 10d0d28] Use DNS runtime in attribution smoke`.
- Changed files: `progress.md` appended with this commit record.
- Interpretation: DNS runtime factoring checkpoint is preserved.
- Next verification gap: final review after runtime factoring; remaining work is likely crate decomposition and production async/resource hardening.
- Commit hash after commit: 10d0d28.

## 2026-06-22T05:00:00Z — Post-runtime-factoring verification sweep

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all >/tmp/foxprox-all-post-factor.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness >/tmp/foxprox-robust-post-factor.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-smoke >/tmp/foxprox-dns-post-factor.jsonl && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr-post-factor.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge-post-factor.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-deny-post-factor.jsonl`
- Environment assumptions: local bwrap/TUN fd handoff and sandbox Python are available for environment smokes; all host egress remains local fixture traffic.
- Expected result: after factoring TCP bridge and DNS behavior into reusable runtime boundaries, deterministic scenarios and key environment smokes still pass.
- Observed result: pass. `foxprox-core` ran 54 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. DNS attribution and TCP bridge smokes completed successfully.
- Relevant output excerpt: `OK`; DNS attribution `"decision":"allow"`, `"attributed_hostname":"lab.example"`, `"forwarded":"true"`; TCP bridge `"decision":"allow"`, `"egress_calls":"1"`, `"inspection_decision":"allow"`.
- Changed files: `progress.md`.
- Interpretation: runtime factoring preserved alpha behavior while moving more broker semantics out of CLI-only smoke code.
- Next verification gap: create dedicated crate boundaries for device/runtime/egress or continue factoring remaining CLI-only explicit proxy forwarding into reusable core helpers.
- Commit hash after commit: pending.

## 2026-06-22T05:20:00Z — Explicit proxy runtime boundary

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke`; `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke`
- Environment assumptions: explicit proxy smokes use local client/proxy/origin TCP fixtures only; no external network.
- Expected result: HTTP proxy, HTTPS CONNECT, and SOCKS5 policy/audit handling should move into a reusable core explicit proxy runtime while smoke commands continue to tunnel bytes through local fixtures.
- Observed result: pass. `foxprox-core` increased to 56 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. HTTP, CONNECT, and SOCKS5 smokes emitted allow records with nested runtime audit from `ExplicitProxyRuntime`.
- Relevant output excerpt: `runtime::tests::explicit_proxy_runtime_allows_http_request_by_host_path ... ok`; `runtime::tests::explicit_proxy_runtime_denies_malformed_socks_before_egress ... ok`; `"event":"https_connect","runtime_audit":"{...}`; `"event":"socks_connect","runtime_audit":"{...}`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit proxy policy/audit semantics are now reusable core runtime behavior rather than CLI-only smoke logic; CLI still owns socket accept/tunnel mechanics.
- Next verification gap: migrate negative proxy smoke onto `ExplicitProxyRuntime`, then final review/commit.
- Commit hash after commit: pending.

## 2026-06-22T05:35:00Z — Proxy deny smoke uses explicit proxy runtime

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke`
- Environment assumptions: local-only HTTP proxy deny fixture; malformed CONNECT and unsupported SOCKS fixtures remain deterministic no-egress checks.
- Expected result: HTTP proxy deny path should use `ExplicitProxyRuntime` and still prove denied traffic does not reach host egress.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 56, `foxprox-cli` 2, `foxproxsetup` 7). `proxy-deny-smoke` emitted `deny_reset` for `/admin` with nested `ExplicitProxyRuntime` audit and zero egress calls; malformed CONNECT and unsupported SOCKS still failed closed.
- Relevant output excerpt: `"rule_id":"deny-http-admin"`; `"egress_calls":"0"`; `"runtime_audit":"{...\"event\":\"http_request\"...\"decision\":\"deny_reset\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit proxy allow and HTTP-deny paths now share the reusable runtime boundary. Remaining malformed CONNECT request-line parsing is still a CLI helper because it extracts the CONNECT target from raw HTTP headers before target policy evaluation.
- Next verification gap: commit runtime factoring work and run a final post-factoring smoke subset.
- Commit hash after commit: pending.

## 2026-06-22T05:50:00Z — Post explicit-proxy-runtime verification sweep

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke >/tmp/foxprox-http-proxy-runtime.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke >/tmp/foxprox-connect-runtime.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke >/tmp/foxprox-socks-runtime.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke >/tmp/foxprox-proxy-deny-runtime.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr-runtime.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge-runtime.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-deny-runtime.jsonl`
- Environment assumptions: local explicit proxy smokes use loopback fixtures; bwrap/TUN smokes use local fd handoff and sandbox Python; no external network services.
- Expected result: explicit proxy runtime factoring and prior TCP/DNS runtime factoring do not regress core tests or key smoke behavior.
- Observed result: pass. `foxprox-core` ran 56 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests. Explicit proxy allow/deny smokes, DNS attribution smoke, and TCP bridge allow/deny smokes all completed.
- Relevant output excerpt: `OK`; proxy deny retained `"egress_calls":"0"`; TCP bridge retained `"decision":"allow"`, `"egress_calls":"1"`, and `"inspection_decision":"allow"`.
- Changed files: `progress.md`.
- Interpretation: core runtime factoring has preserved the harness-backed alpha behavior across transparent and explicit proxy paths.
- Next verification gap: commit verification evidence; remaining next step is structural crate decomposition or production async/device integration beyond the current core/CLI split.
- Commit hash after commit: pending.

## 2026-06-22T06:05:00Z — Bounded audit flush across reusable runtimes

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: deterministic in-memory runtime checks; no Linux/TUN required.
- Expected result: reusable runtime types beyond the TCP bridge can flush audit records into a bounded sink and surface backpressure consistently.
- Observed result: pass. `foxprox-core` increased to 58 tests; `foxprox-cli` ran 2 tests; `foxproxsetup` ran 7 tests.
- Relevant output excerpt: `runtime::tests::udp_runtime_flushes_audit_to_bounded_sink ... ok`; `runtime::tests::explicit_proxy_runtime_flushes_audit_to_bounded_sink ... ok`; previous TCP bridge bounded flush tests still passed.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `progress.md`.
- Interpretation: audit backpressure plumbing is now consistently available across reusable runtime boundaries, not only the TCP bridge.
- Next verification gap: commit this audit flush improvement; remaining larger work is crate decomposition and production async/device integration.
- Commit hash after commit: pending.

## 2026-06-22T06:25:00Z — Device fd helper crate extraction

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: local bwrap/TUN fd handoff works; new `foxprox-device` crate is Unix-only for fd helper APIs and is used by the CLI harness.
- Expected result: move host-side fd receive/read/write/nonblocking/close helpers out of the CLI smoke file into a reusable device crate without regressing handoff or TCP bridge smokes.
- Observed result: pass. Workspace tests now include `foxprox-device` (2 tests), plus `foxprox-core` 58 tests, `foxprox-cli` 2 tests, and `foxproxsetup` 7 tests. `handoff-smoke` and `tcp-bridge-smoke` both emitted `decision":"allow"`.
- Relevant output excerpt: `fd::tests::cmsg_space_includes_aligned_header_and_payload ... ok`; `fd::tests::invalid_fd_is_not_valid ... ok`; handoff `"fd_valid_after_helper_exit":"true"`; TCP bridge `"status":"exit status: 0"`.
- Changed files: `Cargo.toml`, `crates/foxprox-device/{Cargo.toml,src/lib.rs}`, `crates/foxprox-cli/{Cargo.toml,src/main.rs}`, `progress.md`.
- Interpretation: Linux fd/device mechanics are now represented by a reusable crate boundary instead of being embedded in the harness CLI, aligning with the documented broker-device/module split.
- Next verification gap: commit device crate extraction; remaining larger work is integrating setup-side fd send helpers into the same device crate or creating production async broker-device APIs.
- Commit hash after commit: pending.

## 2026-06-22T06:45:00Z — Setup fd send helper uses device crate

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke`
- Environment assumptions: Unix `SCM_RIGHTS` fd handoff is available; bwrap/TUN fd handoff works locally.
- Expected result: move setup-side fd send helper onto the reusable `foxprox-device` crate and remove duplicate cmsg/sendmsg helper code from `foxproxsetup`; handoff smoke must still receive a valid TUN fd after helper exit.
- Observed result: pass. Workspace tests passed with no warnings: `foxprox-core` 58 tests, `foxprox-device` 2 tests, `foxprox-cli` 2 tests, `foxproxsetup` 6 tests. `handoff-smoke` emitted `decision":"allow"` and `fd_valid_after_helper_exit":"true"`.
- Relevant output excerpt: `fd::tests::cmsg_space_includes_aligned_header_and_payload ... ok`; handoff `"reason":"foxproxsetup handed off a live TUN fd and target exited"`.
- Changed files: `Cargo.lock`, `crates/foxprox-setup/{Cargo.toml,src/main.rs}`, `crates/foxprox-device/src/lib.rs`, `progress.md`.
- Interpretation: both host-side fd receive and setup-side fd send now share the device crate boundary, further aligning the implementation with the documented broker-device split.
- Next verification gap: commit device send extraction; remaining work is production async/device integration or broader crate decomposition.
- Commit hash after commit: pending.

## 2026-06-22T07:05:00Z — Host egress adapter crate extraction

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-forward-smoke && target/debug/foxprox-lab run tcp-syn-smoke && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: local UDP/TCP fixtures are available; bwrap/TUN fd handoff works locally; new `foxprox-egress` crate uses synchronous std sockets as harness/future broker adapters.
- Expected result: move local TCP connect, TCP stream data, and UDP datagram host egress adapters out of `foxprox-lab` into a reusable egress crate without regressing UDP/TCP smokes.
- Observed result: pass. Workspace tests now include `foxprox-egress` (1 test), plus `foxprox-core` 58 tests, `foxprox-device` 2 tests, `foxprox-cli` 2 tests, and `foxproxsetup` 6 tests. `udp-forward-smoke`, `tcp-syn-smoke`, and `tcp-bridge-smoke` all emitted `decision":"allow"`.
- Relevant output excerpt: `foxprox_egress::tests::tcp_stream_egress_round_trips_fixture_bytes ... ok`; UDP forward `"forwarded":"true"`; TCP SYN `"egress_calls":"1"`; TCP bridge `"egress_calls":"1"`.
- Changed files: `Cargo.lock`, `Cargo.toml`, `crates/foxprox-egress/{Cargo.toml,src/lib.rs}`, `crates/foxprox-cli/{Cargo.toml,src/main.rs}`, `progress.md`.
- Interpretation: host egress mechanics now have a crate boundary matching the documented architecture, and the CLI harness is further reduced to orchestration and fixture setup.
- Next verification gap: commit egress crate extraction; remaining work is production async integration or more crate decomposition for proxy frontends.
- Commit hash after commit: pending.

## 2026-06-22T07:20:00Z — CONNECT request parsing in core runtime

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke`
- Environment assumptions: explicit proxy smokes use local loopback fixtures only; no external network.
- Expected result: move raw HTTP CONNECT request-line parsing into core origin/runtime helpers so CLI no longer owns CONNECT target parsing logic.
- Observed result: pass. `foxprox-core` increased to 59 tests; `foxprox-device` 2 tests, `foxprox-egress` 1 test, `foxprox-cli` 2 tests, and `foxproxsetup` 6 tests all passed. HTTPS CONNECT allow and malformed CONNECT deny smokes emitted nested core runtime audit.
- Relevant output excerpt: `origin::tests::parses_connect_request_line ... ok`; HTTPS smoke `"event":"https_connect","decision":"allow"`; proxy deny `"reason":"malformed CONNECT request denied before egress: malformed CONNECT request fails closed: request is not CONNECT"`.
- Changed files: `crates/foxprox-core/src/{origin.rs,runtime.rs}`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit proxy CONNECT parsing/policy/audit is now entirely in reusable core runtime/origin code, leaving the CLI with only socket IO and fixture orchestration for that path.
- Next verification gap: commit CONNECT parsing move; remaining work is larger production integration or further extraction of proxy socket accept/tunnel loops into a frontend crate.
- Commit hash after commit: pending.

## 2026-06-22T07:35:00Z — Explicit proxy forwarding uses shared egress adapter

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke`
- Environment assumptions: explicit proxy smokes use loopback client/origin fixtures only; `LocalTcpStreamEgress` is the reusable synchronous host adapter.
- Expected result: HTTP proxy, HTTPS CONNECT, and SOCKS5 allow smokes should route origin/tunnel bytes through `foxprox-egress` instead of direct CLI-owned `TcpStream::connect_timeout` origin IO.
- Observed result: pass. Workspace tests remained green (`foxprox-core` 59, `foxprox-device` 2, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 6). All three explicit proxy allow smokes emitted `"egress_calls":"1"`.
- Relevant output excerpt: HTTP proxy `"bytes_out":45,"metadata":{"egress_calls":"1"`; HTTPS CONNECT `"event":"https_connect","decision":"allow"`; SOCKS5 `"event":"socks_connect","decision":"allow"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit proxy allow-path forwarding now uses the same host egress adapter boundary as transparent UDP/TCP bridge smokes; CLI direct origin sockets are reduced to fixture/client lifecycle.
- Recent structural commit hashes: egress crate extraction `cb9e664`; core CONNECT parsing `579fb4a`.
- Next verification gap: commit explicit proxy forwarding migration; remaining meaningful production work is moving Linux TUN setup helpers into the device crate or designing async long-lived broker loops.
- Commit hash after commit: pending.

## 2026-06-22T07:50:00Z — Capability drop helper moved to device crate

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke`
- Environment assumptions: Unix/Linux capability syscalls and SCM_RIGHTS handoff are available; bwrap/TUN fd handoff works locally.
- Expected result: setup-side `CAP_NET_ADMIN` dropping and fd close wrappers should use the reusable `foxprox-device` crate instead of setup-local syscall code, without regressing TUN fd handoff.
- Observed result: pass. `foxprox-device` now has 3 tests (`caps` plus fd helpers); workspace tests passed (`foxprox-core` 59, `foxprox-cli` 2, `foxproxsetup` 6, `foxprox-egress` 1). `handoff-smoke` emitted `"fd_valid_after_helper_exit":"true"`.
- Relevant output excerpt: `caps::tests::net_admin_capability_bit_is_in_first_word ... ok`; handoff `"reason":"foxproxsetup handed off a live TUN fd and target exited"`.
- Changed files: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-setup/src/main.rs`, `progress.md`.
- Interpretation: more Linux device/capability mechanics now live behind the device crate boundary, reducing duplicated low-level setup code.
- Recent structural commit hash: explicit proxy forwarding migration `e1fc3a0`.
- Next verification gap: commit capability helper extraction; remaining production-factoring work is moving the actual Linux TUN ioctl configurator into `foxprox-device` or designing async long-lived broker loops.
- Commit hash after commit: pending.

## 2026-06-22T08:05:00Z — Post egress/device factoring verification sweep

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all >/tmp/foxprox-all-egress-device.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness >/tmp/foxprox-robust-egress-device.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke >/tmp/foxprox-handoff-egress-device.jsonl && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr-egress-device.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge-egress-device.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-bridge-deny-egress-device.jsonl && target/debug/foxprox-lab run http-proxy-smoke >/tmp/foxprox-http-egress-device.jsonl && target/debug/foxprox-lab run https-connect-smoke >/tmp/foxprox-connect-egress-device.jsonl && target/debug/foxprox-lab run socks5-smoke >/tmp/foxprox-socks-egress-device.jsonl && target/debug/foxprox-lab run proxy-deny-smoke >/tmp/foxprox-proxy-deny-egress-device.jsonl && echo OK`
- Environment assumptions: deterministic scenario groups are local; environment smokes use local bwrap/TUN fd handoff and loopback fixtures only.
- Expected result: recent egress crate, core CONNECT parsing, proxy forwarding, and device capability factoring preserve all deterministic alpha scenarios plus key environment smokes.
- Observed result: pass. Workspace tests passed (`foxprox-core` 59, `foxprox-device` 3, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 6). `run all`, `run robustness`, handoff, DNS attribution, TCP bridge allow/deny, explicit proxy allow paths, and proxy deny all completed; command printed `OK`.
- Relevant output excerpt: `caps::tests::net_admin_capability_bit_is_in_first_word ... ok`; `target/debug/foxprox-lab run all`; `target/debug/foxprox-lab run robustness`; final `OK`.
- Changed files: `progress.md`.
- Interpretation: the current factored structure is verified end-to-end across deterministic and selected Linux environment paths.
- Recent structural commit hashes: capability helper extraction `d3cf7d3`; explicit proxy forwarding migration `e1fc3a0`; core CONNECT parsing `579fb4a`; egress crate extraction `cb9e664`.
- Next verification gap: commit this sweep record; if continuing, the next production step should be moving the Linux TUN ioctl configurator out of setup into `foxprox-device` with tests and handoff-smoke verification.
- Commit hash after commit: pending.

## 2026-06-22T08:25:00Z — Linux TUN configurator moved to device crate

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke`
- Environment assumptions: Linux `/dev/net/tun`, ioctl setup, capability handling, and SCM_RIGHTS handoff are available for the handoff smoke.
- Expected result: move low-level Linux TUN ioctl configuration and related tests out of `foxproxsetup` into `foxprox-device::linux_tun`, leaving setup responsible for argument parsing, environment emission, fd send, capability drop, and target exec.
- Observed result: pass. Workspace tests passed with TUN ioctl unit coverage now under `foxprox-device` (`foxprox-device` 5 tests, `foxprox-core` 59, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). `handoff-smoke` emitted `"fd_valid_after_helper_exit":"true"`.
- Relevant output excerpt: `linux_tun::tests::rejects_overlong_interface_names ... ok`; `linux_tun::tests::sockaddr_v4_places_ipv4_octets_after_port ... ok`; handoff `"decision":"allow"`.
- Changed files: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-setup/src/main.rs`, `progress.md`.
- Interpretation: the broker/device split is now more concrete: Linux TUN fd creation/configuration, fd handoff helpers, and capability helpers live in `foxprox-device`, while `foxproxsetup` is a thin setup executable wrapper.
- Recent verification record commit hash: `bfe8bd4`.
- Next verification gap: commit TUN configurator extraction; then run a final status sweep and identify remaining async long-lived broker integration as the main non-alpha production gap.
- Commit hash after commit: pending.

## 2026-06-22T08:45:00Z — Explicit proxy wire helpers moved to core frontend module

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke && cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke`
- Environment assumptions: explicit proxy verification uses local loopback fixtures only.
- Expected result: move reusable explicit frontend wire details (HTTP origin-form request generation, HTTP CONNECT/deny responses, SOCKS5 no-auth greeting validation, SOCKS5 success response formatting) out of CLI smoke code into platform-independent core helpers.
- Observed result: pass. `foxprox-core` increased to 62 tests; workspace tests passed (`foxprox-device` 5, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). HTTP proxy, HTTPS CONNECT, SOCKS5, and proxy-deny smokes all completed.
- Relevant output excerpt: `frontend::tests::builds_http_origin_form_request ... ok`; `frontend::tests::validates_socks5_no_auth_greeting ... ok`; proxy smokes retained `"egress_calls":"1"` on allow paths and `"egress_calls":"0"` on deny path.
- Changed files: `crates/foxprox-core/src/{frontend.rs,lib.rs}`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit proxy socket handling in the CLI now depends on reusable frontend byte helpers plus the core runtime and shared egress adapter, further shrinking CLI-owned protocol semantics.
- Recent structural commit hash: Linux TUN setup extraction `123bb17`.
- Next verification gap: commit frontend helper extraction; remaining production work is long-lived broker frontend/device loop design and lifecycle management.
- Commit hash after commit: pending.

## 2026-06-22T09:05:00Z — RAII wrapper for handed-off device fd

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke && target/debug/foxprox-lab run writeback-smoke && target/debug/foxprox-lab run udp-forward-smoke && target/debug/foxprox-lab run dns-attribution-smoke && target/debug/foxprox-lab run tcp-bridge-smoke && target/debug/foxprox-lab run tcp-bridge-deny-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; smokes are local-only and use loopback fixtures where host egress is required.
- Expected result: replace raw handed-off fd management in the CLI harness with a reusable `foxprox-device::fd::DeviceFd` RAII wrapper exposing validity, nonblocking, read, write-all, and close behavior.
- Observed result: pass. `foxprox-device` increased to 6 tests; workspace tests passed (`foxprox-core` 62, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). Handoff, writeback, UDP forward, DNS attribution, TCP bridge allow, and TCP bridge deny smokes all completed.
- Relevant output excerpt: `fd::tests::device_fd_rejects_invalid_raw_fd ... ok`; handoff `"fd_valid_after_helper_exit":"true"`; TCP bridge `"response_written":"true"`; TCP bridge deny `"egress_calls":"0"`.
- Changed files: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: broker/device fd lifecycle is now represented by a reusable RAII type instead of bare raw fd integers in the harness, reducing leak/double-close risk and clarifying future long-lived device integration.
- Recent structural commit hash: frontend helper extraction `18e5f75`.
- Next verification gap: commit RAII device fd wrapper; remaining work is consolidating repeated bwrap/handoff process setup or designing long-lived async broker loops.
- Commit hash after commit: pending.

## 2026-06-22T09:20:00Z — PacketDevice trait for TUN packet IO

- Command executed: `cargo fmt --all && cargo test --all`; `cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run writeback-smoke && target/debug/foxprox-lab run udp-forward-smoke && target/debug/foxprox-lab run tcp-bridge-smoke`
- Environment assumptions: local bwrap/TUN fd handoff works; selected smokes exercise packet read/write through the handed-off device fd.
- Expected result: expose a reusable packet-device interface over the handed-off fd (`read_packet`, `write_packet`, nonblocking setup) and update CLI TUN packet loops to use packet-oriented methods rather than generic raw-fd read/write helpers.
- Observed result: pass. Workspace tests passed (`foxprox-core` 62, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). Writeback, UDP forward, and TCP bridge smokes all completed.
- Relevant output excerpt: writeback `"reply_written":"true"`; UDP forward `"forwarded":"true"`; TCP bridge `"response_written":"true"`.
- Changed files: `crates/foxprox-device/src/lib.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: the device frontend boundary now explicitly models packet IO, aligning with the architecture’s TUN frontend responsibilities and further isolating low-level fd helpers from broker/runtime loops.
- Recent structural commit hash: RAII fd wrapper `b048603`.
- Next verification gap: commit packet device trait; remaining work is consolidating bwrap/handoff orchestration or implementing long-lived broker lifecycle loops.
- Commit hash after commit: pending.

## 2026-06-22T09:40:00Z — Transparent packet dispatcher helper

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run dns-attribution-smoke`
- Environment assumptions: deterministic dispatcher tests are local-only; DNS attribution smoke uses bwrap/TUN fd handoff and loopback UDP fixture.
- Expected result: add a reusable core packet-routing helper that dispatches TUN IPv4 packets toward broker DNS, transparent UDP, transparent TCP, ICMP, or unsupported handling, then use it in the DNS-attribution environment smoke instead of ad-hoc CLI IPv4/UDP port parsing.
- Observed result: pass. `foxprox-core` increased to 63 tests; workspace tests passed (`foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). DNS attribution smoke retained `"dns_answered":"true"` and `"forwarded":"true"`.
- Relevant output excerpt: `runtime::tests::routes_transparent_packets_to_runtime_boundaries ... ok`; DNS attribution `"attributed_hostname":"lab.example"`.
- Changed files: `crates/foxprox-core/src/runtime.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: long-lived broker loops now have a tested core dispatch primitive for selecting reusable runtime boundaries from TUN packets, reducing another CLI-only parsing decision.
- Recent structural commit hash: packet device interface `9af9166`.
- Next verification gap: commit dispatcher helper; remaining work is using the dispatcher in more transparent smokes or consolidating process/handoff orchestration.
- Commit hash after commit: pending.

## 2026-06-22T09:55:00Z — HTTP header reader moved to core frontend module

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke`
- Environment assumptions: HTTPS CONNECT smoke uses loopback client/proxy/origin fixtures only.
- Expected result: move reusable bounded HTTP header reading out of CLI smoke code and into `foxprox-core::frontend`, with deterministic tests for complete and incomplete headers.
- Observed result: pass. `foxprox-core` increased to 64 tests; workspace tests passed (`foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). HTTPS CONNECT smoke still emitted `"decision":"allow"` and `"egress_calls":"1"`.
- Relevant output excerpt: `frontend::tests::reads_complete_http_headers_only_until_header_end ... ok`; HTTPS CONNECT `"event":"https_connect","decision":"allow"`.
- Changed files: `crates/foxprox-core/src/frontend.rs`, `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: explicit frontend stream parsing has another reusable core boundary; the CLI no longer owns CONNECT header-read semantics.
- Recent structural commit hash: transparent packet dispatcher `6cfa9b4`.
- Next verification gap: commit HTTP reader extraction; remaining work is final full verification and deciding whether further long-lived broker-loop implementation is still in-scope for this autonomous pass.
- Commit hash after commit: pending.

## 2026-06-22T10:15:00Z — Full verification after frontend/device dispatcher factoring

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all >/tmp/foxprox-all-frontend-device.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness >/tmp/foxprox-robust-frontend-device.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke >/tmp/foxprox-handoff-frontend-device.jsonl && target/debug/foxprox-lab run writeback-smoke >/tmp/foxprox-writeback-frontend-device.jsonl && target/debug/foxprox-lab run udp-forward-smoke >/tmp/foxprox-udp-forward-frontend-device.jsonl && target/debug/foxprox-lab run udp-deny-smoke >/tmp/foxprox-udp-deny-frontend-device.jsonl && target/debug/foxprox-lab run dns-smoke >/tmp/foxprox-dns-frontend-device.jsonl && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr-frontend-device.jsonl && target/debug/foxprox-lab run tcp-syn-smoke >/tmp/foxprox-tcp-syn-frontend-device.jsonl && target/debug/foxprox-lab run tcp-synack-smoke >/tmp/foxprox-tcp-synack-frontend-device.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge-frontend-device.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-bridge-deny-frontend-device.jsonl && target/debug/foxprox-lab run http-proxy-smoke >/tmp/foxprox-http-frontend-device.jsonl && target/debug/foxprox-lab run https-connect-smoke >/tmp/foxprox-connect-frontend-device.jsonl && target/debug/foxprox-lab run socks5-smoke >/tmp/foxprox-socks-frontend-device.jsonl && target/debug/foxprox-lab run proxy-deny-smoke >/tmp/foxprox-proxy-deny-frontend-device.jsonl && echo OK`
- Environment assumptions: Linux bwrap/TUN fd handoff is available locally; all egress/proxy/DNS/TCP fixtures are loopback/local and avoid external network services.
- Expected result: all deterministic alpha scenario groups and key environment smokes pass after frontend wire helper extraction, RAII packet device IO, and transparent packet dispatcher changes.
- Observed result: pass. Workspace tests passed (`foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). Full command completed with final `OK` after deterministic `all`/`robustness`, handoff/writeback, UDP allow/deny, DNS, TCP SYN/SYN-ACK/bridge allow/deny, and explicit proxy allow/deny smokes.
- Relevant output excerpt: `frontend::tests::reads_complete_http_headers_only_until_header_end ... ok`; `runtime::tests::routes_transparent_packets_to_runtime_boundaries ... ok`; final `OK`.
- Changed files: `progress.md`.
- Interpretation: current harness-lab alpha behavior remains intact with reusable core frontend, runtime dispatcher, device, and egress boundaries verified end-to-end.
- Recent structural commit hashes: HTTP reader extraction `a6ebbd0`; packet dispatcher `6cfa9b4`; packet device interface `9af9166`.
- Next verification gap: commit this full verification record. Further work is now larger production broker lifecycle design/implementation rather than small harness-backed extraction.
- Commit hash after commit: pending.

## 2026-06-22T10:35:00Z — Reusable transparent broker orchestration crate

- Command executed: `cargo fmt --all && cargo test -p foxprox-broker`; follow-up: `cargo fmt --all && cargo test --all`
- Environment assumptions: broker orchestration tests are deterministic in-memory packet fixtures with mock egress; no Linux/TUN privileges or external network required.
- Expected result: add a `foxprox-broker` crate that composes reusable core DNS/UDP/TCP/ICMP runtimes behind a one-packet-at-a-time transparent broker loop, using the core dispatcher and preserving audit records for bounded flushing.
- Observed result: pass. New `foxprox-broker` crate has 2 tests. Full workspace tests passed (`foxprox-broker` 2, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4).
- Relevant output excerpt: `broker_dispatches_udp_to_egress_and_returns_device_packet ... ok`; `broker_dns_answer_attributes_later_udp_flow ... ok`.
- Changed files: `Cargo.toml`, `crates/foxprox-broker/{Cargo.toml,src/lib.rs}`, `progress.md`.
- Interpretation: production factoring now includes a broker orchestration crate that can drive reusable runtime boundaries from TUN packets without embedding the decision in the CLI harness. This is a synchronous foundation for future async device loops.
- Recent verification record commit hash: `dbe5d86`.
- Next verification gap: commit broker crate; then wire at least one environment smoke through `foxprox-broker::TransparentBroker` if it can be done without destabilizing the current harness.
- Commit hash after commit: pending.

## 2026-06-22T10:55:00Z — DNS attribution smoke uses broker orchestration crate

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run dns-attribution-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; DNS attribution smoke uses broker-local DNS answer and loopback UDP egress fixture.
- Expected result: wire one environment smoke through `foxprox-broker::TransparentBroker` so packet dispatch, broker DNS handling, DNS cache synchronization, UDP policy, egress, and audit are exercised through the reusable broker orchestration crate instead of CLI-local runtime coordination.
- Observed result: pass. Workspace tests passed (`foxprox-broker` 2, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). DNS attribution smoke emitted `"dns_answered":"true"`, `"forwarded":"true"`, and `"attributed_hostname":"lab.example"`.
- Relevant output excerpt: DNS attribution `"event":"udp_flow_created"`, `"decision":"allow"`, `"runtime_audit":"{...\"hostname\":\"lab.example\"...}"`.
- Changed files: `Cargo.lock`, `crates/foxprox-cli/{Cargo.toml,src/main.rs}`, `progress.md`.
- Interpretation: the new broker orchestration crate is now used by a Linux/TUN environment smoke, not just unit tests. This proves the factoring path from device fd packet IO into reusable broker/runtime/egress boundaries.
- Recent structural commit hash: broker crate `f1acf95`.
- Next verification gap: commit broker smoke integration; if continuing, consider migrating UDP forward or ICMP writeback smokes onto `TransparentBroker`, or run a final full sweep first.
- Commit hash after commit: pending.

## 2026-06-22T11:10:00Z — UDP forward smoke uses broker orchestration crate

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run udp-forward-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; UDP egress is a loopback fixture.
- Expected result: migrate the UDP forward environment smoke from direct `TransparentUdpRuntime` coordination to `foxprox-broker::TransparentBroker`, proving the broker crate handles non-DNS UDP dispatch and device write-back in the Linux harness.
- Observed result: pass. Workspace tests passed (`foxprox-broker` 2, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). `udp-forward-smoke` emitted `"forwarded":"true"` with an allow runtime audit from the broker-owned UDP runtime.
- Relevant output excerpt: UDP forward `"decision":"allow"`, `"rule_id":"allow-udp-forward-smoke"`, `"runtime_audit":"{...\"event\":\"udp_flow_created\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: the transparent broker crate now backs both broker-DNS-plus-attributed-UDP and direct transparent UDP environment smokes.
- Recent broker integration commit hash: `0a04eb2`.
- Next verification gap: commit UDP broker migration; consider migrating ICMP writeback or denied UDP onto the broker, then run a final full sweep.
- Commit hash after commit: pending.

## 2026-06-22T11:25:00Z — UDP deny smoke uses broker orchestration crate

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run udp-deny-smoke`
- Environment assumptions: bwrap/TUN fd handoff works locally; denied UDP path uses a loopback fixture only to prove zero host egress calls.
- Expected result: migrate the negative UDP environment smoke onto `foxprox-broker::TransparentBroker`, preserving deny/drop audit and proving denied packets produce no device reply and no egress call.
- Observed result: pass. Workspace tests passed (`foxprox-broker` 2, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). `udp-deny-smoke` emitted `"denied":"true"` and `"egress_calls":"0"`.
- Relevant output excerpt: UDP deny `"decision":"deny_drop"`, `"policy_reason":"default deny"`, `"runtime_audit":"{...\"event\":\"udp_flow_created\"...}"`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`.
- Interpretation: both positive and negative transparent UDP environment paths now exercise the reusable broker orchestration crate rather than CLI-local runtime dispatch.
- Recent broker migration commit hash: `90cd648`.
- Next verification gap: commit UDP deny broker migration; then run a final broad sweep over broker-backed transparent paths and explicit proxy paths.
- Commit hash after commit: pending.

## 2026-06-22T11:45:00Z — Full verification after broker-backed UDP smokes

- Command executed: `cargo fmt --all && cargo test --all && cargo run -p foxprox-cli --bin foxprox-lab -- run all >/tmp/foxprox-all-broker.jsonl && cargo run -p foxprox-cli --bin foxprox-lab -- run robustness >/tmp/foxprox-robust-broker.jsonl && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke >/tmp/foxprox-handoff-broker.jsonl && target/debug/foxprox-lab run writeback-smoke >/tmp/foxprox-writeback-broker.jsonl && target/debug/foxprox-lab run udp-forward-smoke >/tmp/foxprox-udp-forward-broker.jsonl && target/debug/foxprox-lab run udp-deny-smoke >/tmp/foxprox-udp-deny-broker.jsonl && target/debug/foxprox-lab run dns-smoke >/tmp/foxprox-dns-broker.jsonl && target/debug/foxprox-lab run dns-attribution-smoke >/tmp/foxprox-dns-attr-broker.jsonl && target/debug/foxprox-lab run tcp-bridge-smoke >/tmp/foxprox-tcp-bridge-broker.jsonl && target/debug/foxprox-lab run tcp-bridge-deny-smoke >/tmp/foxprox-tcp-bridge-deny-broker.jsonl && target/debug/foxprox-lab run http-proxy-smoke >/tmp/foxprox-http-broker.jsonl && target/debug/foxprox-lab run https-connect-smoke >/tmp/foxprox-connect-broker.jsonl && target/debug/foxprox-lab run socks5-smoke >/tmp/foxprox-socks-broker.jsonl && target/debug/foxprox-lab run proxy-deny-smoke >/tmp/foxprox-proxy-deny-broker.jsonl && echo OK`
- Environment assumptions: Linux bwrap/TUN fd handoff works locally; all egress/proxy/DNS/TCP fixtures are local or loopback.
- Expected result: broker crate integration for UDP allow, UDP deny, and DNS-attributed UDP does not regress deterministic scenario groups or key environment smokes.
- Observed result: pass. Workspace tests passed (`foxprox-broker` 2, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). Deterministic `all` and `robustness`, transparent environment smokes, TCP bridge allow/deny, and explicit proxy allow/deny smokes all completed; command printed final `OK`.
- Relevant output excerpt: `broker_dispatches_udp_to_egress_and_returns_device_packet ... ok`; `broker_dns_answer_attributes_later_udp_flow ... ok`; final `OK`.
- Changed files: `progress.md`.
- Interpretation: the broker orchestration boundary is now verified both by unit tests and by multiple Linux/TUN environment smokes, while previous alpha coverage remains intact.
- Recent broker migration commit hashes: UDP deny `cd43000`; UDP forward `90cd648`; DNS attribution `0a04eb2`; broker crate `f1acf95`.
- Next verification gap: commit this sweep record. Remaining substantial production work is TCP bridge orchestration in `foxprox-broker` or true async long-lived broker lifecycle integration.
- Commit hash after commit: pending.

## 2026-06-22T12:00:00Z — Broker ICMP dispatch unit coverage

- Command executed: `cargo fmt --all && cargo test --all`
- Environment assumptions: deterministic packet fixtures only; real system `ping` remains outside this check because earlier capability-drop behavior blocks `CAP_NET_RAW` for sandbox ping.
- Expected result: prove `foxprox-broker::TransparentBroker` dispatches ICMP echo packets into `TransparentIcmpRuntime` and writes back an allowed echo reply when ping policy is enabled.
- Observed result: pass. `foxprox-broker` increased to 3 tests; workspace tests passed (`foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4).
- Relevant output excerpt: `broker_replies_to_allowed_icmp_echo ... ok`.
- Changed files: `crates/foxprox-broker/src/lib.rs`, `progress.md`.
- Interpretation: the broker orchestration crate now covers UDP allow/deny, broker DNS attribution, and ICMP dispatch in deterministic tests; Linux environment smokes already cover broker-backed UDP and DNS-attributed UDP.
- Recent verification sweep commit hash: `0b619af`.
- Next verification gap: commit ICMP broker coverage. Remaining large gap is TCP bridge orchestration in the broker crate or async long-lived broker lifecycle integration.
- Commit hash after commit: pending.

## 2026-06-22T12:15:00Z — Broker TCP SYN dispatch unit coverage

- Command executed: `cargo fmt --all && cargo test -p foxprox-broker`; follow-up: `cargo test --all`
- Environment assumptions: deterministic TUN-shaped TCP SYN packet fixture with mock TCP connect egress; no Linux/TUN privileges required.
- Expected result: prove `foxprox-broker::TransparentBroker` dispatches TCP packets into `TransparentTcpRuntime`, applies TCP policy, calls TCP connect egress on allow, and records normalized TCP connect audit.
- Observed result: pass. `foxprox-broker` increased to 4 tests; workspace tests passed (`foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4).
- Relevant output excerpt: `broker_dispatches_tcp_syn_to_connect_egress ... ok`.
- Changed files: `crates/foxprox-broker/src/lib.rs`, `progress.md`.
- Interpretation: the reusable transparent broker now has deterministic coverage for dispatching every currently modeled transparent protocol family: DNS, UDP, TCP connect attempts, and ICMP echo.
- Recent broker ICMP coverage commit hash: `e48cfce`.
- Next verification gap: commit TCP broker coverage. Further production work is the larger TCP byte-bridge orchestration path or async lifecycle integration.
- Commit hash after commit: pending.

## 2026-06-22T12:35:00Z — Real sandbox ping write-back smoke

- Command executed: `cargo fmt --all && cargo test --all && cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run ping-smoke`
- Environment assumptions: Linux bwrap/TUN fd handoff is available; `/usr/bin/ping` exists; this smoke grants bwrap `CAP_NET_RAW` in addition to setup-time `CAP_NET_ADMIN` so the target ping can create ICMP sockets after `foxproxsetup` drops `CAP_NET_ADMIN`.
- Expected result: real sandbox `ping -c 1 10.0.2.1` emits an ICMP echo request through the broker-owned TUN fd, `foxprox-broker::TransparentBroker` routes it to the ICMP runtime, the broker writes a synthetic echo reply back to the fd, and ping reports success.
- Observed result: pass. Workspace tests passed (`foxprox-broker` 4, `foxprox-core` 64, `foxprox-device` 6, `foxprox-egress` 1, `foxprox-cli` 2, `foxproxsetup` 4). `ping-smoke` emitted `"decision":"allow"`, `"reply_written":"true"`, and ping stdout showed `1 packets transmitted, 1 received, 0% packet loss`.
- Relevant output excerpt: `"reason":"sandbox ping received a synthetic ICMP echo reply through handed-off TUN fd"`; `"policy_reason":"ICMP ping allowed by configuration"`; ping stdout `64 bytes from 10.0.2.1`.
- Changed files: `crates/foxprox-cli/src/main.rs`, `progress.md`, `learnings.md`.
- Interpretation: Milestone 1 now has the requested real end-to-end sandbox ping validation, replacing the previous deterministic-only ICMP proof for this path while preserving capability isolation notes.
- Recent broker TCP coverage commit hash: `1a413a2`.
- Next verification gap: commit ping smoke; continue with real transparent HTTP/TCP or HTTPS/SNI environment coverage if still needed for alpha completion.
- Commit hash after commit: pending.
