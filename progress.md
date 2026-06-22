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
