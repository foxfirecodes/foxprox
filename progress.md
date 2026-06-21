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
