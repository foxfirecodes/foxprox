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
