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
