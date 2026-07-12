# Autonomous Crew Worktree Audit

## Review
- Correct: Branch/status verified clean before writing this audit: `autonomous-crew` at `5967248476807792936b9e43445b07cfaaab274c` (`5967248 close-denied-proxy-requests`); `git diff --stat`, `git diff --cached --stat`, and untracked listing were empty. Ignored build artifacts exist only under `.tmp/` and `target/`.
- Correct: Workspace crates are implemented for the expected alpha architecture: `foxprox-core`, `foxprox-device`, `foxprox-egress`, `foxprox-net`, `foxprox-proxy`, `foxprox-setup`, and `foxprox-cli` in `Cargo.toml`.
- Correct: Verification run during this audit passed: `cargo test --workspace`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps`, selected `cargo tree` checks, and `bash -n scripts/live-smoke-bwrap-tun.sh`.
- Blocker: none found in static/code/test review.
- Note: requested `plan.md` is absent at repo root; audit used `progress.md`, `learnings.md`, docs, git history, and source files. This is an evidence/hand-off gap, not a code blocker.
- Note: I did not rerun the privileged live bwrap/TUN smoke during this audit; current evidence is the existing script/docs plus `progress.md` claims. Static tests and shell syntax passed.

## Branch / HEAD / status
- Branch: `autonomous-crew`
- HEAD: `5967248476807792936b9e43445b07cfaaab274c` (`5967248 close-denied-proxy-requests`)
- Recent history: `5967248 close-denied-proxy-requests`, `48c5276 bind-host-ca-certificates-in-sandbox`, `36799a5 add controlled alpha launcher config`, `6136c93 add live bwrap tun smoke docs`, `a5e0daa record final alpha review`.
- Dirty state before writing this report: no staged files, no unstaged tracked changes, no untracked files.
- Ignored files: `.tmp/`, `target/`.
- This audit writes only `reviews/autonomous-crew-audit.md` as required.

## Crates / modules implemented
- `crates/foxprox-core`: dependency-free core boundary (`#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`) exporting audit, config, DNS, egress traits, event model, flow, frontend, inspection, and policy modules (`crates/foxprox-core/src/lib.rs:1-47`). Key types include `NetworkEvent` (`event.rs:387`), `PolicyRule`/`PolicyRuleSet` (`policy.rs:199`, `policy.rs:394`), `AuditBuffer` (`audit.rs:199`), `DnsCache` (`dns.rs:336`), and `UdpFlowTable` (`flow.rs:152`).
- `crates/foxprox-device`: IPv4/ICMP parsing and ICMPv4 echo-reply synthesis with checksum tests.
- `crates/foxprox-egress`: shared std host egress adapter; it calls `ensure_allowed` before TCP/UDP/DNS socket I/O (`crates/foxprox-egress/src/lib.rs:40-141`).
- `crates/foxprox-net`: smoltcp transparent TCP/UDP/DNS runtimes, standalone proofs, combined transparent runtime, DNS cache attribution, HTTP/TLS inspection, audit/backpressure, UDP worker/flow limits, proxy bridge sockets (`crates/foxprox-net/src/combined.rs:41`, `:187-278`).
- `crates/foxprox-proxy`: explicit HTTP proxy, HTTPS CONNECT, and SOCKS5 CONNECT parsing and live proof listeners (`crates/foxprox-proxy/src/lib.rs:38`, `:75`, `:116`, `:174`). Denied HTTP/CONNECT proxy requests are audited then closed without an HTTP 403 (`crates/foxprox-proxy/src/lib.rs:687`).
- `crates/foxprox-setup`: setup helper creates TUN, configures IP/route/DNS, sends fd, drops capabilities/no-new-privs, injects proxy env, and execs target (`crates/foxprox-setup/src/main.rs:196-218`, `:287-337`).
- `crates/foxprox-cli`: proof commands plus controlled launcher `foxprox run`; TOML config parsing rejects unknown fields and validates nonzero ports/limits (`crates/foxprox-cli/src/run_config.rs:55-104`). Combined launcher starts proxy backends, bridges them over TUN, verifies setup peer credentials, and runs combined proof (`crates/foxprox-cli/src/main.rs:101-213`).

## Coverage versus `docs/initial-impl.md`
- Milestone 0 TUN setup proof: covered. `foxproxsetup` opens `/dev/net/tun`, issues `TUNSETIFF`, configures address/MTU/default route with `/usr/bin/ip` under `env_clear`, writes broker DNS, sends the fd, waits for broker ready, drops capabilities, sets no-new-privs, and execs target (`crates/foxprox-setup/src/main.rs:196-337`).
- Milestone 1 packet write-back proof: covered by `foxprox-device` ICMP echo synthesis and `proof-icmp`; tests include valid reply, checksum, malformed/drop cases.
- Milestone 2 smoltcp TCP forwarding: covered by `foxprox-net` standalone and combined runtimes using `TunTapInterface`, smoltcp sockets, policy-gated host egress, byte bridging, and lifecycle audit (`crates/foxprox-net/src/lib.rs:39-146`; combined ready/listener setup at `combined.rs:187-278`).
- Milestone 3 minimal broker core: covered by normalized events, audit schema/buffer/JSON drain, config/resource limits, frontend/egress traits, default-deny policy, IP/CIDR/port/host/domain/method/path rules (`crates/foxprox-core/src/lib.rs:13-47`).
- Milestone 4 UDP/DNS foundation: covered by UDP pseudo-flow tracking, broker DNS service, direct external DNS denial, DNS parser/cache/audit, generic UDP forwarding and worker limits (`crates/foxprox-net/src/udp.rs:30`, `crates/foxprox-core/src/dns.rs:336`).
- Milestone 5 transparent policy/attribution: substantially covered. HTTP Host/method/path parser (`inspection.rs:74`), TLS ClientHello/SNI/ECH parser (`inspection.rs:132`), DNS-to-TCP/UDP attribution in combined runtime, SNI/DNS mismatch and hidden-SNI audit kinds, QUIC UDP/443 candidate classification. QUIC is intentionally limited to candidate classification plus DNS attribution, documented in `docs/arch.md:296` and `docs/production-runner.md:164-166`.
- Milestone 6 explicit proxy networking: covered. HTTP proxy, HTTPS CONNECT, SOCKS5 CONNECT, shared policy and egress, audit/backpressure, TUN-reachable HTTP/SOCKS bridges in `proof-transparent` (`crates/foxprox-cli/src/main.rs:678-852`). SOCKS UDP ASSOCIATE remains unsupported as allowed by docs.
- Milestone 7 robustness: covered by bounded audit queues/drain, worker/flow/connection limits, parser fuzz-smoke tests, malformed packet/proxy/DNS/HTTP/TLS fail-closed audit, setup socket cleanup, and non-lossy audit-backpressure behavior. Unit tests cover these paths across core/device/net/proxy/CLI.
- Success criteria: static review finds the code supports transparent TUN TCP/UDP/DNS/ICMP/QUIC-candidate traffic, explicit HTTP/CONNECT/SOCKS, default-deny policy/audit, direct DNS blocking, and controlled bwrap launcher. Full live behavior depends on privileged environment; `progress.md` records successful live smokes and `scripts/live-smoke-bwrap-tun.sh` documents repeatable validation.

## Verification evidence
Commands run in this audit:
- `git status --porcelain=v2 --branch`; clean at branch/head above.
- `git log --oneline --decorate -n 12`; confirmed current history.
- `git diff --stat`, `git diff --cached --stat`, `git ls-files --others --exclude-standard`; no code diffs/untracked before report.
- `cargo test --workspace`; passed: 14 CLI tests, 53 core, 9 device, 7 egress, 49 net, 30 proxy, 4 setup, doctests.
- `cargo fmt --all -- --check`; passed.
- `cargo clippy --workspace --all-targets -- -D warnings`; passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps`; passed.
- `cargo tree -p foxprox-core`; confirms `foxprox-core` has no dependencies.
- `cargo tree -p foxprox-net --depth 1`; expected deps: `foxprox-core`, `foxprox-egress`, `libc`, `smoltcp`.
- `cargo tree -p foxprox-proxy --depth 1`; expected deps: `foxprox-core`, `foxprox-egress`.
- `cargo tree -p foxprox-cli --depth 1`; expected deps: workspace crates plus `libc`, `nix`, `serde`, `toml`.
- `bash -n scripts/live-smoke-bwrap-tun.sh`; passed syntax check.

## Important gaps / blockers
- No implementation blockers found.
- Evidence gap: `plan.md` is missing although the task requested it.
- Evidence gap: `progress.md` is mostly comprehensive but final entries do not record commit hashes for the latest commits (`36799a5`, `48c5276`, `5967248`) even though git history shows them. This weakens handoff traceability but not runtime functionality.
- Residual validation risk: privileged live smoke was not rerun by this audit. Existing docs/script and `progress.md` claim coverage of direct HTTP, direct TLS, broker DNS, UDP/443 QUIC-candidate audit, HTTP/CONNECT proxy bridge, SOCKS5 bridge, and proxy env injection.

## Notable quality / security observations
- Good: core/proxy/device/egress crates forbid unsafe; unsafe is isolated to Linux fd/ioctl/fcntl/peer-credential paths in CLI/setup/net.
- Good: setup helper uses absolute `/usr/bin/ip` with `env_clear` (`crates/foxprox-setup/src/main.rs:254-255`), drops caps/no-new-privs before target exec (`:287-313`), and only injects proxy env values explicitly requested (`:318-337`).
- Good: explicit proxy backend bridge validation is loopback-only in CLI, and TUN proxy allow rules are scoped to broker IP/port (`crates/foxprox-cli/src/main.rs:149-184`, `:1098`).
- Note: `crates/foxprox-net/src/lib.rs:1-6` crate-level documentation is stale; it still describes a narrow one-port allow-all Milestone 2 adapter, while current code supports combined multi-port policy/audit runtimes. Documentation drift only.
- Note: `docs/production-runner.md:5-8` correctly warns this is controlled alpha, not a polished production hardening boundary.

## Confidence
High confidence that the claimed alpha implementation is functionally complete at the source/test level and matches the documented alpha scope. Confidence is not absolute because live bwrap/TUN validation was not rerun in this audit.

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audit-only task completed without modifying project/source files; required report written to reviews/autonomous-crew-audit.md."
    },
    {
      "id": "criterion-2",
      "status": "satisfied",
      "evidence": "Report includes branch/head/status, implemented crates, coverage against docs/initial-impl.md, command evidence, gaps, and residual risks."
    }
  ],
  "changedFiles": [
    "reviews/autonomous-crew-audit.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "git status --porcelain=v2 --branch && git diff --stat && git diff --cached --stat && git ls-files --others --exclude-standard",
      "result": "passed",
      "summary": "Clean branch autonomous-crew at 5967248476807792936b9e43445b07cfaaab274c before report output; no staged files."
    },
    {
      "command": "cargo test --workspace",
      "result": "passed",
      "summary": "All workspace unit/doc tests passed: CLI, core, device, egress, net, proxy, setup."
    },
    {
      "command": "cargo fmt --all -- --check",
      "result": "passed",
      "summary": "Formatting check passed."
    },
    {
      "command": "cargo clippy --workspace --all-targets -- -D warnings",
      "result": "passed",
      "summary": "Clippy passed with warnings denied."
    },
    {
      "command": "RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps",
      "result": "passed",
      "summary": "Documentation built without warnings."
    },
    {
      "command": "cargo tree -p foxprox-core; cargo tree -p foxprox-net --depth 1; cargo tree -p foxprox-proxy --depth 1; cargo tree -p foxprox-cli --depth 1",
      "result": "passed",
      "summary": "Dependency boundaries match expectations; foxprox-core remains dependency-free."
    },
    {
      "command": "bash -n scripts/live-smoke-bwrap-tun.sh",
      "result": "passed",
      "summary": "Live smoke script syntax check passed; privileged live smoke not rerun."
    }
  ],
  "validationOutput": [
    "cargo test --workspace: passed all workspace tests (14 CLI, 53 core, 9 device, 7 egress, 49 net, 30 proxy, 4 setup, doctests).",
    "cargo fmt/clippy/doc: passed.",
    "git status before report: clean, no staged files."
  ],
  "residualRisks": [
    "plan.md missing at requested path.",
    "Privileged live bwrap/TUN smoke was not rerun by this audit.",
    "progress.md does not record final commit hashes for the latest commits, although git history does.",
    "foxprox-net crate-level docs are stale relative to current multi-port policy/audit runtime."
  ],
  "noStagedFiles": true,
  "diffSummary": "No project/source diff before audit output; this run added only reviews/autonomous-crew-audit.md.",
  "reviewFindings": [
    "no blockers",
    "note: plan.md missing; evidence gap only",
    "note: live smoke not rerun in this audit",
    "note: crates/foxprox-net/src/lib.rs:1-6 stale crate-level documentation"
  ],
  "manualNotes": "Acceptance level reviewed. The audit report itself is the only file written by this review task."
}
```
