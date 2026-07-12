# Foxprox Worktree Functionality Comparison

This document synthesizes reviewer audits of the seven implementation worktrees. The source audits were written under each worktree's `reviews/` directory.

## Executive Summary

| Worktree | Overall Assessment | Best Use | Acceptance Risk |
| --- | --- | --- | --- |
| `autonomous-crew` | Strongest implementation by static/test evidence. Broad alpha coverage, clean verification, no audit blockers found. | Best merge candidate / reference implementation. | Medium: privileged live smoke was not rerun by reviewer; minor evidence/doc drift. |
| `observability-ledger` | Very strong alpha with real bwrap/TUN integration script passing in reviewer environment. | Best source for audit/integration evidence and live bwrap proof. | Medium: proxy listener config is ignored; lifecycle exit audit is simplified. |
| `contract-boundary` | Broad, coherent, boundary-oriented implementation with fuzz harnesses and passing tests. | Best source for architecture seams and dependency isolation. | Medium: unrelated docs deleted; CLI default policy is permissive. |
| `verification-kernel` | Broad implementation with alpha CLI and strong unit coverage. | Best source for verification-kernel/core/runtime structure. | Medium: unrelated docs deleted; live smoke not rerun; several product gaps. |
| `vertical-evidence` | Broad vertical prototype with many crates and passing tests. | Useful source for slice-based implementation patterns and config/policy loading. | High: TLS fragmentation/truncation can bypass transparent HTTPS inspection. |
| `harness-lab` | Strong harness-driven prototype with useful smoke tooling. | Best source for deterministic lab/harness ideas. | High: retained `CAP_NET_RAW`, clippy failure, smoke exit status weakness. |
| `security-invariants` | Strong pure-core invariant model and tests. Runtime wiring is less complete. | Best source for policy/parser invariant tests. | High: live runtime does not use mediated packet gate; direct DNS bypass is unproven end-to-end. |

Recommended immediate reference order:

1. `autonomous-crew`
2. `observability-ledger`
3. `contract-boundary`
4. `verification-kernel`
5. `vertical-evidence`
6. `harness-lab`
7. `security-invariants`

## Review Artifacts

| Worktree | Review artifact |
| --- | --- |
| `verification-kernel` | `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel/reviews/verification-kernel-audit.md` |
| `vertical-evidence` | `/home/foxfire/code/foxprox/.tmp/worktrees/vertical-evidence/reviews/vertical-evidence-audit.md` |
| `contract-boundary` | `/home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary/reviews/contract-boundary-audit.md` |
| `harness-lab` | `/home/foxfire/code/foxprox/.tmp/worktrees/harness-lab/reviews/harness-lab-audit.md` |
| `security-invariants` | `/home/foxfire/code/foxprox/.tmp/worktrees/security-invariants/reviews/security-invariants-audit.md` |
| `autonomous-crew` | `/home/foxfire/code/foxprox/.tmp/worktrees/autonomous-crew/reviews/autonomous-crew-audit.md` |
| `observability-ledger` | `/home/foxfire/code/foxprox/.tmp/worktrees/observability-ledger/reviews/observability-ledger-audit.md` |

## Feature Matrix

Legend:

* ✅ implemented and reviewer found meaningful verification
* ◐ partially implemented, prototype-only, or not fully wired into live runtime
* ⚠️ implemented but has an important blocker or acceptance risk
* ❌ not found / not implemented
* ? not independently verified by reviewer

| Feature / Requirement | verification-kernel | vertical-evidence | contract-boundary | harness-lab | security-invariants | autonomous-crew | observability-ledger |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rust workspace / crate split | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Core policy isolated from OS/frontend types | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Unsafe confined outside core | ✅ | ✅ | ✅ | ? | ✅ | ✅ | ✅ |
| Default-deny core policy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User-facing launcher default-deny | ◐ broad alpha allow rules | ◐ config-dependent | ⚠️ CLI defaults allow | ✅ host allow flags | ✅ | ✅ controlled config | ✅ policy-backed, but proxy enable flags ignored |
| Structured audit schema | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Bounded audit/backpressure | ✅ | ⚠️ bounded sink exists, live launcher uses unbounded `Vec` | ✅ | ✅ model exists | ✅ | ✅ | ✅ |
| Append-only `progress.md` / `learnings.md` | ✅ | ✅ but noisy duplicates | ✅ | ✅ but noisy duplicates | ✅ | ✅ minor hash gaps | ✅ |
| TUN setup / fd handoff | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| bwrap-compatible setup helper | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Drops setup capabilities before target | ✅ | ✅ | ✅ | ⚠️ leaves `CAP_NET_RAW` | ✅ | ✅ | ✅ |
| Packet parsing / validation | ✅ IPv4 | ✅ IPv4/IPv6 parsing but live paths IPv4-centered | ✅ | ✅ | ✅ | ✅ | ✅ |
| Packet write-back proof | ✅ ICMP/UDP | ✅ ICMP/UDP | ✅ | ✅ | ✅ core | ✅ | ✅ |
| smoltcp TCP forwarding | ✅ one-port/domain alpha | ✅ alpha one-shot/sequential | ✅ | ✅ | ✅ | ✅ | ✅ |
| Host TCP egress policy gate | ✅ | ✅ | ✅, but hostname denies can occur after connect | ✅ | ✅ | ✅ | ✅ |
| UDP forwarding | ✅ one mapping | ✅ runtime but flow limits not fully live | ✅ | ✅ | ✅ simple bridge | ✅ | ✅ |
| DNS broker | ✅ static/alias/cache | ✅ broker DNS/cache | ✅ | ✅ | ✅ | ✅ | ✅ |
| Direct external DNS deny | ✅ | ✅ core/runtime evidence | ✅ | ✅ smoke | ⚠️ core yes, live original-destination evidence gap | ✅ | ✅ |
| DNS attribution cache | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Transparent HTTP Host/path inspection | ✅ parser/runtime pieces | ✅ | ✅ | ✅ | ◐ core only for richer runtime | ✅ | ✅ |
| TLS ClientHello/SNI inspection | ✅ parser/runtime pieces | ⚠️ parse error/truncation forwarded | ✅ recent buffering fixes | ✅ | ◐ core only for richer runtime | ✅ | ✅ |
| SNI/DNS mismatch and hidden-SNI handling | ✅ | ✅ but TLS bypass risk | ✅ | ✅ | ✅ core | ✅ | ✅ |
| QUIC support | ◐ candidate classification | ◐ candidate classification | ✅ classification/fuzz-ish coverage | ✅ classification | ◐ core only | ◐ candidate classification | ✅ candidate/runtime audit |
| ICMP support | ◐ echo proof; limited errors | ◐ echo/write-back; runtime partial | ✅ | ✅ | ✅ core | ✅ | ✅ |
| IPv6 runtime support | ❌/◐ packet core mainly IPv4 | ◐ tests/parser, live paths IPv4-centered | ✅ claimed broad packet support | ? | ◐ policy/core; runtime unclear | ? | ✅ packet/parser coverage claimed |
| Explicit HTTP proxy | ◐ parser/runtime step, not production listener flags | ✅ one-request/listener helpers | ✅ | ✅ | ◐ core only not live listener | ✅ | ✅ |
| HTTPS CONNECT proxy | ◐ parser/runtime step | ✅ | ✅ | ✅ | ◐ core only | ✅ | ✅ |
| SOCKS5 CONNECT | ◐ parser/runtime step | ✅ | ✅ | ✅ | ◐ core only | ✅ | ✅ |
| Proxy listener configurability | ❌/◐ not exposed | ◐ | ✅ | ✅ | ❌ richer proxy not live | ✅ | ⚠️ config ignored; listeners/env always enabled |
| Config file / TOML policy | ❌ in-memory only | ✅ TOML config crate | ✅ policy flags/config | ◐ CLI allow flags | ✅ core config | ✅ controlled TOML launcher config | ✅ runtime config exists |
| Resource limits / flow expiry | ◐ | ⚠️ implemented but UDP live path bypasses limits | ✅ | ✅ | ◐ core tables, simple launcher | ✅ | ✅ |
| Fuzz targets | ❌ | ❌ fuzz-like tests only | ✅ fuzz harnesses compile | ❌ | ◐ parser fuzz smoke, not real fuzz targets | ✅ fuzz-smoke tests | ? no fuzz-specific blocker noted |
| Live bwrap/TUN tests rerun by reviewer | ❌ not rerun | ❌ `/dev/net/tun` missing | ❌ not rerun | ✅ selected smokes rerun | ❌ `/dev/net/tun` missing | ❌ not rerun | ✅ integration script passed 14 tests |
| Cargo tests | ✅ 226 tests | ✅ 157 tests | ✅ 173 tests | ✅ tests pass | ✅ tests pass | ✅ all workspace tests | ✅ all tests |
| Clippy `-D warnings` | ✅ | ✅ | ✅ | ⚠️ fails | ✅ | ✅ | ✅ |
| Rustdoc `-D warnings` | ? | ? | ? | ? | ? | ✅ | ? |
| Branch hygiene vs main | ⚠️ unrelated docs deleted | ⚠️ unrelated docs deleted, untracked `policy.toml` | ⚠️ unrelated docs deleted | ✅ no source diff from auditor; branch-specific docs status not flagged | ⚠️ unrelated docs deleted | ✅ clean/no blocker | ✅ untracked context/subagents only |

## Per-Worktree Summaries

### `autonomous-crew`

Reviewer confidence: **high** for source/test-level alpha completion.

Implemented:

* Rust workspace with `foxprox-core`, `foxprox-device`, `foxprox-egress`, `foxprox-net`, `foxprox-proxy`, `foxprox-setup`, and `foxprox-cli`.
* TUN setup helper with `/dev/net/tun`, `TUNSETIFF`, IP/route/DNS configuration, fd handoff, capability drop, `NO_NEW_PRIVS`, and target exec.
* smoltcp transparent TCP/UDP/DNS runtimes, combined transparent runtime, DNS cache attribution, HTTP/TLS inspection, UDP workers/limits, audit/backpressure.
* Explicit HTTP proxy, HTTPS CONNECT, and SOCKS5 CONNECT parsing and live proof listeners.
* Controlled launcher config and proxy env injection.
* Broad unit coverage, clippy, fmt, rustdoc, dependency boundary checks.

Important gaps:

* Reviewer did not rerun privileged live bwrap/TUN smoke.
* `plan.md` missing.
* `progress.md` does not record final commit hashes for latest commits.
* `foxprox-net` crate-level docs are stale relative to current implementation.

Why it matters:

* This appears to be the cleanest and most complete implementation branch by reviewer evidence. It should be the first branch to inspect for an integration baseline.

### `observability-ledger`

Reviewer confidence: **medium-high** for alpha proof; medium for production semantics.

Implemented:

* Workspace with `foxprox-core`, `foxprox-cli`, `foxprox-egress`, `foxprox-device`, and `foxprox-stack`.
* Platform-independent core with audit, broker, config, DNS, flow, inspect, packet, policy, proxy, runtime, setup, TCP/TUN/UDP contracts.
* TUN/bwrap setup, fd handoff, route/DNS/proxy configuration, target exec.
* smoltcp stack adapter, transparent TCP/UDP, DNS handler, explicit HTTP proxy, CONNECT, SOCKS proxy.
* Strong audit/lifecycle/event coverage.
* Reviewer ran full tests, fmt, clippy, and real bwrap/TUN integration script; all 14 integration tests passed.

Important gaps/blockers:

* `proxy_listeners.http_enabled` / `socks_enabled` config is ignored; setup/runtime always inject proxy env and starts both proxy ports.
* `network_session_exit` audit always reports allow/cleanup complete, even on child/process failure or blocking denial.
* TCP/UDP/proxy forwarding is alpha request/response oriented, not fully general streaming/full-duplex.
* `plan.md` missing.

Why it matters:

* This is the best branch for live bwrap/TUN proof and audit-oriented implementation ideas, but proxy configurability needs fixing before acceptance.

### `contract-boundary`

Reviewer confidence: **medium-high**.

Implemented:

* Workspace with many architecture crates: core, policy, audit, egress, frontends, integrations, net, packet, DNS, config, device, runtime, smoltcp, CLI.
* Strong architecture boundary enforcement: policy/audit depend only on core; smoltcp isolated; runtime composes generic traits.
* Broad alpha coverage: TUN setup/fd handoff, ICMP/write-back, smoltcp bridge loop, UDP/DNS, transparent HTTP/TLS/QUIC attribution, explicit proxy/CONNECT/SOCKS, resource limits, fuzz harnesses.
* Tests, clippy, fuzz target compilation, and binary build pass.

Important gaps/blockers:

* Branch deletes unrelated implementation-approach docs versus `main`.
* CLI initializes `RuntimeConfig::allow_by_default()` while docs say default policy should deny unless a profile allows.
* Transparent hostname deny rules may deny after host TCP connect rather than before host contact.
* Privileged bwrap/curl smokes were not rerun by reviewer.

Why it matters:

* This is the best branch for preserving modular architecture and may contain useful fuzz harnesses. It needs merge hygiene and default-policy review.

### `verification-kernel`

Reviewer confidence: **high** for foundation and minimal alpha CLI; low for full `docs/initial-impl.md` completion.

Implemented:

* Workspace with core/runtime/smoltcp/device/integrations/setup/launcher crates.
* Platform-independent core with policy, audit, DNS, event, flow, frontend, inspect, packet, config, origin, and verification-kernel modules.
* Runtime policy-gated TCP/UDP/proxy/DNS/TUN components.
* `foxprox run` alpha CLI with bwrap launch, TUN fd handoff, one TCP mapping, one TCP-domain mapping, and one UDP mapping.
* Packet validation/write-back, direct DNS deny, DNS attribution, audit line sink, smoltcp bridge proof.
* Full fmt/clippy/tests pass; reviewer saw 226 total tests passing.

Important gaps/blockers:

* Branch deletes unrelated implementation-approach docs versus `main`.
* CLI supports only one mutually-exclusive TCP/TCP-domain/UDP mapping per run.
* No production HTTP/SOCKS listener flags despite parser/runtime pieces.
* No config-file CLI policy loader.
* IPv4-only packet core for live path; limited ICMP errors; limited QUIC metadata.
* No fuzz targets.
* Live bwrap/curl smoke not rerun by reviewer.

Why it matters:

* Strong core/runtime implementation and useful minimal CLI shape, but less complete than `autonomous-crew` / `observability-ledger`.

### `vertical-evidence`

Reviewer confidence: **high** as alpha prototype; low-to-medium for full success criteria.

Implemented:

* Workspace with core, packet, broker, audit, config, CLI, inspect, flow, proxy, egress, DNS, integrations, device, and TCP crates.
* Many vertical slices: policy/audit core, fail-closed packet parsing, ICMP/UDP write-back, Linux TUN primitives, bwrap setup/CAP drop, transparent runtime, UDP flow/resource types, explicit proxy helpers, TOML policy config.
* Tests/clippy/fmt pass; 157 non-ignored tests. Live tests are ignored when `/dev/net/tun` is absent.
* Recent fix normalizes broker DNS for bwrap policies.

Important gaps/blockers:

* Transparent TLS inspection can be bypassed by fragmentation/truncation: parse errors mark application audited and forwarding continues.
* Runtime audit backpressure is not integrated; launcher accumulates audit lines in unbounded `Vec`.
* UDP flow/resource limit logic exists but live transparent UDP forwards without using it.
* QUIC is mostly candidate classification.
* IPv6 runtime support partial; live paths IPv4-centered.
* Branch deletes unrelated implementation-approach docs; untracked `policy.toml` present.
* Live bwrap/TUN tests not rerun due missing `/dev/net/tun`.

Why it matters:

* Useful as a vertical-slice reference, especially config-to-policy behavior. The TLS truncation bypass is a serious blocker.

### `harness-lab`

Reviewer confidence: **medium-high** for harness behavior; not acceptable until blockers are fixed.

Implemented:

* Workspace with `foxprox-core`, `foxprox-cli`, `foxprox-setup`, `foxprox-device`, `foxprox-egress`, and `foxprox-broker`.
* Strong deterministic harness/CLI: `foxprox-lab run ...`, sandbox launcher, broker-session smokes, direct-DNS-deny smoke, TLS-SNI-deny smoke.
* Core modules for audit, DNS, egress, flow, frontend, integration, origin, packet, policy, runtime, scenario, smoltcp gate.
* Transparent UDP/DNS/TCP, explicit proxy runtime, audit backpressure model.
* Tests and fmt pass; representative smokes pass.

Important gaps/blockers:

* Sandbox launcher grants `CAP_NET_RAW` to all sandbox targets and setup only drops `CAP_NET_ADMIN`.
* Environment smoke commands can emit `fail_closed` audit records but still exit success; `&& echo OK` is not sufficient pass evidence.
* `cargo clippy --all-targets --all -- -D warnings` fails.
* No fuzz targets despite robustness requirements.
* `plan.md` missing; progress ledger noisy.

Why it matters:

* Best branch for test harness patterns, but not a clean acceptance candidate as-is.

### `security-invariants`

Reviewer confidence: **high** for pure core invariants; moderate/low for live runtime completion.

Implemented:

* Workspace with `foxprox-core`, `foxprox-device`, `foxprox-integrations`, `foxprox-net`, and `foxprox-cli`.
* Strong platform-independent core with default-deny config, policy, audit, DNS, packet/TUN decisions, HTTP/TLS/QUIC/SOCKS/proxy handlers, ICMP, flow tables, egress permits.
* Linux TUN creation, bwrap construction, fd passing, peer credential checks.
* smoltcp TUN adapter and alpha broker runtime; CLI creates bwrap sandbox and runs broker.
* Tests/check/clippy pass; ignored bwrap/TUN tests exist but were not rerun due missing `/dev/net/tun`.

Important gaps/blockers:

* Branch deletes unrelated implementation-approach docs versus `main`.
* Live alpha runtime uses unmediated `SmolTunDevice`, not `MediatedTunDevice`, so packet-level fail-closed/audit invariants are not proven in launcher path.
* Direct external DNS bypass is unproven end-to-end because runtime constructs policy destination as broker IP and may lose original destination.
* Explicit proxy support and transparent HTTP/TLS/QUIC runtime inspection are core-only, not wired into live `foxprox` listeners/inspection paths.

Why it matters:

* Strong source of security invariant tests and policy design, but runtime integration lags behind its core model.

## Cross-Cutting Gaps

These gaps appeared across multiple worktrees and should be treated as integration checklist items:

1. **Unrelated docs deleted versus `main`.** Reviewers flagged this in `verification-kernel`, `vertical-evidence`, `contract-boundary`, and `security-invariants`. Restore or explicitly isolate approach-doc changes before merging implementation branches.
2. **Live bwrap/TUN evidence varies.** Only `observability-ledger` reran the full privileged integration script during audit. Several branches have ignored tests or ledgered smokes that could not be rerun due missing `/dev/net/tun`.
3. **Default policy ambiguity.** Some implementations keep core default-deny but CLI defaults to allow or broad alpha allow rules. Before acceptance, decide whether alpha CLI may default allow for proofs or must default deny.
4. **Proxy listener exposure/configuration.** Several branches have proxy parsers/runtime pieces but incomplete production listener exposure. `observability-ledger` has the inverse issue: listener config exists but is ignored and proxy env/listeners are always enabled.
5. **Transparent TLS/SNI robustness.** `vertical-evidence` has a concrete TLS truncation/parse-error bypass. Other branches should be checked for the same class: first-payload buffering must not convert incomplete/malformed TLS into an allowed unaudited path.
6. **Direct DNS bypass end-to-end.** Core policy usually denies direct external DNS, but live runtime must preserve original destination and prove sandbox DNS to external resolver is denied before egress.
7. **Audit backpressure in live path.** Bounded audit structures exist in many branches, but ensure live runtime does not accumulate unbounded `Vec`s or otherwise bypass fail-closed backpressure behavior.
8. **Capability drop and raw socket capability.** `harness-lab` leaves `CAP_NET_RAW` in the sandbox target. Check other branches for capability retention and ensure only setup capabilities survive until setup, then are dropped before target exec.
9. **Fuzz coverage.** `contract-boundary` has real fuzz harnesses; several other branches only have unit/fuzz-smoke tests or no fuzzing.
10. **Long-lived/full-duplex behavior.** Several branches are alpha request/response or one-shot proof oriented. Full production semantics still need long-lived TCP/proxy forwarding, resource cleanup, and supervision.

## Feature Groups by Best Source Branch

| Feature group | Best source branch(es) | Notes |
| --- | --- | --- |
| Overall alpha implementation | `autonomous-crew`, `observability-ledger` | `autonomous-crew` has clean static/test audit; `observability-ledger` has strongest live integration evidence. |
| Architecture boundaries | `contract-boundary`, `autonomous-crew` | `contract-boundary` explicitly verifies dependency separation and fuzz harnesses. |
| Live bwrap/TUN integration | `observability-ledger`, `autonomous-crew` | `observability-ledger` reviewer ran integration script; `autonomous-crew` has script and progress evidence but not rerun. |
| Verification/test harness | `harness-lab`, `observability-ledger` | `harness-lab` has useful deterministic smoke/harness design despite blockers. |
| Policy/security invariants | `security-invariants`, `contract-boundary`, `autonomous-crew` | `security-invariants` has strong pure core tests; ensure runtime uses them. |
| Audit and observability | `observability-ledger`, `autonomous-crew`, `verification-kernel` | `observability-ledger` strongest audit focus but has proxy config/lifecycle audit blockers. |
| Explicit proxy implementation | `autonomous-crew`, `observability-ledger`, `contract-boundary` | Check configurability and full-duplex limitations. |
| Config/TOML UX | `autonomous-crew`, `vertical-evidence`, `contract-boundary` | `verification-kernel` lacks config-file loader. |
| Fuzzing | `contract-boundary` | Other branches need real fuzz targets or explicit deferral. |

## Suggested Acceptance Strategy

1. Start from `autonomous-crew` or `observability-ledger` as the primary candidate.
2. Borrow from `observability-ledger` any live bwrap/TUN integration test harness not present in the chosen branch.
3. Borrow from `contract-boundary` fuzz harnesses and dependency-boundary checks if absent.
4. Borrow from `harness-lab` deterministic smoke scenario design, but do not carry over the `CAP_NET_RAW` retention or smoke-exit-status weakness.
5. Borrow from `security-invariants` pure policy/parser invariant tests, but ensure live runtime uses the same mediated packet and direct-DNS decision paths.
6. Before merging any worktree, run a hygiene pass:
   - restore unrelated approach docs deleted versus `main`;
   - confirm no untracked `policy.toml`, `context.md`, `subagents/`, or review artifacts are accidentally included;
   - require `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets --all-features`, and the appropriate bwrap/TUN integration script when environment permits;
   - verify default-deny CLI behavior or document an explicit alpha-only default-allow proof mode;
   - verify proxy listener config is honored;
   - verify TLS incomplete/malformed first payload fails closed or waits for more data without bypassing policy;
   - verify direct external DNS attempts preserve original destination and are denied before egress.
