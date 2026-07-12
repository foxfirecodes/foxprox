# Foxprox Production-Grade Alpha Requirements

## Goal and strategy

Produce one production-grade alpha from the seven preserved worktrees using **reference-first, selective-import-early**:

1. use [`.tmp/worktrees/autonomous-crew`](../.tmp/worktrees/autonomous-crew) as the sole runtime lineage;
2. port portable tests, fuzz targets, invariants, and harness assets before major runtime restructuring;
3. harden that candidate to satisfy every acceptance gate below;
4. import runtime code from another worktree only for a measured gap and only when it fits the canonical interfaces.

Do not merge competing runtimes or replace the crate graph wholesale. Progress and evidence belong in [`docs/production-alpha-progress.md`](production-alpha-progress.md), not here.

## Authority and references

Precedence when sources conflict:

1. this document for execution and production acceptance;
2. [`docs/initial-impl.md`](initial-impl.md) for alpha scope and protocol semantics;
3. [`docs/arch.md`](arch.md) for boundaries and fail-closed behavior;
4. [`docs/bubblewrap-fork.md`](bubblewrap-fork.md) for bwrap integration;
5. worktree code/tests as evidence, never as authority.

Useful synthesis sources:

| Worktree | Path | Use | Do not import |
| --- | --- | --- | --- |
| `autonomous-crew` | [path](../.tmp/worktrees/autonomous-crew) | Canonical runtime, TOML launcher, full-duplex TCP, proxies, live smoke | — |
| `observability-ledger` | [path](../.tmp/worktrees/observability-ledger) | Privileged bwrap/TUN tests, byte relay, capability and audit assertions | Synchronous per-chunk runtime, singleton tunnels |
| `contract-boundary` | [path](../.tmp/worktrees/contract-boundary) | Fuzz targets, dependency checks, boundary ideas | Wholesale crate migration, permissive CLI defaults |
| `security-invariants` | [path](../.tmp/worktrees/security-invariants) | Pure policy/parser/security invariant tests | Incomplete runtime wiring |
| `harness-lab` | [path](../.tmp/worktrees/harness-lab) | Deterministic negative scenarios | Retained `CAP_NET_RAW`, unreliable smoke status |
| `verification-kernel` | [path](../.tmp/worktrees/verification-kernel) | Narrow typed-state/verification patterns | Runtime or CLI replacement |
| `vertical-evidence` | [path](../.tmp/worktrees/vertical-evidence) | Selected config/test fixtures | TLS/runtime path with truncation bypass |

Strategy and audit context:

- [`.tmp/audits/strategy-recommendation.md`](../.tmp/audits/strategy-recommendation.md)
- [`.tmp/audits/requirements-checklist.md`](../.tmp/audits/requirements-checklist.md)
- [`docs/worktree-functionality-comparison.md`](worktree-functionality-comparison.md)

## Required user experience

The supported command is:

```sh
foxprox run --config /path/to/config.toml -- target args...
```

It must validate configuration, start the host broker, create/configure and hand off the sandbox TUN, wait for readiness, drop setup privileges/fds, execute the target, mediate and audit traffic until exit, clean up, and return a stable exit status.

The strict, versioned config must support ordered allow/deny rules for:

- IP/CIDR and destination ports/ranges;
- TCP, UDP, broker DNS/query type, and ICMP;
- exact hostname/domain suffix and attribution confidence;
- transparent HTTP Host/method/port/path;
- transparent TLS SNI, DNS attribution, mismatch, missing SNI, and visible ECH state;
- HTTP proxy, HTTPS `CONNECT`, and SOCKS5 TCP `CONNECT`;
- QUIC candidates using UDP/IP/port/DNS and feasible visible metadata;
- frontend where represented by normalized policy events.

Default is deny. Listener or inspection configuration must never authorize egress. A direct inline JSON/TOML argument is optional if the file form is complete.

## Scope

All alpha Milestones 0–7 in `docs/initial-impl.md` are required, including richer policy/proxy features—not only forwarding proofs.

The production alpha may be explicitly IPv4-only if IPv6 config is rejected before launch, IPv6 traffic fails closed and audits, and no interface claims IPv6 support.

Non-goals unless separately approved:

- TLS MITM/custom CA or encrypted HTTPS content inspection;
- HTTP/3 semantics, TAP/L2, SOCKS UDP ASSOCIATE, or proxy authentication;
- arbitrary multicast/broadcast;
- full filesystem/seccomp/Landlock/process sandbox policy;
- a bwrap fork/`foxwrap` hook;
- mandatory IPv6 dataplane or complete prevention of unidentifiable encrypted DNS.

## Non-negotiable invariants

- Default deny in core and CLI; malformed/unsupported policy-sensitive paths fail closed.
- The target has no direct host networking; all host sockets are opened by shared trusted egress after an allow decision.
- TUN and all proxy frontends share normalized policy, audit, DNS, and egress contracts.
- Listener exposure, protocol inspection, and authorization are separate.
- Domain rules require adequate attribution; IP-only fallback requires explicit IP/CIDR/port allow.
- External UDP/TCP DNS is denied by default. Broker DNS applies policy before upstream egress or cache mutation.
- SNI/DNS mismatch denies; missing/hidden SNI or ECH cannot satisfy a domain allow.
- Authorization audit is committed before egress. Audit and all flow/task/socket/fd/buffer resources are bounded.
- Setup failure prevents target execution. `CAP_NET_ADMIN`, setup fds, and default `CAP_NET_RAW` do not survive exec.
- Policy/audit contain no unsafe code; other unsafe code is isolated and reviewed.
- Core/runtime remain bwrap-agnostic.

## Acceptance checklist

`[~]` means a reference proof exists but is not accepted. Only retained executable evidence permits `[x]`.

### M0 — setup, handoff, and teardown

- [~] Bwrap user/net namespaces, temporary `CAP_NET_ADMIN`, `/dev/net/tun`, TUN address/MTU/route/DNS, fd handoff, readiness, capability drop, `no_new_privs`, and target exec exist.
- [ ] Authenticate handoff to the expected session/config; reject replay or fd substitution.
- [ ] Every setup stage has timeout, rollback, audit, nonzero failure, and proof the target did not run.
- [ ] Teardown reliably removes sockets and reclaims broker/session resources.

### M1 — packet write-back and ICMP

- [~] Valid write-back and ICMPv4 echo synthesis exist.
- [ ] Integrate supported ICMP types, policy, write-back/errors, limits, and audit into `foxprox run`.
- [ ] Privileged tests prove allow, deny, malformed, and unsupported ICMP behavior.

### M2 — production TCP flows

- [~] TUN/smoltcp-to-host byte forwarding exists.
- [ ] Key connections by complete flow identity; support concurrent same-port flows and one persistent host socket per flow.
- [ ] Correctly handle full duplex, FIN/half-close/RST, connect failure, retransmission, timeout, slow peers, and cleanup.
- [ ] Bound per-flow buffers and global/session flow counts with audited limit behavior.
- [ ] Real-TUN tests cover large upload/response, keepalive, interactive traffic, concurrency, churn, and failures.

### M3 — core, configuration, and CLI

- [~] Normalized events, shared policy/audit/egress, frontend abstractions, and strict TOML loading exist.
- [ ] Version config; reject unknown, contradictory, unsafe, or unsupported fields before launch.
- [ ] Normatively test rule precedence, matching/normalization, defaults, units, and active-flow semantics.
- [ ] Separate listeners, inspection mappings, and policy; configured ports must not synthesize allow rules.
- [ ] Provide successful `--help`/`--version`, stable exit codes, config validation/dry-run/effective-config, and kernel/feature diagnostics.
- [ ] Enforce dependency boundaries and reject unsupported IPv6 config if IPv4-only.

### M4 — UDP and DNS

- [~] UDP/DNS forwarding, cache, direct-DNS guard, and resource concepts exist.
- [ ] Key UDP pseudo-flows and support one-way, zero-, one-, and multi-response traffic.
- [ ] Use monotonic configured DNS/generic/QUIC/one-shot timeouts; enforce live flow/socket/worker/queue/memory bounds.
- [ ] Apply policy to broker DNS before upstream/cache; define and audit denied-query behavior.
- [ ] Deny external UDP/TCP DNS before host egress.
- [ ] Safely handle response validation, truncation/TCP fallback, CNAME, TTL/negative cache, expiry, eviction, and upstream failure.
- [ ] Scope attribution by session, hostname, type, address, TTL, and time so stale/ambiguous data cannot authorize.

### M5 — transparent inspection and attribution

- [~] Initial HTTP metadata, TLS SNI, DNS attribution, and QUIC candidate inspection exist.
- [ ] Incrementally parse and reevaluate every HTTP request on fragmented/keepalive/pipelined connections.
- [ ] Fail closed on Host conflicts, malformed framing, smuggling ambiguities, upgrades, and limits.
- [ ] Configure generic/HTTP/TLS inspection by port rather than hard-coding only 80/443.
- [ ] Parse fragmented/coalesced/malformed TLS ClientHello, SNI, missing SNI, and visible ECH without truncation bypass.
- [ ] Enforce mismatch, attribution confidence, IP fallback, QUIC timeout/attribution, and identifiable DoT/DoH defaults without overclaiming visibility.
- [ ] Privileged positive/negative tests cover every policy dimension and malformed path.

### M6 — explicit proxies

- [~] HTTP, CONNECT, and SOCKS5 TCP proof listeners exist.
- [ ] Honor enable/disable settings and omit disabled listeners/environment variables.
- [ ] Key parser/tunnel state per flow/session; prevent cross-client data or policy leakage.
- [ ] Reevaluate every plaintext HTTP request; provide bounded full-duplex CONNECT/SOCKS with correct half-close/cleanup.
- [ ] Bound/audit resolution and connect; malformed/denied requests must not open host egress.
- [ ] Real-TUN tests cover concurrent allow/deny/malformed HTTP, CONNECT, and SOCKS clients.

### M7 — robustness, audit, and lifecycle

- [~] Bounded audit types, parser limits, unit tests, and partial resource controls exist.
- [ ] Continuously drain a versioned audit schema with session/event correlation, policy identity, decision/reason, attribution, bytes, duration, and lifecycle data.
- [ ] Define and load-test bounded audit-sink outage behavior; expose flow/cache/limit/audit/error metrics and readiness.
- [ ] Deterministically contain and clean up SIGINT/SIGTERM, target/helper/broker exit, handoff loss, and cancellation.
- [ ] Add real packet/DNS/HTTP/TLS/proxy/SOCKS fuzz targets and retained regressions.
- [ ] Property-test policy precedence, normalization, domain matching, attribution, and fail-closed behavior.
- [ ] Load/soak tests prove bounded memory/fds/tasks/sockets/queues and eventual cleanup.
- [ ] Review unsafe code, dependencies, licenses, vulnerabilities, and supported versions.

## Cross-cutting production gates

- [ ] Partial startup cannot leak a runnable target, capability, fd, listener, setup socket, TUN ownership, or broker task.
- [ ] Broker failure prevents target egress; multiple sessions cannot share packet, flow, DNS, policy, tunnel, audit, or identifier state.
- [ ] Runtime `/proc` or equivalent evidence verifies capability/fd inheritance and broker-only host sockets.
- [ ] Versioned policy docs cover precedence, suffix/case/IDNA/trailing-dot semantics, ranges/default ports, invalid rules, and unsupported features.
- [ ] Hot reload is atomic and tested, or explicitly rejected as unsupported. File trust/permissions and CLI/file/env precedence are documented.
- [ ] CI distinguishes executed from skipped privileged tests and retains a requirement-to-test evidence matrix.
- [ ] Format, clippy, all tests/docs/features/targets, fuzz build/run, property, privileged integration, failure injection, concurrency, load/soak, and security checks pass.
- [ ] Installation, upgrade/rollback/uninstall, compatibility, readiness, runbooks, capacity/alerts, audit retention/rotation/redaction, and residual visibility limits are documented.
- [ ] No known critical/high defect remains in privileged setup, packet/parser, policy, audit, or egress boundaries.

## Execution plan

### Phase 0 — candidate baseline

Create the candidate from preserved `autonomous-crew`; record commit/tool/kernel/bwrap/userns/TUN environment; retain current fmt/clippy/test/doc/live-smoke evidence; create a requirement-to-test matrix.

**Exit:** baseline reproduces and every known gap is `fail`, `missing`, or `unverified` rather than implicit.

### Phase 1 — portable verification imports

Port, one source at a time:

- privileged integration/audit tests from `observability-ledger`;
- fuzz and dependency checks from `contract-boundary`;
- pure invariant tests from `security-invariants`;
- corrected negative scenarios from `harness-lab`;
- only gap-justified ideas from `verification-kernel` and test/config fixtures from `vertical-evidence`.

**Exit:** assets run against the candidate with provenance recorded; no competing runtime was wholesale merged.

### Phase 2 — policy/config correctness

Fix broker-DNS policy, implicit port authorization, listener/inspection/policy separation, strict versioned config, combined ICMP, and persistent incremental HTTP/TLS enforcement. Add privileged allow/deny matrices.

**Exit:** no known policy bypass; denials occur before host egress and audit correctly.

### Phase 3 — production flow management

Implement dynamic TCP/proxy flows, keyed UDP/DNS flows, monotonic timers, resource limits, full-duplex/backpressure, lifecycle, expiry, cancellation, and cleanup.

**Exit:** concurrency, large-body, keepalive, interactive, one-way/multi-response UDP, churn, bounds, and isolation pass.

### Phase 4 — lifecycle and observability

Implement continuous audit, sink policy, metrics/readiness, correlation/policy identity, signals, containment, authenticated setup, rollback, and cleanup failure tests.

**Exit:** failure injection proves atomic setup, fail-closed containment, bounded audit, and cleanup.

### Phase 5 — release acceptance

Run fuzz/property/privileged/concurrency/load/soak/security/compatibility gates, complete operational documentation, and obtain independent review.

**Exit:** every required checkbox is `[x]` with retained evidence and no production-alpha blocker remains.

## Import and validation rules

For every import: record worktree/commit/paths/purpose; port the smallest failing test/contract first; implement against canonical interfaces; cherry-pick only cleanly fitting code; add default-deny negative coverage; run focused then phase gates; commit a meaningful checkpoint and continue.

Forbidden: wholesale/octopus merges, unapproved crate-graph replacement, weakening fail-closed behavior, importing review claims as proof, or deleting unrelated docs.

Baseline commands, adapted if packages change:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Privileged tests must use real bwrap/user/net namespaces and `/dev/net/tun`; a skip is not a pass. Retain command, exit code, counts/skips, environment, audit artifacts, and load/soak resource measurements.

Required E2E categories: setup success/failure; TUN read/write; concurrent TCP; TCP/UDP/DNS policy; UDP response modes/limits; HTTP fragmentation/keepalive/malformed; TLS SNI/mismatch/ECH/fragmentation; QUIC; ICMP; proxy/CONNECT/SOCKS concurrency and denial; audit outage; signals/crashes/cleanup; cross-session isolation and churn.

## Agent rules and definition of done

Work autonomously on routine reversible details with one candidate writer. Escalate scope-changing, security-sensitive, irreversible, dependency/trust-boundary, or materially different architecture decisions. A verified commit is a checkpoint, not completion; continue while meaningful required progress remains. Never claim a privileged/concurrency/fuzz/load gate from unit tests alone.

Done means the supported command performs setup through cleanup; policy is enforced/audited across every required protocol/frontend; concurrent long-lived traffic is isolated and bounded; all checkboxes have retained evidence; all validation/release/operations documentation passes independent review; and every omission is an approved non-goal rather than an untracked gap.
