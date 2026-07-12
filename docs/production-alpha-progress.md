# Foxprox Production-Grade Alpha Progress

Append-oriented evidence ledger for [`docs/production-alpha-requirements.md`](production-alpha-requirements.md). Requirements are normative; claims here require executable evidence. Preserve useful failures and superseded decisions.

## References

- Runtime lineage: [`.tmp/worktrees/autonomous-crew`](../.tmp/worktrees/autonomous-crew)
- Strategy: [`.tmp/audits/strategy-recommendation.md`](../.tmp/audits/strategy-recommendation.md)
- Audits: [requirements](../.tmp/audits/requirements-checklist.md), [autonomous-crew](../.tmp/audits/autonomous-crew.md), [observability-ledger](../.tmp/audits/observability-ledger.md)
- Comparison: [`docs/worktree-functionality-comparison.md`](worktree-functionality-comparison.md)
- Other preserved sources: [observability](../.tmp/worktrees/observability-ledger), [contract](../.tmp/worktrees/contract-boundary), [invariants](../.tmp/worktrees/security-invariants), [harness](../.tmp/worktrees/harness-lab), [verification](../.tmp/worktrees/verification-kernel), [vertical](../.tmp/worktrees/vertical-evidence)

## Phase status

| Phase | Status | Exit condition |
| --- | --- | --- |
| 0 — baseline | Not started | Candidate reproduces reference; every gap is classified |
| 1 — verification imports | Not started | Portable assets run with provenance recorded |
| 2 — policy/config | Not started | No known bypass; denials precede egress |
| 3 — flow runtime | Not started | Concurrent/long-lived TCP, proxy, UDP, DNS and bounds pass |
| 4 — lifecycle/audit | Not started | Atomic setup, containment, continuous bounded audit and cleanup pass |
| 5 — release | Not started | Full acceptance, fuzz/property/load/soak/security/ops gates pass |

## Baseline — 2026-07-12

- Runtime reference: `.tmp/worktrees/autonomous-crew`, audited HEAD `5967248`.
- `autonomous-crew` workspace tests and `scripts/live-smoke-bwrap-tun.sh` passed in the audit environment.
- `observability-ledger` workspace tests and all 14 privileged bwrap/TUN integration tests passed.
- Both principal references expose one-command launch and config-file policy.

These prove reference behavior only, not production acceptance.

### Known blockers

- Broker DNS bypasses configured DNS policy.
- Transparent port configuration injects implicit allow rules.
- One smoltcp socket/state per destination port prevents same-port concurrency.
- ICMP is separate from `foxprox run`.
- Transparent and explicit plaintext HTTP inspect only the first request.
- HTTP/TLS inspection is tied to conventional ports.
- UDP/resolver behavior remains proof-grade.
- Graceful shutdown, production audit/metrics/readiness, and load/soak evidence are missing.
- Fuzz-smoke tests are not real fuzzing.
- IPv6 config exceeds the supported dataplane and must be rejected or implemented.

### Pending portable imports

- [ ] `observability-ledger`: privileged integration and audit assertions.
- [ ] `contract-boundary`: fuzz targets and dependency checks.
- [ ] `security-invariants`: pure invariant tests.
- [ ] `harness-lab`: corrected deterministic negative scenarios.
- [ ] `verification-kernel`: only gap-justified typed-state ideas.
- [ ] `vertical-evidence`: only config/test fixtures, excluding TLS/runtime.

## Acceptance index

| Area | State | Main missing evidence |
| --- | --- | --- |
| M0 setup | Reference proof | Authentication, rollback, teardown, failure matrix |
| M1 ICMP | Separate proof | Primary-command integration and privileged allow/deny |
| M2 TCP | Partial | Dynamic concurrent flows and lifecycle/load evidence |
| M3 core/config | Partial | Versioned semantics, diagnostics, listener/auth separation |
| M4 UDP/DNS | Partial | DNS policy, production pseudo-flows and DNS correctness |
| M5 inspection | Partial | Persistent HTTP, configurable ports, robust TLS/DoH/DoT matrix |
| M6 proxies | Partial | Bridge concurrency, repeat policy, bounded lifecycle |
| M7 robustness | Partial | Continuous audit, signals, metrics, fuzz/property/load/soak |
| Production | Missing | Containment, isolation, release, compatibility and operations |

## Import provenance

| Date | Source commit/paths | Candidate paths | Purpose | Validation/status |
| --- | --- | --- | --- | --- |
| — | — | — | Nothing ported yet | Pending |

## Validation evidence

| Date | Source/candidate | Command | Result | Evidence note |
| --- | --- | --- | --- | --- |
| 2026-07-12 | `autonomous-crew` `5967248` | `cargo test --workspace` | Pass | Rerun and retain for candidate baseline |
| 2026-07-12 | `autonomous-crew` `5967248` | `scripts/live-smoke-bwrap-tun.sh` | Pass | Linux/bwrap/TUN; rerun for candidate |
| 2026-07-12 | `observability-ledger` `4052771` | `cargo test --workspace` | Pass | Reference evidence only |
| 2026-07-12 | `observability-ledger` `4052771` | `scripts/integration/bwrap-setup-e2e.sh` | Pass, 14/14 | Reference evidence only |

## Decisions

### 2026-07-12 — synthesis strategy

- `autonomous-crew` is the sole runtime lineage.
- Import low-coupling verification assets before major runtime work.
- Preserve all seven worktrees; do not wholesale merge competing runtimes.

## Checkpoint template

```markdown
### YYYY-MM-DD — <checkpoint>
- Candidate commit before/after:
- Phase/requirements:
- Import provenance (worktree, commit, source and candidate paths):
- Behavior and tests changed:
- Commands/results and retained artifacts:
- Privileged environment and resource evidence:
- Review findings accepted/rejected:
- Failures/learnings:
- Remaining blockers and next highest-value requirement:
```

## Checkpoints

Append new checkpoints here without rewriting prior history.
