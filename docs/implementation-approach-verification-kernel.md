# Implementation Approach: Verification Kernel

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`

Use those documents as the source of truth for scope, architecture boundaries, Rust stack expectations, safety rules, and fail-closed behavior.

## Core Directive

Build from a small, always-correct verification kernel outward. Treat every code change as unfinished until it is covered by deterministic verification, recorded in append-only history, and committed as a meaningful unit.

Prefer correctness, testability, and explicit failure behavior over speed. Never add a traffic path, parser path, policy path, or integration path whose unsupported cases are undefined.

## Operating Protocol

1. Start each session by reading `docs/arch.md`, `docs/initial-impl.md`, `progress.md`, and `learnings.md` if present.
2. If `progress.md` or `learnings.md` does not exist, create it before code changes.
3. Append a session-start entry to `progress.md` with timestamp, current git status summary, intended slice, and verification plan.
4. Select the smallest change that increases verified correctness.
5. Implement only that change.
6. Run the verification commands that prove the change.
7. Append command results, changed files, failures, and next action to `progress.md`.
8. Append a short entry to `learnings.md` whenever a design assumption changes, a tool behaves unexpectedly, a test reveals a misconception, or the approach changes.
9. Commit only after a coherent, verified change. Do not commit pure churn or half-working experiments.
10. Continue autonomously by selecting the next highest-risk unverified behavior.

## Verification Requirements

Every completed change must include at least one verification command and a written explanation of what it proves.

Use this verification ladder, choosing the strongest applicable level:

* `cargo fmt --check`
* `cargo clippy --all-targets --all-features -- -D warnings`
* `cargo test --all-targets --all-features`
* focused unit tests for policy, parsing, audit, attribution, and config behavior
* property tests for deterministic policy decisions and boundary normalization
* fuzz targets for packet-facing, proxy-facing, DNS, TLS ClientHello, and QUIC metadata parsers when those surfaces exist
* integration tests for Linux/TUN/network-namespace behavior when code touches those paths
* runtime smoke commands for sandbox-visible network behavior when relevant

If a stronger verification layer is not possible yet, record why in `progress.md` and add the closest executable check.

## Correctness Enforcement

Use Rust as an active correctness tool:

* Prefer typed states and enums over booleans for protocol, decision, attribution, and lifecycle state.
* Keep error variants explicit and auditable.
* Make unsupported behavior impossible to ignore: return typed denial/failure outcomes rather than silent `None` where security is involved.
* Forbid unsafe code in core, policy, audit, config, and event modules.
* Confine any required unsafe or platform-specific code to the smallest integration modules with comments explaining invariants.
* Make fail-closed behavior the default for malformed, unsupported, unattributed, or policy-sensitive cases.

## Code Quality Standards

* Keep modules small and named around architecture boundaries from `docs/initial-impl.md`.
* Do not let TUN, bwrap, Linux fd, parser crate, or `smoltcp` types leak into policy decisions.
* Do not duplicate policy logic across transparent and proxy paths.
* Prefer explicit validation over permissive parsing.
* Prefer deterministic tests over timing-sensitive tests. If timing is required, isolate it and document tolerances.
* Maintain structured errors and audit records instead of ad-hoc log strings for decision-relevant events.

## Progress Ledger Rules

`progress.md` is append-only. Never rewrite or delete earlier entries.

Each meaningful entry should include:

* timestamp
* current objective
* files changed or expected to change
* verification commands run
* observed result
* commit hash when committed
* remaining risks
* exact next step

## Learning Ledger Rules

`learnings.md` is append-only. Keep entries short and reflective.

Append when:

* a previous assumption was wrong
* an integration path is harder or easier than expected
* a dependency has an important limitation
* a test reveals a missing invariant
* the implementation strategy changes
* a reusable workflow should become a skill or steering instruction

## Commit Discipline

Commit after meaningful verified changes only.

A commit is meaningful when it has:

* a coherent purpose
* passing relevant verification
* updated `progress.md`
* updated `learnings.md` if a learning occurred
* no unrelated formatting or opportunistic churn

Use concise commit messages that name the verified behavior or invariant.

## Autonomy Rules

Continue without asking for permission when the next step is consistent with `docs/arch.md`, `docs/initial-impl.md`, and the current verified state.

Autonomy means proceed by default. Pause only for decisions that are scope-changing, security-sensitive, hard to reverse, or explicitly outside the source docs. For ordinary implementation choices, choose the safest documented option, record the assumption in `progress.md`, and continue.
