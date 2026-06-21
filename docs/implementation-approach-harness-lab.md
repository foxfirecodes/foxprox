# Implementation Approach: Harness Lab

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`
* `docs/bubblewrap-fork.md` when work touches bwrap-compatible setup or future bwrap-hook assumptions

Use these documents to align the test harness with the intended sandbox, TUN, broker, and backend model.

## Core Directive

Build a reproducible verification lab around the broker. Every meaningful behavior should be demonstrable by a local command, fixture, or harness test. The harness is part of the product quality strategy, not disposable debugging code.

This approach prioritizes autonomous feedback loops and reduces the risk of code that compiles but fails in real network-namespace conditions.

## Operating Protocol

1. Read source docs and append-only history files.
2. Create `progress.md` and `learnings.md` if missing.
3. Append current harness capability, known gaps, and intended verification target to `progress.md`.
4. Before implementing behavior, define how the harness will observe it.
5. Add or update the smallest reusable harness command, fixture, or test helper needed.
6. Implement the behavior.
7. Run the harness and capture output.
8. Append exact command, result, logs, and interpretation to `progress.md`.
9. Append discoveries or harness limitations to `learnings.md`.
10. Commit harness and behavior together when both are meaningful and verified.

## Harness Design Rules

* Prefer deterministic commands with clear pass/fail output.
* Keep privileged, Linux-specific, and namespace-sensitive setup isolated and documented.
* Make harness failures actionable: include logs, exit codes, and likely cause.
* Capture structured audit output where relevant.
* Keep fixtures small and named by behavior.
* Make it easy to run focused checks before full workspace checks.
* Avoid relying on external network services when a local fixture can prove the behavior.
* When external network behavior is unavoidable, mark the test as environment-dependent and provide a local fallback where possible.

## Verification Requirements

The verification lab should support a mix of:

* unit tests for pure Rust logic
* fixture tests for parsers and normalized events
* mock-backend tests for policy/audit/egress boundaries
* namespace/TUN smoke checks for Linux integration
* CLI or script checks for sandbox-visible behavior
* structured audit output comparisons
* negative-path checks for deny/fail-closed behavior

Every harness addition must itself be verified by running it and recording the result in `progress.md`.

## Correctness Enforcement

Use Rust and harness structure together:

* Model expected outputs with typed structs where possible.
* Compare normalized events and audit records structurally, not with brittle freeform text matching.
* Make fixture parsing fail closed on malformed inputs.
* Keep test helpers honest by asserting both allowed and denied/error outcomes.
* Avoid test-only shortcuts that bypass policy or egress paths unless the test name clearly states the boundary being isolated.

## Code Quality Standards

* Test helpers should be readable and maintainable, not hidden magic.
* Scripts should use strict shell behavior when shell is necessary.
* Prefer Rust integration tests for reusable behavior.
* Keep environment assumptions documented near the harness entry point.
* Do not let harness-only types leak into production APIs.

## Progress Ledger Rules

`progress.md` is the authoritative lab notebook. Include:

* command executed
* environment assumptions
* expected result
* observed result
* relevant output excerpt
* changed files
* interpretation
* next verification gap
* commit hash after commit

Do not remove failed harness attempts. Append a later entry explaining the fix or superseding approach.

## Learning Ledger Rules

Append to `learnings.md` when:

* local environment behavior differs from expectation
* bwrap, TUN, namespace, or capability behavior has an important constraint
* a harness test is flaky and why
* a dependency or system command requires a specific invocation
* a better reusable verification pattern emerges

## Commit Discipline

Commit after a harness-backed behavior works or after a harness exposes a valuable failing test that will guide the next change. In the latter case, the commit message and `progress.md` must clearly state that the failure is intentional evidence, not completed functionality.

## Autonomy Rules

Keep going by turning unknowns into runnable checks. When blocked, reduce the problem to the smallest harness command that distinguishes environment failure, dependency limitation, implementation bug, or architecture mismatch.

Autonomy means proceed by default. Pause only for decisions that are scope-changing, security-sensitive, hard to reverse, or explicitly outside the source docs. For ordinary implementation choices, choose the safest documented option, record the assumption in `progress.md`, and continue.
