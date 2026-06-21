# Implementation Approach: Observability Ledger

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`

Use these documents for audit event expectations, policy decision data, frontend source attribution, flow lifecycle requirements, and backpressure constraints.

## Core Directive

Make behavior externally visible before considering it complete. Every meaningful code path must produce inspectable verification evidence through tests, structured audit output, metrics/traces where appropriate, and append-only historical ledgers.

This approach treats observability as a correctness mechanism for autonomous implementation.

## Operating Protocol

1. Read source docs and append-only ledgers.
2. Create `progress.md` and `learnings.md` if missing.
3. Append the target observable behavior and expected evidence to `progress.md`.
4. Define the audit, trace, metric, test assertion, or harness output that will prove behavior.
5. Implement behavior and its observability together.
6. Verify that observable output is present, structured, and bounded.
7. Append command results and evidence excerpts to `progress.md`.
8. Append learning entries when observability exposes hidden complexity or changes the approach.
9. Commit once behavior and evidence are coherent.
10. Continue with the least observable high-risk path.

## Observability Rules

* Audit records must be structured, not freeform-only.
* Decision-relevant events must include enough context to explain allow, deny, and fail-closed outcomes.
* Frontend source and attribution source should be visible where relevant.
* Error paths should be observable without requiring a debugger.
* Slow sinks must not create unbounded memory growth.
* Test assertions should check structured fields, not just log existence.
* Progress entries should cite evidence from commands or tests, not vague claims.

## Verification Requirements

Use verification that proves both behavior and visibility:

* snapshot/schema tests for audit records
* tests for denied and malformed paths producing audit evidence
* flow lifecycle event assertions where flow state exists
* slow-sink or bounded-buffer tests for audit backpressure
* focused parser/policy tests that assert denial reasons
* runtime harness checks that capture logs or audit output
* `cargo fmt --check`
* `cargo clippy --all-targets --all-features -- -D warnings`
* `cargo test --all-targets --all-features` when feasible before commit

## Correctness Enforcement

* Represent audit event kinds, decisions, protocols, frontends, and attribution as enums.
* Include structured denial reasons.
* Avoid unbounded channels for audit-critical paths.
* Use typed counters and durations where possible.
* Ensure audit serialization is tested.
* Ensure sensitive or overly noisy data is intentionally handled according to documented audit needs.

## Code Quality Standards

* Observability should not dominate business logic.
* Keep event construction close enough to behavior to avoid missing context.
* Keep sinks replaceable.
* Avoid hidden global state.
* Make logs useful for an autonomous agent reading `progress.md` later.
* Prefer concise event names and stable schemas.

## Progress Ledger Rules

`progress.md` is the human-readable companion to machine-readable audit output. Include:

* behavior under work
* evidence expected
* commands run
* audit/log/test excerpts
* interpretation of evidence
* changed files
* remaining blind spots
* commit hash after commit

## Learning Ledger Rules

Append to `learnings.md` when:

* a code path lacked enough evidence to debug
* an audit schema needed new fields
* a test exposed missing context
* backpressure behavior was misunderstood
* event noise required a better filtering strategy
* progress entry format needs improvement

## Commit Discipline

Commit only when behavior and observability land together, unless a commit intentionally introduces reusable observability infrastructure. Commit messages should mention the observable behavior or evidence path.

## Autonomy Rules

Keep working by finding high-risk code paths that are not yet observable. Improve visibility first, then behavior.

Autonomy means proceed by default. Pause only for decisions that are scope-changing, security-sensitive, hard to reverse, or explicitly outside the source docs. For ordinary implementation choices, choose the safest documented option, record the assumption in `progress.md`, and continue.


A verified commit is a checkpoint, not a completion signal. After each meaningful commit, continue by selecting the next highest-value documented implementation or verification gap from `progress.md`, `learnings.md`, or the source docs.

Do not continue by making ledger-only, cosmetic, or speculative changes. Each loop must advance product code, tests, harnesses, verification coverage, or an explicitly required architecture boundary.

Stop only when one of these is true:

* the documented success criteria are complete;
* the next step requires a scope-changing, security-sensitive, hard-to-reverse, or outside-docs decision;
* verification is impossible after reducing the issue to a minimal repro;
* two consecutive work cycles produce no meaningful product or verification progress;
* an explicit runtime or turn budget is reached.
