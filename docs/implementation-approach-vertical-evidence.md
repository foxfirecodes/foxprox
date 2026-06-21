# Implementation Approach: Vertical Evidence Slice

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`

Use these documents for architectural scope, Rust stack expectations, frontend/backend separation, and security posture.

## Core Directive

Always prefer the next narrow end-to-end evidence slice over broad speculative scaffolding. A slice is complete only when it demonstrates observable behavior across the relevant boundary, records verification evidence, updates append-only history, and lands as a meaningful commit.

This approach values working proof, real feedback, and rapid discovery of incorrect assumptions while still enforcing Rust correctness and architecture boundaries.

## Operating Protocol

1. Read the source context and existing history files at session start.
2. Create `progress.md` and `learnings.md` if missing.
3. Append a session-start entry to `progress.md` with the selected evidence slice and verification plan.
4. Choose the smallest vertical slice that crosses at least one real architectural boundary.
5. Implement the minimum production-quality code needed for that slice.
6. Remove or quarantine temporary scaffolding before commit unless it is an intentional test harness.
7. Verify the slice with compile checks, tests, and runtime evidence where applicable.
8. Append evidence and remaining gaps to `progress.md`.
9. Append approach changes or technical discoveries to `learnings.md`.
10. Commit the verified slice.
11. Select the next slice based on the largest unresolved integration risk.

## Slice Selection Rules

Prefer slices that expose real behavior through:

* frontend-to-core boundaries
* core-to-policy boundaries
* policy-to-audit boundaries
* frontend-to-egress boundaries
* integration-backend boundaries
* parser-to-normalized-event boundaries
* runtime setup-to-broker boundaries

Do not choose a slice that only creates unused abstractions unless the abstraction itself is verified by compile-time or test evidence.

## Verification Requirements

Every slice must prove something concrete.

Acceptable evidence includes:

* a passing focused test that fails before the change
* a compile-time boundary check
* a runtime command with captured output
* a structured audit event assertion
* a packet, request, DNS, policy, or parser fixture test
* an integration harness result
* a before/after failure showing the slice removes a real blocker

Always run:

* formatting checks for touched Rust code
* clippy with denied warnings when feasible
* the focused test suite for the changed boundary
* broader cargo tests before committing when runtime permits

Record exact commands and outcomes in `progress.md`.

## Correctness Enforcement

Use Rust types to make the slice hard to misuse:

* encode boundary inputs and outputs as explicit types
* avoid passing raw buffers or dependency-specific objects beyond the owning adapter
* use `Result` with meaningful errors for all fallible parsing, IO, policy, and config work
* represent allow/deny/fail-closed outcomes explicitly
* include tests for both success and denial/error paths

## Code Quality Standards

* Keep the slice thin but production-shaped.
* Avoid knowingly temporary architecture unless it is isolated in tests or harness code.
* Refactor immediately when a slice reveals an abstraction leak.
* Keep policy logic centralized.
* Keep bwrap and Linux-specific details outside broker core.
* Keep audit output structured enough to verify behavior externally.

## Progress Ledger Rules

`progress.md` is an append-only evidence ledger. Each entry should answer:

* What slice was attempted?
* Why was it the next highest-value slice?
* What changed?
* How was it verified?
* What failed or surprised the agent?
* What remains unproven?
* What commit recorded it?

## Learning Ledger Rules

`learnings.md` is an append-only strategy ledger. Add short entries when:

* a slice invalidates an assumption
* a boundary needs to move
* a dependency behaves unexpectedly
* a simpler route is discovered
* verification exposes a missing invariant

## Commit Discipline

Commit after each meaningful verified slice. A good commit should correspond to one evidence statement, such as “this boundary now accepts normalized events and emits auditable decisions” or “this parser path now fails closed on malformed input.”

Do not batch unrelated slices into one commit. Do not commit failing checks unless the commit intentionally documents a harness or test exposing an existing failure, and explain that in `progress.md`.

## Autonomy Rules

The agent should keep moving by choosing the next smallest evidence slice that reduces uncertainty. Prefer direct runtime or test evidence over discussion.

Autonomy means proceed by default. Pause only for decisions that are scope-changing, security-sensitive, hard to reverse, or explicitly outside the source docs. For ordinary implementation choices, choose the safest documented option, record the assumption in `progress.md`, and continue.
