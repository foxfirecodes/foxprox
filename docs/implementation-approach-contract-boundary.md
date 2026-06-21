# Implementation Approach: Contract Boundary Discipline

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`

Treat the documented architecture boundaries as contracts. The implementation must preserve frontend independence, shared policy/audit/egress behavior, backend isolation, and future TAP compatibility.

## Core Directive

Use compile-time contracts to prevent architecture drift. The agent should define narrow interfaces, enforce dependency direction, verify boundary behavior with tests, and only then deepen implementation behind those interfaces.

This approach prioritizes maintainability, replaceability, and long-running autonomous safety.

## Operating Protocol

1. Read source docs and existing append-only ledgers.
2. Create `progress.md` and `learnings.md` if missing.
3. Append current boundary objective and dependency-risk assessment to `progress.md`.
4. Identify the architecture boundary being changed.
5. Define or refine the smallest public contract for that boundary.
6. Add tests, compile checks, or mock implementations that prove the contract.
7. Implement behind the contract without leaking external dependency types.
8. Run verification.
9. Append results and any boundary learning.
10. Commit after the boundary change is coherent and verified.

## Boundary Rules

Enforce these rules continuously:

* Policy code consumes normalized events, never raw packets, frontend-specific structs, Linux fd types, bwrap details, or external parser/stack types.
* Audit code records normalized event and decision data, not ad-hoc frontend internals.
* Egress code is shared by transparent and explicit proxy paths.
* TUN, future TAP, HTTP proxy, and SOCKS frontends are replaceable producers of normalized events.
* Network stack choices remain behind an adapter.
* Integration backends own launcher and namespace details; broker core remains backend-independent.
* Parser crates may influence local adapter code but must not define core policy data models.

## Verification Requirements

Use verification that proves boundaries cannot be accidentally violated:

* `cargo check` across the workspace
* `cargo clippy --all-targets --all-features -- -D warnings`
* dependency-direction checks using crate layout, feature flags, or compile tests where available
* tests with mock frontends and mock egress backends
* tests proving policy decisions do not require frontend-specific data
* snapshot or schema tests for normalized events and audit records
* focused denial-path tests for unsupported normalized events

When a dependency boundary is intentionally changed, record why in `learnings.md`.

## Correctness Enforcement

* Prefer small crates/modules with explicit public APIs.
* Keep public structs minimal and semantically named.
* Use private fields and constructors when invariants matter.
* Encode hostname attribution source and confidence in types.
* Encode policy decisions as exhaustive enums.
* Avoid stringly typed protocol, frontend, and decision values.
* Make config validation produce typed, normalized runtime configuration.

## Code Quality Standards

* Do not add “temporary” cross-layer imports.
* Do not duplicate normalized event definitions.
* Do not allow convenience shortcuts that tie policy to a current frontend.
* Use mocks for contract tests, not production-specific hacks.
* Keep documentation comments on contracts that are security-sensitive or future-extension-sensitive.

## Progress Ledger Rules

`progress.md` must include:

* the boundary under work
* allowed dependency direction
* verification commands
* observed results
* changed files
* commit hash after commit
* remaining boundary risks

## Learning Ledger Rules

Append to `learnings.md` when:

* a boundary was too wide or too narrow
* a dependency tried to leak across layers
* a mock revealed missing semantics
* a contract changed to preserve future TAP/proxy/backend support
* a crate layout or feature gate decision becomes important

## Commit Discipline

Commit once the boundary contract and its verification are coherent. Keep commits small enough that reviewers can see which architecture rule is being enforced.

A boundary commit should not mix unrelated feature expansion with contract reshaping unless the feature is necessary to prove the contract.

## Autonomy Rules

Continue autonomously by selecting the most fragile or security-important boundary next. Prefer enforcing architecture with code over documenting intent. Pause only if a requested shortcut would violate the source architecture or permanently collapse replaceable components into one layer.
