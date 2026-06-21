# Implementation Approach: Autonomous Crew

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`
* `docs/bubblewrap-fork.md` when setup-helper or bwrap-hook assumptions are relevant

Use these documents as the operating charter for architecture, Rust implementation boundaries, and backend responsibilities.

## Core Directive

Run the work as a self-managing crew: one active implementation thread, periodic specialized review, append-only historical records, and regular verified commits. Optimize for hands-off progress that can survive long sessions, interruptions, and handoff to another agent.

## Operating Protocol

1. At session start, read source docs, steering files, `progress.md`, `learnings.md`, and current git status.
2. Create `progress.md` and `learnings.md` if missing.
3. Append a session-start entry with current state, active objective, verification plan, and expected commit boundary.
4. Maintain one writer at a time. Do not allow multiple agents to edit the same worktree concurrently.
5. Use subagents for read-only research, planning, architecture review, security review, networking review, and test review when available.
6. Convert review findings into a small accepted fix list before editing.
7. Implement accepted changes in the single writer thread.
8. Verify locally.
9. Append results, review outcomes, and next action to `progress.md`.
10. Append important approach changes to `learnings.md`.
11. Commit meaningful verified changes.
12. Continue with the next accepted objective.

## Subagent Use

Use subagents as specialists, not as uncontrolled parallel writers.

Recommended read-only review roles:

* architecture boundary reviewer
* Rust correctness reviewer
* fail-closed/security reviewer
* networking/TUN/protocol reviewer
* verification/test reviewer
* documentation/steering reviewer

Reviewer instructions should require concrete findings with file paths, line references where possible, severity, and minimal fix suggestions. Ignore broad speculation unless it identifies a verifiable risk.

Only delegate editing when the delegated worker is the sole writer and receives explicit acceptance criteria and verification commands.

## Verification Requirements

Each accepted change must pass:

* focused tests for touched behavior
* formatting checks for touched Rust code
* clippy with denied warnings when feasible
* broader cargo tests before meaningful commits when runtime permits
* additional integration, harness, fuzz, or property checks when the changed surface requires them

After reviewer rounds, run verification again before committing.

## Correctness Enforcement

* Use Rust type boundaries to encode architectural and security assumptions.
* Keep policy, audit, config, and event logic unsafe-free.
* Keep integration-specific details out of core logic.
* Require structured errors and denial reasons for reviewable behavior.
* Treat warnings, flaky tests, and unexplained logs as crew-visible blockers until resolved or recorded.

## Code Quality Standards

* Small coherent patches.
* One purpose per commit.
* Review findings resolved by smallest safe fix.
* No speculative rewrites during a fix pass.
* No concurrent worktree edits.
* No hidden state outside `progress.md`, `learnings.md`, git status, and committed code.

## Progress Ledger Rules

`progress.md` must enable another agent to resume without conversation context. Include:

* timestamp
* current objective
* subagents/reviews requested and summary of findings
* accepted and rejected findings with reasons
* commands run and outcomes
* files changed
* current git status summary
* commit hash after commit
* next exact action

## Learning Ledger Rules

`learnings.md` should capture reusable crew-level improvements:

* review role that found important issues
* review role that produced noise and should be refined
* better verification sequence
* subagent prompt pattern that worked
* coordination failure to avoid
* architecture or dependency insight

## Commit Discipline

Commit after coherent verified changes and after progress history is updated. If a review round causes follow-up fixes, include those fixes in the same commit only when they are part of the same coherent purpose; otherwise commit separately.

## Autonomy Rules

Keep the crew moving without user input. Use reviews to reduce risk, not to stall. Pause only if reviewers identify a scope conflict with source docs, a security exception requiring approval, or an architecture decision that cannot be resolved from the documented design.
