# Implementation Approaches

These approaches are intended for autonomous implementation of the Rust transparent network broker described in `docs/arch.md` and `docs/initial-impl.md`. Approaches that touch bwrap-compatible setup should also follow `docs/bubblewrap-fork.md`.

All approaches share these strict requirements:

* explicit verification steps
* hands-off autonomous operation
* Rust correctness enforcement
* append-only `progress.md`
* append-only `learnings.md`
* regular commits after meaningful verified changes only

## Ranking Summary

| Rank | Approach | Confidence | Best Use |
| --- | --- | --- | --- |
| 1 | Verification Kernel | High | Security-sensitive Rust correctness and fail-closed behavior |
| 2 | Harness Lab | Medium-High | Real networking feedback and reproducible autonomous validation |
| 3 | Contract Boundary Discipline | Medium-High | Preventing architecture drift across long sessions |
| 4 | Vertical Evidence Slice | Medium-High | Fast discovery of integration risks with narrow working proofs |
| 5 | Security Invariants | Medium | Conservative safety-first implementation |
| 6 | Autonomous Crew | Medium | Long-running implementation with subagent review loops |
| 7 | Observability Ledger | Medium | Auditability, debugging, and externally visible behavior |

## 1. Verification Kernel

**File:** `docs/implementation-approach-verification-kernel.md`

**Concise summary:** Build from a small always-correct core outward. Every change must be verified, recorded, and committed as a coherent unit.

**Hypothesis and rationale:** Rust correctness gates, typed states, fail-closed defaults, and rigorous verification will produce the highest-quality implementation for a security-sensitive network broker. This should reduce subtle policy, parser, and audit bugs.

**High-level parameters:**

* verification-first workflow
* strict Rust typing and explicit error/decision enums
* unsafe forbidden outside tiny integration modules
* append-only evidence in `progress.md`
* short strategy learnings in `learnings.md`
* commits only after coherent verified changes

**Confidence/ranking:** High; ranked #1. Strong fit for this project because correctness and fail-closed behavior matter more than raw implementation speed.

## 2. Harness Lab

**File:** `docs/implementation-approach-harness-lab.md`

**Concise summary:** Build a reproducible local verification lab with commands, fixtures, smoke checks, and structured output before expanding behavior.

**Hypothesis and rationale:** Network code often fails at runtime despite compiling cleanly. A reusable harness gives autonomous agents fast feedback and makes environment, namespace, TUN, and audit failures observable.

**High-level parameters:**

* command-driven verification
* reusable fixtures and smoke checks
* structured audit/log capture
* environment-dependent checks clearly marked
* failed attempts preserved in `progress.md`
* harness limitations captured in `learnings.md`

**Confidence/ranking:** Medium-High; ranked #2. Very likely to improve practical implementation quality, though setup complexity may slow early progress.

## 3. Contract Boundary Discipline

**File:** `docs/implementation-approach-contract-boundary.md`

**Concise summary:** Use compile-time contracts and crate/module boundaries to preserve frontend, policy, audit, egress, network-stack, and backend separation.

**Hypothesis and rationale:** Long autonomous sessions tend to introduce convenience leaks. Enforcing boundaries in code will preserve the architecture described in the docs and keep future TAP/proxy/backend work additive.

**High-level parameters:**

* normalized event contracts
* dependency-direction enforcement
* mock frontend/egress tests
* no external stack/parser/frontend types in policy core
* boundary changes recorded in `learnings.md`
* commits scoped to one coherent contract change

**Confidence/ranking:** Medium-High; ranked #3. Strong protection against architecture drift, with moderate risk of over-abstracting before enough runtime evidence exists.

## 4. Vertical Evidence Slice

**File:** `docs/implementation-approach-vertical-evidence.md`

**Concise summary:** Always select the smallest end-to-end slice that proves real behavior across an architectural boundary.

**Hypothesis and rationale:** Narrow working slices reveal incorrect assumptions earlier than broad scaffolding. This should improve implementation speed while still requiring verification and clean commit discipline.

**High-level parameters:**

* small vertical slices
* runtime or test evidence for each slice
* immediate refactoring of abstraction leaks
* no broad unused scaffolding
* `progress.md` as evidence ledger
* `learnings.md` for assumption changes

**Confidence/ranking:** Medium-High; ranked #4. Good for discovery and momentum, but requires discipline to prevent early proof code from becoming permanent shortcuts.

## 5. Security Invariants

**File:** `docs/implementation-approach-security-invariants.md`

**Concise summary:** Treat deny-by-default, fail-closed, attribution, DNS-bypass prevention, audit, and bounded-resource behavior as executable invariants.

**Hypothesis and rationale:** A broker that mediates sandbox networking should be shaped by security properties from the start. This approach should catch bypasses and permissive parser behavior early.

**High-level parameters:**

* invariant-first testing
* positive and negative policy checks
* malformed-input tests
* structured denial reasons
* resource/backpressure verification
* conservative commit policy

**Confidence/ranking:** Medium; ranked #5. High safety value, but may slow visible functionality and can become too conservative if not paired with practical harness evidence.

## 6. Autonomous Crew

**File:** `docs/implementation-approach-autonomous-crew.md`

**Concise summary:** Use one writer thread plus specialized read-only subagent reviews for architecture, Rust correctness, security, networking, and tests.

**Hypothesis and rationale:** Role-separated review can improve quality while preserving hands-off autonomy, especially for long-running work that benefits from fresh context and adversarial review.

**High-level parameters:**

* one writer at a time
* read-only specialized subagents
* accepted/rejected findings recorded
* verification rerun after review fixes
* `progress.md` supports handoff and restart
* commits after reviewed, verified changes

**Confidence/ranking:** Medium; ranked #6. Promising for quality, but effectiveness depends on subagent discipline and avoiding review noise or uncontrolled parallel edits.

## 7. Observability Ledger

**File:** `docs/implementation-approach-observability-ledger.md`

**Concise summary:** Make every meaningful behavior externally visible through structured audit output, tests, logs, and append-only progress evidence.

**Hypothesis and rationale:** Autonomous agents need strong feedback. If broker behavior is observable and audit records are structured, debugging, review, and policy validation become much easier.

**High-level parameters:**

* audit-first completion criteria
* structured event assertions
* denial/error visibility
* slow-sink/backpressure tests
* evidence excerpts in `progress.md`
* observability learnings in `learnings.md`

**Confidence/ranking:** Medium; ranked #7. Excellent for debugging and audit quality, but can overemphasize logging infrastructure if not balanced with functional progress.
