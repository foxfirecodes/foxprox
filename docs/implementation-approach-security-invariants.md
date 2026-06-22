# Implementation Approach: Security Invariants

## Source Context

Before working, read and follow:

* `docs/arch.md`
* `docs/initial-impl.md`

Use these documents as the authority for non-goals, fail-closed behavior, DNS and hostname attribution expectations, frontend separation, audit requirements, and Rust safety rules.

## Core Directive

Treat security invariants as executable requirements. Every behavior must either preserve a known invariant or add a new verified invariant. The agent should bias toward deny-by-default, explicit attribution, auditable decisions, and bounded resource use.

This approach is conservative by design. It is better to delay a feature than to merge behavior with unclear denial, bypass, or audit semantics.

## Operating Protocol

1. Read source docs and append-only ledgers.
2. Create `progress.md` and `learnings.md` if missing.
3. Append the active security invariant and planned verification to `progress.md`.
4. Write or update the invariant test before or alongside implementation.
5. Implement the smallest change that satisfies the invariant.
6. Verify success and relevant failure cases.
7. Append results, denials observed, and any residual risk to `progress.md`.
8. Append security-relevant discoveries to `learnings.md`.
9. Commit only after invariant verification passes.
10. Continue with the highest-risk unverified invariant.

## Required Invariant Categories

Continuously preserve these categories:

* deny-by-default policy behavior
* fail-closed handling for malformed and unsupported inputs
* direct DNS bypass prevention according to documented policy
* explicit hostname attribution confidence for domain-based decisions
* mismatch handling for conflicting attribution sources
* multicast, broadcast, unusual ICMP, and unsupported protocol denial unless explicitly configured otherwise
* no direct host-network bypass around broker-controlled egress
* no TLS MITM or custom CA behavior
* audit record emission for allow, deny, fail-closed, lifecycle, and error decisions
* bounded memory behavior under slow audit sinks or hostile traffic
* no unsafe code in policy, audit, config, or event logic

## Verification Requirements

For each invariant, include positive and negative checks where possible:

* unit tests for pure policy and config decisions
* property tests for rule ordering, defaults, and deterministic outcomes
* malformed fixture tests for packet, proxy, DNS, TLS, and QUIC metadata parsing surfaces as they appear
* audit snapshot/schema tests for denied and failed paths
* resource/backpressure tests for queues and buffers
* integration checks for bypass-sensitive behavior where environment permits
* `cargo clippy --all-targets --all-features -- -D warnings`
* full test suite before committing security-sensitive changes

Record exact commands and outputs in `progress.md`.

## Correctness Enforcement

* Represent policy outcomes with exhaustive enums.
* Represent attribution source and confidence explicitly.
* Make denial reasons structured and testable.
* Normalize configuration before use.
* Reject invalid config early.
* Avoid permissive parser fallbacks for policy-sensitive metadata.
* Use bounded queues and explicit backpressure strategies.
* Keep unsafe code forbidden in security-critical modules.

## Code Quality Standards

* Security-sensitive code should be simple, explicit, and boring.
* Avoid clever abstractions that obscure allow/deny logic.
* Keep denial tests near the behavior they protect.
* Prefer table-driven tests for policy matrices.
* Document why an allow path is safe when the default would otherwise deny.
* Do not silence warnings in security-relevant code.

## Progress Ledger Rules

`progress.md` must record:

* invariant under work
* threat or failure mode addressed
* tests or commands run
* observed allow/deny/fail-closed behavior
* audit evidence when relevant
* residual risk
* commit hash after commit

## Learning Ledger Rules

Append to `learnings.md` when:

* a bypass risk is discovered
* a denial behavior changes
* a parser or dependency is less strict than expected
* an audit event is missing information needed for security review
* a resource-limit assumption changes

## Commit Discipline

Commit only verified invariant-preserving changes. Avoid bundling unrelated functionality into security commits. Commit messages should name the invariant or denial behavior protected.

## Autonomy Rules

Continue autonomously by selecting the most severe unverified invariant, especially those related to bypass, malformed input, attribution, and resource exhaustion.

Autonomy means proceed by default. Pause only for decisions that are scope-changing, security-sensitive, hard to reverse, or explicitly outside the source docs. For ordinary implementation choices, choose the safest documented option, record the assumption in `progress.md`, and continue.


A verified commit is a checkpoint, not a completion signal. After each meaningful commit, continue by selecting the next highest-value documented implementation or verification gap from `progress.md`, `learnings.md`, or the source docs.

Do not continue by making ledger-only, cosmetic, or speculative changes. Each loop must advance product code, tests, harnesses, verification coverage, or an explicitly required architecture boundary.

Stop only when one of these is true:

* the documented success criteria are complete;
* the next step requires a scope-changing, security-sensitive, hard-to-reverse, or outside-docs decision;
* verification is impossible after reducing the issue to a minimal repro;
* two consecutive work cycles produce no meaningful product or verification progress;
