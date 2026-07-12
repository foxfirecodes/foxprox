Implement the foxprox production-grade alpha defined by:

- docs/production-alpha-requirements.md
- docs/production-alpha-progress.md
- docs/initial-impl.md
- docs/arch.md
- docs/bubblewrap-fork.md

Read each file completely before modifying source. Follow their precedence rules and treat docs/production-alpha-requirements.md as the execution and acceptance contract.

GOAL

Produce a production-grade alpha with one supported command:

    foxprox run --config /path/to/config.toml -- target args...

It must perform bwrap/TUN setup, policy loading, readiness, capability/fd cleanup, target execution, complete traffic mediation and auditing, shutdown, and resource cleanup.

Default-deny allow/deny policy must work across:

- IP/CIDR/port
- TCP and UDP
- broker and external DNS
- domain/hostname attribution
- transparent HTTP Host/method/path
- transparent TLS SNI/DNS/mismatch/missing-SNI/ECH visibility
- QUIC candidates
- ICMP
- HTTP proxy
- HTTPS CONNECT
- SOCKS5 TCP CONNECT

RUNTIME LINEAGE

The active candidate must descend solely from:

    .tmp/worktrees/autonomous-crew

The seven preserved worktrees are read-only reference sources:

- .tmp/worktrees/autonomous-crew
- .tmp/worktrees/observability-ledger
- .tmp/worktrees/contract-boundary
- .tmp/worktrees/security-invariants
- .tmp/worktrees/harness-lab
- .tmp/worktrees/verification-kernel
- .tmp/worktrees/vertical-evidence

Do not wholesale merge another worktree, perform an octopus merge, or replace the candidate with another crate graph.

IMPORT STRATEGY

Import portable verification assets before major runtime restructuring:

1. From observability-ledger:
   - privileged bwrap/TUN integration cases
   - fd-handoff and capability-drop checks
   - TCP/UDP/DNS combined-session tests
   - HTTP/CONNECT/SOCKS byte-relay and audit assertions

2. From contract-boundary:
   - real fuzz targets
   - dependency-boundary checks

3. From security-invariants:
   - pure policy/parser tests
   - default-deny and direct-DNS invariants
   - attribution, malformed-input, hidden-SNI/ECH, audit-before-egress, and resource-bound tests

4. From harness-lab:
   - selected deterministic negative scenarios
   - correct their exit-status checks
   - do not retain CAP_NET_RAW by default

5. Use verification-kernel only for a concrete typed-state or verification gap.

6. Use vertical-evidence only for selected config/test fixtures. Do not import its TLS/runtime implementation.

For each import, record source worktree, commit, paths, purpose, candidate paths, and validation in docs/production-alpha-progress.md.

EXECUTION ORDER

Work through the phases in docs/production-alpha-requirements.md:

Phase 0:
- Establish and verify the candidate baseline.
- Record commit, Rust/kernel/bwrap/userns/TUN environment.
- Run baseline format, clippy, tests, docs, and live smoke.
- Build the requirement-to-test matrix.

Phase 1:
- Port the low-coupling verification assets above.
- Adapt branch-specific assumptions to the canonical candidate interfaces.

Phase 2:
- Enforce broker-DNS policy.
- Remove implicit authorization from transparent listener ports.
- Separate listener, inspection, and policy configuration.
- Integrate ICMP into foxprox run.
- Version and strictly validate config.
- Fix persistent/incremental HTTP and TLS inspection, including truncation bypasses.
- Add privileged positive and negative policy matrices.

Phase 3:
- Replace one-socket-per-port handling with dynamic keyed TCP flows.
- Support concurrent same-port connections and persistent full-duplex host sockets.
- Implement correct FIN/RST/half-close/backpressure/timeout/cleanup.
- Implement keyed UDP pseudo-flows supporting one-way and multiple-response traffic.
- Use monotonic configured timeouts and enforce all resource bounds.
- Ensure proxy parser/tunnel state is isolated per flow/session.

Phase 4:
- Continuously drain bounded, versioned audit output.
- Define and test audit-sink outage behavior.
- Add correlation/policy identity, metrics, and readiness.
- Implement signal handling, broker/target containment, authenticated setup, rollback, and deterministic cleanup.

Phase 5:
- Complete fuzz, property, privileged integration, failure-injection, concurrency, load, soak, dependency, license, vulnerability, unsafe-code, compatibility, and operational documentation gates.
- Obtain independent review against every requirement.

WORKING RULES

- Maintain one writer thread for the candidate.
- You may use read-only reviewers or isolated research helpers.
- Work autonomously on routine, reversible implementation details.
- Escalate only for:
  - scope changes
  - security-sensitive or hard-to-reverse choices
  - conflicts with the normative docs
  - new dependencies or trust boundaries
  - materially different architecture
- Never weaken default-deny or fail-closed behavior to make a test pass.
- Host egress must occur only after an allow decision and committed audit evidence.
- Listener configuration must never authorize traffic.
- A verified commit is a checkpoint, not completion. Continue to the next highest-value unmet requirement.
- Do not stop after planning, baseline verification, importing tests, or one successful commit.
- Avoid churn-only work: each checkpoint must close a requirement, expose a missing requirement with evidence, or remove a demonstrated defect.
- Preserve unrelated documentation and all reference worktrees.

PROGRESS

Update docs/production-alpha-progress.md after each meaningful checkpoint using its template.

Record:

- candidate commits
- requirements addressed
- import provenance
- behavior and tests changed
- exact commands and results
- privileged environment and artifacts
- resource measurements
- reviewer findings
- failures and learnings
- remaining blockers
- next highest-value requirement

Do not mark a requirement complete based solely on preserved worktree code, prose claims, or unit tests when privileged/concurrency/fuzz/load evidence applies.

VALIDATION

At applicable checkpoints run focused tests. At phase exits run at least:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-targets --all-features
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
    cargo check --manifest-path fuzz/Cargo.toml --bins

Run real privileged bwrap/user/net namespace tests with /dev/net/tun whenever required. A skipped privileged test is not a pass.

Retain exact commands, exit codes, pass/skip counts, environment versions, audit artifacts, and resource measurements.

DEFINITION OF DONE

Do not report completion until:

- the supported command performs setup through cleanup;
- every required protocol/frontend enforces and audits default-deny policy;
- concurrent and long-lived traffic is correctly isolated and bounded;
- every required checkbox in docs/production-alpha-requirements.md has retained executable evidence;
- format, clippy, tests, docs, fuzz, property, privileged integration, failure injection, concurrency, load, soak, and security gates pass;
- installation, configuration, policy, audit, compatibility, operations, security boundaries, and visibility limits are documented;
- an independent reviewer finds no production-alpha blocker or critical/high security defect;
- every remaining omission is an explicitly approved non-goal.

Begin by verifying the candidate lineage and completing Phase 0. Then continue through the phases without waiting for routine approval.
