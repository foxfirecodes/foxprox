# Session Approach Research Synthesis

This document synthesizes targeted session audits for the seven foxprox implementation worktrees. The goal is to understand how each implementation approach affected autonomy, intervention burden, iteration count, product-completion behavior, and spec/prompt lessons.

Source audits:

* `docs/session-audits/verification-kernel.md`
* `docs/session-audits/vertical-evidence.md`
* `docs/session-audits/contract-boundary.md`
* `docs/session-audits/harness-lab.md`
* `docs/session-audits/security-invariants.md`
* `docs/session-audits/autonomous-crew.md`
* `docs/session-audits/observability-ledger.md`
* Strategy used by subagents: `subagent-session-audit-strategy.md`

## Methodology and Caveats

The session audits intentionally did not read every token from every JSONL file. They used a targeted strategy:

* inventory session files, sizes, artifacts, git history, and worktree status;
* read `progress.md` and `learnings.md` first;
* extract user messages from JSONL and classify them by intervention level;
* extract tool errors, final digests, stop/final-answer patterns, and selected reviewer artifacts;
* map completion milestones to git commits and progress ledger evidence.

Intervention levels:

* **L1:** simple continuation / “keep working”.
* **L2:** directional approval, prioritization, or status steering.
* **L3:** corrective scope/autonomy intervention.
* **L4:** debug/product blocker, pasted failing command, or concrete production usability failure.

Counts are good enough for research comparison, not exact behavioral telemetry. Some sessions contain duplicated restart prompts or delegated subagent prompts, which audits excluded where identifiable.

## Headline Findings

### 1. Every approach reached production-launcher completion extremely late

Across all worktrees, “full production launcher end-to-end” arrived in the final few commits:

| Worktree | Commits after `main` | First credible production launcher | Final usable/full launcher point | Interpretation |
| --- | ---: | --- | --- | --- |
| `verification-kernel` | 120 | commit 117 `4ed919a` for `foxprox run`; commit 119 `a87921c` for real `curl example.com` | commit 120 `aebbe2f` for stderr audit/fail-fast UX | Product launcher came after kernel/runtime proofs. |
| `vertical-evidence` | 99 | commit 94 `2e1e007` for `bwrap-run` | commit 99 `89c5bf6` after stdout/audit/HTTPS/GitHub/policy fixes | First launcher was not fully usable until final commit. |
| `contract-boundary` | 205 | commit 194 `ee8dc28` initial launcher | commit 204 `8c7c585` / 205 ledger after HTTP/HTTPS/GitHub/policy fixes | Library was called alpha-complete before launcher worked. |
| `harness-lab` | 81 | commit 77 `dc69f5c` usable bwrap sandbox prototype | commit 81 `4978978` after stdout/CA/backpressure/host allow fixes | Harness proof came before product usability. |
| `security-invariants` | 109 | commit 107 `a340165` usable bwrap alpha launcher | commit 109 `da2264c` transparent real-domain curl | Core security model preceded real-domain launcher. |
| `autonomous-crew` | 51 | commit 49 `36799a5` controlled production launcher | commit 51 `5967248` after CA and denied-proxy UX fixes | Fastest to final launcher, but still late by percentage. |
| `observability-ledger` | 269 | commit `75175c0` plausible combined alpha launcher | commit 269 `4052771` after proxy/UDP/reviewer fixes | Most exhaustive; final completion at branch tip. |

Main lesson: **agents interpreted “alpha implementation” as core architecture/proof completion unless the prompt made a user-runnable production launcher an explicit early acceptance criterion.**

### 2. Human interventions were mostly about autonomy and product reality, not low-level Rust help

The user generally did not need to explain Rust implementation details. The biggest interventions were:

* “continue; do not stop after a commit”;
* “all of `docs/initial-impl.md` means all alpha scope”;
* “test with real rootless bwrap/TUN”;
* “build a real production launcher/wrapper”;
* “curl a real site like `example.com` / `github.com`”;
* pasted failing live command output.

### 3. Real user command output was the highest-value validation signal

User-pasted failures found issues that internal tests missed:

* suppressed target stdout;
* audit emitted after command output or not visibly separated;
* CA trust anchors missing in sandbox;
* `curl -L` redirect / sequential TCP flow issues;
* TLS stream corruption / `bad record mac`;
* default-deny policy footguns around broker DNS;
* denied proxy requests returning origin-like `403` instead of closing;
* direct curl requiring awkward TCP maps instead of transparent domain routing.

### 4. Approach docs improved engineering style but did not define “done” sharply enough

The approaches generated different implementation shapes, but all needed stronger acceptance criteria. The repeated issue was not that agents lacked diligence; it was that they optimized for the approach’s local ideals before product completion:

* verification approaches optimized tests/core correctness;
* vertical approaches optimized slices/evidence;
* contract approaches optimized boundaries;
* harness approaches optimized lab scenarios;
* security approaches optimized invariants;
* observability approaches optimized audit/proof surfaces;
* crew approach optimized reviews and quality loops.

None of those automatically forced “normal user runs one command in bwrap and curls real sites successfully” early.

## Quantitative Comparison

| Worktree | Sessions | Commits | Counted Interventions | L1 | L2 | L3 | L4 | Burden | Burden / Commit | Production Completion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `verification-kernel` | 6 | 120 | 14 | 3 | 3 | 5 | 3 | 39 | 0.33 | commit 119/120; UX at 120/120 |
| `vertical-evidence` | 4 | 99 | 22 | 2 | 5 | 6 | 9 | 75 | 0.76 | commit 94 first; fully usable 99/99 |
| `contract-boundary` | 4 | 205 | 26 | 7 | 7 | 6 | 6 | 69 | 0.34 | initial 194; credible 204/205 |
| `harness-lab` | 5 | 81 | 18 | 3 | 4 | 7 | 4 | 52 | 0.64 | first 77; usable 81/81 |
| `security-invariants` | 6 | 109 | 13 | 3 | 2 | 5 | 3 | 37 | 0.34 | launcher 107; real curl 109/109 |
| `autonomous-crew` | 3 | 51 | 23 | 3 | 8 | 8 | 3 | 70 | 1.37 | launcher 49; fixes 51/51 |
| `observability-ledger` | 3 | 269 | 15 | 2 | 2 | 7 | 4 | 47 | 0.17 | plausible near tail; final 269/269 |

Observations:

* `autonomous-crew` had the fewest commits but high intervention density. It moved fastest, but required concentrated human steering around completion and product semantics.
* `observability-ledger` had the lowest burden per commit but the highest total iteration count. It autonomously did a huge amount of work, but took many proof/review cycles before final production completion.
* `security-invariants` and `verification-kernel` had relatively low intervention burden per commit, but product-launcher completion still occurred at the very end.
* `vertical-evidence` and `harness-lab` had high L4/product-debug burden because real user commands exposed late issues.
* `contract-boundary` had the most interventions and a very high commit count; architecture quality was strong but product completion lagged.

## Approach Effectiveness Rankings

These rankings combine autonomy, implementation quality, iteration efficiency, and final product usefulness.

### 1. `autonomous-crew`

**Effectiveness:** High overall; best practical candidate.

Why:

* Reached production launcher in 51 commits, much fewer than other approaches.
* Final functionality audit found no implementation blockers.
* Review loops and one-writer discipline produced a broad implementation.

Costs:

* High intervention density.
* Subagents timed out during large launcher/context reviews.
* Production launcher still arrived late, after explicit user pressure.

Best lesson: a review crew can accelerate quality if the parent agent keeps ownership, but completion criteria must be concrete or the crew optimizes internal quality before user-facing usability.

### 2. `observability-ledger`

**Effectiveness:** High quality, low autonomy friction per commit, but inefficient.

Why:

* Strongest live bwrap/TUN evidence and final reviewer confidence.
* Real integration script passed 14 tests in the functionality audit.
* Reviewer fanout caught subtle product blockers and false-positive E2E tests.

Costs:

* 269 commits; largest session footprint.
* First “complete” launcher was invalidated by reviewer findings.
* It spent a long time on proof seams before production launcher completion.

Best lesson: observability-first is excellent for final confidence, but it needs an earlier product-runner milestone to avoid proof-infrastructure sprawl.

### 3. `verification-kernel`

**Effectiveness:** Strong correctness, moderate autonomy.

Why:

* Good engineering discipline and manageable intervention burden.
* Produced a working alpha CLI with live rootless bwrap/TUN and real curl evidence.
* Strong typed core/runtime structure.

Costs:

* Invented or inferred stop/budget behavior early.
* Product launcher was only implemented after user clarified it was alpha scope.
* Audit/failure UX came after user debug feedback.

Best lesson: verification-first agents need an explicit “verification ladder must end in product acceptance commands” clause.

### 4. `contract-boundary`

**Effectiveness:** Strong architecture, weaker product readiness.

Why:

* Best boundary/dependency discipline and fuzz-harness story.
* Broad runtime/proxy/smoltcp work and strong tests.

Costs:

* 205 commits and 26 interventions.
* Claimed alpha-complete from library/contract evidence before real launcher was usable.
* Subagent artifacts mostly timed out.

Best lesson: contract-first approaches need a product-runner acceptance gate early, otherwise they can “complete the architecture” before completing the user workflow.

### 5. `harness-lab`

**Effectiveness:** Excellent for finding environment bugs; mixed for autonomous completion.

Why:

* Harness/log discipline made reconstruction easy.
* Real smokes found important gaps.
* Produced a usable sandbox prototype by commit 77/81.

Costs:

* Required repeated scope/autonomy corrections.
* Clippy failure and CAP_NET_RAW issue remained in functionality audit.
* Smoke exit status could hide `fail_closed` audit records.

Best lesson: harness approaches should make smoke assertions semantic, not merely command-exit based, and should explicitly include product CLI usability tests.

### 6. `security-invariants`

**Effectiveness:** Strong pure-core security; weaker live integration.

Why:

* Conservative default-deny/fail-closed model.
* Broad parser/policy/audit invariants.
* Low intervention burden compared with work size.

Costs:

* Runtime did not wire all core invariants into the live path.
* Direct DNS bypass was unproven end-to-end in live runtime.
* Transparent real-domain curl arrived only at final commit.

Best lesson: security-invariant specs need an end-to-end invariant requirement: “the live launcher must use the same mediated decision path proven by core tests.”

### 7. `vertical-evidence`

**Effectiveness:** Good risk discovery, but high product-debug burden.

Why:

* Strong slice-by-slice evidence and useful config/policy work.
* Quickly crossed many technical boundaries.

Costs:

* 22 interventions, 9 L4 product/debug blockers.
* TLS fragmentation/truncation bypass remained a serious functionality-audit blocker.
* Several production usability failures required user-pasted debug output.

Best lesson: vertical slices must be sequenced around representative real user journeys, not just narrow boundary proofs.

## Shared Implementation Struggles

### Premature stopping after verified commits

Repeated in almost every worktree. Agents treated clean tests, a verified slice, or a commit as a natural time to summarize. The later continuation-stop wording helped, but the original launch prompts needed an even stronger loop contract.

Better prompt:

```md
A successful commit is never a completion signal. After every commit, immediately run the alpha acceptance checklist. If any item is incomplete, choose the next highest-value item and continue without final-answering.
```

### Product launcher arrived after proofs

Every agent built libraries, tests, harnesses, examples, or proof commands before the production launcher. This was useful but caused late discovery of UX/product issues.

Better spec:

```md
The production launcher is an alpha milestone, not polish. Start a skeletal `foxprox run` / `bwrap-run` path early, even if it initially handles one flow. All later features must be integrated into that path, not only proved in examples.
```

### Live bwrap/TUN tests were delayed or treated as exceptional

Several agents assumed live bwrap/TUN was unavailable or too sensitive until corrected. Once allowed, live tests quickly uncovered the true issues.

Better spec:

```md
Assume rootless bwrap/TUN live tests are authorized when `/usr/bin/bwrap` and `/dev/net/tun` are available. Use temporary namespaces only. Do not defer live tests unless prerequisites are absent; record exact missing prerequisite.
```

### “All alpha scope” was too abstract

Agents frequently interpreted alpha scope as the parts best aligned with their approach. The docs were broad enough that agents needed an executable checklist.

Better spec format:

```md
Alpha is complete only when these commands pass from a fresh shell:
1. build all binaries;
2. run setup helper under bwrap and observe TUN configured;
3. run `foxprox run --config examples/alpha.toml -- curl http://example.com/`;
4. run `curl -L https://github.com/` or equivalent HTTPS large-body smoke;
5. run a denied-host smoke and verify prompt failure plus audit;
6. run DNS/direct-DNS-deny smoke;
7. run explicit HTTP proxy, HTTPS CONNECT, and SOCKS smoke;
8. run fmt/clippy/test/doc/fuzz checks as applicable.
```

### Tests passed while user-facing behavior was broken

Common examples:

* proxy tests validated handshake/status but not byte relay;
* smoke commands exited success while audit record said `fail_closed`;
* unit tests passed while child stdout was suppressed;
* simple curl passed but redirect/large TLS body failed;
* config allowed upstream DNS but runtime required broker DNS.

Better verification rule:

```md
For each smoke test, assert semantic output, not just exit code. If an audit record contains `deny`, `fail_closed`, or `broker_error`, the smoke must fail unless that exact denial is the expected result.
```

### User-pasted failures were essential

The research shows that the most valuable interventions were not architectural suggestions; they were real command outputs. Agents should have generated those commands themselves sooner.

Better prompt:

```md
Before reporting completion, run the same commands a user would paste into a terminal. Capture stdout, stderr, audit output, exit code, and elapsed time in `progress.md`.
```

### Subagents timed out in large contexts

`autonomous-crew`, `contract-boundary`, and others saw subagent timeouts. Large context plus broad review prompts made subagents less effective late in implementation.

Better subagent pattern:

* give reviewers narrow file ranges or specific diffs;
* ask for partial findings before timeout;
* use multiple small reviewers instead of one huge “review alpha” task;
* keep artifacts file-only and scoped;
* have parent synthesize; do not let subagents own completion.

## What Could Have Been Better in Specs

### 1. Put user-visible acceptance tests before architecture detail

The architecture docs were strong, but agents needed a front-page “done means these commands work” block. This would have reduced ambiguity around proofs vs production launcher.

Suggested spec addition:

```md
## Alpha Acceptance Commands

The alpha is not complete until a fresh checkout can run these commands successfully in the target environment. Unit tests and examples are insufficient without these commands.

[commands...]
```

### 2. Define “production launcher” explicitly

Agents repeatedly built proof commands and examples. The spec should define the launcher’s minimum UX:

* one command runs arbitrary target args;
* bwrap setup is automatic;
* TUN fd handoff is automatic;
* target stdout/stderr remain usable;
* audit goes to a separate stream/file;
* config file controls allow/deny;
* no `--tcp-map` is required for ordinary domain curl;
* proxy env injection is optional/configurable;
* failures return promptly.

### 3. Make “real network” tests required, not optional

Docs said integration-test real namespaces, but agents still delayed this. Specify when to run them and what counts as evidence.

### 4. Specify negative-path UX

Several issues involved denial semantics:

* should denied proxy CONNECT close or return 403?
* should curl fail fast or wait for timeout?
* where should audit lines appear?
* what exit status should the wrapper return on policy denial?

These should be in the spec because agents otherwise optimize local correctness but may choose poor product behavior.

### 5. Specify policy config examples early

Default-deny policies were a recurring footgun. Include copy/paste examples for:

* allow `example.com` HTTP;
* allow `github.com` HTTPS including DNS;
* deny `github.com` and show expected audit/failure;
* direct DNS bypass denied;
* proxy enabled/disabled behavior.

## What Could Have Been Better in Prompts

### 1. Use an explicit autonomous loop contract

```md
Work in cycles: choose next acceptance-check gap → implement → run semantic verification → append progress/learnings → commit → immediately re-run the acceptance checklist. Do not final-answer while any checklist item is incomplete.
```

### 2. Bound “continue” by meaningful progress, not time/turns

The “Ralph loop” risk is real. The best wording is:

```md
Continue after commits, but do not churn. Each cycle must advance product code, tests, harnesses, verification coverage, or an explicitly required architecture boundary. Stop only if two consecutive cycles produce no meaningful product or verification progress, or if a documented stop condition is hit.
```

For worktrees where runtime/turn budgets were undesirable, omit budget language entirely.

### 3. Name the first product milestone

```md
Within the first substantial implementation phase, create a skeletal production launcher path. It can initially be narrow, but all future work must integrate into it or explain why not.
```

### 4. Tell agents how to handle security-sensitive uncertainty

Agents sometimes stopped for permission around live host egress or bwrap tests. Better:

```md
If the docs already require a security-sensitive behavior, implement the narrowest fail-closed version and verify it. Ask only when proceeding would weaken an invariant, expand host privileges, or contradict non-goals.
```

### 5. Require self-review against user workflow

```md
Before final response, impersonate a user with no session context. Run the README command exactly. If it fails, fix the product or docs; do not summarize completion.
```

## What to Change in Future Approach Docs

Add a standard “Product Acceptance Loop” section to every approach:

```md
## Product Acceptance Loop

A verified commit is a checkpoint. After each checkpoint, run the acceptance checklist from the source docs. If any item remains incomplete, choose the next highest-value product or verification gap and continue.

Do not count a parser, crate, unit test, harness, one-shot proof, or example as complete until the production launcher path uses it or the source docs explicitly mark it as a standalone proof.

Completion requires semantic live evidence from the production launcher path, including stdout/stderr behavior, audit output, allow and deny cases, and representative real network commands.
```

Add a standard “No False-Positive Smoke Tests” section:

```md
A smoke test passes only if it asserts the expected behavior. Exit code 0 is insufficient. Check target stdout/stderr, audit records, policy decision, egress calls where applicable, and absence of unexpected `fail_closed` or `broker_error` records.
```

Add a “Launcher First Thread” requirement:

```md
Once core boundaries compile, start a skeletal production launcher. Keep it narrow, but route future proof work through this path as soon as possible. Do not leave the launcher as post-alpha polish.
```

## Useful Repeated Bug Classes to Add to Specs/Tests

1. **Suppressed child stdout/stderr.** Test target output is visible and audit is separated.
2. **Audit ordering/flushing.** Test audit appears live enough to debug failures.
3. **CA trust in sandbox.** Test HTTPS to a real CA-backed site.
4. **Redirect and sequential flow.** Test `curl -L` or equivalent.
5. **Large TLS response / backpressure.** Test a response larger than one buffer/window.
6. **TLS partial ClientHello.** Incomplete TLS metadata should wait for more bytes or fail closed, not bypass.
7. **Direct DNS bypass.** Test sandbox query to external resolver address, not only broker DNS.
8. **Broker DNS policy normalization.** Policy config should allow broker DNS endpoint inside sandbox, not accidentally require upstream resolver address.
9. **Proxy byte relay.** Assert body/tunnel bytes, not just CONNECT/handshake status.
10. **Denied proxy UX.** Decide and test close/reset/HTTP error behavior.
11. **CAP retention.** Verify setup-only caps are gone before target exec; avoid retaining `CAP_NET_RAW` except for explicit ping mode.
12. **Smoke semantic failure.** If JSON audit says `fail_closed`, smoke should fail unless denial is expected.

## Final Research Takeaways

1. **Approach style mattered less than acceptance specificity.** All approaches eventually converged once the user forced product-real commands.
2. **Production launcher should be introduced earlier.** Every branch discovered product issues only after late launcher work.
3. **Autonomy needs explicit continuation plus anti-churn stop rules.** “Keep going” alone is not enough; “commit is checkpoint, run checklist, continue meaningful gap” worked better.
4. **Real live tests are irreplaceable.** Unit tests and proof harnesses missed several decisive product bugs.
5. **Reviewer subagents are best for narrow post-diff checks.** Broad “review alpha completion” subagents often timed out or accepted too narrow a scope.
6. **Progress/learnings ledgers were very valuable.** They made reconstruction possible without reading huge session files; keep them mandatory.
7. **The best final strategy is hybrid:** autonomous crew + observability ledger + contract-boundary + harness semantics, all tied to a front-loaded product acceptance checklist.

## Recommended Next Experiment Prompt Shape

```md
Goal: implement the alpha, but optimize for production-user acceptance first.

Read docs/arch.md and docs/initial-impl.md. Before coding, create an acceptance checklist of exact commands a user will run. The production launcher path is mandatory alpha scope, not polish.

Work in cycles:
1. choose the highest-value incomplete acceptance item;
2. implement the smallest meaningful slice;
3. verify with semantic assertions, not just exit codes;
4. append progress/learnings;
5. commit;
6. immediately re-run the checklist and continue.

Do not final-answer after successful commits. Stop only for documented stop conditions or if two consecutive cycles produce no meaningful product or verification progress.

Early milestone: create a skeletal production launcher and route future work through it. Examples and one-shot harnesses are allowed only as temporary risk reduction and do not count as alpha completion unless the production launcher uses the same path.
```
