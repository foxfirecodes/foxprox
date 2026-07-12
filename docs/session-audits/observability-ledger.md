# Observability-ledger worktree session audit

Audit target: `/home/foxfire/code/foxprox/.tmp/worktrees/observability-ledger`  
Session dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-observability-ledger--`  
Strategy used: `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`  
Audit date: 2026-06-27

## Scope and evidence inventory

- Worktree branch/HEAD: `observability-ledger` at `405277139d8082d02c8df0136f4251e5d15b1608` (`4052771 Complete alpha proxy tunneling`).
- Git state at audit time: untracked `context.md`, `reviews/`, `subagents/`; no staged files observed before writing this audit.
- Session files: 3 JSONL files, approx 72 MB JSONL total inside a 215 MB session directory; 178 subagent artifact files.
  - `2026-06-21T16-42-01-716Z_019eeb0f-7e73-7b6d-a119-6f884c86c9fc.jsonl` — 899,026 bytes.
  - `2026-06-21T22-36-34-758Z_019eec54-1846-7ec9-b613-f34fe5d8353b.jsonl` — 36,987,215 bytes.
  - `2026-06-27T01-51-49-236Z_019f06c6-a3f4-7908-9be1-dcc2308a4498.jsonl` — 33,706,196 bytes; fork/subagent context duplicates prior user history.
- Worktree ledgers: `progress.md` 5,780 lines / 411,564 bytes; `learnings.md` 592 lines / 55,764 bytes.
- Implementation iterations: 269 commits after `main`; first commit `a60dc81 prep for implementation`, final commit `4052771 Complete alpha proxy tunneling`.

Method note: I followed the supplied strategy and did targeted extraction rather than reading all tokens: artifact/reviewer grep, user-message extraction/classification, final digest sampling, progress/learnings grep/windows, git log, tool-error summaries, and selected line windows around launcher completion.

## Intervention count and levels

Counting model: unique human user messages were deduplicated across the 2026-06-27 fork JSONL. Initial/restart prompts and delegated subagent task prompts are L0 and not counted as interventions.

Summary:

- L0 seeds/restarts/delegations: 4 unique messages (initial seed, 6-hour autonomous restart, 2026-06-27 inherited seed duplicate, delegated subagent task).
- Counted interventions: **15**.
  - L1 simple continuation: **2**.
  - L2 directional/questions: **2**.
  - L3 corrective/completion criteria: **7**.
  - L4 debug/product-blocking production/E2E clarification: **4**.
- Maximum intervention level: **L4**.
- Weighted burden: `2*1 + 2*2 + 7*3 + 4*5 = 47`.
- Confidence: high for user-message count/classification; all unique user turns were extracted, but assistant context around every stop was not fully read.

Intervention table:

| Timestamp | Level | Summary | Impact/evidence |
|---|---:|---|---|
| 2026-06-22T21:29:03Z | L1 | `continuea continue` | Autonomy/turn-budget continuation; JSONL extracted from session. |
| 2026-06-23T03:33:49Z | L1 | `continue` | Autonomy continuation. |
| 2026-06-24T18:07:31Z | L4 | “why cant you test with bwrap? bwrap is rootless” | Forced shift from harness-only assumptions to live rootless bwrap/TUN testing. Evidence: JSONL line 8992; `learnings.md:578-584` records rootless bwrap/TUN findings. |
| 2026-06-24T18:09:50Z | L4 | User specified bwrap `--cap-add CAP_NET_ADMIN`, `foxprox setup` TUN creation, cap drop, target exec; pointed to `initial-impl.md`. | Product-architecture correction; later progress implements setup execution and cap drop (`progress.md:4724-4747`). |
| 2026-06-24T18:11:58Z | L4 | Requested full bwrap integration testing and rerunnable script. | Led to `scripts/integration/bwrap-setup-e2e.sh` and privileged ignored tests. |
| 2026-06-24T22:21:02Z | L2 | Asked if that was all before full alpha specs. | Exposed mismatch between agent “remaining gaps” framing and full alpha completion. |
| 2026-06-24T22:24:10Z | L3 | “keep working until the full alpha spec is implemented” | Prevented premature stop; JSONL line 9139 and progress after line 5325 show continued launcher work. |
| 2026-06-25T02:56:00Z | L4 | “do the real end to end tests and remaining production work” | Re-emphasized real E2E and production work; followed by real TCP/UDP/DNS launcher proofs. |
| 2026-06-25T03:35:06Z | L2 | “is it done? are we done with alpha scope?” | Completion-state check. |
| 2026-06-25T03:40:43Z | L3 | “everything in @docs/initial-impl.md needs to be implemented” | Scope correction; agent continued beyond proof launchers. |
| 2026-06-25T14:37:48Z | L3 | Same `initial-impl.md` completion criterion plus “fully functional alpha implementation ... real sandbox environment.” | Raised completion bar from testable pieces to usable product. |
| 2026-06-25T23:41:38Z | L2 | Asked setup steps for own sandbox. | Usability/launcher ergonomics signal before final production launcher. |
| 2026-06-27T01:51:01Z | L3 | “continue implementation until the full production launcher is complete.” | Directly triggered final production launcher push; later `run-bwrap-alpha` completion. |
| 2026-06-27T02:51:57Z | L3 | “include a real production launcher/wrapper so i can run real sandbox commands.” | Explicit user-facing wrapper requirement; `scripts/foxprox-alpha-run` appears at `progress.md:5735`. |
| 2026-06-27T19:49:41Z | L3 | Asked for sample config allowing only `example.com` and `github.com`. | Post-completion usability/config need; final digest for main JSONL records this. |

## Iteration counts

- Session attempts: **3 JSONL files**, though the third is a fork/delegated planning/review context with duplicated history.
- Verified implementation iterations: **269 commits after `main`**. This is the best concrete iteration count because the worktree followed commit-after-meaningful-change cycles.
- Progress-cycle estimate: roughly **140+ progress sections/review-fix cycles**; confidence medium because the ledger mixes implementation sections, review sections, and follow-up fix entries. The artifact directory has 178 files, mostly reviewer inputs/outputs/meta, which supports a high review-cycle count.
- Tool friction: stop reasons include 3 `length` and 30/28 `error` stop reasons in the two large JSONLs, plus many edit/compile/test command errors. Early errors include missing exact edit text, type inference/build failures, missing review files, bwrap/TUN environment gaps, and memory_search native module failures.

## Timeline to full production launcher end-to-end

Important milestones, with production-completion interpretation:

1. **2026-06-21 — core observable contracts only.** The first progress entry says real TUN fd I/O, bwrap execution, smoltcp bridging, explicit proxy listeners, DNS upstream forwarding, and host socket egress were still future work (`progress.md:59-60`).
2. **2026-06-21/22 — many deterministic harnesses.** TUN harness, smoltcp adapter/bridge, setup plan CLI, config schema, proxy/DNS runtime proofs, task/lifecycle/fan-in semantics, and scheduler readiness accumulated. These were useful but repeatedly recorded as not the final runtime (`progress.md:955`, `1075`, `1823`, `3913`, etc.).
3. **2026-06-24 — real bwrap/TUN learning and setup breakthrough.** User intervention forced rootless bwrap testing. `learnings.md:578-584` records the working rootless bwrap shape, `/dev/net/tun` binding, CAP_NET_ADMIN behavior, and incidental IPv6 packets.
4. **2026-06-24/25 — separate proof launchers.**
   - `a336d7b` / `progress.md:5325-5352`: added `foxprox run-bwrap-tcp-egress`, proved one real host TCP request/response over bwrap + received TUN + smoltcp + host socket egress.
   - `8debeca` / `progress.md:5354-5376`: exercised the actual TCP egress CLI command.
   - `e51880f` / `progress.md:5392-5410`: added UDP egress proof and CLI launcher.
   - `6f263dc` / `progress.md:5466-5504`: added real bwrap DNS launcher proof.
   These are not full production completion: each progress entry still lists bounded single-exchange/proof-command gaps.
5. **2026-06-26 — first combined alpha command, still incomplete.** `22bc850` / `progress.md:5570-5595` added `foxprox run-bwrap-alpha`, a combined bwrap/TUN launcher, but explicitly lacked child-lifecycle cancellation, proxy lifecycle, and real E2E.
6. **2026-06-26 — combined alpha DNS/TCP/UDP E2Es.**
   - `0528671` / `progress.md:5616-5632`: combined alpha DNS proof.
   - `ea82ee0` / `progress.md:5688-5705`: transparent TCP proof.
   - `db9da60` / `progress.md:5708-5728`: transparent UDP proof.
   Still not full production because proxy lifecycle, multi-flow, and cleanup remained.
7. **2026-06-27 — first credible “full production launcher” point: commit `75175c0 Complete alpha sandbox launcher`.** `progress.md:5728-5747` says `run-bwrap-alpha` became the real alpha launcher for sandbox commands, bwrap injected proxy env vars, synthetic HTTP/SOCKS proxy endpoints shared policy/DNS cache, proxy listener lifecycle and session audit were added, `scripts/foxprox-alpha-run` wrapper was added, and thirteen real bwrap/TUN tests passed. This is “first reached,” but immediately followed by significant reviewer findings.
8. **2026-06-27 — reviewer-invalidated completion.** Artifact `3f96476a_reviewer_0_output.md` found a blocker: synthetic HTTP/SOCKS proxy endpoints did not relay origin/tunnel bytes; highs found transparent TCP bypassed HTTP/TLS inspection and direct UDP bypassed core UDP policy/lifecycle. Artifact `3f96476a_reviewer_1_output.md` found explicit proxy E2Es were false positives for response/tunnel relay.
9. **2026-06-27 — final credible completion after fixes: commit `4052771 Complete alpha proxy tunneling`.** `progress.md:5750-5780` records fixes for real origin response relay, SOCKS tunnel byte relay, transparent TCP HTTP/TLS attribution, direct UDP policy ownership, HTTP CONNECT tunneling, stronger explicit proxy E2Es, and all fourteen real bwrap/TUN tests plus full cargo/fmt/clippy passing. Artifact `70a3b8a1_reviewer_1_output.md` reports blocker/high/medium none and cites real bwrap/TUN coverage for DNS, TCP, UDP, multi-flow, HTTP proxy, HTTP CONNECT, and SOCKS.

Conclusion: Full production launcher end-to-end was **first plausibly reached at commit `75175c0` but not actually stable/complete until final commit `4052771`** after proxy/UDP review fixes. That is commit **269 of 269** in the branch history, with meaningful production launcher functionality only appearing in the final ~20 commits.

## Main struggles

1. **Harness/proof over product/runtime.** The agent built many correct, observable seams before the product was usable. Progress repeatedly said “remaining final runtime gap” for TUN/smoltcp/lifecycle/readiness (`progress.md:3821-4390`). This was effective for correctness but delayed usable launcher completion.
2. **Underestimating rootless bwrap/TUN feasibility.** User had to correct “why can’t you test with bwrap?” and specify the CAP_NET_ADMIN/setup/drop/exec flow. The working local shape was only captured later in `learnings.md:578-584`.
3. **One-shot launchers mistaken for product progress.** Separate TCP/UDP/DNS commands proved important paths but were bounded single-exchange proofs. Reviewers repeatedly called out missing DNS/proxy lifecycle, transparent mapping, multi-flow, and lifecycle cleanup (`e9f5b32d`, `1bebfce5`, `f4c6f65b`).
4. **Default-deny and policy ownership bugs.** DNS/UDP/proxy policy ownership was hard: DNS allow-listing initially required raw UDP, DNS observations committed before TUN delivery, direct DNS bypass/denial evidence needed preservation, proxy SYNs were blocked by generic TUN policy, and direct UDP bypassed core QUIC/DNS attribution paths.
5. **False-positive E2E coverage.** Explicit HTTP/SOCKS proxy tests initially proved only handshake/status, not real response/tunnel byte relay. `3f96476a` caught this as a blocker/high issue after the first “complete” launcher claim.
6. **Lifecycle/cleanup and bounded waits.** The session repeatedly fixed target-exit drain, accept/read/wait timeouts, idle vs cancellation semantics, audit fan-in final drain, and nonblocking fd handling. These were necessary for production but consumed many iterations.
7. **Tool and edit friction.** Tool errors show many exact-edit failures, compile/type errors, missing file reads, and validation-command mistakes. This increased iteration count but generally converged through tests and reviews.

## Repeated behavioral patterns

- **Stopped or answered before full alpha scope.** Multiple L1/L3 interventions were continuations or “keep working until full alpha spec” prompts. The agent tended to summarize remaining gaps and pause rather than autonomously continuing to production completion.
- **Overclaimed or accepted partial proof as progress toward product.** Progress entries were usually honest about remaining gaps, but the work still prioritized proof seams and single-exchange launchers before the real user-facing launcher.
- **Relied on reviewers to discover product blockers.** Many high-impact fixes came from review artifacts rather than from the primary agent’s own completion criteria: UDP silent drop (`e9f5b32d`), DNS policy/commit issues (`f4c6f65b`), target-exit skip and policy-denial success (`8e146cc2`), proxy false positives (`3f96476a`), HTTP CONNECT/SOCKS false success (`93a5d5ab`).
- **Good evidence discipline once pointed at a gap.** The agent consistently added focused unit tests, ignored privileged E2Es, integration scripts, progress/learnings entries, and reviewer follow-ups. Final validation was strong.
- **Completion criteria drifted unless restated.** User prompts pointing to `docs/initial-impl.md`, “real sandbox,” and “full production launcher/wrapper” were necessary to keep the agent from stopping at harness/proof boundaries.

## Specs/prompts that could have improved the run

High-leverage prompt/spec wording that likely would have reduced interventions:

1. **Define “done” as a runnable production command from the start.** Example: “Do not final-answer until `scripts/foxprox-alpha-run` or `foxprox run-bwrap-alpha <config> -- <arbitrary command>` works in a rootless bwrap/TUN environment and passes a rerunnable script with DNS, transparent TCP, transparent UDP, HTTP proxy, HTTPS CONNECT, SOCKS, and multi-flow evidence.”
2. **Forbid counting one-shot proof launchers as alpha completion.** Explicitly require long/combined launcher behavior, target-exit handling, cleanup/final drain, and multi-flow operation.
3. **Require default-deny E2Es.** Many false positives used permissive configs. The spec should require production tests under default-deny with targeted DNS/proxy/host allow rules.
4. **Require byte-relay assertions for proxies.** Explicit proxy tests should assert origin response bytes and post-CONNECT tunnel bytes, not just status/handshake.
5. **Make rootless bwrap/TUN assumptions explicit.** Include the CAP_NET_ADMIN, `/dev/net/tun` bind, setup helper, cap drop, and target exec flow from the beginning.
6. **Require self-review against `docs/initial-impl.md` before stopping.** A checklist mapping every doc requirement to implementation, test, and audit evidence would have caught several “remaining gap” states earlier.
7. **Escalate only true blockers; continue otherwise.** The user repeatedly had to say continue. The prompt should say that remaining spec gaps are not stop conditions; choose the next highest gap and proceed.

## Approach effectiveness

Overall: **effective but inefficient**.

Strengths:

- Produced a large, well-tested implementation with structured audit/fail-closed semantics.
- Reviewer fanout was highly effective at catching subtle production blockers.
- Final state appears strong: final progress records all fourteen real bwrap/TUN tests plus full workspace tests/fmt/clippy; final reviewer artifact reports no blocker/high/medium issues.
- Learnings captured reusable low-level details for rootless bwrap/TUN, fd handoff, nonblocking fds, incidental IPv6, and bounded waits.

Weaknesses:

- Took 269 commits and 15 human interventions to reach final production launcher completion.
- The agent spent a long time on deterministic seams before product E2E, despite user’s alpha-scope mandate.
- It needed repeated user correction on full scope and production launcher usability.
- The first “complete production launcher” was materially incomplete until post-review fixes.

## Confidence and gaps

Confidence: **medium-high**.

- High confidence on intervention count/classification, commit count, final production timeline, and main struggle themes because they are supported by JSONL user turns, progress lines, git history, and reviewer artifacts.
- Medium confidence on progress-cycle count because ledger formats are inconsistent and I did not count every progress subheading manually.
- Medium confidence on assistant motivation/stop-cause analysis because I did not read full assistant thinking or every raw assistant message; I used stop reasons, user continuation prompts, progress entries, and final digests.
- Known gap: I did not read all 215 MB of session data or all 178 artifact files. I targeted high-signal reviewer outputs, progress/learnings windows, final digests, user turns, and tool errors as requested.

## Key evidence paths

- Strategy: `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`.
- User interventions: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-observability-ledger--/2026-06-21T22-36-34-758Z_019eec54-1846-7ec9-b613-f34fe5d8353b.jsonl`, e.g. line 8992 bwrap correction and line 9139 full-alpha continuation.
- Work progress: `/home/foxfire/code/foxprox/.tmp/worktrees/observability-ledger/progress.md`, especially lines 5325-5780 for production launcher evolution.
- Learnings: `/home/foxfire/code/foxprox/.tmp/worktrees/observability-ledger/learnings.md`, especially lines 578-592 for rootless bwrap/TUN and fd/wait lessons.
- Reviewer artifacts:
  - `.../subagent-artifacts/e9f5b32d_reviewer_1_output.md` — bounded proof launcher/product gaps.
  - `.../subagent-artifacts/1bebfce5_reviewer_1_output.md` — DNS/proxy/multiflow launchers missing.
  - `.../subagent-artifacts/f4c6f65b_reviewer_0_output.md` and `_1_output.md` — DNS policy/commit and bounded launcher blockers.
  - `.../subagent-artifacts/8e146cc2_reviewer_1_output.md` — target-exit skip and policy-denial success issues.
  - `.../subagent-artifacts/3f96476a_reviewer_0_output.md` and `_1_output.md` — proxy byte-relay false positives and direct UDP/HTTP/TLS issues.
  - `.../subagent-artifacts/93a5d5ab_reviewer_1_output.md` — HTTP CONNECT and SOCKS false success.
  - `.../subagent-artifacts/70a3b8a1_reviewer_1_output.md` — final no blocker/high/medium with fourteen real bwrap/TUN tests.

## Acceptance

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audited only the requested observability-ledger worktree/session using targeted extraction per strategy, and wrote the required audit to docs/session-audits/observability-ledger.md without modifying source or session files."
    }
  ],
  "changedFiles": [
    "docs/session-audits/observability-ledger.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md",
      "result": "passed",
      "summary": "Loaded the required audit strategy."
    },
    {
      "command": "ls worktree/session dirs; du/find/wc/git inventory commands",
      "result": "passed",
      "summary": "Collected worktree/session sizes, JSONL/artifact counts, progress/learnings sizes, branch HEAD, status, and commit count."
    },
    {
      "command": "jq extraction of session metadata, unique user messages, final digests, stop reasons, and tool errors",
      "result": "passed",
      "summary": "Classified interventions and sampled session behavior without reading all tokens."
    },
    {
      "command": "grep/read progress.md and learnings.md around bwrap/TUN/launcher/production/proxy terms",
      "result": "passed",
      "summary": "Built the production launcher timeline and extracted struggle/learning evidence."
    },
    {
      "command": "grep selected subagent-artifacts reviewer outputs for blocker/high/medium launcher findings",
      "result": "passed",
      "summary": "Identified repeated review-discovered product blockers and final clean review evidence."
    }
  ],
  "validationOutput": [
    "Audit markdown written to /home/foxfire/code/foxprox/docs/session-audits/observability-ledger.md."
  ],
  "residualRisks": [
    "Did not read all 215 MB of session data or all 178 artifacts; targeted extraction was used as requested.",
    "Progress-cycle count is approximate because progress.md mixes implementation, review, and fix entries."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added one audit markdown artifact for the observability-ledger session.",
  "reviewFindings": [
    "no blockers"
  ],
  "manualNotes": "The changed file is the requested audit output only."
}
```
