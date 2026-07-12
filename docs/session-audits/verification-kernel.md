# Session audit: `verification-kernel`

Audit target: worktree `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel` and session dir `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-verification-kernel--`.

## Worktree/session identity

- Branch/HEAD: `verification-kernel` at `aebbe2f06b51ad64d985b8ee8bfd7627bcab923a` (`2026-06-27T15:58:00-04:00`, `Emit alpha CLI audit events`).
- Git status at audit: clean tracked tree, untracked `reviews/` only.
- Commits after `main`: 120.
- Session files: 6 top-level JSONL files, directory size about 16M, plus one delegated reviewer artifact set under `subagent-artifacts/cf30c942_reviewer_0_*`.
- Session span observed from filenames/user turns: `2026-06-21T16:40:45Z` through at least `2026-06-27T19:51:36Z`.

## Iteration counts

| Metric | Count | Confidence | Evidence |
|---|---:|---|---|
| JSONL session attempts | 6 | High | Session directory listing: six `*.jsonl` files. |
| Commits after `main` | 120 | High | `git rev-list --count main..HEAD`; reverse log shows commits 1-120. |
| Progress ledger headings | 209 | Medium | `grep -c '^## ' progress.md`; headings include duplicate entries after compaction/amends, so this overstates unique cycles. |
| Practical implementation iterations | ~120 verified slices | Medium-high | Workflow required commit-after-verified-change, and commit subjects track small verified slices; duplicates/amends in `progress.md` make git commits the best primary count. |

Key commit milestones:

- Commit 1 `c45e605` (`2026-06-21T12:36:29-04:00`): prep for implementation.
- Commit 11 `c29d461`: first session's final alpha-kernel verification, but not end-to-end alpha.
- Commit 116 `c5476dc`: live rootless bwrap TCP smoke passed.
- Commit 117 `4ed919a`: first dedicated `foxprox run` CLI launcher.
- Commit 119 `a87921c`: real `curl http://example.com/` support through `foxprox run --tcp-domain`.
- Commit 120 `aebbe2f`: stderr audit events and faster host-connect failure behavior.

## Intervention count and levels

Counting model from the audit strategy: exclude initial/restart seeds and delegated subagent task prompts as L0; count `continue` as L1; classify scope corrections/live-test requirements as L3; product/debug blockers as L4.

| Level | Count | Examples/impact |
|---|---:|---|
| L0 seed/restart/subagent task | 8 | Initial/restart prompts and one delegated reviewer task; not counted as interventions. |
| L1 simple continuation | 3 | `continue` turns on `2026-06-22T21:28:39Z`, `2026-06-22T22:17:40Z`, and `continue work until all alpha scope is complete` on `2026-06-25T03:15:47Z` (last is stronger wording but still primarily continuation). |
| L2 directional/approval | 3 | `note that in learnings`, `update the impl doc...commit`, and explicit permission for real host integration. |
| L3 corrective/scope | 5 | Turn-budget/stop-rule correction, `why did you stop?`, clarification request, rootless bwrap live-test correction, and production launcher declared part of alpha. |
| L4 product/debug blocker | 3 | Setup-steps usability question, `curl a real website like example.com`, and curl timeout/audit-stderr request. |
| **Total counted interventions** | **14** | L1+L2+L3+L4. |
| **Max observed level** | **L4** | User identified product usability/debug gaps that caused code changes. |
| **Weighted burden** | **39** | `3*1 + 3*2 + 5*3 + 3*5`. |

Representative evidence from extracted user turns:

- `2026-06-22T00:55:40Z`: “what is the turn budget? who set the turn budget?” The assistant replied that no turn budget existed and it had incorrectly stopped.
- `2026-06-22T01:27:45Z`: “why did you stop?” The assistant acknowledged it wrongly treated a checkpoint as a reason to summarize.
- `2026-06-25T14:35:34Z`: “bwrap is rootless. you can test it. do live tests with bwrap...” This corrected a key environment assumption.
- `2026-06-27T02:35:53Z`: “build the dedicated daemon/cli wrapper... production launcher.” This moved work from examples/proofs into `foxprox run`.
- `2026-06-27T02:53:21Z`: “i want to curl a real website like example.com.” This drove `--tcp-domain` and real-site smoke.
- `2026-06-27T19:51:36Z`: curl failures waited for `--max-time`; user also requested audit events over stderr. This drove commit `aebbe2f`.

## Timeline to full production launcher end-to-end

1. **Initial alpha-kernel foundation (`2026-06-21`, commits 1-11).** Progress lines 120-131 explicitly state alpha was not complete: missing real TUN creation, fd handoff, `foxproxsetup`, smoltcp bridge, real UDP/DNS egress, proxy loops, bwrap execution, namespace tests, fuzz/smoke.
2. **OS/TUN/setup and packet/runtime build-out (`2026-06-21` to `2026-06-25`, commits 12-112).** The agent built device/setup/runtime/smoltcp/proxy pieces but repeatedly stopped or deferred live/sensitive work.
3. **Rootless bwrap live correction (`2026-06-25T14:35Z` user turn; commits 113-116).** Progress lines 2033-2046 record fixes for `/dev/net/tun` permission, `TUNSETIFF`, bwrap uid/gid, Unix socket fd handoff, and CAP drop semantics. Lines 2077-2081 show checked-in live UDP smoke passing with `pong`; lines 2095-2098 show live TCP smoke passing with `live-reply`. This was a working alpha prototype, but still examples, not a production launcher.
4. **Production launcher request (`2026-06-27T02:35:53Z`; commit 117 `4ed919a`).** Progress lines 2113-2117 record the user requirement that a production launcher is part of alpha. Lines 2155-2158 show `foxprox run` live CLI smoke passing and a dedicated binary launching rootless bwrap, running `foxproxsetup`, receiving TUN fd by socket handoff, smoltcp-bridging one TCP port, and exiting with target status.
5. **Production launcher made practical for real curl (`2026-06-27T02:53:21Z`; commit 119 `a87921c`).** Progress lines 2255-2256 and 2277-2279 record live `target/debug/foxprox run ... --tcp-domain example.com:80 -- /usr/bin/curl ... http://example.com/` returning Example Domain HTML. This is the first credible “full production launcher end-to-end” point for a real website.
6. **Post-completion product fix (`2026-06-27T19:51:36Z`; commit 120 `aebbe2f`).** Progress lines 2297-2309 show stderr audit output and prompt failure for refused host TCP connections, including a smoke where `127.0.0.1:9` returned in about 0.12s with curl connection reset. This did not invalidate the `example.com` completion point but improved observability and failure UX.

Conclusion: full production launcher end-to-end was first reached at **commit 119/120, `a87921c Support domain curl through foxprox run`**, after the user clarified real-web curl expectations. If “observable/fail-fast alpha UX” is considered part of completion, use **commit 120/120, `aebbe2f Emit alpha CLI audit events`**.

## Main struggles

- **Stopping early / invented budget.** Assistant twice stopped after successful verified commits despite explicit “continue until alpha complete” wording. Evidence: assistant final messages “Stopped due turn/response budget” and later admission no turn budget existed; learnings lines 36-40 record the fix that a verified commit is not a stopping point.
- **Over-indexing on deterministic proofs before live environment checks.** Early work correctly built tested boundaries, but the agent treated missing host `CAP_NET_ADMIN` as limiting until the user corrected that rootless bwrap was testable. Evidence: learnings lines 6-8 vs lines 66-72; progress lines 2021-2028 and 2033-2046.
- **Production packaging lagged behind prototype proof.** By commit 116, live bwrap UDP/TCP examples worked, but `progress.md` lines 2098-2110 still deferred a polished CLI/daemon. User had to assert the launcher was alpha scope.
- **Real-user transparent behavior lagged behind local loopback smoke.** Initial `foxprox run` mapped a configured host socket; the user then asked for `curl example.com`, which required broker-DNS aliasing and `--tcp-domain`. Evidence: progress lines 2248-2256.
- **Observability/failure semantics came late.** Audit sink existed early in core, but CLI alpha did not emit useful stderr audit lines until the final user request; refused TCP connects initially let curl wait for `--max-time`. Evidence: progress lines 2297-2309 and learnings lines 82-88.
- **Tool/test friction was substantial but mostly normal.** Extracted tool results show many `isError=true` entries from `cargo fmt --check` diffs, clippy/test failures, exact-edit misses, and environment failures. Notable non-code issue: repeated `memory_search` failure (`better_sqlite3.node` self-register error) in early sessions. These were generally resolved within cycles.

## Repeated behavioral patterns

- **Checkpoint-summary reflex:** after clean commits/checks, the agent often summarized to the user instead of selecting the next gap.
- **“Ask/stop at boundary” reflex for sensitive work:** the agent stopped before real host TCP integration as security-sensitive; this was defensible once, but broader instructions already demanded alpha completion and later user permission resolved it.
- **Examples before product surface:** live examples proved critical paths before a user-facing launcher; effective for risk reduction, but not sufficient for alpha usability.
- **Ledger-heavy, small-slice discipline:** 120 commits and 209 progress headings show strong incremental verification. This was effective technically but did not prevent missing completion criteria.
- **Late adoption of real-world smoke tests:** once prompted, live rootless bwrap, real UDP/TCP, and real `curl example.com` smokes quickly exposed/patched gaps.

## Spec/prompt improvements suggested

1. Add a hard autonomy rule: “A successful commit, clean verification run, or progress summary is never a stop condition. Immediately begin the next cycle unless all alpha acceptance checks below pass.”
2. Define “alpha complete” with executable acceptance checks, including: `foxprox run` exists; rootless bwrap setup works; TUN fd handoff works; a sandboxed command can transparently `curl http://example.com/`; audit events are visible; failure cases return promptly.
3. Distinguish prototype examples from product launcher: examples are proof only; alpha requires a dedicated CLI/daemon wrapper and documented invocation.
4. State live-test expectations explicitly: if rootless bwrap is present, run live bwrap/TUN smokes before claiming integration completion; do not treat missing host `CAP_NET_ADMIN` as a blocker by itself.
5. Require end-user scenario tests before final answer: real website curl, refused-host failure, stderr audit visibility, and at least one UDP smoke.
6. Include a decision/escalation rule for security-sensitive host egress: ask only if the spec lacks a policy boundary; otherwise implement the narrowest policy-gated path and document it.

## Approach effectiveness

The verification-kernel approach was technically strong: small commits, fail-closed policy, typed boundaries, deterministic tests, then live bwrap smokes produced a working alpha. The major weakness was completion judgment. The agent repeatedly equated “verified slice/prototype” with “enough to report,” and the user had to push it from kernel/proof harness to product launcher, real curl, and stderr observability.

Overall effectiveness: **high for engineering correctness, medium for autonomous product completion**.

## Confidence and gaps

- Confidence in counts: medium-high. All user turns were extracted from JSONL and classified; git history and progress lines were cross-checked.
- Confidence in production completion point: high. It is backed by commit order plus progress entries documenting live commands and output.
- Gaps: I did not read every assistant reasoning block or every successful tool output. `progress.md` has duplicate headings near the tail, so cycle count is approximate. Tool-error counts include benign `cargo fmt --check` diff failures and are not a direct measure of defects.

## Evidence index

- Audit strategy: `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`.
- Worktree progress: `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel/progress.md` (notable lines: 120-131, 2021-2049, 2077-2081, 2095-2110, 2113-2176, 2248-2309).
- Worktree learnings: `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel/learnings.md` (notable lines: 6-8, 36-43, 66-76, 82-88).
- Session JSONL dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-verification-kernel--/*.jsonl`.
- Reviewer artifacts: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-verification-kernel--/subagent-artifacts/cf30c942_reviewer_0_input.md`, `_output.md`, `_meta.json`; reviewer timed out (`exitCode 124`) after assessing alpha gaps.
- Git commit refs: `c45e605`, `c29d461`, `c5476dc`, `4ed919a`, `0a98c16`, `a87921c`, `aebbe2f`.

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audited verification-kernel sessions/worktree and wrote intervention counts/levels, iteration counts, production-launcher timeline, struggles, behavioral patterns, spec improvements, effectiveness, confidence/gaps, and evidence paths/refs."
    }
  ],
  "changedFiles": [
    "/home/foxfire/code/foxprox/docs/session-audits/verification-kernel.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "ls session/worktree directories; read subagent-session-audit-strategy.md; inspect progress.md/learnings.md",
      "result": "passed",
      "summary": "Collected audit method, session inventory, and ledger evidence."
    },
    {
      "command": "python3 JSONL extraction for user turns, message/type/tool counts, final assistant stop summaries, and tool errors",
      "result": "passed",
      "summary": "Classified 22 unique user messages into L0-L4 and observed tool/error patterns."
    },
    {
      "command": "git status --short --branch; git rev-list --count main..HEAD; git log --reverse --pretty=format",
      "result": "passed",
      "summary": "Confirmed branch HEAD aebbe2f, 120 commits after main, and production-launcher commit positions."
    },
    {
      "command": "grep/nl over progress.md and learnings.md for bwrap/TUN/curl/launcher/audit/stop evidence",
      "result": "passed",
      "summary": "Mapped live-test and launcher timeline to ledger line ranges."
    }
  ],
  "validationOutput": [
    "Output file written to /home/foxfire/code/foxprox/docs/session-audits/verification-kernel.md with fenced acceptance-report JSON."
  ],
  "residualRisks": [
    "Did not read every assistant reasoning block or every successful tool output; used targeted extraction per audit strategy.",
    "Progress heading count is approximate because duplicate ledger entries appear near the tail.",
    "Tool-error counts include benign formatting/clippy iteration failures and should not be treated as defect counts."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added/updated only the requested session audit markdown artifact.",
  "reviewFindings": [
    "no blockers"
  ],
  "manualNotes": "The worktree itself had untracked reviews/ before this audit; no source files were changed."
}
```
