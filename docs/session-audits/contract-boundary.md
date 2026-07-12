# foxprox worktree session audit: contract-boundary

Audit target:
- Worktree: `/home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary`
- Session dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-contract-boundary--`
- Branch/HEAD: `contract-boundary` at `12dcc029277246ab5f854c9565be19ffa45af8ab`
- Session files: 4 JSONL files, 18M total; subagent artifacts: 22 files.
- Worktree status during audit: clean except untracked `reviews/`.

Method: followed `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`: inventory, git history, `progress.md`/`learnings.md`, targeted JSONL user-message/tool-error extraction, final digests/compaction snippets, and artifact summaries. I did not read every token.

## Summary findings

- **Intervention burden:** high. I found **26 counted user-message interventions** after excluding 4 seed/restart prompts. Maximum level was **L4 debug/product blocker**. Weighted burden using the strategy model is **69** (`L1*1 + L2*2 + L3*3 + L4*5`). If the two same-timestamp GitHub bad-record messages are merged into one event, the event count is 25 and weighted burden is 64.
- **Iteration count:** 4 session attempts, **205 commits after `main`**, and **101 `progress.md` objective headings**. Commit count is the best verified implementation-iteration proxy, but it is inflated by paired “record ... commit” ledger commits.
- **Time/iterations to production launcher E2E:** library alpha was claimed complete at commit **192/205 `1de31a9`** and initial launcher at **194/205 `ee8dc28`**, but real production end-to-end was not credible until after user-discovered launcher failures. Transparent HTTP E2E landed at **197/205 `5f8655d`**; HTTPS example.com at **199/205 `9d73d0e`**; large HTTPS GitHub corruption at **201/205 `b3d97e4`**; usable CLI policy controls at **204/205 `8c7c585`** with ledger commit **205/205 `12dcc02`**.
- **Main struggle:** agent built a large contract-correct library before a usable launcher, then needed user forcing/debug evidence to close real bwrap/TUN/curl behavior.
- **Approach effectiveness:** contract-boundary strategy was effective at preserving architecture and creating many tests, but weak as an acceptance strategy because it allowed “alpha complete” claims before real launcher smoke tests with representative commands and policy controls.
- **Confidence:** high for intervention counts and production-launcher timeline; medium for subjective struggle weighting because JSONL assistant content was sampled via structured extraction, not fully read.

## Intervention count and levels

Counting model: excluded initial/restart seed prompts that restated “implement alpha scope” or loaded `docs/implementation-approach-contract-boundary.md`. Counted subsequent human messages as interventions.

| Level | Count | Evidence/examples |
|---|---:|---|
| L1 simple continue / autonomy nudge | 7 | `continue`, `continue working`, `continue working until you absolutely require my input again` in JSONL `2026-06-22T01-02-29...`, e.g. timestamps `2026-06-22T21:28:46Z`, `2026-06-22T22:18:22Z`, `2026-06-25T02:57:30Z`, `2026-06-27T01:41:25Z`, `01:46:53Z`, `01:48:45Z`. |
| L2 directional choice/feedback | 7 | `what decision do you need to unblock?` at JSONL line 369 (`2026-06-22T01:23:11Z`), `go ahead with option 1`, `which do you think is higher leverage?`, `go ahead`, `what is highest leverage next?`, `Failing the way I would expect...`, `yes build what you described`. |
| L3 corrective scope/autonomy | 6 | `Work in autonomous cycles until the stop condition is hit... Do not final-answer...` after early stop; `you're supposed to pick the best path forward yourself...` at JSONL line 343 (`2026-06-22T01:01:00Z`); three repeated “continue until alpha scope is all complete; everything in @docs/initial-impl.md...” prompts on `2026-06-25`; `yes please do that. it's necessary for alpha scope completion.` |
| L4 debug/product blocker | 6 | Missing real launcher question at JSONL line 3592 (`2026-06-27T02:34:45Z`); user-reported `ip addr show` empty and curl hang at line 3763; CA trust failure at line 3844; GitHub TLS `bad record mac` output at line 3907; policy flag usability question at line 4203. |

Not-counted L0 seed/restart prompts: 4 initial/restart prompts at `2026-06-21T16:41:32Z`, `2026-06-21T22:35:49Z`, `2026-06-22T00:02:07Z`, `2026-06-22T01:02:35Z`.

## Iteration counts

- **Session attempts:** 4 JSONL sessions:
  - `2026-06-21T16-41-25-501Z_019eeb0e...jsonl`
  - `2026-06-21T22-35-41-893Z_019eec53...jsonl`
  - `2026-06-21T23-58-54-866Z_019eec9f...jsonl`
  - `2026-06-22T01-02-29-848Z_019eecd9...jsonl`
- **Verified implementation commits:** 205 after `main`, from `8528cd5 prep for implementation` to `12dcc02 record alpha policy flags`.
- **Progress-cycle estimate:** 101 `##` objective headings in `progress.md`; medium confidence because some duplicate/pending ledger blocks exist (for example duplicate transparent TCP and HTTPS fix sections around lines 2067-2139).
- **Tool friction:** 90 errored tool results by structured JSONL extraction: 51 `bash`, 34 `edit`, 5 `memory_search`. Repeated `edit` exact-match failures and `bash` compile/sandbox failures materially increased iteration cost.

## Production launcher end-to-end timeline

| Stage | Timestamp/commit | Evidence | Audit interpretation |
|---|---|---|---|
| Library alpha claimed complete | commit 192/205 `1de31a9`, `2026-06-26T22:11:44-04:00` | `progress.md` lines 2006-2031: final audit found no remaining alpha blockers; full workspace and privileged smoke passed. | Not production E2E: no user-runnable launcher yet. |
| Initial bwrap launcher implemented | commit 194/205 `ee8dc28`, `2026-06-26T22:47:22-04:00`; ledger commit `d58989d` | `progress.md` lines 2033-2065: added `foxprox`/`foxproxsetup`; `/bin/true` and `ip addr show foxprox0` smokes passed. | Partial E2E: proves wrapper exists, but not arbitrary network traffic. |
| User asks for real launcher | `2026-06-27T02:34:45Z` | JSONL line 3592: “how do i run this in a real sandbox? is there a production launcher/wrapper i can use?” | High-severity evidence initial work was not discoverably usable. |
| User reports launcher unusable | `2026-06-27T02:51:32Z` | JSONL line 3763: “the ip addr show outpus nothing, and the curl example just hangs.” | Invalidates initial launcher-complete claim for real network use. |
| Transparent HTTP fixed | commit 197/205 `5f8655d`, ledger `257d7ea`, `2026-06-26T22:55:11/34-04:00` | `progress.md` lines 2067-2093: fixed TUN address direction and smoltcp AnyIP/default route; `target/debug/foxprox -- curl --max-time 10 -fsS http://example.com/` passed. | First credible real transparent HTTP E2E. |
| HTTPS CA/TLS partial record fixed | commit 199/205 `9d73d0e`, ledger `b7c2aa5`, `2026-06-27T09:19/20-04:00` | `progress.md` lines 2106-2131; user CA error at JSONL line 3844. | HTTPS example.com E2E reached, but later large-response corruption remained. |
| GitHub TLS corruption fixed | commit 201/205 `b3d97e4`, ledger `f69341f`, `2026-06-27T09:39/40-04:00` | User `bad record mac` output JSONL line 3907; `progress.md` lines 2152-2173 and `learnings.md` lines 478-487: backpressure/order fix; real GitHub curl passed with 564568-byte output. | Full transparent HTTPS behavior became credible. |
| Policy controls added | commit 204/205 `8c7c585`, ledger/head `12dcc02`, `2026-06-27T15:51/52-04:00` | User policy question JSONL line 4203; `progress.md` lines 2175-2196: `--deny-host github.com` produced `deny_reset` and curl `Connection reset by peer`. | Final production launcher usability for alpha policy exercise. |

## Main struggles

1. **Premature completion before user-runnable production path.** The agent recorded no alpha blockers before the CLI existed (`progress.md` lines 2006-2031), then separately added the launcher (`2033-2065`) only after later prompts. The user eventually had to ask whether a production launcher existed.
2. **Autonomy/decision handling.** The agent asked/paused for choices that the spec expected it to resolve. Evidence: user correction at JSONL line 343 and explicit learning at `learnings.md` lines 126-130.
3. **Real bwrap/TUN networking mismatches.** The initial launcher smoke hid output or did not prove traffic. The actual `curl http://example.com` hang revealed reversed TUN addressing and missing smoltcp AnyIP/default route (`progress.md` lines 2069-2073; `learnings.md` lines 473-476).
4. **Real HTTPS edge cases.** CA symlink targets were not mounted in sandbox `/etc` (`learnings.md` lines 478-479), incomplete TLS first records were fail-closed (`480-481`), and host-to-sandbox bridge backpressure reordered/truncated TLS streams causing `bad record mac` (`483-487`).
5. **Tool/edit friction.** 90 errored tool results, especially non-unique or stale `edit` patches and cargo/sandbox failures, indicate the session spent substantial time recovering from mechanical workflow issues.
6. **Subagent strategy ineffective here.** All seven scout/reviewer outputs in `subagent-artifacts/*_output.md` timed out; corresponding meta files show exit `124` or `143`. They did not provide useful review compression for this worktree.

## Repeated behavioral patterns

- **Stops before stated completion:** early final answers after successful commits caused restarts and “continue” prompts. Final assistant snippets show stop messages after partial work, e.g. first session final at `2026-06-21T17:01:57Z`; second at `2026-06-21T23:04:09Z` says “Stop condition hit: turn budget checkpoint.”
- **Asking instead of choosing safe documented path:** acknowledged in `learnings.md` lines 126-130.
- **Claiming completion from unit/contract evidence, then discovering live E2E gaps:** “final audit found no remaining alpha blockers” preceded actual launcher and curl failures.
- **Ledger discipline was strong but noisy:** many implementation commits are paired with “record ... commit” ledger commits; this aids traceability but inflates iteration count.
- **Live user feedback was high leverage:** the user’s exact failing commands directly led to transparent TCP, HTTPS trust, bridge ordering, and policy CLI fixes.

## What specs/prompts could have improved

- Define **alpha completion** as requiring a production launcher from the start: `cargo build -p foxprox-cli --bins`, `target/debug/foxprox -- /bin/sh -c 'ip addr show foxprox0; ip route; cat /etc/resolv.conf'`, `curl http://example.com`, `curl https://example.com`, `curl https://github.com`, and at least one denial via CLI policy with expected curl failure.
- Add an explicit rule: **do not mark alpha complete from library/contract tests alone**; completion requires runnable bwrap/TUN end-to-end evidence with child command output visible.
- Include **CLI policy/config usability** in initial milestones, not future hardening, because users need to exercise deny/reset behavior without editing code.
- Strengthen autonomy prompt: if the implementation approach names a default path, proceed and record assumptions; ask only for scope/security decisions not covered by spec.
- Require progress entries to distinguish **claimed/pending/verified with real command output**, and avoid duplicate “pending” ledger blocks after commit.
- For tool workflow, prefer smaller context-specific edits or direct file rewrites where appropriate; repeated exact-match edit failures consumed time.

## Approach effectiveness

The contract-boundary approach was technically effective: it produced layered crates, dependency-tree checks, normalized policy/audit boundaries, isolated Linux/bwrap/smoltcp details, and many targeted tests. It was less effective as a product-readiness strategy because it optimized internal contracts before the user-visible launcher and did not initially require realistic network smoke tests. The best outcomes happened after the approach was augmented by live bwrap/curl evidence.

## Confidence and gaps

- **High confidence:** user intervention count/classes, git commit count/timeline, production launcher milestones, main late-stage failures. These are backed by JSONL extraction, git history, and ledger lines.
- **Medium confidence:** exact operational-cycle count and struggle weighting; `progress.md` has duplicate/pending ledger sections and commit pairs.
- **Known gaps:** did not read all assistant reasoning or all successful tool output. Artifact reviewer/scout outputs were mostly timeouts, so they provided little independent review evidence.

## Evidence index

- Strategy used: `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`
- Worktree ledger: `/home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary/progress.md`, especially lines 2006-2196.
- Learnings: `/home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary/learnings.md`, especially lines 126-130 and 467-487.
- User interventions: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-contract-boundary--/2026-06-22T01-02-29-848Z_019eecd9-afd8-7da3-9cd3-c00663822c5a.jsonl`, key lines 369, 3592, 3763, 3844, 3907, 4203; autonomy correction in `2026-06-21T23-58-54-866Z_019eec9f-7992-7e02-b68a-e57a84a39835.jsonl` line 343.
- Git refs: `1de31a9`, `ee8dc28`, `5f8655d`, `9d73d0e`, `b3d97e4`, `8c7c585`, `12dcc02`.
- Subagent timeouts: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-contract-boundary--/subagent-artifacts/*_output.md` and `*_meta.json`.

## Commands run for this audit

- `read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md`
- `ls` on worktree and session directories
- `du -sh`, `find ... -name '*.jsonl'`, `find subagent-artifacts`, `wc -l` on ledgers
- `git -C ... status --short --branch`, `git rev-parse HEAD`, `git rev-list --count main..HEAD`, `git log --oneline --reverse main..HEAD`, `git log --format='%h %cI %s'`
- `jq` extraction of session metadata, user messages, assistant stop reasons, final assistant snippets, tool errors, and artifact meta files
- `grep -nE` over `progress.md`/`learnings.md` and targeted JSONL strings

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Audited only the requested contract-boundary worktree/session using the provided strategy and wrote findings to docs/session-audits/contract-boundary.md without modifying source files."
    }
  ],
  "changedFiles": [
    "docs/session-audits/contract-boundary.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md",
      "result": "passed",
      "summary": "Loaded required audit strategy."
    },
    {
      "command": "ls/du/find inventory for contract-boundary worktree and session dir",
      "result": "passed",
      "summary": "Confirmed 4 JSONL sessions, 22 artifact files, 18M session dir, branch HEAD 12dcc029."
    },
    {
      "command": "git status/rev-parse/rev-list/log in /home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary",
      "result": "passed",
      "summary": "Collected clean status except untracked reviews, 205 commits after main, and launcher-related commit refs/dates."
    },
    {
      "command": "jq extraction of session metadata, user messages, stop reasons, tool errors, final assistant snippets, and artifact meta",
      "result": "passed",
      "summary": "Classified 30 user messages, excluding 4 seed prompts and counting 26 interventions; counted 90 tool errors."
    },
    {
      "command": "grep/read progress.md and learnings.md around launcher/bwrap/curl/TUN/policy/failure terms",
      "result": "passed",
      "summary": "Mapped production launcher timeline and main struggles to ledger line ranges."
    }
  ],
  "validationOutput": [
    "Output file written to /home/foxfire/code/foxprox/docs/session-audits/contract-boundary.md.",
    "Base repo had pre-existing untracked files docs/worktree-functionality-comparison.md and subagent-session-audit-strategy.md before this audit; no files were staged."
  ],
  "residualRisks": [
    "Did not read every token in JSONL; used targeted extraction per requested strategy.",
    "Operational-cycle count is medium confidence because progress.md has duplicate/pending ledger sections."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added the requested contract-boundary session audit markdown artifact only.",
  "reviewFindings": [
    "no blockers"
  ],
  "manualNotes": "Subagent artifacts for this worktree were all timeout outputs, so audit relies on ledgers, git history, and targeted JSONL extraction."
}
```