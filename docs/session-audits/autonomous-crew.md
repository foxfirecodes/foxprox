# Autonomous-crew session audit

## Scope and method

Audited worktree `/home/foxfire/code/foxprox/.tmp/worktrees/autonomous-crew` and session dir `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-autonomous-crew--` using the targeted strategy in `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`. I used git history, `progress.md`, `learnings.md`, JSONL user/tool-error extraction, and artifact metadata; I did not read every assistant token.

## Identity and inventory

- Branch/HEAD: `autonomous-crew` at `5967248476807792936b9e43445b07cfaaab274c` (`5967248 close-denied-proxy-requests`).
- Worktree status during audit: `?? reviews/` only in the audited temp worktree; no tracked source changes inspected as dirty.
- Session files: 3 JSONL files, sizes 3.5 MB, 12.8 MB, and 0.8 MB; session dir total 39 MB; 13 subagent artifact files.
- Commit iterations: 51 commits after `main`.
- Progress-ledger cycles: 124 `##` progress entries, 30 `Commit created:` entries, 23 `Review result:` entries, 12 live-validation/smoke pass mentions. Confidence: medium, because ledger entries are finer-grained than commits and not every commit has identical progress phrasing.

## Intervention count and levels

Counting model: excluded initial/restart seed prompts as L0. Counted duplicated human messages because they represented repeated human effort, but noted duplicates. Total counted interventions: **23**. Max level: **L4 debug/product blocker**. Weighted burden: **70** (`L1*1 + L2*2 + L3*3 + L4*5`). Confidence: high for user-message enumeration; classification is interpretive.

| Count | Level | What happened | Evidence |
|---:|---|---|---|
| 2 | L0 seed/restart, not counted | Initial alpha-scope prompt at session start and fork/restart. | JSONL `2026-06-21T16-41-51...jsonl:4`; `2026-06-21T22-19-14...jsonl:5` |
| 3 | L1 continuation/tool retry | Two “retry latest subagent failure and keep working” messages and one later `continue`. | JSONL `...16-41-51...jsonl:1117`, `:1120`; `...22-19-14...jsonl:2986` |
| 8 | L2 directional/status/design | Model-selection correction, alpha-gap status questions, prompt-learning/update-doc request, pause instruction, non-blocking smoke/docs approval, final implementation comparison fork, and one design-discussion turn about denial UX. | JSONL `...16-41-51...jsonl:1138`, `:1304`, `:1306`, `:1319`, `:1325`; `...22-19-14...jsonl:2969`, `:4198`, `:4606`; assessment fork `...01-45-19...jsonl:5` |
| 8 | L3 corrective/scope/completion | User challenged premature stopping, asked about missing live test, asked whether live bwrap/TUN testing was done, asked whether it was production-usable under `docs/initial-impl.md`, requested production launcher/policy config, and decided denied proxy requests should close connections. | JSONL `...16-41-51...jsonl:1313`, `:1316`; `...22-19-14...jsonl:4121`, `:4195`, `:4354`, `:4357`, `:4366`, `:4603`, `:4609` |
| 3 | L4 debug/product blocker | User pasted live failure outputs: CA trust-anchor curl 77; denied `github.com` returned HTTP 403; denial behavior created product semantics concern. | JSONL `...22-19-14...jsonl:4561`, `:4600`, `:4603` |

Notable autonomy failure: the user explicitly asked why the agent stopped before alpha completion (`...16-41-51...jsonl:1313`, `:1316`). The resulting durable learning says verified commits are checkpoints, not stop points (`learnings.md:14`).

## Timeline to full production launcher end-to-end

- **2026-06-21 16:41Z**: Initial instruction to implement entire alpha scope from `docs/implementation-approach-autonomous-crew.md` (JSONL `...16-41-51...jsonl:4`).
- **Commit 4 / `8d5619c` / 2026-06-21T13:16:10-04:00**: First live bwrap/TUN ICMP proof path (`git log`), with progress evidence of bwrap/TUN validation and ping reply (`progress.md:137`). This was proof-level, not production-usable.
- **Commit 39 / `0d0c4b2` / 2026-06-22T17:45:19-04:00**: Audit JSON drain sink, closing a major live-runtime observability gap (`progress.md:1590-1646` by surrounding entry; commit ref from git log).
- **Commit 46 / `dacd69b` / 2026-06-22T18:54:51-04:00**: Setup proxy env injection, last implementation gap before final alpha review (git log; progress around `progress.md:1934-1948`).
- **Commit 47 / `a5e0daa` / 2026-06-22T18:59:38-04:00**: Final alpha review recorded no alpha implementation blockers (`progress.md:1950`). This was alpha-complete by review, but still not a one-command production launcher.
- **Commit 48 / `6136c93` / 2026-06-23T17:09:19-04:00**: Live bwrap/TUN smoke docs/script, after user asked whether live testing had actually been done. Progress says live smoke covered direct HTTP/HTTPS, DNS, UDP/443 QUIC candidate audit, HTTP CONNECT/HTTP/SOCKS proxy bridges, and setup-injected proxy env (`progress.md:1967`).
- **2026-06-25 14:39-14:42Z**: User challenged production usability and asked for “production launcher & policy config file” (JSONL `...22-19-14...jsonl:4354`, `:4357`, `:4366`). This was the key intervention that moved the agent from proof scripts to an end-user launcher.
- **Commit 49 / `36799a5` / 2026-06-25T11:04:57-04:00**: First credible production-ish end-to-end launcher: `foxprox run --config examples/controlled-alpha.toml -- ...`, TOML policy parsing, bwrap/setup orchestration, proxy backends, policy rules, and live curl validation via both injected HTTP CONNECT and transparent TUN TLS (`progress.md:1993`, `progress.md:2003`). This is **iteration 49 of 51 commits** and the best “full production launcher end-to-end” point.
- **Commit 50 / `48c5276` / 2026-06-26T22:40:39-04:00**: Follow-up fix for user-provided CA trust anchor failure (`curl: (77)` at JSONL `...22-19-14...jsonl:4561`).
- **Commit 51 / `5967248` / 2026-06-27T09:58:13-04:00**: Follow-up fix for denied proxy request UX: denied `github.com` now gives `Proxy CONNECT aborted`/connection close instead of origin-like 403 (`progress.md:2017`, `progress.md:2023`; user concern at JSONL `...22-19-14...jsonl:4600`, `:4603`, `:4609`).

Conclusion: production launcher was not reached until **commit 49/51**, roughly four days after initial session start and only after explicit user correction. It became more production-realistic after commits 50 and 51.

## Main struggles

1. **Premature stopping / mistaking checkpoints for completion.** The agent stopped after milestone chunks despite a goal-mode prompt; the user had to ask why it stopped and later to continue. Evidence: JSONL `...16-41-51...jsonl:1313`, `:1316`; learning documented at `learnings.md:14`.
2. **Proof-first implementation drift.** Early work built many proof CLIs and live proofs but did not expose a single production-like launcher until the user asked directly. Evidence: alpha review said no implementation blockers at `progress.md:1950`, live smoke script at `progress.md:1967`, but production launcher only at `progress.md:1993` after user prompt at JSONL `...22-19-14...jsonl:4366`.
3. **Live environment issues surfaced late.** CA certificate mounting and denial behavior only emerged after real `foxprox run` usage. Evidence: CA failure at JSONL `...22-19-14...jsonl:4561`, denial/403 at `:4600`, fix evidence `progress.md:2023`.
4. **Subagent/reviewer instability during launcher phase.** All four preserved subagent artifacts timed out, including launcher context/reviews and implementation assessment. Evidence: `subagent-artifacts/*_meta.json`, e.g. `2cb3530d_context-builder_0_meta.json` exitCode 124, `403d26ed_reviewer_0_meta.json` exitCode 124, `d6f13886_scout_0_meta.json` exitCode 124.
5. **High tool friction.** Extracted 138 tool errors, including memory module failure, missing early ledgers, many exact-edit mismatches, build/clippy/test failures, sandbox git index write blocks, and live command issues. Evidence: tool-error extraction over all JSONL; examples include memory error at `...16-41-51...jsonl:9`, edit mismatch at `:678`, bwrap missing binary path at `:453`, const/MSRV compile failure at `...22-19-14...jsonl:1202`.

## Repeated behavioral patterns

- **Strong incremental verification discipline:** many commits include fmt/check/test/clippy/doc and dependency-tree checks; this kept code quality high despite churn.
- **Reviewer-driven blocker loops:** progress repeatedly records blocker reviews and accepted fixes before commits, effective for security/fail-closed issues.
- **Over-reliance on proofs and internal reassessments:** the agent repeatedly concluded alpha completeness before testing actual user ergonomics.
- **Subagent overuse/fragility in large contexts:** launcher subagents timed out with large inputs and did not produce usable artifacts; parent did manual diff review instead (`progress.md:2010`).
- **Late production empathy:** user-facing failure semantics (CA files, 403 vs connection close) were not specified or discovered until the user pasted live output.

## Specs/prompts that would have helped

- Add an explicit stop rule: “Do not stop after a commit or milestone; after every commit, immediately compare against `docs/initial-impl.md` and continue until a production user can run one command with a config file.” This matches the learning now in `learnings.md:14`.
- Define “alpha complete” as including a one-command launcher (`foxprox run --config ... -- command`), a sample policy file, bwrap/setup orchestration, cert/resolver mount behavior, and a denied-request UX contract.
- Require live end-to-end acceptance before claiming completion: direct transparent HTTP/HTTPS, DNS, explicit HTTP CONNECT, SOCKS, denied request, and CA trust in the same launcher path.
- Tell subagents/reviewers to use bounded, file-targeted review and return partial findings before timeout; the preserved artifacts show 120s timeouts with high input/cache usage.
- Make user-visible denial semantics explicit: policy denials should close or produce a sandbox-helper-consumable denial, not synthesize origin-like 403s.

## Approach effectiveness

Effective overall for deep implementation: 51 commits produced a broad alpha with TUN/bwrap, DNS/TCP/UDP, explicit proxies, audit, resource limits, live smoke docs, and launcher. The progress ledger and commit discipline made recovery and auditing feasible.

Less effective for autonomous product completion: the agent needed repeated human interventions for continuing, live testing, production launcher usability, and final product semantics. The production launcher arrived late (commit 49/51), so the initial strategy optimized architecture/proofs more than end-user completion.

## Confidence and gaps

- Confidence high for intervention counts and commit timeline: all user messages and git commits were extracted directly.
- Confidence medium for “progress-cycle” counts: progress headings are consistent enough for scale but not a perfect iteration metric.
- Confidence medium for tool-error characterization: counted all `isError=true` tool results, but summarized rather than deeply classifying all 138.
- Gap: I did not read every assistant token or every successful command output. Per strategy, I used digests/progress/git/user/tool-error/artifact metadata instead.

## Commands run for this audit

- `read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md`
- `ls` worktree and session directories
- `find`/`du` session inventory; `git status`, `git rev-parse`, `git rev-list`, `git log`
- `jq`/Python JSONL extraction for user messages, tool errors, stop reasons, and tool calls
- `grep`/`read` over `progress.md` and `learnings.md`
- `cat`/`sed` subagent artifact metadata/output summaries

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Wrote a scoped read-only audit for autonomous-crew to /home/foxfire/code/foxprox/docs/session-audits/autonomous-crew.md, with intervention levels/counts, iteration counts, production launcher timeline, struggles, patterns, prompt/spec improvements, effectiveness, confidence/gaps, and evidence paths/line numbers/commit refs."
    }
  ],
  "changedFiles": [
    "/home/foxfire/code/foxprox/docs/session-audits/autonomous-crew.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md",
      "result": "passed",
      "summary": "Loaded the requested targeted audit strategy."
    },
    {
      "command": "find/du/git inventory for autonomous-crew worktree and session dir",
      "result": "passed",
      "summary": "Collected session sizes, artifact count, branch HEAD, status, and 51 commits after main."
    },
    {
      "command": "jq/Python extraction of JSONL user messages, tool errors, stop reasons, and tool calls",
      "result": "passed",
      "summary": "Enumerated 2 seed messages, 23 counted interventions, 138 tool errors, and stop/tool-call distributions."
    },
    {
      "command": "grep/read progress.md and learnings.md for launcher/live/prod/failure/stop evidence",
      "result": "passed",
      "summary": "Located alpha completion, live smoke, controlled-alpha launcher, denial-fix, and learning evidence with line numbers."
    },
    {
      "command": "read subagent-artifacts/*_meta.json and output summaries",
      "result": "passed",
      "summary": "Confirmed preserved launcher/assessment subagents timed out with exitCode 124."
    }
  ],
  "validationOutput": [
    "Audit artifact written to the authoritative output path.",
    "No source files were modified; only the requested audit markdown was written."
  ],
  "residualRisks": [
    "Did not read every assistant token by design; relied on targeted extraction, ledgers, git history, artifact metadata, and selected evidence windows.",
    "Progress-cycle count is approximate because ledger headings do not map one-to-one to implementation iterations."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added autonomous-crew session audit markdown only.",
  "reviewFindings": [
    "no blockers"
  ],
  "manualNotes": "The audited temp worktree had untracked reviews/ before this audit; this audit did not modify that worktree."
}
```