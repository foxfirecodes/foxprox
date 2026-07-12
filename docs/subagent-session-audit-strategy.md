# Pi session audit strategy for foxprox worktree agents

## Scope inspected

Read-only inspection was performed for:

- Pi session roots under `/home/foxfire/.pi/agent/sessions` matching `--home-foxfire-code-foxprox*--`.
- Git worktrees under `/home/foxfire/code/foxprox/.tmp/worktrees`.

Observed foxprox worktree session directories:

| Worktree/session | JSONL files | Artifact files | Approx size | Severity notes |
|---|---:|---:|---:|---|
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox--` | 7 | 29 | 8.3M | main/parent context; use for prompt changes and orchestration decisions |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-autonomous-crew--` | 3 | 13 | 39M | high intervention signal around stopping early and production launcher follow-up |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-contract-boundary--` | 4 | 22 | 18M | medium/high intervention signal; repeated “continue until alpha complete” nudges |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-harness-lab--` | 5 | 10 | 14M | user-supplied live smoke failures are important |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-observability-ledger--` | 3 | 178 | 215M | highest audit cost; artifacts are likely essential to avoid huge JSONL rereads |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-security-invariants--` | 6 | 16 | 11M | early delegated-subagent session mixed into same directory; beware duplicate prompt lines |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-verification-kernel--` | 6 | 4 | 16M | explicit stop-rule/turn-budget prompt lesson signal |
| `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-vertical-evidence--` | 4 | 16 | 16M | production launcher and output-ordering follow-up signal |

Observed git worktrees:

- `/home/foxfire/code/foxprox/.tmp/worktrees/autonomous-crew` branch `autonomous-crew`, HEAD `5967248476807792936b9e43445b07cfaaab274c`, untracked `reviews/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/contract-boundary` branch `contract-boundary`, HEAD `12dcc029277246ab5f854c9565be19ffa45af8ab`, untracked `reviews/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/harness-lab` branch `harness-lab`, HEAD `49789786d3bde35c07df4cd025b7b5c130275b72`, untracked `reviews/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/observability-ledger` branch `observability-ledger`, HEAD `405277139d8082d02c8df0136f4251e5d15b1608`, untracked `context.md`, `reviews/`, `subagents/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/security-invariants` branch `security-invariants`, HEAD `da2264cc28fc9134207dfe685ba47ec7747d98cd`, untracked `reviews/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel` branch `verification-kernel`, HEAD `aebbe2f06b51ad64d985b8ee8bfd7627bcab923a`, untracked `reviews/`.
- `/home/foxfire/code/foxprox/.tmp/worktrees/vertical-evidence` branch `vertical-evidence`, HEAD `89c5bf6586be4eacb2ac76e6f31cd31103d8a2f4`, untracked `policy.toml`, `reviews/`.

All temp worktrees have `progress.md` and `learnings.md`; these are the highest-value first pass before JSONL.

## Recommended audit order

1. **Inventory sessions and sizes** so large sessions are handled with targeted extraction only.
2. **Read worktree `progress.md` and `learnings.md` summaries first**, especially final 200-400 lines and grep hits for launcher/end-to-end/failure terms.
3. **Extract JSONL metadata and human-visible turns only**: session timestamp/cwd, user messages, assistant stop reasons, tool calls/results names, failed tool results, and final `pi-auto-digest` entries.
4. **Use `subagent-artifacts` as reviewer/intervention evidence**. Reviewer outputs often compress problems without reading the parent JSONL.
5. **Cross-check with git history**: commit count and commit subjects show iteration granularity better than token volume.
6. **Only then sample raw assistant content around anomalies**: user corrections, `isError=true`, `stopReason`, failed commands, “why did you stop”, “continue”, “production launcher”, “bwrap”, “TUN”.

## Concrete commands

### Session/worktree inventory

```bash
root=/home/foxfire/.pi/agent/sessions
find "$root" -maxdepth 1 -type d -name '--home-foxfire-code-foxprox*--' | sort |
while read -r d; do
  printf '%-82s jsonl=%-2s artifacts=%-3s size=%s\n' \
    "${d##*/}" \
    "$(find "$d" -maxdepth 1 -name '*.jsonl' | wc -l)" \
    "$(find "$d/subagent-artifacts" -maxdepth 1 -type f 2>/dev/null | wc -l)" \
    "$(du -sh "$d" | cut -f1)"
done
```

```bash
cd /home/foxfire/code/foxprox
git worktree list --porcelain
for d in .tmp/worktrees/*; do
  [ -d "$d" ] || continue
  echo "### $d"
  git -C "$d" status --short --branch | sed -n '1,8p'
  printf 'commits after main: '
  git rev-list --count main.."${d##*/}" 2>/dev/null || true
done
```

### Cheap JSONL structure check

```bash
f=/path/to/session.jsonl
wc -l "$f"
jq -r '.type' "$f" | sort | uniq -c
jq -r 'select(.type=="custom") | .customType' "$f" | sort | uniq -c
```

Known schema from sampled file:

- `type=session` has `id`, `timestamp`, `cwd`.
- `type=model_change` has provider/model.
- `type=thinking_level_change` has `thinkingLevel`.
- `type=message` wraps `.message.role`, `.message.content[]`, `.message.stopReason`, `.message.usage`, `.message.model`.
- Tool calls are assistant content items with `type=toolCall`, `name`, and `arguments`.
- Tool results are `message.role=="toolResult"` with `toolName`, `isError`, `content[].text`.
- `type=custom`, `customType=pi-auto-digest` has `.data.digest` and is cumulative/repetitive.

### Extract all human interventions without assistant tokens

```bash
find /home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-WORKTREE-- \
  -maxdepth 1 -name '*.jsonl' -print0 |
xargs -0 jq -r '
  select(.type=="message" and .message.role=="user") |
  [.timestamp, (.message.content | map(select(.type=="text") | .text) | join(" ") | gsub("\n";" ") | .[0:240])] | @tsv
'
```

Classify user messages:

- **Initial/restart seed**: contains `Your goal is to implement this project's entire alpha scope` or `Implementation approach:`. Count as session/restart, not intervention.
- **Simple continuation**: exact-ish `continue`, `continue working`, `continuea continue`. Count as low intervention; it proves the agent stopped before final scope.
- **Corrective intervention**: user gives a missing requirement, rejects an answer, asks “why did you stop?”, “what decision do you need?”, “go ahead with option”. Count as medium/high depending on impact.
- **Production/end-to-end intervention**: user insists on bwrap/TUN/live tests/production launcher/real curl. Count as high because it changes or clarifies completion criteria.
- **Debug evidence injection**: user pastes command output, audit logs, error messages. Count as high if it leads to code changes or reveals unusable behavior.

Useful classifier grep:

```bash
jq -r 'select(.type=="message" and .message.role=="user") |
  [.timestamp, (.message.content|map(select(.type=="text")|.text)|join(" ")|gsub("\n";" "))] | @tsv' *.jsonl |
grep -Ein 'why did you stop|continue|what is next|go ahead|option|bwrap|tun|live test|production launcher|real sandbox|curl|example\.com|github\.com|not implemented|alpha scope|complete|done|error|panic|failed|audit event'
```

### Extract failures and tool friction

```bash
find SESSION_DIR -maxdepth 1 -name '*.jsonl' -print0 |
xargs -0 jq -r '
  select(.type=="message" and .message.role=="toolResult" and (.message.isError==true)) |
  [.timestamp, .message.toolName, (.message.content|map(.text // "")|join(" ")|gsub("\n";" ")|.[0:300])] | @tsv
'
```

```bash
find SESSION_DIR -maxdepth 1 -name '*.jsonl' -print0 |
xargs -0 jq -r '
  select(.type=="message" and .message.role=="assistant") |
  .message.content[]? | select(.type=="toolCall") |
  [.name, (.arguments.command // .arguments.path // (.arguments|tostring) | tostring | .[0:160])] | @tsv
' | sort | uniq -c | sort -nr | head -80
```

### Use digests as indexes, not truth

```bash
for f in SESSION_DIR/*.jsonl; do
  echo "### $f"
  jq -r 'select(.type=="custom" and .customType=="pi-auto-digest") | .data.digest' "$f" | tail -1
  echo
done
```

Pitfall: `pi-auto-digest` entries are cumulative and numerous; counting them overstates work. Use the last digest per file as a table of contents, then jump to exact user/tool-result lines.

### Progress/learnings and implementation struggle signals

```bash
wt=/home/foxfire/code/foxprox/.tmp/worktrees/WORKTREE
printf 'progress bytes/lines: '; wc -lc "$wt/progress.md"
printf 'learnings bytes/lines: '; wc -lc "$wt/learnings.md"

grep -RInE 'launcher|end-to-end|e2e|smoke|production|bwrap|TUN|tun|curl|example\.com|github\.com|alpha scope|complete|done|remaining|blocked|stopped|stop rule|turn budget|decision|authorization|rootless|CAP_NET_ADMIN|audit event|unsupported|timeout|flaky|panic|error|fail|clippy|fmt' \
  "$wt/progress.md" "$wt/learnings.md" | sed -n '1,240p'
```

Observed rough first-pass signals from `progress.md`/`learnings.md` grep counts:

| Worktree | Commits after main | Launcher/smoke mentions | Failure/error mentions | Audit interpretation |
|---|---:|---:|---:|---|
| autonomous-crew | 51 | 125 | 289 | many corrections relative to low commit count; inspect stop/production-launcher turns |
| contract-boundary | 205 | 138 | 328 | many small commits; inspect decision/escalation and repeated continue prompts |
| harness-lab | 81 | 459 | 145 | heavy live-test/smoke focus; inspect pasted user failures |
| observability-ledger | 269 | 245 | 1236 | largest struggle surface; use artifacts/digests before raw JSONL |
| security-invariants | 109 | 81 | 492 | likely security/fail-closed friction plus launcher mismatch late |
| verification-kernel | 120 | 332 | 518 | stop-rule and turn-budget lessons are central |
| vertical-evidence | 99 | 297 | 542 | production launcher usability/output issues late |

Treat these as triage only, not final counts: progress formats differ heavily by worktree.

## Reasonable counting model

### Iteration count

Use three tiers and report all three when possible:

1. **Session attempts**: number of JSONL files per worktree. Good for restart/fork count.
2. **Verified implementation iterations**: number of commits after `main`, adjusted downward for pure ledger/doc commits if needed. Good primary iteration count because the workflow required commit-after-verified-change.
3. **Operational cycles**: count progress entries containing objective/check/commit/result markers. Use only when formatting is consistent; otherwise sample and estimate.

Recommended formula:

```text
iteration_count = commits_after_main
session_attempts = count(jsonl files)
cycle_estimate = count of progress.md headings/check/result entries, with confidence note
```

If commit count is high, group by day or subject prefix to avoid inflating “iterations” with mechanical fix commits.

### Intervention count/level

Count only user messages after removing initial seed/restart messages. Then split:

- `L0` not counted: initial prompt, duplicated fork seed, generated subagent task text.
- `L1 continue`: user only says continue/keep working. Low severity but important autonomy failure signal.
- `L2 directional`: user selects among options, approves sensitive path, asks “what next/highest leverage”, tells agent to commit/update docs.
- `L3 corrective`: user corrects scope/completion criteria, points to `docs/initial-impl.md`, insists on live bwrap/TUN testing, says not done.
- `L4 debug/product blocker`: user provides failing command output/logs or identifies product unusability, e.g. production launcher missing, curl cannot work transparently, output missing/misordered.

Report per worktree as:

```text
interventions_total = L1+L2+L3+L4
intervention_level = max level observed
intervention_burden = weighted score: L1*1 + L2*2 + L3*3 + L4*5
confidence = high if all user messages were classified; medium if grep-based; low if sampled only
```

### “Full production launcher end-to-end” completion iteration

Look for the first point where all are true:

1. Code contains a dedicated production-ish launcher/wrapper/CLI path, not just lab scripts.
2. User can run an arbitrary command in a bwrap/sandbox environment.
3. Network behavior is transparent enough for real `curl example.com`/similar, or limitation is explicitly accepted.
4. Audit/log output does not hide the child command output and has usable config/policy examples.
5. The agent ran or documented an end-to-end smoke test with actual command output.

Signals:

```bash
grep -RInE 'production launcher|wrapper|foxprox.*(run|sandbox|launch)|bwrap|curl|example\.com|github\.com|proxy-env|policy.*toml|sample config|end-to-end|E2E|smoke' \
  /home/foxfire/code/foxprox/.tmp/worktrees/WORKTREE/progress.md \
  /home/foxfire/code/foxprox/.tmp/worktrees/WORKTREE/learnings.md
```

Then map the line date/commit hash in `progress.md` back to:

```bash
git -C /home/foxfire/code/foxprox/.tmp/worktrees/WORKTREE log --oneline --decorate --reverse main..WORKTREE
```

Report “reached by commit N of M” and include the first commit hash where launcher end-to-end is credibly complete. If the user later reports a real failure, move the completion point after the fix.

## Signals to extract from JSONL

High-value, low-token fields:

- Session identity: `.timestamp`, `.cwd`, filename.
- Model/thinking: `.type==model_change`, `.type==thinking_level_change` for capability differences.
- User text: all `.message.role=="user"` text.
- Assistant stop reasons: `.message.stopReason`, especially `toolUse`, `endTurn`, max turn/token stops.
- Tool calls: names and command/path arguments, not full outputs.
- Tool errors: `.message.role=="toolResult" and .message.isError==true`.
- Final assistant messages: last assistant content text per JSONL; often contains what the agent believed was done.
- Last `pi-auto-digest` per JSONL.
- `subagent-artifacts/*_output.md` and `*_meta.json`: reviewer findings, scout summaries, model failures.

Avoid reading/counting:

- Assistant `thinking` blocks.
- Full successful tool outputs unless a command is directly relevant.
- Every `pi-auto-digest`; they are repeated snapshots.
- Long source file reads embedded as tool results; extract only filenames and later inspect repo files directly if needed.

## Pitfalls

- **Session directory names are escaped paths**, e.g. `/home/foxfire/code/foxprox/.tmp/worktrees/verification-kernel` maps to `--home-foxfire-code-foxprox-.tmp-worktrees-verification-kernel--`.
- **Fork/restart prompts duplicate initial user text**. Do not count these as interventions.
- **Subagent task prompts can appear as user messages** in delegated sessions; classify them as L0 unless they represent real human correction.
- **`continue` is low semantic content but strong autonomy evidence**: count separately from corrective interventions.
- **Progress ledger formats differ**. Some worktrees have hundreds of bullet entries but few headings; grep counts are triage, not facts.
- **Git commit count can overcount tiny fixups** and undercount uncommitted final work. Cross-check `progress.md` and `git status`.
- **User-pasted command output may be the most important evidence** because it captures real end-to-end failures not present in repo tests.
- **Large observability-ledger JSONL files are costly**; start with artifacts, final digests, user lines, tool errors.
- **Completion claims are not completion evidence**. Require command output or a user-confirmed working invocation for the production launcher.

## Compact audit prompt template for one worktree

```text
Task: Audit the foxprox WORKTREE Pi sessions without reading every token.

Scope:
- Worktree: /home/foxfire/code/foxprox/.tmp/worktrees/WORKTREE
- Session dir: /home/foxfire/.pi/agent/sessions/SESSION_DIR_NAME
- Do not modify files.

Goal:
Infer intervention count/level, implementation iteration count to reach full production launcher end-to-end, major struggles, repeated bugs/behavior patterns, and prompt/spec lessons.

Required method:
1. Inventory JSONL files, artifact files, sizes, branch HEAD, git status, and commits after main.
2. Read/summarize progress.md and learnings.md using grep around launcher/end-to-end/bwrap/TUN/curl/alpha/fail/error/stop/decision terms.
3. Extract all JSONL user messages and classify them as L0 seed/restart, L1 continue, L2 directional, L3 corrective, L4 debug/product blocker.
4. Extract JSONL tool errors, assistant stop reasons, tool-call command names, final digest per file, and relevant artifact reviewer outputs.
5. Determine the first credible commit/date where production launcher end-to-end was complete; if later user failures invalidate it, move to the fixing commit/date.
6. Return evidence-backed findings with paths and line numbers where available.

Output format:
- Worktree identity: branch, HEAD, dirty/untracked files, session files.
- Iteration counts: JSONL sessions, commits after main, progress-cycle estimate with confidence.
- Intervention table: timestamp, class L0-L4, user text summary, impact, evidence path/file.
- Production launcher timeline: first requested, first implemented/claimed, first verified, later failures/fixes.
- Major struggles: grouped by theme with severity and evidence.
- Repeated behavioral patterns: stopping early, asking for decisions already in spec, avoiding live tests, launcher/config gaps, etc.
- Prompt/spec lessons: concrete wording or workflow changes that would have reduced interventions.
- Residual risks/confidence: what was not read and why.
```

## Acceptance evidence

Review findings:

- medium: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-observability-ledger--` is ~215M with 178 artifact files; a full-token audit would be wasteful and likely error-prone. Use artifacts/digests/user/tool-error extraction first.
- medium: Multiple worktrees show repeated human `continue`/completion/prod-launcher interventions in JSONL user turns; intervention counts must exclude restart seed prompts but preserve autonomy-failure signals.
- low: All temp worktrees have large `progress.md`/`learnings.md`; these should be first-pass evidence, but inconsistent formatting makes raw heading counts unreliable.

Residual risks:

- This strategy inspected structure and sampled schema/signals; it did not perform a complete per-worktree audit or read every `progress.md`/`learnings.md` line.
- Count examples are triage counts, not final intervention/iteration figures.

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Wrote concrete findings with paths, observed sizes/counts, severity-tagged review findings, residual risks, commands, heuristics, JSONL signals, counting model, pitfalls, and one-worktree audit prompt to /home/foxfire/code/foxprox/subagent-session-audit-strategy.md"
    }
  ],
  "changedFiles": [
    "/home/foxfire/code/foxprox/subagent-session-audit-strategy.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "ls /home/foxfire/.pi/agent/sessions and ls /home/foxfire/code/foxprox/.tmp/worktrees",
      "result": "passed",
      "summary": "Confirmed foxprox main and seven temp worktree session directories plus seven git worktrees."
    },
    {
      "command": "find /home/foxfire/.pi/agent/sessions -maxdepth 1 -type d -name '--home-foxfire-code-foxprox*--' ...",
      "result": "passed",
      "summary": "Collected JSONL counts, artifact counts, and directory sizes."
    },
    {
      "command": "git worktree list --porcelain and git -C worktree status --short --branch",
      "result": "passed",
      "summary": "Collected branch, HEAD, and untracked-file context for each foxprox worktree."
    },
    {
      "command": "jq schema/type sampling on verification-kernel JSONL",
      "result": "passed",
      "summary": "Identified message/custom/session schema and useful extraction fields."
    },
    {
      "command": "grep/jq triage counts over progress.md, learnings.md, and user messages",
      "result": "passed",
      "summary": "Derived practical heuristics and observed intervention/launcher/failure signals."
    }
  ],
  "validationOutput": [
    "Output file written at the authoritative path with acceptance-report block included."
  ],
  "residualRisks": [
    "Strategy-level inspection only; final per-worktree audit counts require running the proposed classifiers and reading selected evidence windows.",
    "Triage grep counts are approximate because progress/learnings formats differ across worktrees."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added a read-only audit strategy markdown artifact; no repository source files modified.",
  "reviewFindings": [
    "medium: /home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-observability-ledger-- - 215M session directory with 178 artifacts; audit should avoid full-token reading and use targeted extraction.",
    "medium: foxprox worktree JSONL user messages - repeated continue/completion/production-launcher prompts indicate interventions must be classified by severity, not simply counted.",
    "low: /home/foxfire/code/foxprox/.tmp/worktrees/*/progress.md and learnings.md - inconsistent ledger formatting makes heading-count iteration estimates unreliable without confidence notes."
  ],
  "manualNotes": "No source edits were made. The requested artifact itself is listed under changedFiles because it was written as required."
}
```
