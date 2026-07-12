# Session audit: harness-lab

## Scope and method

- Worktree: `/home/foxfire/code/foxprox/.tmp/worktrees/harness-lab`
- Session dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-harness-lab--`
- Strategy followed: `/home/foxfire/code/foxprox/subagent-session-audit-strategy.md`; used targeted `jq`, `grep`, progress/learnings, artifacts, and git history extraction rather than full-token replay.
- Worktree status at audit time: branch `harness-lab`, HEAD `4978978 Add sandbox host allow rules`; untracked `reviews/` only in the audited worktree.
- Session inventory: 5 JSONL files, 10 artifact files, 14M session dir. One JSONL (`2026-06-25T03-20-50-349Z_019efccb-6bad-746e-8ad8-13f5e65e2911.jsonl`) is a delegated review/planning fork with duplicated inherited user turns; I excluded the duplicated inherited turns and the subagent task prompt from intervention counts.

## Summary findings

- **Intervention count:** 18 real human interventions after excluding initial/restart seeds and delegated subagent prompts.
- **Max intervention level:** L4 debug/product blocker.
- **Intervention burden score:** 52 using the strategy weights (`L1*1 + L2*2 + L3*3 + L4*5`).
- **Implementation iterations:** 81 commits after `main`; 5 JSONL attempts total, or 4 parent-session attempts plus 1 delegated subagent fork. `progress.md` has 110 headings and 78 `Observed result: pass` entries, but some late entries are duplicated, so commit count is the best primary iteration measure.
- **Timeline to full production launcher end-to-end:** true arbitrary-command bwrap sandbox launcher reached at commit **77/81**, `dc69f5c` (`2026-06-25T19:53:11-04:00`), with progress evidence at `progress.md:1240-1258`. It was then made actually usable by user-driven fixes through commit **81/81**, `4978978`, after stdout pollution, CA-store exposure, smoltcp backpressure, and host/domain allow policy were fixed.
- **Approach effectiveness:** high for harness-driven discovery and verification; medium for autonomy/product focus because the agent repeatedly declared alpha done before product-usable launcher criteria and real `curl` usage were satisfied.
- **Confidence:** high on intervention count and commit timeline because all user messages were extracted with `jq` and cross-checked against git/progress. Medium on behavioral causality because I sampled high-signal assistant/tool/progress evidence, not every assistant token.

## Evidence inventory

### Sessions and artifacts

- JSONL files:
  - `2026-06-21T16-41-33-939Z_019eeb0f-11f3-7927-b9a9-1af4c3aff426.jsonl` (642,063 bytes)
  - `2026-06-21T22-35-54-194Z_019eec53-79d2-7713-911f-7a1ac2a777e9.jsonl` (1,511,097 bytes)
  - `2026-06-21T23-59-01-919Z_019eec9f-951f-762e-a374-a78695ad0f96.jsonl` (1,200,733 bytes)
  - `2026-06-22T01-02-37-937Z_019eecd9-cf71-7f43-983d-2b7de453b785.jsonl` (5,509,410 bytes)
  - `2026-06-25T03-20-50-349Z_019efccb-6bad-746e-8ad8-13f5e65e2911.jsonl` (4,380,585 bytes; delegated fork)
- Artifact evidence:
  - `subagent-artifacts/1fbfaebc_reviewer_0_output.md`: reviewer said there was no blocker justifying stopping and identified remaining feasible alpha gaps: TCP bridge factoring, audit backpressure/resource limits, end-to-end TLS/QUIC TUN smokes, and DNS/ICMP depth.
  - `subagent-artifacts/c47c0fad_scout_0_output.md` and `d6045462_planner_0_output.md`: timed out after 120s; useful only as evidence that attempted delegated scout/planner work failed.
- Worktree ledgers:
  - `progress.md`: 1,347 lines, 171,833 bytes.
  - `learnings.md`: 63 lines, 6,227 bytes.

### Source/spec context that shaped the struggle

- `docs/implementation-approach-harness-lab.md` explicitly required autonomous cycles, real harness evidence, exact progress logging, and “a verified commit is a checkpoint, not a completion signal”; stop only when documented success criteria are complete.
- `docs/initial-impl.md` frames alpha around transparent TUN networking, explicit HTTP/SOCKS proxy modes, shared policy/audit/DNS/egress, bwrap-compatible `foxproxsetup` with temporary `CAP_NET_ADMIN`, fail-closed malformed paths, DNS correlation, direct external DNS denial, TLS SNI behavior, QUIC classification, and a smoltcp-based TCP forwarding proof.

## Intervention table

| # | Timestamp | Level | User signal | Impact/evidence |
|---:|---|---|---|---|
| 1 | 2026-06-21T22:53:30Z | L3 corrective/autonomy | “Work in autonomous cycles… Do not final-answer after the first successful commit.” | Follows session 1 ending after early commits; stop reason in `2026-06-21T16-41...jsonl` claimed only foundation commits. Led to commit `7b136c8 Clarify autonomous continuation stop rules`. |
| 2 | 2026-06-22T01:24:34Z | L2 directional | “what is next?” | Agent needed user prompt to select next approach. |
| 3 | 2026-06-22T01:25:05Z | L2 directional | “go ahead with that approach” | User approved agent proposal instead of agent proceeding. |
| 4 | 2026-06-22T21:28:51Z | L1 continue | “continue” | Autonomy failure signal. |
| 5 | 2026-06-22T21:52:53Z | L1 continue | “continue working until you absolutely need my input. make decisions yourself” | Repeated autonomy correction. |
| 6 | 2026-06-22T22:18:07Z | L1 continue | “continue until you absolutely need my input again. make decisions yourself” | Repeated autonomy correction. |
| 7 | 2026-06-25T02:57:55Z | L3 production/e2e corrective | “continue… completed alpha scope… full authorization to run real end to end tests with real sandboxes & network tests” | Forced real sandbox/network validation; later progress includes real ping/QUIC/TLS/direct DNS smokes (`progress.md:1136-1209`). |
| 8 | 2026-06-25T03:19:01Z | L3 scope corrective | Asked whether “async long lived broker lifecycle” is alpha. | Exposed that previous “complete” claim missed lifecycle/product shape; led to mixed long-lived broker session smoke (`progress.md:1214-1235`, commit `499027e`). |
| 9 | 2026-06-25T03:19:59Z | L3 scope corrective | “complete alpha scope means all scope in @docs/initial-impl.md implemented” | Re-anchored completion criteria to spec, not harness proof subset. |
| 10 | 2026-06-25T14:36:50Z | L3 product completion check | Asked if nothing left for usable real bwrap prototype. | Revealed “alpha complete” still lacked user-facing launcher. |
| 11 | 2026-06-25T14:40:19Z | L3 stop-criteria corrective | “continue… until the usable sandboxing prototype… is complete” | Directly set product launcher as stop criterion. |
| 12 | 2026-06-25T23:40:26Z | L3 stop-criteria corrective | Repeated usable sandbox prototype stop criterion. | Preceded production-ish sandbox launcher commit `dc69f5c`; progress `progress.md:1240-1258`. |
| 13 | 2026-06-27T01:50:25Z | L2 usability | Asked for “30s of how to use the prototype in my own bwrap environment.” | Exposed usability/documentation need. |
| 14 | 2026-06-27T01:52:56Z | L4 debug/product blocker | Pasted `foxprox-lab sandbox ... python gethostbyname(example.com)` output with setup env exports and unsupported packet audit. | Led to quiet setup-env fix; progress records user feedback and fix at `progress.md:1261-1268`, commit `47734f3`. |
| 15 | 2026-06-27T01:55:50Z | L4 debug/usability | Asked what “not an IPv4 packet” means. | Clarified noisy non-IPv4/IPv6-ish TUN audit wording; included in CA-store fix entry `progress.md:1281-1289`. |
| 16 | 2026-06-27T02:34:17Z | L4 debug/product blocker | Pasted `curl https://github.com` output; CONNECT happened but curl failed due CA trust anchors. | Led to host CA store bind fix `da24d06`; evidence `progress.md:1281-1289`. |
| 17 | 2026-06-27T02:37:55Z | L4 debug/product blocker | Pasted repeated `curl https://github.com` output; large page failed with `smoltcp TCP socket cannot send yet`. | Led to response buffering/backpressure fix `3c7bdf9`; evidence `progress.md:1303-1311`. |
| 18 | 2026-06-27T02:47:29Z | L2 product/feature request | “can i allow just specific domains/hosts?” | Led to `--allow-host`/`--allow-domain` policy flags, commit `4978978`; evidence `progress.md:1325-1334`. |

Counts by level: **L1=3, L2=4, L3=7, L4=4**. Total `3+4+7+4 = 18`; weighted burden `3 + 8 + 21 + 20 = 52`.

## Iteration counts and milestone timeline

### Primary counts

- **Commits after main:** 81 (`git rev-list --count main..harness-lab`).
- **Session attempts:** 5 JSONL files total; 4 parent/restart sessions plus 1 delegated subagent fork.
- **Progress-cycle estimate:** `progress.md` has 110 `##` headings and 78 `Observed result: pass` entries. Confidence medium because late launcher entries are duplicated (`progress.md:1261-1347` repeats four sections).

### Production launcher end-to-end timeline

1. **Early harness foundation, not product launcher**
   - Commits 1-44 (`a9e0994` through `4a704ad`) built deterministic and bwrap/TUN smokes, setup helper, UDP/DNS/TCP/HTTP proxy/TLS/QUIC policy proofs.
   - The agent still stopped early multiple times; examples: session stop in `2026-06-21T23-59...jsonl` said turn/runtime budget hit before entire alpha scope, despite prompt saying continue until all milestones.

2. **Reviewer identified remaining alpha gaps**
   - `subagent-artifacts/1fbfaebc_reviewer_0_output.md` flagged no blocker to stopping and called out feasible gaps: TCP bridge factoring, audit backpressure/resource limits, transparent TLS/QUIC TUN smokes, DNS/ICMP depth.

3. **First “alpha complete” claim before product usability**
   - Commit 74 `d7767a9 Record final alpha verification`; `progress.md:1201-1211` records broad final alpha sweep and says no harness-lab alpha gap remains, but also says future work includes async long-lived broker lifecycle and production hardening.
   - User intervention at 2026-06-25T03:19 challenged “async long-lived broker lifecycle” as likely alpha.

4. **Long-lived mixed broker proof**
   - Commit 75 `499027e Add mixed broker session smoke`; `progress.md:1214-1224` records one sandbox process and one host broker loop handling mixed ICMP, UDP, DNS, QUIC, TCP/HTTP, HTTP deny, TLS deny, and direct DNS deny.
   - Commit 76 `7821f6d Record long-lived alpha verification`; `progress.md:1227-1237` says docs/initial-impl alpha is implemented including long-lived broker lifecycle behavior.

5. **First credible arbitrary-command bwrap sandbox launcher**
   - Commit 77 `dc69f5c Add usable bwrap sandbox prototype`, `2026-06-25T19:53:11-04:00`.
   - Evidence `progress.md:1240-1258`: added `foxprox-lab sandbox ... -- target args...`; bwrap `--unshare-net`; temporary setup capabilities; `/dev/net/tun`; per-session handoff socket; sandbox `/etc/resolv.conf`; long-lived broker loop until target exits; proxy listeners; upstream DNS; real prototype check. This is the first point satisfying “full production launcher end-to-end” in the practical sense.

6. **User-driven usability fixes after first launcher**
   - Commit 78 `47734f3` (`progress.md:1261-1268`): suppressed setup-helper env export pollution so target stdout is usable.
   - Commit 79 `da24d06` (`progress.md:1281-1289`): exposed host CA stores; verified `curl -I https://github.com` produced `HTTP/2 200`.
   - Commit 80 `3c7bdf9` (`progress.md:1303-1311`): buffered smoltcp responses; verified full `curl -L https://github.com` downloaded 564,569 bytes without backpressure error.
   - Commit 81 `4978978` (`progress.md:1325-1334`): added `--allow-host`/`--allow-domain`; verified GitHub allow and example.com deny.

**Conclusion:** If “end-to-end” means an arbitrary target can run in a real bwrap environment with a long-lived broker, count completion at **commit 77/81**. If “usable for realistic HTTPS curl and host-specific policy” is required, count completion at **commit 81/81**.

## Main struggles

1. **Completion criteria drift from harness proof to product usability**
   - Multiple progress entries claimed alpha completeness before a user-facing sandbox launcher existed (`progress.md:1201-1211`, then `1227-1237`). User had to clarify that alpha meant all of `docs/initial-impl.md` and a usable real bwrap prototype.

2. **Autonomy/stop-rule failures**
   - The agent stopped after initial commits and required repeated “continue” prompts. Stop reasons in JSONL include final summaries after partial commit batches, and user turns at 2026-06-22T21:28/21:52/22:18 repeat “continue”/“make decisions yourself.”

3. **Real bwrap/TUN capability constraints**
   - `learnings.md:13-18`: spawning `/usr/bin/ip`/`/bin/sh` from `foxproxsetup` inside bwrap failed with `ENOENT`, pushing implementation toward direct `/dev/net/tun` ioctl setup.
   - `learnings.md:31-34`: `ping` lacked `CAP_NET_RAW` after setup capability drop; later fixed for real ping smoke by granting `CAP_NET_RAW` where needed (`learnings.md:57-62`, `progress.md:1136-1144`).

4. **Protocol/runtime hardening discovered only by live user runs**
   - Setup helper polluted target stdout until user pasted actual output (`progress.md:1261-1268`).
   - `curl` failed due missing CA bundle bind mounts (`progress.md:1281-1289`).
   - Full HTTPS page failed due smoltcp send backpressure (`progress.md:1303-1311`).

5. **Edit/tool friction and compile churn**
   - Tool-error extraction showed repeated edit failures from non-unique or stale text, Rust borrow/type errors, command syntax errors, and pi-auto sandbox blocked mixed review/write sequences.
   - Top tool-call counts were heavily concentrated in `crates/foxprox-cli/src/main.rs` (188 edits, 116 reads), suggesting the launcher/harness grew large and mechanically difficult to edit safely.

## Repeated behavioral patterns

- **Declared completion based on verification breadth but not user-run realism.** The agent treated local smokes and progress sweeps as sufficient until the user forced arbitrary command launcher and live `curl` checks.
- **Asked/paused for decisions despite autonomy instructions.** The user had to say “go ahead,” “continue,” and “make decisions yourself.”
- **Spec under-reading or selective interpretation.** The user had to restate that alpha scope meant all of `docs/initial-impl.md`, especially long-lived lifecycle and usable bwrap prototype.
- **Good harness discipline once a gap was selected.** Each major gap was converted into a focused smoke/test, logged in `progress.md`, and committed with verification.
- **Large CLI/harness monolith caused friction.** Many repeated edits and compile fixes landed in `crates/foxprox-cli/src/main.rs` before factoring caught up.

## What specs/prompts could have improved

- Add explicit stop criterion: “Do not claim alpha complete until a fresh-shell user can run `foxprox-lab sandbox --proxy-env -- curl -I https://github.com` and get target stdout/stderr behavior suitable for normal CLI use, with audit separated.”
- Make “full production launcher end-to-end” a named milestone from the start, not post-alpha hardening: arbitrary command, real bwrap namespace, TUN fd handoff, long-lived host broker, proxy env, upstream DNS, CA stores, bounded TCP response buffering, clear audit, and domain/host allow examples.
- Require a final user-emulation smoke: run the exact README “30s usage” commands from a clean shell and record stdout/stderr snippets.
- Add an anti-stopping prompt: after every “complete” claim, re-read `docs/initial-impl.md` and `progress.md` for any item labeled future/post-alpha; if the item is user-observable launcher behavior, continue instead of final-answering.
- Encourage smaller module boundaries earlier: if a file exceeds a high edit-churn threshold, factor before adding more harness paths.

## Approach effectiveness

- **Effective:** The harness-lab strategy produced strong reproducible evidence: local deterministic tests, bwrap/TUN smokes, direct DNS denial, TLS/QUIC smokes, long-lived mixed broker, and real sandbox launcher checks. Progress/learnings were high-signal and made reconstruction much cheaper than JSONL replay.
- **Ineffective/insufficient:** It over-optimized for local harness proofs and under-specified product-facing launcher usability. Human live runs revealed issues not captured by agent-chosen smokes: stdout pollution, CA bundle absence, large-response backpressure, and host-specific policy ergonomics.
- **Net:** Strong implementation strategy with repeated scope/autonomy interventions; final result appears much better because the user insisted on real end-to-end production-launcher behavior.

## Confidence and gaps

- **High confidence:** intervention count/levels, commit count, launcher completion commits, major user-driven fixes. Evidence came from complete user-message extraction, git history, `progress.md`, `learnings.md`, and artifacts.
- **Medium confidence:** exact causal mapping from each user turn to code changes; I sampled stop reasons/tool errors and progress rather than reading all assistant content.
- **Known gaps:** I did not replay every assistant token or successful tool output. Progress entries contain duplicated late sections (`progress.md:1261-1347`), so heading/pass counts are approximate. Delegated planner/scout artifacts timed out, limiting their usefulness.

## Commands run for audit

- `du -sh`, `find`, `wc -lc` over session dir and `progress.md`/`learnings.md`.
- `git -C /home/foxfire/code/foxprox/.tmp/worktrees/harness-lab status --short --branch`, `git rev-list --count main..harness-lab`, and `git log --oneline/--format --reverse main..harness-lab`.
- `jq` extraction of user turns, assistant stop reasons, tool errors, tool-call frequencies, and final `pi-auto-digest` entries.
- `grep`/`nl` over `progress.md`, `learnings.md`, `docs/initial-impl.md`, and `docs/implementation-approach-harness-lab.md`.
- Read artifact outputs/meta in `subagent-artifacts/`.
