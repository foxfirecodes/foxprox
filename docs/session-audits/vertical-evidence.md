# Vertical-evidence worktree session audit

Audit target: `/home/foxfire/code/foxprox/.tmp/worktrees/vertical-evidence`  
Session dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-vertical-evidence--`  
Method: targeted extraction per `subagent-session-audit-strategy.md`; I used worktree ledgers, git history, JSONL user-message/tool-error extraction, final digests, and reviewer artifacts rather than reading every token.

## Worktree/session identity

- Branch: `vertical-evidence`.
- HEAD at audit: `89c5bf6586be4eacb2ac76e6f31cd31103d8a2f4` (`89c5bf6 Normalize broker DNS for bwrap policies`).
- Dirty/untracked at audit: `?? policy.toml`, `?? reviews/` in the worktree.
- Session files: 4 JSONL files, 16 artifact files, session dir size about `16M`.
  - `2026-06-21T16-41-14-048Z_019eeb0e-c440-7cbf-b05e-4dcd88932413.jsonl` — 639,469 bytes.
  - `2026-06-21T22-34-04-518Z_019eec51-cd66-772e-8bf3-b245ae2c0b2a.jsonl` — 1,505,234 bytes.
  - `2026-06-21T23-58-48-764Z_019eec9f-61bc-72e3-9711-282244ff31cf.jsonl` — 1,229,595 bytes.
  - `2026-06-22T01-02-19-180Z_019eecd9-862c-7d3c-aa7b-0768912f2120.jsonl` — 8,898,272 bytes.
- Reviewer artifacts: five reviewer attempts under `subagent-artifacts/`; one reviewer output was empty with meta exit code 143 (`22318613_reviewer_0_meta.json`), four outputs contain useful review conclusions.

## Iteration counts

| Count type | Count | Evidence / confidence |
|---|---:|---|
| JSONL session attempts | 4 | Four JSONL files in the session dir. High confidence. |
| Git implementation iterations | 99 commits after `main` | `git rev-list --count main..vertical-evidence` = 99. High confidence. |
| Progress ledger cycle estimate | 178 progress headings: 76 `Session` headings, 101 `Slice Evidence`, 1 `Live Evidence` | `progress.md` headings. Medium confidence because duplicate entries appear near the end and ledger format is manually appended. |
| Tool-error/friction events | 126 errored tool results | JSONL `toolResult.isError == true`. Medium confidence; includes harmless `cargo fmt --check` diffs and edit misses as well as real failures. |

Commit distribution by committer date: 50 on 2026-06-21, 22 on 2026-06-22, 13 on 2026-06-24, 8 on 2026-06-25, 6 on 2026-06-27.

## Human interventions

Counting model: L0 seed/restart prompts excluded; L1 continue; L2 directional/authorization; L3 corrective/scope reinforcement; L4 product/debug blocker or production launcher usability failure.

Summary:

- L0 excluded: 4 initial/restart seed prompts (`/tmp/ve_users.tsv` rows 1, 2, 4, 5).
- Counted interventions: **22 total**.
  - L1: 2.
  - L2: 5.
  - L3: 6.
  - L4: 9.
- Max level observed: **L4**.
- Weighted burden: `2*1 + 5*2 + 6*3 + 9*5 = 75`.
- Confidence: high for raw user-message extraction; medium for classification because severity boundaries between “continue with authorization” and “scope correction” are interpretive.

Key intervention evidence:

| Timestamp | Class | Summary | Impact / evidence |
|---|---:|---|---|
| 2026-06-21T22:52:54Z | L2 | “Work in autonomous until the stop condition is hit...” | Reinforced autonomous continuation after a restart/final-answer pattern. Evidence: `/tmp/ve_users.tsv` row 3; JSONL file `2026-06-21T22-34-04...`. |
| 2026-06-22T01:21:55Z | L2 | “what is the documented stop rule?” | User had to probe whether agent understood when to stop. Evidence: JSONL `2026-06-22T01-02...:370`. |
| 2026-06-22T01:22:51Z | L2 | Approved sensitive continuation. | Agent needed explicit approval for privileged/bwrap/TUN direction. Evidence: `/tmp/ve_users.tsv` row 7. |
| 2026-06-22T21:28:42Z | L1 | “continue” | Agent stopped before alpha complete. Evidence: `/tmp/ve_users.tsv` row 8. |
| 2026-06-22T21:51:21Z | L2 | “what is highest leverage next?” | Directional prompt to unblock prioritization. Evidence: `/tmp/ve_users.tsv` row 9. |
| 2026-06-22T21:52:15Z | L3 | “implement the setup command and test it...” | Specific missing executable setup-helper path. Evidence: `/tmp/ve_users.tsv` row 10. |
| 2026-06-22T22:17:55Z | L2 | “continue until you absolutely need my input. make decisions yourself” | Autonomy correction. Evidence: `/tmp/ve_users.tsv` row 11. |
| 2026-06-25T02:57:23Z | L3 | “do real live tests, you have my authorization” | Pushed agent from unit/integration proof toward live bwrap/TUN evidence. Evidence: `/tmp/ve_users.tsv` row 12. |
| 2026-06-25T03:06:57Z | L3 | Continue real live tests until alpha complete. | Same live-test/scope nudge. Evidence: `/tmp/ve_users.tsv` row 13. |
| 2026-06-25T03:41:12Z | L3 | “everything in @docs/initial-impl.md must be complete...” | Reframed completion criteria after reviewer bounded “evidence scope”. Evidence: JSONL `2026-06-22T01-02...:1794`; progress response at `progress.md:1659-1663`. |
| 2026-06-25T14:36:09Z / 23:40:18Z | L3 | “usable inside a real bwrap sandbox environment” repeated. | Kept pressure on actual prototype usability. Evidence: `/tmp/ve_users.tsv` rows 15-16. |
| 2026-06-27T02:53:48Z | L4 | “full alpha scope... production launcher... arbitrary commands inside bwrap” | Major product requirement; led to `bwrap-run`. Evidence: JSONL `2026-06-22T01-02...:2540`; `progress.md:1859-1872`; commit `2e1e007` at 2026-06-27T09:15:59-04:00. |
| 2026-06-27T13:13:04Z | L1 | “continue” | Agent stopped before user-facing issues were resolved. Evidence: `/tmp/ve_users.tsv` row 18. |
| 2026-06-27T13:31:48Z | L4 | Working command needed `--bin foxprox-cli`; curl output suppressed. | Production launcher UX bug; led to stdout/stderr behavior fix. Evidence: JSONL `...:2656`; `progress.md:1891-1903`; commit `3aafe9d`. |
| 2026-06-27T13:46:23Z | L4 | Audit logs emitted after curl output. | Output ordering/timing bug; led to live audit emission. Evidence: JSONL `...:2729`; `progress.md:1919-1930`; commit `8842a17`. |
| 2026-06-27T19:52:47Z | L4 | “still not seeing any output from curl” for GitHub HTTP. | Exposed real-world redirect/no-body/confusing output problem. Evidence: JSONL `...:2780`. |
| 2026-06-27T23:37:39Z / 23:37:49Z | L4 | `curl -L http://github.com/` failed after redirect/resolution. | Led to sequential TCP flow and CA-root work. Evidence: JSONL `...:2795` and `...:2797`; `progress.md:1945-1956`; commit `c081b24`. |
| 2026-06-27T23:49:57Z | L4 | GitHub HTML died midstream with OpenSSL `bad record mac`; asked about allowlisting. | Exposed TLS stream corruption/partial smoltcp write issue and policy UX gap. Evidence: JSONL `...:2884`; `progress.md:1973-1984`; commit `3cccb26`. |
| 2026-06-27T23:55:27Z | L4 | `--config policy.toml` GitHub run “isnt working”. | Exposed broker-DNS vs upstream-DNS policy footgun. Evidence: JSONL `...:2932`; `progress.md:2001-2012`; commit `89c5bf6`. |

## Timeline to full production launcher end-to-end

Interpretation: “full production launcher end-to-end” means a user-facing launcher that can run arbitrary commands inside real bwrap with mediated network, command output usable, live audit usable, and real curl/GitHub-style behavior corrected.

1. **Pre-launcher foundation, commits 1-76.** The agent built platform-independent policy/audit/packet slices, fd handoff, live bwrap TUN setup, live UDP/DNS/TCP smokes, and smoltcp relay. This was effective vertical-risk retirement, but repeatedly left “production launcher orchestration” as unproven.
2. **Production-shaped TCP helper, commit 77.** `bab3b16 Add production-shaped bwrap TCP once launcher` (2026-06-24T23:11:09-04:00). Progress says reusable code launches bwrap/`foxproxsetup`, accepts TUN fd, runs one smoltcp TCP relay, and waits for target (`progress.md:160?` area; reviewer references `progress.md:1606-1618` in `e638fe7d_reviewer_0_output.md:11-12`). This was product-code launcher orchestration, but not yet a user-facing arbitrary-command command.
3. **Live curl through helper, commit 78.** `042c8aa Prove live curl forwarding through launcher` (2026-06-24T23:12:15-04:00). Validated application-level TCP; learnings emphasize curl is stronger evidence than socket bytes (`learnings.md:300-302`).
4. **User-facing one-flow command, commit 80.** `b1458eb Expose bwrap TCP once CLI command` (2026-06-24T23:23:41-04:00). Progress records `bwrap-tcp-once` parser and live CLI curl smoke with `tcp_connect`/`tcp_flow_closed` audit (`progress.md:1643-1656`). Reviewer `12c5d2fb` accepted this as documented alpha evidence scope (`subagent-artifacts/12c5d2fb_reviewer_0_output.md:3-14`).
5. **Broader alpha completion after user correction, commits 81-93.** After the user insisted `docs/initial-impl.md` be complete (`progress.md:1659-1663`), the agent added fuzz/property, live ICMP, live HTTP allow/deny, audit attribution/duration, live TLS SNI, explicit proxy CLI, DNS attribution, original-destination TCP, DNS+TCP in one launcher, original-destination UDP, and ICMP in CLI launcher. Reviewer blockers at `83970257_reviewer_0_output.md:10-16` were addressed by later progress entries (`progress.md:1725-1780`, `1754-1766`).
6. **Production `bwrap-run` arbitrary-command launcher, commit 94.** `2e1e007 Add production bwrap run launcher` (2026-06-27T09:15:59-04:00). Progress records `foxprox-cli bwrap-run`, default paths, broker socket/resolver paths, isolated `/etc/resolv.conf`, broker-DNS policy, TUN fd, ICMP/DNS/UDP/first TCP, and live curl-by-hostname smoke 13/13 (`progress.md:1859-1872`). This is the first credible “arbitrary commands inside bwrap” point, but it still suppressed target stdout.
7. **Usable command output, commit 95.** `3aafe9d Preserve target stdout in bwrap run` (2026-06-27T09:34:59-04:00). Triggered by user L4 report. Progress records target stdout inherited and audit moved to stderr (`progress.md:1891-1903`).
8. **Live audit timing, commit 96.** `8842a17 Emit bwrap run audit live` (2026-06-27T09:48:31-04:00). Triggered by user L4 report. Progress records audit lines emitted immediately/flushed; terminal interleaving caveat remains (`progress.md:1919-1930`).
9. **Redirected HTTPS, commit 97.** `c081b24 Support redirected HTTPS in bwrap run` (2026-06-27T19:43:35-04:00). Triggered by GitHub `curl -L` failure. Progress records sequential TCP flows, CA trust preservation, and truncated ClientHello no longer aborting flow (`progress.md:1945-1956`).
10. **Large HTTPS bodies, commit 98.** `3cccb26 Stabilize large HTTPS bwrap run responses` (2026-06-27T19:52:06-04:00). Triggered by `bad record mac`; progress records fixing partial `send_slice` drops and passing ~551 KiB GitHub body (`progress.md:1973-1984`).
11. **Policy usability, commit 99.** `89c5bf6 Normalize broker DNS for bwrap policies` (2026-06-27T19:58:19-04:00). Triggered by `--config policy.toml` failure; progress records normalizing actual in-sandbox broker DNS endpoint and documenting explicit DNS allow rule (`progress.md:2001-2012`).

Conclusion: the first credible arbitrary-command production launcher appeared at **commit 94 of 99** (`2e1e007`) after 4 JSONL sessions and 94 git iterations. The first point I would call “full production launcher end-to-end usable with real curl and policy footguns addressed” is **commit 99 of 99** (`89c5bf6`) because later user-supplied real runs invalidated earlier “done” claims.

## Main struggles

1. **Stopping before the user’s actual completion bar.** The agent repeatedly produced final answers after bounded slices or “evidence scope” even though the user wanted all alpha scope. Evidence: final summaries in earlier JSONL files say stopped on runtime/turn budget or committed multiple slices, not alpha complete; user then restated autonomy and scope (`/tmp/ve_users.tsv` rows 3, 8, 11-17). Progress explicitly says the user clarified every milestone in `docs/initial-impl.md` must be complete (`progress.md:1659-1663`).
2. **Underestimating product launcher usability.** Early launcher claims were one-flow/evidence oriented. User had to ask for arbitrary `bwrap-run`, then report missing stdout, audit ordering, redirect failures, TLS corruption, and default-deny policy confusion. Evidence: JSONL lines `2540`, `2656`, `2729`, `2780`, `2795`, `2797`, `2884`, `2932` in the final session file.
3. **Live environment and namespace quirks.** The agent had to learn bwrap resolver isolation, `/dev/net/tun`/capability behavior, ICMP raw capability requirements, and target lifecycle polling. Evidence: progress `progress.md:1871` (resolver bind over `/etc` issue), `progress.md:1827` (glibc/curl resolver needed isolated `/etc/resolv.conf`, TUN reads could hang), `progress.md:1691` and `learnings.md:316-318` (CAP_NET_RAW needed for ICMP).
4. **smoltcp/TCP relay correctness.** Sequential redirects and larger TLS bodies exposed limitations after initial live curl success. Evidence: user `bad record mac` JSONL `...:2884`; progress `progress.md:1949` (sequential flows, CA roots, truncated ClientHello), `progress.md:1977` (partial `send_slice` writes dropped bytes; chunk size reduced).
5. **Tooling/edit friction.** 126 tool errors include many edit misses, rustfmt diffs, clippy/test failures, and review-only command routing issues. Common examples: memory_search native module failure, `cargo test` multi-filter misuse, missing `PolicyConfig.icmp`, `libc` missing capability constants, `bwrap: execvp /bin/sh`, ETXTBSY fake executable races, sandboxed git index lock denial, and malformed Python/regex editing that produced Rust syntax errors.

## Repeated behavioral patterns

- **Vertical-slice discipline was strong.** The agent repeatedly chose narrow boundary-crossing slices, ran focused checks plus workspace clippy/tests/fmt, appended progress/learnings, and committed. This produced high traceability and low regression risk.
- **But “evidence proof” substituted for user-facing completion too often.** Reviewers and agent summaries repeatedly scoped success as bounded one-flow proof, while the user wanted an actually usable alpha launcher. The need for `bwrap-run` arrived only after explicit L4 user correction.
- **Review fanout was useful but sometimes accepted too narrow a definition.** `e638fe7d` and `12c5d2fb` accepted one-flow alpha evidence with caveats (`e638...:3-18`, `12c...:3-14`); `83970257` caught missing full-alpha items (`839...:10-16`); `307df8bc` later found no blockers after those were addressed (`307...:3-20`).
- **User-pasted live command output was the most valuable validation.** It found issues no in-tree test exposed: suppressed stdout, audit timing, HTTP redirect/no output, sequential HTTPS, TLS stream corruption, and default-deny DNS policy footgun.
- **The agent tended to ask/stop for authorization around sensitive live tests despite standing scope.** User had to approve real live bwrap/TUN testing and “make decisions yourself” (`/tmp/ve_users.tsv` rows 7, 11-13).

## Specs/prompts that could have improved the run

1. Add a hard, front-loaded acceptance clause: “Do not stop until `foxprox-cli bwrap-run -- ... arbitrary command` works in a real bwrap namespace, preserves target stdout, emits live audit separately, supports DNS+TCP+UDP+ICMP, and passes `curl -L` against a real HTTPS site or documented equivalent.”
2. Define “alpha complete” as user-observable behavior, not just one-flow evidence. Include examples: `curl http://example.com`, `curl -L -I http://github.com/`, full-body HTTPS, and a default-deny allowlist with an explicit DNS rule.
3. Require user-facing docs and copy/paste command verification before final answer. The `--bin foxprox-cli` gap would likely have been caught earlier.
4. Tell the agent explicitly that live tests are authorized for bwrap/TUN and should be run whenever host prerequisites exist; only escalate if a privileged action affects host state outside temp namespaces.
5. Make output contract explicit: target command stdout/stderr should behave like a normal launcher; foxprox audit should be machine-readable and separated, with known terminal interleaving caveat.
6. Add a reviewer prompt distinction: “Do not accept bounded evidence scope if the user requested full alpha; check `docs/initial-impl.md` and a production launcher runbook.”

## Approach effectiveness

Overall effectiveness: **high for architectural risk retirement, medium for autonomous product completion**.

What worked:

- The vertical-evidence approach produced 99 small commits with strong ledgers and validation evidence.
- It crossed hard boundaries incrementally: policy/audit, packet parsing, TUN setup, fd handoff, live bwrap, UDP/DNS/TCP, smoltcp, CLI, production `bwrap-run`.
- Reviewer artifacts helped identify missing audit/source/proxy/TLS/DNS attribution work.
- Final state had real manual reproduction evidence for redirected HTTPS headers, full GitHub body, and default-deny GitHub policy (`progress.md:1951`, `1979`, `2007`).

What did not work:

- The agent’s “done” threshold lagged the user’s; high-severity interventions were needed late.
- The first production launcher was not truly usable until several user-reported issues were fixed.
- Live real-world command tests came too late; early live smokes used controlled loopback/simple cases and missed redirects, TLS record size, stdout/stderr behavior, and policy UX.

## Confidence and gaps

Confidence: **medium-high**.

- High confidence in counts based on direct JSONL extraction (4 sessions, 26 user messages, 22 counted interventions after excluding 4 seeds, 99 commits, 126 tool errors).
- High confidence in production-launcher timeline because progress entries, commit order, and user interventions align.
- Medium confidence in severity classification because some “continue” prompts combine autonomy correction and scope correction.
- Medium confidence in progress-cycle count because duplicated progress entries exist near the end (`production bwrap-run`, `stdout`, `audit emission`, `HTTPS`, `GitHub policy` repeated), so commit count is the better iteration metric.

Gaps / not read fully:

- I did not read every assistant token or full tool output; this was intentional per strategy.
- I did not independently rerun live bwrap tests; this audit is evidence extraction, not code validation.
- Some artifact meta files lack timestamps; reviewer timing is inferred from surrounding progress/session context rather than artifact metadata.
- I used `/tmp/ve_users.tsv` as a temporary extraction for row numbering; authoritative raw evidence remains the JSONL paths and line numbers cited above.
