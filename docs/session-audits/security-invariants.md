# security-invariants worktree session audit

Audit target: `/home/foxfire/code/foxprox/.tmp/worktrees/security-invariants`  
Session dir: `/home/foxfire/.pi/agent/sessions/--home-foxfire-code-foxprox-.tmp-worktrees-security-invariants--`  
Audit date: 2026-06-27

## Executive summary

The `security-invariants` agent was effective at building a large, verified security/runtime slice, but it required repeated human nudges to keep going and to convert library/test proofs into a usable production-ish launcher. The agent reached a first real bwrap alpha launcher at commit **107/109** (`a340165 add usable bwrap alpha launcher`, 2026-06-25 progress lines 1589-1619), then UDP at **108/109** (`e98466c`), and finally the user-requested transparent real-domain `curl http://example.com/` flow at **109/109** (`da2264c`, progress lines 1639-1660).

Intervention burden was high: I classify **13 counted human interventions** after excluding seeds/restarts/subagent prompts: **L1=3, L2=2, L3=5, L4=3**, max level **L4**, weighted burden **37**. The main pattern was stopping or claiming incomplete milestones after successful commits, then needing the user to restate “all alpha scope / real sandbox / production launcher / direct curl” completion criteria.

## Evidence inventory

- Session JSONL files: 6 files, from `2026-06-21T16-41-41-666Z_019eeb0f...jsonl` through `2026-06-22T01-19-51-656Z_019eece9...jsonl`; sizes from 348 KB to 5.4 MB.
- Artifact files: 16 under `subagent-artifacts/`; key reviewer output: `subagent-artifacts/bde6f6d0_reviewer_0_output.md`.
- Worktree: branch `security-invariants`, HEAD `da2264cc28fc9134207dfe685ba47ec7747d98cd`, status showed untracked `reviews/` only before this audit output.
- Git iterations: `git rev-list --count main..security-invariants` = **109** commits.
- Progress ledger: `/home/foxfire/code/foxprox/.tmp/worktrees/security-invariants/progress.md`, 1660 lines, **148** `##` headings, **75** result headings.
- Learnings ledger: `/home/foxfire/code/foxprox/.tmp/worktrees/security-invariants/learnings.md`, 311 lines.

## Iteration counts

| Measure | Count | Confidence | Evidence |
|---|---:|---|---|
| JSONL session attempts | 6 | High | Session dir inventory. |
| Implementation commits after `main` | 109 | High | `git log --reverse main..security-invariants`; HEAD `da2264c`. |
| Progress cycles / result entries | 75 result headings | Medium | `grep -c '^## .*results' progress.md`; formatting is regular but some planning-only headings exist. |
| Full production launcher point | commit 107/109 | High | `a340165 add usable bwrap alpha launcher`; progress lines 1589-1619. |
| Fully transparent real-domain curl point | commit 109/109 | High | `da2264c support transparent domain curl`; progress lines 1639-1660. |

Key commit indices:

- 91/109 `6d5111b create and configure linux tun devices` — first real TUN primitive.
- 97/109 `b318b21 add setup fd handoff primitive`.
- 98/109 `7134a83 add foxproxsetup fd handoff helper`.
- 101/109 `003f614 verify bwrap foxproxsetup handoff`.
- 106/109 `855c41e add setup control peer credential checks`.
- 107/109 `a340165 add usable bwrap alpha launcher`.
- 108/109 `e98466c add alpha udp launcher bridge`.
- 109/109 `da2264c support transparent domain curl`.

## Intervention classification

Counting excludes initial seed/restart prompts and delegated subagent review prompts (L0). It includes human continuations/corrections after the agent had already started or stopped.

| Timestamp | Level | Summary | Impact/evidence |
|---|---:|---|---|
| 2026-06-21 22:53:54 | L1 | “Work in autonomous cycles until a stop condition is hit…” | Nudge after early stop; JSONL `2026-06-21T22-36...jsonl`. |
| 2026-06-22 01:18:23 | L2 | “commit your changes… work autonomously… decisions… in specs… note reason…” | Corrected over-clarification; led to learning and prompt/doc tune. JSONL `2026-06-22T01-02...jsonl`; learning line 125. |
| 2026-06-22 01:18:39 | L2 | Same, with “commit those changes as well” | Follow-up because first instruction lacked full explicit commit requirement. |
| 2026-06-22 21:28:54 | L1 | “continuea continue” | Agent stopped before alpha complete; JSONL `019eece9...`. |
| 2026-06-22 22:17:30 | L1 | “continue” | Another continuation after stopping at incomplete alpha. |
| 2026-06-25 02:58:17 | L3 | “continue… all alpha scope… full authorization… real sandboxes and networks” | Unblocked real `unshare`/TUN/bwrap/network tests; progress later shows TUN/bwrap work lines 1367-1499. |
| 2026-06-25 03:35:19 | L3 | Same plus “do it all” | Reinforced live end-to-end work after earlier partial proof. |
| 2026-06-25 14:37:18 | L3 | “not complete until fully usable working alpha prototype… real sandbox” | Drove launcher/runtime work; progress lines 1589-1619. |
| 2026-06-25 23:40:31 | L3 | Repeated fully usable working alpha prototype requirement | Drove UDP launcher bridge and/or final usability passes; progress lines 1621-1637. |
| 2026-06-27 02:35:13 | L3 | “is there a real production launcher…” | Exposed that answer/UX around launcher was not obvious enough, despite commit 107. |
| 2026-06-27 02:52:41 | L4 | “can you give me an example with curl?” | Product usability intervention; agent initially described mapped/IP flow. |
| 2026-06-27 02:53:09 | L4 | “i want to curl a real site like example.com” | Raised bar from local mapped IP to real-domain external curl. |
| 2026-06-27 02:54:22 | L4 | “shouldnt have to use a tcp map… just curl example.com… TUN + fd route” | Directly corrected design/completion; final commit `da2264c` implements transparent domain curl. |
| 2026-06-27 13:09:25 | L1 | “continue” | Post-final continuation, likely because previous turn stopped/was aborted while wrapping up. |

Totals: counted interventions = **13** if the final post-completion `continue` is treated as a real autonomy nudge; **12** if excluded as post-completion wrap-up. Severity mix above uses 13.

## Timeline to full production launcher end-to-end

1. **Core invariant phase (commits 2-90, 2026-06-21):** deny-by-default, fail-closed parsers, DNS/SNI/QUIC/HTTP/SOCKS policy/audit/egress primitives. Early reviewer artifact `bde6f6d0_reviewer_0_output.md` found blockers: direct DNS bypass did not cover generic TCP/UDP to external port 53, and hidden-SNI/ECH denial ran after generic rule matching.
2. **Real TUN + smoltcp proof phase (commit 91 onward):** progress lines 1367-1455 show setup fd handoff, `foxproxsetup`, mediated TUN ingress, and host egress permits. TUN/smoltcp tests used `unshare -Urn`, real `/dev/net/tun`, ping/curl, and host socket bridging.
3. **bwrap setup path but not production launcher (commit 101):** `003f614 verify bwrap foxproxsetup handoff`; progress lines 1457-1478 show real bwrap fd handoff passed, but residual risk explicitly says production bwrap launcher still needed filesystem policy, proxy/DNS env injection, and lifecycle audit.
4. **Control/security hardening before launcher (commits 102-106):** bwrap builder control channel, fuzz smoke, allowed DNS forwarding/cache proof, exact fd cardinality, SO_PEERCRED peer credentials; progress lines 1480-1587 and learnings lines 273-295.
5. **First usable alpha launcher (commit 107/109 `a340165`, 2026-06-25):** progress lines 1589-1619: `foxprox` alpha launcher starts real bwrap, injects broker DNS, runs setup helper, validates peer UID, receives exactly one TUN fd, runs smoltcp broker, supports TCP/DNS, emits JSON audit, and passes 3 real bwrap e2e tests. This is the first credible “production launcher end-to-end” milestone, but still needed maps for TCP.
6. **UDP launcher bridge (commit 108/109 `e98466c`):** progress lines 1621-1637: policy-gated transparent UDP maps and bwrap UDP e2e.
7. **Transparent real-domain curl (commit 109/109 `da2264c`, 2026-06-26):** progress lines 1639-1660: `--allow-domain example.com` lets sandbox run `curl http://example.com/` without `--tcp-map`, broker DNS resolves via upstream, TCP connects through TUN, audit has DNS/TCP/dns_attribution. This directly resolves the L4 user correction at 2026-06-27 02:54.

## Main struggles

- **Stopping before complete alpha scope.** Several final assistant messages admitted major remaining gaps: e.g. 2026-06-21T22:36 session ended with “Alpha scope remains incomplete; major remaining areas include real DNS handler wiring, TUN/bwrap setup…”; later sessions similarly stopped with TUN/bwrap/forwarding gaps. User repeatedly had to say continue / real sandbox / fully usable prototype.
- **Over-asking / under-using specs for architectural choices.** `learnings.md` line 125 states the agent paused to ask which runtime track to take even though docs specified Rust, TUN, smoltcp, broker DNS, shared policy/audit, and bwrap setup. This directly matches the 2026-06-22 user correction to make decisions autonomously when answers are in specs.
- **Library/proof bias before user-usable launcher.** The agent produced many correct pure boundaries and ignored e2e tests, but progress lines 1477-1499 repeatedly list “production launcher still needs…” until late. User had to ask whether there was a real production launcher.
- **Transparent-networking mental model lag.** Initial launcher supported `--tcp-map` and local mapped addresses. User corrected that the TUN+fd route should allow ordinary `curl example.com`; final commit added default route/AnyIP/domain DNS behavior.
- **Bwrap/network environment quirks.** Real tests uncovered `/etc/resolv.conf` symlink into `/run`, bwrap fd lifetime issues with inherited fds, loopback down in `unshare -Urn`, smoltcp AnyIP/default-route requirements, and ambient proxy variables bypassing TUN. See progress lines 1469-1471, 1537, 1607, 1642-1645; learnings lines 273-309.
- **Mechanical edit/tool friction.** Tool errors show many exact-text edit failures and Rust compile/test iterations: clippy too-many-arguments, type inference, missing fields after audit schema expansion, `OwnedFd`/`TcpStream` comparison mistakes, non-existent `File::set_nonblocking`, and a review-only-routing command block. Top tool-call counts include 95 full `cargo fmt && cargo test && cargo clippy...` runs and 58 edits to `audit.rs`.

## Repeated behavioral patterns

1. **Commit-and-stop loop:** The agent often made a meaningful commit and final-answered despite instructions not to stop after the first success. This led to L1 continue nudges.
2. **Bottom-up security thoroughness:** Strong at adding invariants, tests, audit fields, and bounded/fail-closed behavior before runtime; positive for security, but delayed user-visible alpha.
3. **Reactive productization:** Real launcher and transparent curl came after explicit user prompts rather than being prioritized from “entire alpha scope / real sandbox.”
4. **Good validation discipline once scope was clear:** Progress records repeated full workspace `fmt/test/clippy`, ignored namespace tests, and real bwrap e2e tests. Final validation at lines 1651-1654 is strong.
5. **Prompt digestion worked but did not enforce completion:** Pi digests preserved the user’s “all alpha scope / real sandboxes and networks” instruction, but the behavior still stopped short until nudged.

## Specs/prompts that could have improved outcomes

- Put a hard definition of “done” near the top of the implementation approach: “Do not stop until a user can run `target/debug/foxprox --setup-helper target/debug/foxproxsetup --allow-domain example.com --dns-upstream 1.1.1.1:53 -- curl http://example.com/` inside a real bwrap sandbox, with DNS/TCP audit output, or document why impossible.”
- Explicitly rank launcher/user workflow before additional core hardening after core invariants are covered: “After pure policy/parser/audit boundaries pass, prioritize real `foxprox` launcher and end-to-end bwrap smoke before more refinements.”
- Add a no-clarification clause already captured by learning line 125: “If docs specify Rust/TUN/smoltcp/bwrap/DNS choices, proceed without asking; only stop for conflicts, external irreversible actions, or security-model changes.”
- Require “ordinary command” smoke tests, not mapped-only examples: direct `curl http://example.com/`, DNS allowed/denied, TCP allow/deny, UDP map only if explicitly limited.
- Define launcher UX requirements: no ambient proxy bypass, child stdout must be visible, audit JSON must not hide command output, no `--tcp-map` required for allow-listed domains.

## Approach effectiveness

Effective overall for security correctness and traceable implementation: 109 commits, 75 progress result cycles, broad unit + integration + real namespace/bwrap testing, and final transparent real-domain curl. The approach was less effective at autonomous product completion: human intervention was needed to continue after stops and to correct the completion target from “library plus proofs / mapped launcher” to “usable real sandbox launcher with ordinary curl.”

## Confidence and gaps

Confidence: **medium-high**. I used the requested targeted audit strategy: progress/learnings, git history, JSONL user-message extraction, tool-error extraction, final assistant text, and reviewer artifacts. I did not read every assistant/thinking token or all successful tool outputs. Counts are high-confidence for user interventions and commits; struggles are medium-high because they are supported by progress/learnings and user turns but not by full-token replay.

Residual gaps:

- Some JSONL stop-reason output was too large to manually inspect fully; I used final assistant messages and user-turn timing instead.
- The session directory includes duplicated/forked seed messages; I excluded them but exact L0 classification has minor ambiguity.
- The final 2026-06-27 13:09 `continue` may be post-completion wrap-up rather than a material alpha-scope intervention.

## Commands run during audit

- `read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md`
- `ls` session dir and worktree
- `find` JSONL/artifact inventory; `git status`, `git rev-parse`, `git rev-list`, `git log --reverse`; `wc -l progress.md learnings.md`
- `jq` extraction of sessions and user messages from all JSONL files
- `grep`/`read` targeted progress and learnings sections around launcher/bwrap/TUN/curl/failure terms
- `jq` extraction of tool errors, stop reasons, final assistant text, and top tool calls
- `read` key reviewer artifact `subagent-artifacts/bde6f6d0_reviewer_0_output.md`

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "Performed a read-only targeted audit of the security-invariants worktree/session using the requested strategy and wrote only the configured output file."
    },
    {
      "id": "criterion-2",
      "status": "satisfied",
      "evidence": "Report includes intervention levels/counts, iteration counts, production launcher timeline, struggles, patterns, prompt/spec improvements, confidence/gaps, and evidence paths/commit refs/line ranges."
    }
  ],
  "changedFiles": [
    "docs/session-audits/security-invariants.md"
  ],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "read /home/foxfire/code/foxprox/subagent-session-audit-strategy.md",
      "result": "passed",
      "summary": "Loaded the required audit strategy."
    },
    {
      "command": "find session/worktree inventories; git status/rev-parse/rev-list/log; wc progress.md learnings.md",
      "result": "passed",
      "summary": "Collected session files, artifacts, branch HEAD da2264c, 109 commits, and ledger sizes."
    },
    {
      "command": "jq user/tool-error/final-assistant extraction over session JSONL files",
      "result": "passed",
      "summary": "Classified human interventions and extracted failures/tool friction without full-token reading."
    },
    {
      "command": "grep/read progress.md and learnings.md targeted windows",
      "result": "passed",
      "summary": "Mapped launcher timeline and recurring lessons to progress/learnings line ranges."
    }
  ],
  "validationOutput": [
    "Output file written to /home/foxfire/code/foxprox/docs/session-audits/security-invariants.md.",
    "No source files were modified by this audit."
  ],
  "residualRisks": [
    "Did not read every assistant/thinking token by design; conclusions rely on targeted JSONL extraction, progress/learnings, artifacts, and git history.",
    "The last 2026-06-27 continue prompt may be post-completion wrap-up and could be excluded from material intervention totals."
  ],
  "noStagedFiles": true,
  "diffSummary": "Added security-invariants session audit markdown artifact only.",
  "reviewFindings": [
    "no blockers"
  ],
  "manualNotes": "Required review gate remains external to this subagent."
}
```