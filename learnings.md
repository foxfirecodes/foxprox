# Learning Ledger

## 2026-06-21T16:42:34Z — Crew setup

- Start every autonomous implementation session by creating/updating `progress.md` before code changes so another agent can resume from git plus ledgers alone.
- First useful commit boundary for this repository is platform-independent `foxprox-core` foundation; Linux/TUN/bwrap/smoltcp code should wait until core event/policy/audit boundaries are encoded.

## 2026-06-21T16:54:22Z — Core policy review pattern

- For `foxprox-core`, fresh architecture review is useful even for type-only commits: it caught fail-closed gaps that ordinary Rust tests did not (generic UDP/53 bypass, hidden SNI, directed broadcast handling).
- Keep `foxprox-core` dependency-free while defining core boundaries; use `cargo tree -p foxprox-core` as a cheap regression check for accidental Linux/TUN/runtime dependency creep.
- With workspace MSRV 1.80, avoid APIs stabilized later (for example `Option::is_none_or`, stable in 1.82) even when the local stable toolchain accepts them; clippy with MSRV catches this.

## 2026-06-21T22:18:00Z — Commit checkpoints are not stop points

- For goal-mode work such as “complete alpha scope,” a verified commit is only a checkpoint. Do not treat clean git status, a passing validation suite, or completion of one milestone slice as a reason to stop.
- After each commit, immediately compare current behavior against the remaining source-doc requirements, select the next smallest coherent implementation slice, and continue unless alpha is complete, blocked, or explicitly paused/stopped by the user.
- User checkpoint/status questions should be answered briefly without cancelling the active implementation loop.
