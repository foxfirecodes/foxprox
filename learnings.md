# Learning Ledger

## 2026-06-21 — Alpha implementation starts from core observability contracts

The repository only had a minimal `foxprox-core` marker crate. To keep behavior externally visible before runtime forwarding exists, the first implementation must make policy, flow, packet, setup, and audit contracts testable through structured records and bounded ledgers. Real network namespace/TUN/smoltcp execution remains a later integration surface, but the denial reasons and event schema can be locked down now.

## 2026-06-21 — Audit backpressure must affect decisions, not only storage

A bounded audit buffer alone proves memory cannot grow unbounded, but alpha forwarding should also fail closed when audit-critical decisions cannot be recorded. `BrokerCore` now joins policy evaluation to audit append and returns an `audit_backpressure` fail-closed decision when the ledger is full, while retaining a lossy backpressure record for postmortem visibility. Zero requested capacity is normalized to one slot so the fail-closed evidence remains inspectable.

## 2026-06-21 — Flow lifecycle events must not claim policy decisions they did not make

UDP and QUIC lifecycle records are useful observability, but they should not encode `decision=allow` unless a policy decision actually produced that outcome. The flow manager now emits lifecycle metadata without a decision field, leaving allow/deny authority to `BrokerCore`/`PolicyEngine` audit records.

## 2026-06-21 — DNS returned-address observations are audit-critical

DNS policy allow evidence alone is not enough for transparent hostname attribution. The handler must also record returned addresses before releasing an upstream response; otherwise later DNS-to-flow decisions could rely on invisible cache state. When the observation audit cannot be appended, the DNS path now fails closed and returns REFUSED with audit-backpressure evidence instead of silently allowing an untraceable attribution update.

## 2026-06-21 — Packet write-back must be audit-gated before bytes leave

The ICMP write-back proof is only externally debuggable if outbound packet synthesis is recorded before the reply is written to the device. The in-memory TUN harness now appends `packet_observed` with `direction=to_sandbox` and `write_back=icmp_echo_reply` before writing bytes; audit backpressure prevents the write and leaves `audit_backpressure` evidence.

## 2026-06-21 — UDP egress must wait for lifecycle audit, not just policy audit

For UDP, an allow decision without `udp_flow_created` evidence is insufficient because later expiration and byte-count accounting depend on flow state. The UDP forwarding harness now appends lifecycle records before fake egress sends; if lifecycle audit backpressures, no datagram is sent.

## 2026-06-21 — TCP close evidence is a separate lifecycle contract from connect policy

A TCP connect allow audit proves host egress was authorized, but it does not prove what bytes crossed or how the flow ended. The TCP forwarding harness now emits `tcp_flow_closed` with byte counts and duration. Close audit backpressure is visible, but real async stream integration must preserve this boundary even when close/error happens after bytes have already moved.

## 2026-06-21 — IP-version dispatch changes malformed-packet evidence

Switching the TUN harness from IPv4-only parsing to IP-version dispatch changed all-zero short packets from `short_ipv4_header` to `unsupported_ip_version`. Tests should assert the structured parse detail produced by the dispatch boundary, not assume every malformed packet entered the IPv4 parser.

## 2026-06-21 — Observation and authorization must stay separate at frontend boundaries

The TUN packet harness originally emitted `packet_observed` and then treated successful parsing as allow/write-back. Review caught that this bypassed default-deny and `allow_ping=false`. Frontend harnesses must record packet observation first, then still run normalized policy decisions before any forwarding or write-back.

## 2026-06-21 — Mutable attribution/flow state must commit after audit success

DNS cache updates and UDP flow byte counts are decision-relevant state. Review caught that both could mutate before audit append succeeded, leaving invisible state after fail-closed outcomes. Future state managers should use prepare-audit/commit or rollback patterns when audit is required for correctness.

## 2026-06-21 — Upstream DNS responses must be validated before attribution

Review caught that parsing returned addresses without matching transaction ID, question, rcode, or answer owner can poison DNS attribution. The DNS handler now validates upstream responses against the original query before releasing a response or committing cache observations; mismatch/malformed responses fail closed with `dns_upstream_error=malformed_response`.

## 2026-06-21 — Egress failures need their own audit event after allow

Policy allow and lifecycle creation are not enough when a host egress operation fails. UDP, TCP, and explicit proxy harnesses now append `broker_error` records for send/connect failures so post-allow errors are inspectable instead of only visible as returned Rust errors.

## 2026-06-21 — MSRV-sensitive helpers in validation code

- `Option::is_none_or` is convenient for validation predicates but violates this workspace's Rust 1.80 MSRV; use an explicit `match` for helper predicates that must pass `cargo clippy --all-targets --all-features -- -D warnings` with `clippy::incompatible_msrv` enabled.

## 2026-06-21 — smoltcp IP-medium adapter boundary

- `smoltcp` can be kept out of `foxprox-core` by wrapping it in a separate adapter crate with an IP-medium `Device`; `Interface::poll` can consume TUN-style raw IP packets and emit outbound IP packets through token-backed queues, which is enough to prove the TUN-to-userspace-stack boundary before real fd wiring.

## 2026-06-21 — smoltcp TCP listener proof shape

- A bounded in-memory TCP proof can drive smoltcp by injecting raw IPv4 SYN/ACK/PSH packets into an IP-medium device, reading the emitted SYN-ACK sequence number, and then draining bytes from a `tcp::Socket` listener. This keeps TCP stack behavior testable before host egress bridging is wired.

## 2026-06-21 — Audited smoltcp TCP egress bridge

- For smoltcp TCP egress proofs, split the stack operation into draining received stream bytes and sending response bytes back through the socket. This lets the bridge evaluate/audit host egress before opening the egress path, then append a structured `tcp_flow_closed` record with byte counts after stack response emission.

## 2026-06-21 — foxproxsetup contract as plan-first helper

- The setup helper can be made testable before privileged execution by parsing the exact bwrap-emitted `foxproxsetup` flag shape into a structured `SetupHelperPlan`. Tests should assert helper steps and audit fields rather than executing `ip` or requiring `CAP_NET_ADMIN`.

## 2026-06-21 — Smoltcp stream identity and packet-device writes

- When bridging smoltcp TCP stream bytes to host egress, preserve `tcp::Socket` remote/local endpoints before auditing egress. Host responses sent into a smoltcp socket must also be collected from the stack's emitted packet queue, audited as `to_sandbox` write attempts, and written through the `PacketDevice`; `packets_emitted` alone is not sufficient runtime evidence.

## 2026-06-21 — Concrete DNS upstream boundary

- DNS upstream socket code can live in `foxprox-egress` by implementing the core `DnsUpstream` trait. Tests should run a local UDP resolver and assert that `DnsBrokerHandler` still owns response validation, audit, and cache commit behavior, while socket timeout/IO errors map to `DnsUpstreamError::Unavailable`.

## 2026-06-22 — DNS upstream config needs a socket identity

- Treat DNS upstream identity as a full `SocketAddr`, not just an IP. The port is part of both runtime configuration and source-validation evidence for UDP DNS replies; zero ports should fail config validation before runtime.

## 2026-06-22 — DNS source mismatch deserves distinct audit evidence

- Wrong-source DNS responses are not just generic upstream unavailability: they are attribution-safety failures. Model them as `DnsUpstreamError::SourceMismatch` so fail-closed audit records can distinguish spoofed/misdelivered replies from timeouts or socket errors.

## 2026-06-22 — DNS client delivery gates attribution usefulness

- DNS attribution should not outlive failed client delivery in listener paths. If a broker listener cannot send the DNS response back to the sandbox, rollback the just-committed observation and emit `dns_client_send_failed` broker-error evidence so cache state reflects what the sandbox could actually observe.

## 2026-06-22 — Explicit proxy listener proof boundary

- A concrete proxy listener can remain bounded and observable by handling one TCP request at a time, delegating parse/policy/egress to `ExplicitProxyFrontend`, and returning a structured listener step result with client address, request/response lengths, status code, send status, decision, and forwarded flag.

## 2026-06-22 — SOCKS5 listener proof boundary

- A bounded SOCKS5 listener proof should separate the method handshake from CONNECT policy evaluation: only the CONNECT request enters `ExplicitProxyFrontend`, while the listener step records greeting length, request length, reply code, send status, decision, and forwarding status.

## 2026-06-22 — Explicit proxy host egress proof boundary

- Concrete HTTP/SOCKS proxy host egress belongs in `foxprox-egress`: it can use blocking host sockets while `foxprox-core` continues to own only parse, policy, and audit contracts. Listener tests should prove host-socket reachability only after shared allow audit evidence exists.

## 2026-06-22 — Setup execution harness boundary

- Setup execution can be made observable without tying core to Linux command execution by running `SetupHelperPlan` steps through an injectable runner. The harness should stop at the first failed step and emit `broker_error` with `setup_step`, `setup_step_index`, and `completed_steps`.

## 2026-06-22 — Pre-exec setup evidence and proxy DNS boundary

- Setup execution reports must emit `tun_configured` before any target `exec`; an actual exec cannot return to produce audit evidence. Keep target command separate from setup steps and mark it ready only after setup/drop steps finish.
- Blocking explicit proxy host egress must not call host name resolution for proxy domain destinations. Domain CONNECT/HTTP forwarding should fail closed or be resolved through an audited broker DNS path before host TCP connect.

## 2026-06-22 — Proxy egress broker-DNS resolution boundary

- Explicit proxy host egress can support domain destinations without libc DNS by resolving through `DnsCache::addresses_for_hostname` populated by delivered broker DNS observations. Without a live broker-DNS cache entry, domain proxy egress should fail closed rather than resolve on the host.

## 2026-06-22 — Audit-gated proxy DNS resolution

- Explicit proxy domain egress must resolve hostnames in the frontend with a per-request timestamp, append `proxy_destination_resolved` evidence containing selected IP/source/query type/TTL, and only then evaluate policy/open egress. Keeping resolution outside egress avoids hidden libc DNS and makes audit backpressure fail closed before sockets open.

## 2026-06-22 — Shared DNS cache runtime boundary

- Live DNS-to-proxy attribution can be modeled with `SharedDnsCache`: DNS handlers commit/rollback delivered observations into the shared cache, while explicit proxy frontends resolve per request from that same cache and append resolution audit evidence before policy/egress.

## 2026-06-22 — Runtime lifecycle ledger boundary

- Runtime lifecycle supervision should emit `network_session_start` before components run and `network_session_exit` on clean or failed shutdown. If exit evidence is backpressured, preserve `audit_backpressure` and treat the lifecycle result as fail-closed.

## 2026-06-22 — Delivery-gated shared DNS cache

- Shared DNS cache publication must happen after the DNS listener successfully sends the response to the sandbox client. Handler-level query processing should return a pending observation and audit evidence, but must not publish it to shared proxy-visible cache before delivery.

## 2026-06-22 — Runtime lifecycle state must be terminal

- Runtime lifecycle evidence needs an explicit state machine rather than an optional start timestamp. Invalid transitions (`exit` before `start`, duplicate `start`, duplicate `exit`, or `start` after `exit`) should emit structured `broker_error` records and must not create misleading extra `network_session_start` or `network_session_exit` records.

## 2026-06-22 — Listener wiring proofs must share the actual cache handle

- Runtime listener wiring regressions should construct DNS and proxy listeners through the same runtime harness and `SharedDnsCache` handle, then drive real listener I/O. Manually seeding proxy cache is useful for unit tests but does not prove runtime wiring preserves delivery-gated DNS attribution.

## 2026-06-22 — Include SOCKS in shared listener wiring proofs

- A DNS-to-proxy runtime proof is incomplete if it only covers HTTP. SOCKS domain destinations need the same delivered-DNS shared-cache path and structured `proxy_destination_resolved` evidence before `socks_connect_decision`.

## 2026-06-22 — Cleanup must be part of lifecycle exit evidence

- Session exit evidence should include cleanup attempts and failures, not just child/runtime status. Cleanup failures after otherwise clean process exit are still fail-closed session outcomes and must make failed resources visible in structured audit details.

## 2026-06-22 — Listener bind evidence belongs in lifecycle ledger

- Runtime start evidence that only lists component names is not enough for proxy/DNS reachability. Listener setup must emit structured `proxy_listener_configured` records with component, protocol, bind address, and sandbox-reachable address, and listener-config audit backpressure must fail closed before claiming readiness.

## 2026-06-22 — Runtime proofs need aggregate audit access

- Even when components keep bounded per-broker ledgers in harnesses, runtime-level proofs should expose an aggregate audit view that includes lifecycle, listener configuration, DNS, and proxy decision records so validation can inspect one session's evidence end-to-end.

## 2026-06-22 — Cleanup evidence must retire callable resources

- A runtime harness must not claim listener cleanup complete while still owning active listener objects. On exit, archive component audit evidence, drop/retire listener handles, and ensure post-exit listener operations fail instead of accepting more work. Aggregate audit views should place session exit after component activity.

## 2026-06-22 — Child exit status is part of session outcome

- Runtime lifecycle exit should not only record broker status and cleanup. The supervised child process status (PID, exit code, signal) belongs in `network_session_exit`, and abnormal child termination should turn an otherwise clean runtime exit into fail-closed evidence.

## 2026-06-22 — Runtime aggregate ledgers need capture-time ordering

- Aggregating per-component audit ledgers after the fact can misrepresent interleaved runtime activity if records are grouped by component. Runtime proofs should archive new records immediately after each handled event so the aggregate evidence reflects capture order; unknown child status is not a clean exit and must fail closed.

## 2026-06-22 — Child supervision proof can use a blocking process runner

- A host-runtime proof should convert real `std::process::Command` results into `RuntimeChildExit` and feed that into lifecycle exit evidence. Test-harness subprocesses are a deterministic way to prove clean and non-zero child exits without depending on external binaries.

## 2026-06-22 — Aggregate audit cursors should track sequence numbers

- Bounded ledgers can replace records with lossy `audit_backpressure` while preserving length. Aggregate archive cursors must track last seen audit `sequence`, not record count, or they can miss replacement/backpressure evidence. A child exit is clean only when both process id and zero exit code are known.

## 2026-06-22 — Signal and supervision-error paths need explicit evidence

- A blocking child supervisor should preserve Unix signal status when available, and spawn/wait failures should be converted into structured lifecycle/broker-error evidence instead of only returning an error. Tests should start the lifecycle before launching the child so session records bracket the child lifetime.

## 2026-06-22 — Child sessions require terminal status and fan-in needs backpressure proof

- If a runtime session includes `child_process`, exiting without child status is not clean; it must emit `child_status=unknown` and fail closed. A runtime-level audit fan-in contract should ingest records by per-source sequence and surface fan-in backpressure as structured `audit_backpressure` evidence.

## 2026-06-22 — Fan-in cursor updates must survive partial backpressure

- Runtime audit fan-in batches can accept some source records before a later record hits bounded-ledger backpressure. Persist the last accepted source sequence before returning backpressure so retries skip already archived records instead of reattempting from a stale cursor.

## 2026-06-22 — Supervised child proof should own start-to-exit evidence

- A child supervisor proof is stronger when it owns the lifecycle: emit `network_session_start` before spawn, record structured `broker_error` on spawn/wait failure, and always emit terminal `network_session_exit`. Spawn failure must not leave only a running lifecycle plus broker error.

## 2026-06-22 — Task joins are lifecycle evidence, and lifecycle errors must retain ledgers

- Runtime exit evidence should include task join/cancellation outcomes; failed or unjoined runtime tasks are `runtime_state` failures, while graceful cancellation can be recorded as a successful join outcome.
- Helpers that own lifecycle ledgers must return partial ledger evidence on audit backpressure. Returning only the error can hide the structured `broker_error`/`audit_backpressure` records needed to debug fail-closed shutdown.

## 2026-06-22 — Blocking runtimes should expose task join exit paths

- Runtime task-join contracts are more useful when blocking runtime harnesses can pass them through their concrete exit methods. This keeps listener cleanup/retirement evidence and task join outcomes on the same `network_session_exit` record.

## 2026-06-22 — TUN read failures must be ledger-visible

- Packet loops can fail before a packet exists to parse or authorize. TUN/device read failures still need structured `broker_error` evidence (`device_io_error=read_failed`) so runtime shutdown can explain why packet processing stopped.

## 2026-06-22 — Task reports must prove coverage, not just success

- A non-empty task report with only successful outcomes can still be incomplete. Runtime exit must compare task outcomes with the components started for the session and fail closed with `task_join_status=incomplete` when any component is missing.

## 2026-06-22 — Packet loops should return task outcomes

- Single-step packet processing is not enough for runtime supervision. A bounded TUN packet loop should report processed count, terminal device error, and a `RuntimeTaskOutcome` so lifecycle exit can include concrete task join evidence.

## 2026-06-22 — Task expectations need names, and loop branches need direct proof

- Component-level task coverage can still hide missing spawned handles when one component owns multiple tasks. Runtime lifecycle start should be able to record expected task names, and exit should compare task outcomes against those names when provided.
- Progress claims for packet-loop terminal states should have direct tests for each branch: idle completion, bounded cancellation, read failure, and write failure.

## 2026-06-22 — smoltcp bridge loops need the same task/outcome contract as TUN

- Userspace stack bridges can stop before packet parsing when the device read fails. smoltcp/TUN bridge loops should emit structured read-failure audit evidence and return `RuntimeTaskOutcome` so lifecycle exit can explain stack-loop shutdown.

## 2026-06-22 — Expected task reports must be mandatory and name-complete

- Once lifecycle start records expected runtime task names, exit without a task report must fail closed with `task_join_status=not_recorded`; otherwise clean shutdown can overclaim success.
- Named task expectations must not replace component coverage. If any started component has no expected task, missing task evidence should still include that component.

## 2026-06-22 — smoltcp loop outcomes need all terminal branches tested

- Like the TUN loop, the smoltcp bridge loop should directly prove idle completion, bounded cancellation, read failure, and write failure. Otherwise progress can overclaim that loop outcomes map to lifecycle task evidence.

## 2026-06-22 — Task expectations should come from a supervisor registry

- Harness-declared task names are a useful contract, but a runtime needs a registry-like supervisor that records handles, derives expectations from registered tasks, and rejects unknown or duplicate task outcomes before lifecycle exit consumes the join report.

## 2026-06-22 — Task names must be unique when reports match by name

- If task join reports match outcomes to expectations by `(component, task_name)`, the task supervisor must reject duplicate registrations for that pair. Otherwise one outcome can satisfy multiple same-named expected tasks.
- Runtime audit fan-in also needs a concrete drain-to-sink contract: successful drains should advance a drain cursor, and sink write failures should leave structured fail-closed evidence in the fan-in ledger.

## 2026-06-22 — Blocking thread tasks can prove supervisor integration

- A concrete blocking task-set proof can bridge the gap between abstract task reports and real handles: register task names, spawn threads, translate join success/panic into runtime task statuses, and feed the resulting report into lifecycle exit.

## 2026-06-22 — Direct lifecycle expectations and fan-in sink failures need fail-closed preservation

- Duplicate task-name protection must exist both at supervisor registration and direct lifecycle start with explicit expectations; direct callers can bypass supervisor checks otherwise.
- Audit sink write failure evidence should not be lossy-appended into the same full ledger that still contains undrained records. Return the failure record separately so retry/durable-drain evidence is not evicted before it reaches the sink.

## 2026-06-22 — Primary audit sink failures need a separate emergency path

- Returning sink-failure records preserves undrained in-memory records, but a caller also needs a way to write the failure record somewhere other than the failed primary sink. A fan-in drain helper can attempt an emergency/failure sink without advancing the primary drain cursor.

## 2026-06-23 — Fallback audit and blocking task spawn failures need observable second-order failures

- Do not discard secondary evidence-path failures with `let _ = ...`; if an emergency/failure audit sink fails, return a structured failure record so the caller can distinguish persisted fallback evidence from total sink loss.
- Blocking runtime task spawning should use `std::thread::Builder::spawn` rather than `std::thread::spawn` so OS thread creation failure can be represented as a task `join_failed` outcome and drive fail-closed lifecycle exit evidence instead of panicking.

## 2026-06-23 — Blocking task joins need bounded timeout evidence

- A task registry can still hang shutdown if joining waits forever. Blocking task supervision needs a bounded join path that records a structured `timed_out` task outcome so lifecycle exit can fail closed with inspectable evidence.

## 2026-06-23 — Cancellable blocking tasks close the timeout-only supervision gap

- Bounded join timeouts make hangs observable, but cooperative cancellation is needed before timeout to prove clean shutdown. A simple cancellation token lets blocking task proofs return `cancelled` and lifecycle exit can remain `allow` with structured task evidence.

## 2026-06-23 — Runtime exit should own task cancellation/join handoff

- Proving cancellable tasks independently is not enough; the runtime exit path should accept the task set, request cancellation, bounded-join it, and feed the resulting report into lifecycle exit so cleanup, listener teardown, and task evidence stay in one observable shutdown path.

## 2026-06-23 — Packet loops need external cancellation predicates, not just budgets

- Budget-based loop cancellation proves bounded harness execution, but runtime shutdown needs an external cancellation signal. Packet-loop helpers should accept cancellation predicates and return the same structured `cancelled` task outcome before consuming further device input.

## 2026-06-23 — TUN and smoltcp loops should share shutdown semantics

- The smoltcp bridge loop needs the same external cancellation contract as the raw TUN loop so final runtime shutdown can cancel either packet path without relying on packet budgets or idle devices.

## 2026-06-23 — Cleanup must run even when exit audit is backpressured

- Runtime shutdown cannot return early on lifecycle audit backpressure before retiring listeners/devices. Archive whatever evidence exists, close listener handles, then return the audit error so fail-closed evidence and cleanup robustness both hold.

## 2026-06-23 — Cancellation-aware loops require nonblocking IO contracts

- Checking a cancellation token before each loop iteration is only meaningful if the underlying IO operation is nonblocking or time-bounded. Listener accept loops and TUN reads should treat WouldBlock/no-ready as idle, allowing shutdown tokens to be observed without waiting for traffic.

## 2026-06-23 — DNS listeners also need idle cancellation semantics

- HTTP/SOCKS accept loops were made cancellation-aware, but DNS listener loops can still wait on UDP receive unless the socket is nonblocking/time-bounded. Treating no-packet-ready as an idle step lets DNS listener tasks observe cancellation without traffic.

## 2026-06-23 — DNS idle is not an upstream failure

- Once DNS listener sockets are nonblocking, `WouldBlock`/timeout must be modeled as an idle no-packet-ready step, not `DnsUpstreamError::Unavailable`. Cancellation loops may ignore idle, but real receive errors must remain distinct so task failure evidence is meaningful.

## 2026-06-23 — Proxy listener idle is not send failure

- After HTTP/SOCKS listeners become nonblocking, idle accepts must return a distinct no-client-ready result. Mapping `WouldBlock` to `SendFailed` makes cancellation tests pass only by ignoring errors and hides real listener failures.

## 2026-06-23 — Listener loop wrappers turn idle/error/cancel into task outcomes

- Once listener `handle_one` methods distinguish idle from failure, runtime task loops should use that distinction directly: idle continues, cancellation returns `cancelled`, and real listener errors return `failed` so lifecycle exit can emit structured task evidence.

## 2026-06-23 — Listener task loops need reusable status mapping

- Per-listener cancellation loops should share one idle/handled/error mapping so DNS, HTTP, and SOCKS cannot drift: handled work resets idle budget, idle advances it, cancellation returns `cancelled`, and real listener errors return `failed` for lifecycle task evidence.

## 2026-06-23 — Idle budget exhaustion is not cancellation evidence

- Listener loop helpers must reserve `RuntimeTaskStatus::Cancelled` for an observed cancellation signal. Idle-budget exhaustion without cancellation is a timeout/fail-closed task outcome, while per-client read timeouts should be audited as request failures and should not stop the listener task.

## 2026-06-23 — Listener error audits should be asserted per frontend

- Shared listener-loop status tests are not enough on their own; each listener frontend should have structured audit assertions for `listener_loop_error` records so DNS/HTTP/SOCKS task failures retain component, task, frontend/protocol, and error detail evidence.

## 2026-06-23 — Audit assertions should cover typed and detail fields

- When documenting structured audit coverage, assert both typed record fields (`frontend`, `protocol`, `decision`, `reason`) and string details (`runtime_error`, component, task, error detail) for every frontend to avoid overclaiming observability evidence.

## 2026-06-23 — HTTP proxy reads must require complete headers

- Treat HTTP proxy client reads that time out or close before `\r\n\r\n` as malformed per-request failures. Returning partial parseable request lines can accidentally allow/forward slow-client requests after a read timeout.

## 2026-06-23 — Partial HTTP read evidence needs source and status

- Fail-closed HTTP proxy read handling should not collapse every incomplete read into an empty parse error. Add explicit read-failure audit evidence with client/source, observed byte count, and status (`empty_error`, `partial_error`, EOF, or limit) before passing malformed bytes to the parser.

## 2026-06-23 — Listener socket adapters make fault paths testable

- Wrap concrete listener sockets behind small traits when OS-level accept/recv faults are otherwise hard to trigger safely. Test fakes can then drive DNS recv and HTTP/SOCKS accept failures through the real `run_until_cancelled(...)` wrappers and assert both task failure status and structured `listener_loop_error` audit records.

## 2026-06-23 — Runtime aggregate must archive read-failure evidence promptly

- When listener handlers emit per-client failure audits, runtime-level aggregate tests should prove those records are archived immediately after `handle_*_once(...)`, not only visible through the individual frontend broker ledger.

## 2026-06-23 — Sink drains need no-duplicate cursor proof

- In-memory runtime aggregates should expose a sink drain with its own cursor and tests proving first drain writes all currently aggregated records and the next drain writes none. This is a stepping stone toward full async fan-in without overclaiming readiness integration.

## 2026-06-23 — Drain failures must preserve aggregate cursor

- Sink-backed aggregate drains should prove write failures do not advance the drain cursor. A subsequent successful drain must still emit all previously aggregated records, then repeated successful drains should emit zero duplicates.

## 2026-06-23 — Commit aggregate drain cursor only after full success

- A sink drain can succeed for some records and then fail. To preserve retry semantics, stage the aggregate drain cursor locally and commit it only after every pending record is appended successfully; otherwise a retry may skip records after partial sink failure.

## 2026-06-23 — Fan-in must ingest live source ledgers by source

- Runtime aggregate records can contain duplicate per-ledger sequence numbers, so core fan-in should ingest live lifecycle/DNS/HTTP/SOCKS ledgers as separate named sources rather than treating a flattened aggregate vector as one source. This preserves source cursors and avoids sequence collisions.

## 2026-06-23 — Audit fan-in needs task lifecycle evidence

- A fan-in bridge should be paired with task-supervisor evidence: register an `audit_fan_in` runtime component/task, pump/drain fan-in work until cancellation, and prove lifecycle exit records the fan-in task outcome alongside listener tasks.

## 2026-06-23 — Fan-in task failures must fail closed in lifecycle

- In addition to clean cancellation, audit fan-in runtime tasks need failure-path lifecycle coverage. Pump/drain errors should return `RuntimeTaskStatus::Failed`, and `network_session_exit` should fail closed with the `audit_fan_in:audit_fan_in_loop:failed` task outcome.

## 2026-06-23 — Live source fan-in should run through the same pump loop

- After proving source-specific fan-in ingestion directly, also drive live runtime ledgers through the fan-in pump loop. This verifies progress/idle handling, duplicate source cursor behavior, and sink output under the same loop semantics used by the audit fan-in runtime task.

## 2026-06-23 — Listener and fan-in task outcomes should join together

- Runtime lifecycle coverage should include listener loops and audit fan-in in the same task report. This catches ordering/coverage bugs where listeners cancel cleanly but the fan-in task is omitted from expected runtime components or cleanup evidence.

## 2026-06-23 — Runtime fan-in sink cursor must be all-or-nothing

- `RuntimeAuditFanIn::drain_to_sink_with_failure_sink` must stage `last_drained_sequence` locally and commit it only after every pending record appends successfully. Advancing the cursor per record can skip already-written-but-uncommitted records on retry if the sink fails mid-batch.

## 2026-06-23 — Runtime-owned fan-in must be in the runtime contract

- When a runtime owns audit fan-in, include `AuditFanIn` in lifecycle components, task expectations, cleanup actions, and joined task reports. Standalone fan-in tests are not enough to catch missing runtime-exit ownership.

## 2026-06-23 — Runtime fan-in ownership applies to reduced runtimes too

- If a reduced blocking runtime variant starts listener task expectations, it should also declare and clean up audit fan-in consistently with the fuller runtime. Otherwise lifecycle proofs can pass in the full path while older DNS/HTTP-only runtime evidence omits the fan-in task contract.

## 2026-06-23 — Runtime fan-in needs a sink-backed API, not only test plumbing

- Source-specific fan-in ingestion should be paired with a runtime-owned drain-to-sink method that reports both accepted source records and drained sink records. Tests can then assert duplicate calls make no progress and that the sink contains stable JSONL evidence without manually reimplementing the pump body.

## 2026-06-23 — Final fan-in drain needs pre-exit and post-exit phases

- A shutdown drain must collect live listener ledgers before runtime exit drops listener ownership, then drain again after lifecycle exit to capture `network_session_exit`. A single post-exit live-source drain only sees lifecycle records after listeners have been closed.

## 2026-06-23 — Shutdown must not be gated by audit sink success

- Final-drain helpers must attempt lifecycle exit and resource cleanup even when the pre-exit audit fan-in drain fails. Return phase-specific evidence for pre-exit drain, exit, and post-exit drain failures instead of using `?` before cleanup.

## 2026-06-23 — TUN and smoltcp budgets are timeouts, not cancellation

- Packet-loop budget exhaustion should report `RuntimeTaskStatus::TimedOut`; reserve `Cancelled` for observed cancellation tokens. This keeps TUN/smoltcp task lifecycle semantics aligned with listener and fan-in loops.

## 2026-06-23 — smoltcp timer readiness should be explicit evidence

- `smoltcp` exposes the next required poll via `Interface::poll_delay(...)`. Preserve that value in stack poll evidence so the eventual runtime scheduler can distinguish immediate re-polls, finite timer waits, and no active timer.

## 2026-06-23 — Scheduler planning needs task readiness and timer inputs

- Keep readiness planning independent of a concrete async runtime: model ready tasks, next timer delay, and idle state as typed evidence first. smoltcp poll evidence can then be converted into this scheduler input without claiming the final scheduler exists.

## 2026-06-23 — Readiness plans need audit records before scheduler wiring

- Runtime readiness/timer decisions should be auditable before the final scheduler exists. Recording readiness plans in lifecycle audit makes ready tasks, timer waits, idle states, and invalid lifecycle transitions inspectable as structured evidence.

## 2026-06-23 — Readiness audit invalid transitions need both lifecycle edges

- When adding lifecycle-scoped audit evidence, test both not-started and already-exited rejection paths. The exited case should preserve prior duration/runtime status details while still recording the attempted transition as fail-closed evidence.
