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
