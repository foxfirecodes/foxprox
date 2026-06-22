# Learning Ledger


## 2026-06-21 — keep first core slice dependency-free

The initial normalized event → policy → audit proof did not require serde or networking dependencies. Typed audit records plus unit tests were enough evidence for the first platform-independent boundary; external serialization can wait until an audit sink slice needs it.

## 2026-06-21 — parser slice should own raw buffers briefly

Keeping raw IPv4 bytes inside a dedicated packet crate made the architecture boundary explicit: parser tests can use fixtures, but policy/audit only see `foxprox-core` normalized events. Fragmentation is rejected before normalization and converted to fail-closed evidence when needed.

## 2026-06-21 — packet write-back can be proven before TUN privileges

ICMP echo reply synthesis gives useful checksum and source/destination reversal evidence without needing `/dev/net/tun` or bwrap. The remaining risk is connecting this packet builder to real TUN IO and sandbox ping behavior.

## 2026-06-21 — broker orchestration can stay platform-independent

A single-packet broker handler can prove parser → policy/audit → write-back behavior without importing Linux or async IO. This gives the eventual TUN frontend a narrow contract: supply packet bytes and write returned outbound packets.

## 2026-06-21 — stable audit output can map from core records

The audit output crate can avoid coupling serialization derives into `foxprox-core` by mapping `AuditRecord` into a JSON-specific schema. This keeps the core boundary typed and allows audit output format to evolve independently.

## 2026-06-21 — config parsing should terminate in core types

The TOML config layer is safest when it validates strings at the edge and returns `PolicyConfig`; broker code does not need to know whether policy came from tests, TOML, or a future live reload source.

## 2026-06-21 — keep CLI audit stdout separate from packet bytes

The first process-boundary harness should emit JSON Lines audit on stdout and write synthesized packet bytes only to an explicit output target. Mixing binary write-back with audit stdout would make runtime evidence and downstream log collection ambiguous.

## 2026-06-21 — DNS observations need payload fixtures, not just UDP/53

Port-based DNS classification is enough for direct-bypass denial, but hostname attribution requires real DNS question fixtures. Minimal uncompressed QNAME parsing gives useful audit evidence now while leaving compression and response caching for a later DNS subsystem slice.

## 2026-06-21 — DNS attribution should not overwrite stronger metadata

DNS cache correlation is only medium-confidence. The enrichment layer should fill missing transparent flow attribution but preserve higher-confidence metadata from future HTTP Host, TLS SNI, QUIC metadata, or explicit proxy frontends.

## 2026-06-21 — HTTP policy needs audit fields, not just match logic

Adding method/path matching without carrying those fields into structured audit would make policy behavior hard to verify externally. Semantic inspection slices should update both rule evaluation and audit output together.

## 2026-06-21 — TLS metadata parsers must stay length-first

Even a minimal SNI-only ClientHello parser has multiple nested length fields. Keep it isolated in inspection code, fail on truncation, and emit only normalized metadata so policy never depends on TLS parser internals.

## 2026-06-21 — host-only proxy events still need port matching

Policy port rules cannot depend solely on IP endpoints. Explicit proxy events may know host and port before DNS resolution, so core matching should use an event-level destination port abstraction.

## 2026-06-21 — SOCKS5 CONNECT parsing should expose both host string and IP when available

Domain-form SOCKS requests feed hostname policy directly, while IP-form requests should preserve destination IP for audit/IP policy. Do not infer domain attribution from IP-form requests.

## 2026-06-21 — DNS response parsing needs compression loop protection

DNS answer names commonly use compression pointers, so response parsing is necessary for realistic cache population. Pointer following must be bounded and fail closed on loops before using any hostname attribution.

## 2026-06-21 — flow tables should not force endpoint ordering

Core endpoints are hashable but not ordered. Use hash-keyed flow tables for lifecycle state rather than adding ordering constraints to core types without a policy reason.

## 2026-06-21 — keep policy-only config loading as a compatibility wrapper

As runtime config grows beyond policy, expose a combined validated config while retaining a policy-only loader for callers and tests that only need `PolicyConfig`.

## 2026-06-21 — lifecycle audit events need a non-decision state

Flow expiration is observed lifecycle evidence, not an allow/deny decision. Audit schemas should distinguish policy decisions from lifecycle observations to avoid misleading logs.

## 2026-06-21 — default-deny safeguards should run after explicit allow rules

For policy defaults like multicast/broadcast denial, evaluate explicit rules first so narrowly configured opt-ins can work without adding special bypass flags.

## 2026-06-21 — protocol-specific defaults should produce protocol-specific denial reasons

When a protocol has documented defaults, audit reasons should identify that layer (for example `icmp-default-deny`) rather than falling through to global `default-deny`.

## 2026-06-21 — minimal IPv6 support should reject extension headers until handled deliberately

Fixed-header IPv6 TCP/UDP/ICMPv6 parsing can reuse normalized core events, but extension headers include fragmentation and routing semantics that should fail closed until explicitly modeled.

## 2026-06-21 — ICMP type semantics depend on IP family

The normalized `IcmpMessage` type can still distinguish ICMPv4 from ICMPv6 by endpoint address family. Use IPv6 error types 1–4 and echo type 128 for ICMPv6; do not reuse IPv4 type 8/3/11/12 semantics blindly.

## 2026-06-21 — dispatch IP version before fail-closed parsing

The broker-facing packet boundary should inspect only the first version nibble, then hand raw bytes to the appropriate packet parser. Unknown or empty input becomes an unsupported normalized event, while IPv4-only packet synthesis must remain guarded by IPv4 endpoints and ICMPv4 type numbers.

## 2026-06-21 — proxy frontend preflight should fail closed before egress

Explicit proxy handlers can safely prove request parsing, policy, audit, and response generation before TCP tunneling exists. Malformed proxy requests should be converted to unsupported normalized events so they produce fail-closed audit records and denial responses instead of parser-only errors.

## 2026-06-21 — SOCKS5 denial responses should preserve denial class

For SOCKS5 CONNECT preflight, policy denials should return reply code 0x02 (connection not allowed by ruleset), while malformed or unsupported requests should fail closed in audit and return general failure 0x01. This keeps client-visible behavior aligned with audit semantics.

## 2026-06-21 — explicit HTTP proxy parsing needs absolute-form normalization

Transparent HTTP inspection can consume origin-form paths plus Host headers, but explicit HTTP proxy requests should parse absolute-form URLs and normalize the policy path to `/path?query`. Otherwise path-prefix rules would accidentally match against `http://host/...` instead of the request target path.

## 2026-06-21 — use loopback servers for host egress evidence

Host egress can be verified without external network dependencies by binding a loopback listener in the test, connecting through the egress backend, and exchanging bytes. This proves the socket boundary while keeping tests deterministic and offline.

## 2026-06-21 — keep CONNECT target available outside audit records

Audit records are not a replacement for frontend control state. HTTP CONNECT egress establishment needs the parsed host/port target alongside the policy evaluation because host-only CONNECT events do not produce an IP endpoint in audit output.

## 2026-06-21 — SOCKS IP-form requests make deterministic egress tests

When testing SOCKS5-to-egress integration, use IPv4 address-form CONNECT requests to loopback. The parsed event yields a direct IP target and avoids DNS resolution variability while still exercising the shared egress boundary.

## 2026-06-21 — UDP egress connect needs datagram evidence

A UDP socket can connect locally without proving a peer exists. Verify UDP egress with an actual send/receive exchange against a loopback UDP server rather than treating `UdpSocket::connect` alone as forwarding evidence.

## 2026-06-21 — DNS forwarding can feed attribution from response answers

The DNS forwarder does not need to trust or retain the original query name to populate attribution. It can parse answer owner names from the upstream response and record A/AAAA TTLs into the attribution cache, provided malformed responses fail closed.

## 2026-06-21 — DNS broker denial should answer before egress

A broker-owned DNS resolver needs a pre-egress request boundary: parse the question into a policy event, audit the decision, and synthesize REFUSED/FORMERR/SERVFAIL responses for denied, malformed, or upstream-failed queries. This prevents direct fallback behavior while keeping upstream UDP egress reserved for allowed queries only.

## 2026-06-21 — HTTP proxy forwarding must rewrite before upstream egress

Explicit HTTP proxy requests arrive in absolute-form, but origin servers expect origin-form request targets. Reuse the parsed `HttpRequest` event to choose the host egress target and rewrite only the request line to the normalized path/query before writing to the shared TCP egress connection.

## 2026-06-21 — SOCKS5 greeting is protocol state, not policy state

SOCKS5 method negotiation should be validated before CONNECT policy events exist. Keep it as a frontend protocol preflight that accepts only no-authentication for alpha and rejects unsupported or malformed greetings without emitting misleading network-policy audit records.

## 2026-06-21 — TCP tunnel pumps need EOF and byte-count evidence

A deterministic blocking tunnel proof can use cloned `TcpStream`s, copy upload in one thread, copy download in the caller, and shut down write halves on EOF. Return byte counts separately so later flow-close audit code can consume forwarding evidence without coupling egress to policy types.

## 2026-06-21 — flow-close audit should keep directional bytes optional

TCP bridge statistics are directional, but many audit records only have a total byte count or no bytes. Keep directional counts optional in the core audit schema so TCP close records can be precise without forcing UDP expiration or policy-decision records to invent fields.

## 2026-06-21 — live DNS listener tests should bind policy to the actual socket

When testing a broker DNS socket on loopback with an ephemeral port, construct the policy broker-resolver endpoint from `socket.local_addr()` instead of assuming UDP/53. This keeps direct-DNS policy and listener validation aligned with the live socket under test.

## 2026-06-21 — one-request proxy listeners prove socket boundaries without async runtime

A blocking one-request TCP listener is enough to prove explicit proxy reachability and egress integration with deterministic loopback tests. Keep it narrow: read a bounded request head, reuse preflight/egress helpers, and defer concurrency, body streaming, and backpressure to later runtime slices.

## 2026-06-21 — CONNECT listeners should send the proxy response before bridging

For HTTPS CONNECT, perform policy and egress setup first, write the `200 Connection Established` response to the client, and only then hand the client stream plus egress connection to the bidirectional bridge. This keeps proxy handshake bytes out of tunnel byte counts.

## 2026-06-21 — SOCKS5 listener state joins unaudited greeting to audited CONNECT

The SOCKS5 listener should treat method negotiation as protocol state, write the no-auth response first, then parse CONNECT and hand that request to the shared policy/audit/egress path. Only CONNECT represents network intent worthy of policy audit.

## 2026-06-21 — bwrap command shape belongs outside broker core

Keep bwrap-specific flags, `foxproxsetup -- target` wrapping, `/dev/net/tun` exposure, and proxy env injection in an integrations crate. The broker core should continue to see only normalized sessions, policy, audit, and device/egress abstractions.

## 2026-06-21 — fd handoff needs one reviewed unsafe conversion

SCM_RIGHTS delivers raw file descriptors owned by the receiving process. Wrap each received raw fd exactly once in `OwnedFd` immediately after `recvmsg`; drop extras to avoid leaks. Keep this unsafe conversion isolated in the integration handoff module, not in broker core.

## 2026-06-21 — TUN creation tests should prove fail-early on unprivileged hosts

Opening `/dev/net/tun` may be possible without effective `CAP_NET_ADMIN`, while `TUNSETIFF` can still fail. Keep the Linux device primitive explicit about open versus ioctl failures and let live tests accept either a transient successful fd or a clear permission/setup error.

## 2026-06-21 — setup network command tests should use fake executables

For namespace setup behavior, fake `ip` executables provide concrete process-boundary evidence of exact arguments and failure handling without mutating the host network namespace or requiring root. Reserve live privileged verification for a smaller end-to-end bwrap/TUN slice.

## 2026-06-21 — resolver setup should be deterministic and narrow

Have setup write a minimal generated resolver file pointing at the broker nameserver and `ndots:0`; keep path selection separate so tests can verify file content without requiring a mount namespace or mutating host `/etc/resolv.conf`.

## 2026-06-21 — setup fd handoff should be last after network config succeeds

In the setup helper sequence, configure the interface and resolver before sending the fd to the broker. If setup fails first, the broker never receives a fd and cannot treat a partially configured sandbox network as ready.

## 2026-06-21 — create TUN before mutating sandbox network config

The production setup sequence should create the TUN fd first, then configure interface state, resolver, and handoff. If TUN creation fails, do not run `ip` commands or write resolver files; this avoids partial sandbox network setup with no broker fd.

## 2026-06-21 — flow limits should reject only new state

When a UDP flow table is at capacity, reject new flow creation but keep allowing updates to existing flows. Otherwise a full table could break cleanup/refresh behavior for flows that are already being tracked.

## 2026-06-21 — resource limits need config-level validation

Resource limit primitives are not enough; runtime config should reject nonsensical values like zero before constructing stateful components. Keep policy-only loading compatible while extending the combined runtime config.

## 2026-06-21 — test temp paths need more than process id

Rust tests in one process can run in parallel, so temp paths based only on process id can collide and cause odd executable-file races like `Text file busy`. Include a per-test unique suffix such as timestamp nanos for fake scripts and files.

## 2026-06-21 — TUN fd consumption can be tested with fd stand-ins

A broker-facing TUN IO wrapper only needs an owned fd with read/write behavior for boundary tests. Use a Unix stream pair as a deterministic fd stand-in, and keep real `/dev/net/tun` behavior in the create/ioctl tests.

## 2026-06-21 — fd-backed packet processing can reuse packet-once core

Keep packet processing byte-oriented and isolate fd reads/writes in `TunPacketIo`; then a TUN runtime helper can read one packet from a received fd, call the existing broker path, and write replies without duplicating policy/audit logic.

## 2026-06-21 — use datagram fd stand-ins for multi-packet TUN tests

For tests that need to prove multiple TUN packet reads remain separate, a Unix datagram pair is a better fd stand-in than a Unix stream pair because each send maps to one read-sized datagram.

## 2026-06-22 — setup command tests can prove the process boundary without privileges

Keep the production `foxproxsetup` path responsible for creating the real TUN fd, but expose a setup-sequence test seam that accepts a raw TUN-like fd. A Unix listener plus fake `ip` command can prove parser shape, resolver writes, SCM_RIGHTS handoff, and broker-side fd usability without requiring `CAP_NET_ADMIN`.

## 2026-06-22 — Linux capability syscalls need local FFI layouts

The Rust `libc` crate may not expose `CAP_NET_ADMIN` or `__user_cap_*` structs on this target. For narrow `capget`/`capset` usage, define the Linux v3 capability header/data as small `repr(C)` structs and keep tests on pure bitset mutation so the test process does not drop its own capabilities.

## 2026-06-22 — keep launcher plans in sync with executable helper parsers

Once a setup helper has a real CLI parser, the bwrap plan must construct that exact argument vector, including placing setup-helper args before the target `--` separator. Otherwise library setup tests can pass while the actual launch command cannot start.

## 2026-06-22 — live setup proof should use unprivileged UDP, not ping

After `foxproxsetup` drops setup capabilities, `ping` may fail because the target lacks raw-socket privileges. For live TUN ingress proof, use a normal UDP socket from the target namespace and read the resulting IPv4 UDP packet from the broker's received TUN fd.

## 2026-06-22 — fd handoff tests need read/write fd stand-ins

SCM_RIGHTS can transfer a write-only descriptor successfully, but broker-side read evidence will fail with `Bad file descriptor`. Use read/write fd stand-ins when the test needs to verify the broker can consume received setup fds.

## 2026-06-22 — keep privileged namespace smoke tests ignored but runnable

For bwrap/TUN proofs that depend on host kernel features and `/dev/net/tun`, add ignored integration tests and run them explicitly during vertical-evidence work. Default workspace tests should compile them but not require privileged namespace support.
