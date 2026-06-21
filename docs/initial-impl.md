# Rust Transparent Network Broker Architecture and Stack

## Decision

The transparent network broker will be implemented in Rust.

Rust is chosen for:

* memory safety
* strong correctness guarantees
* good performance without a garbage collector
* mature async/networking ecosystem
* maintainability for security-sensitive network policy code
* lower implementation risk than C/C++ for packet and policy handling

A Zig rewrite is out of scope for the initial implementation.

## Scope

This document covers the transparent network broker only.

The broker is responsible for:

* creating or attaching to a network device for a sandbox network namespace
* mediating all network traffic that crosses that device
* enforcing network policy
* producing network audit logs
* exposing optional explicit proxy listeners
* supporting transparent networking for applications that do not use proxies

The broker is not responsible for:

* creating the full sandbox
* configuring filesystem isolation
* applying mount namespace policy
* applying Landlock policy
* applying seccomp policy
* creating PID/IPC/UTS namespaces
* deciding what host files or sockets are exposed to the sandbox
* launching arbitrary sandbox profiles beyond network-device setup and broker wiring

Those responsibilities belong to the sandbox launcher/runtime that uses the broker.

## Goals

The Rust broker provides mediated network access for sandboxed applications.

It supports two network access modes:

* transparent TUN-based networking for applications that do not support proxy configuration
* explicit HTTP/SOCKS proxy networking for richer origin-aware filtering

The same policy engine, audit subsystem, DNS subsystem, and host egress backend must be shared by both modes.

Alpha implementation is staged around a small forwarding proof before richer policy features.

Foundation alpha features:

* TUN device creation/configuration inside a sandbox network namespace
* packet logging from the TUN fd
* packet write-back proof, such as synthetic ICMP echo replies
* `smoltcp`-based TUN TCP forwarding proof
* unfiltered TCP forwarding through host sockets
* minimal UDP forwarding proof
* DNS handling sufficient for transparent traffic tests
* structured audit/log output for packet, flow, and setup events
* bwrap-compatible setup using a `foxproxsetup` command with temporary `CAP_NET_ADMIN`
* backend design not hardwired to bwrap
* fail-closed behavior for malformed or unsupported packet paths

Richer alpha features after the forwarding proof:

* configurable default network policy
* IP/CIDR/port allow and deny rules
* transparent DNS correlation
* hostname/domain policy when attribution exists
* transparent hostname-aware HTTP/HTTPS filtering
* plaintext HTTP Host/method/path inspection
* TLS ClientHello SNI parsing for direct HTTPS
* best-effort QUIC metadata classification
* HTTP proxy support
* HTTPS `CONNECT` support
* SOCKS5 TCP `CONNECT` support
* ICMP basics beyond the packet write-back proof
* QUIC-over-UDP support
* configurable UDP flow timeouts

## Non-Goals

The initial implementation does not support:

* TLS MITM
* custom CA installation
* TAP/Layer 2 networking
* slirp4netns
* pasta
* full HTTPS URL/path visibility
* encrypted HTTP header/body inspection
* full browser-origin policy
* arbitrary LAN broadcast/multicast
* SOCKS UDP ASSOCIATE
* proxy authentication
* hand-written TCP stack from scratch unless unavoidable
* full sandbox creation
* filesystem policy
* process namespace policy
* syscall policy

## Network Visibility Model

Transparent TUN mode gives compatibility with applications that do not support proxy configuration.

TUN mode can evaluate:

* protocol
* source IP/port
* destination IP/port
* DNS-correlated hostname where available
* plaintext HTTP method, host, port, and path/query
* TLS SNI for direct HTTPS where available
* QUIC candidate status
* best-effort QUIC/TLS metadata where feasible
* byte counts and timing

TUN mode cannot evaluate:

* full HTTPS URL/path
* encrypted HTTPS headers
* encrypted HTTPS request/response bodies
* encrypted HTTP/3 request metadata
* hidden SNI/ECH-protected hostnames

Explicit proxy mode gives richer semantic visibility for applications that support it.

HTTP proxy mode can evaluate:

* HTTP method
* scheme
* host
* port
* plaintext path/query
* selected plaintext headers if needed

HTTPS proxy mode can evaluate:

* `CONNECT` hostname
* `CONNECT` port
* requested HTTPS origin at host/port granularity

SOCKS5 mode can evaluate:

* requested destination host/IP
* requested destination port
* TCP connect intent

No mode performs TLS decryption.

## HTTP/HTTPS Filtering Semantics

The broker supports multiple levels of HTTP/HTTPS filtering.

### Explicit HTTP Proxy

For plaintext HTTP proxy requests, the broker can evaluate:

* scheme
* host
* port
* method
* path/query
* selected plaintext headers if needed

This is the richest HTTP policy mode.

### Explicit HTTPS Proxy

For HTTPS proxy requests using `CONNECT`, the broker can evaluate:

* scheme = `https`
* destination hostname
* destination port

The broker cannot inspect encrypted URL paths, headers, or bodies.

### Transparent Plaintext HTTP

For direct non-proxy HTTP over TUN, the broker should inspect plaintext HTTP request bytes.

The broker can evaluate:

* method
* `Host` header
* destination port
* path/query
* selected plaintext headers if needed

This allows origin/path-aware policy for direct HTTP traffic without requiring proxy support.

### Transparent HTTPS

For direct non-proxy HTTPS over TUN, the broker should use:

* broker-controlled DNS correlation
* TLS ClientHello SNI parsing
* destination IP/port policy

The broker can evaluate:

* destination IP
* destination port
* DNS-correlated hostname where confidence is high
* TLS SNI where present and not encrypted
* SNI/DNS mismatch behavior

The broker cannot evaluate:

* full URL path
* HTTP method
* encrypted headers
* encrypted bodies

Default behavior:

* require hostname attribution for domain-based allow rules
* deny or require explicit IP/port allow rule when hostname attribution is unavailable
* deny/log SNI mismatch against DNS attribution by default
* deny/log hidden-SNI/ECH cases unless explicitly allowed by IP/port policy

### Transparent QUIC

For QUIC over UDP, usually UDP/443, the broker should use:

* broker-controlled DNS correlation
* destination IP/port policy
* best-effort QUIC/TLS metadata parsing where feasible

The broker can evaluate:

* UDP destination IP/port
* DNS-correlated hostname where confidence is high
* QUIC candidate classification
* visible TLS metadata where feasible

The broker cannot evaluate:

* HTTP/3 request path
* encrypted headers
* encrypted bodies
* hidden-SNI/ECH-protected metadata

Default behavior:

* QUIC support configurable
* longer UDP flow timeout
* require hostname attribution for domain-based allow rules
* deny or require explicit IP/port allow rule when hostname attribution is unavailable

## Hostname Attribution Model

The broker should maintain hostname attribution for transparent traffic.

Sources:

* broker-controlled DNS query/response cache
* plaintext HTTP `Host` header
* TLS SNI
* QUIC/TLS visible metadata where feasible
* explicit proxy destination host

Attribution confidence levels:

* explicit proxy host: high
* plaintext HTTP Host header: high for that HTTP request
* TLS SNI: high for that TLS connection when present
* DNS correlation: medium, because IPs can be shared/reused
* IP-only: low

Default policy:

* domain rules require high or medium hostname attribution
* IP-only flows are denied unless explicitly allowed by IP/CIDR/port rule
* SNI and DNS mismatch is denied/logged by default
* direct external DNS is denied
* DoH/DoT is denied by default where identifiable
* ECH/hidden-SNI is denied unless explicitly allowed by IP/CIDR/port rule

## High-Level Architecture

The broker is split into these layers:

* network namespace/device integration layer
* frontend layer
* transparent protocol inspection layer
* network stack adapter
* flow manager
* policy engine
* host egress backend
* DNS subsystem
* ICMP subsystem
* audit subsystem

Core rule:

Policy code operates on normalized request/flow events, not raw packet buffers or frontend-specific protocol objects.

## Network Namespace and Device Integration Layer

The broker must support mediation through a TUN device associated with a sandbox network namespace.

Initial device type:

* TUN

Initial namespace integration mode:

* bwrap-compatible setup helper: bwrap runs `foxproxsetup -- target args...` with temporary `CAP_NET_ADMIN`; `foxproxsetup` configures networking inside the sandbox network namespace, hands the TUN fd to the host broker, drops setup privileges, and execs the target app

The broker should not require bwrap specifically. It should support a generic model where another launcher/runtime provides:

* TUN fd, network namespace path/fd, or setup helper handoff channel
* sandbox/session ID
* desired TUN device config
* desired broker listener config
* policy config
* audit config

The broker integration layer is responsible for:

* creating or receiving the TUN device for the sandbox network namespace
* configuring sandbox-side IP addressing
* configuring routes needed to send traffic through the TUN device
* configuring broker DNS address inside the namespace
* creating proxy listener addresses reachable from the sandbox
* passing or retaining the TUN fd needed by the broker
* returning network environment values to the caller when needed
* dropping setup-only privileges before target application exec when using a setup helper

The broker integration layer is not responsible for:

* choosing application filesystem mounts except setup-helper requirements
* keeping network setup capabilities available to the target app
* applying final application seccomp before network setup completes
* applying non-network security policy

## Frontend Layer

The broker has multiple frontend types.

### TUN Frontend

Responsibilities:

* open or receive TUN fd
* read inbound IP packets from sandbox
* write outbound IP packets to sandbox
* expose packet stream to network stack adapter
* contain Linux-specific TUN IO code

The TUN frontend is the compatibility path for applications that ignore proxy settings.

### HTTP Proxy Frontend

Responsibilities:

* accept explicit HTTP proxy requests
* handle plaintext HTTP requests
* parse method, scheme, host, port, path/query
* handle HTTPS via `CONNECT`
* emit normalized HTTP/HTTPS policy events
* forward allowed requests through shared egress backend

The HTTP proxy frontend is the preferred path for applications that support HTTP proxy configuration.

### SOCKS5 Frontend

Responsibilities:

* accept SOCKS5 TCP connect requests
* parse destination host/IP and port
* emit normalized SOCKS/TCP policy events
* forward allowed streams through shared egress backend

SOCKS UDP ASSOCIATE is not alpha scope.

### Future TAP Frontend

TAP is not alpha scope.

Future TAP support should be implemented as another frontend that:

* parses Ethernet frames
* handles ARP
* handles IPv6 NDP
* extracts IPv4/IPv6 packets
* wraps outbound IP packets in Ethernet frames
* drops/logs unsupported EtherTypes

TAP must not require rewriting the policy engine or flow manager.

## Transparent Protocol Inspection Layer

The transparent protocol inspection layer enriches TUN-derived flows with higher-level metadata when available.

Responsibilities:

* parse plaintext HTTP request metadata
* parse TLS ClientHello SNI for direct HTTPS
* classify QUIC candidates
* attempt QUIC/TLS visible metadata parsing where feasible
* correlate flows with broker DNS cache
* detect attribution mismatches
* emit enriched normalized policy events

Inspection must be fail-closed for policy-sensitive cases.

If the policy requires hostname attribution and the broker cannot attribute a hostname, the flow must be denied unless an explicit IP/CIDR rule allows it.

## Normalized Policy Events

All frontends and transparent inspection paths emit common policy events.

Core event types:

* `TcpConnectAttempt`

  * source frontend
  * source IP/port where available
  * destination IP/port
  * hostname where known
  * hostname attribution source
  * hostname attribution confidence
  * requested origin where known
  * sandbox ID

* `UdpFlowAttempt`

  * source frontend
  * source IP/port
  * destination IP/port
  * hostname where known
  * hostname attribution source
  * hostname attribution confidence
  * protocol classification, such as DNS or QUIC candidate
  * sandbox ID

* `DnsQuery`

  * hostname
  * query type
  * sandbox ID
  * source frontend

* `HttpRequest`

  * source frontend
  * method
  * scheme
  * host
  * port
  * path/query
  * sandbox ID

* `HttpsConnect`

  * source frontend
  * host
  * port
  * sandbox ID

* `TlsClientHello`

  * source frontend
  * SNI where present
  * destination IP/port
  * DNS-correlated hostname where available
  * mismatch status
  * sandbox ID

* `SocksConnect`

  * destination host/IP
  * destination port
  * sandbox ID

* `IcmpMessage`

  * type/code
  * source/destination
  * sandbox ID

* `UnsupportedNetworkEvent`

  * reason
  * source frontend
  * safe metadata

## Network Stack Adapter

Preferred approach:

* use an existing Rust TCP/IP stack where practical
* do not hand-roll the TCP state machine in alpha

Primary candidate:

* `smoltcp`

The `smoltcp` integration is an early alpha gate. The broker must prove that a TUN fd can feed a userspace TCP/IP stack, accept sandbox TCP connections, open host TCP sockets, bridge bytes in both directions, and emit outbound IP packets back to the sandbox before the policy model grows beyond minimal allow-all/deny-all behavior.

The adapter owns integration between TUN packets and the userspace stack.

Responsibilities:

* receive IP packets from TUN frontend
* feed packets into TCP/IP stack
* expose TCP connect/stream events
* expose UDP datagram events
* expose ICMP events
* emit outbound IP packets back to TUN
* handle checksums, timers, and packet lifecycle
* isolate stack-specific types from policy code

The rest of the broker must not depend directly on stack-specific APIs.

## Flow Manager

The flow manager tracks active network activity.

Responsibilities:

* TCP flow lifecycle
* UDP pseudo-flow lifecycle
* QUIC candidate classification
* DNS correlation
* hostname attribution state
* flow timeouts
* byte counters
* policy decision caching
* cleanup

TCP flow key:

* sandbox source IP
* sandbox source port
* destination IP
* destination port
* protocol = TCP

UDP flow key:

* sandbox source IP
* sandbox source port
* destination IP
* destination port
* protocol = UDP

Default UDP flow timeouts:

* DNS: 5–15 seconds
* generic UDP: 30–120 seconds
* QUIC: 2–5 minutes
* NTP-like one-shot UDP: short timeout
* multicast/broadcast: deny by default

All defaults must be configurable.

## Policy Engine

The policy engine makes deterministic allow/deny decisions.

Inputs:

* sandbox ID
* frontend type
* protocol
* source IP/port where available
* destination IP/port
* hostname where known
* hostname attribution source
* hostname attribution confidence
* origin where known
* HTTP method where known
* HTTP path/query where known and plaintext
* DNS query type where known
* TLS SNI where known
* SNI/DNS mismatch status
* QUIC candidate status
* flow age
* byte counts
* configured rule set

Decisions:

* allow
* deny/drop
* deny/reset
* deny/ICMP unreachable
* fail closed
* require broker DNS
* allow with timeout override

Rule dimensions:

* protocol:

  * TCP
  * UDP
  * DNS
  * ICMP
  * HTTP
  * HTTPS CONNECT
  * TLS SNI
  * SOCKS
  * QUIC candidate

* destination:

  * IP
  * CIDR
  * port
  * hostname
  * domain suffix
  * origin tuple: scheme + host + port

* request metadata:

  * HTTP method
  * plaintext HTTP path prefix
  * DNS query type
  * frontend type
  * attribution confidence
  * sandbox profile

Default policy:

* deny by default unless profile allows
* DNS only through broker resolver
* direct external DNS denied
* DoH/DoT denied by default where identifiable
* HTTP proxy requests evaluated by origin
* HTTPS CONNECT evaluated by host/port origin
* SOCKS CONNECT evaluated by destination host/port
* transparent HTTP evaluated by Host/method/path
* transparent HTTPS evaluated by SNI and DNS correlation
* transparent TCP evaluated by DNS-correlated hostname where available, otherwise IP/port
* UDP denied by default unless allowed
* QUIC configurable
* multicast/broadcast denied by default
* unsupported protocols denied
* hidden-SNI/ECH denied unless explicitly allowed by IP/CIDR/port rule

## Host Egress Backend

The host egress backend opens host-side sockets for allowed traffic.

Responsibilities:

* host TCP connect
* host UDP socket management
* proxy request forwarding
* response routing back to sandbox
* timeout handling
* error translation
* backpressure
* resource limits

This layer is trusted.

The sandboxed app must never receive direct host networking.

Both transparent and proxy frontends must use this shared egress layer.

## DNS Subsystem

The broker provides DNS service to the sandbox.

Responsibilities:

* answer DNS queries from sandbox
* forward allowed DNS queries upstream
* block denied DNS queries
* cache hostname-to-address mappings
* feed DNS observations into policy/audit
* detect direct DNS bypass attempts
* support configurable upstream resolver
* provide attribution metadata to the flow manager

Default behavior:

* sandbox resolver points to broker
* direct DNS to arbitrary external servers is denied
* DoH/DoT is denied by default where identifiable
* all DNS queries are logged
* DNS results are cached for flow correlation
* DNS correlation is treated as medium-confidence attribution

## ICMP Subsystem

Responsibilities:

* allow required ICMP errors
* optionally allow ping
* synthesize ICMP unreachable where useful
* deny unsupported ICMP types
* log ICMP decisions

Default behavior:

* essential ICMP errors allowed
* ping configurable
* unusual ICMP denied

## QUIC Support

QUIC is supported as UDP traffic.

Initial support:

* classify UDP/443 as QUIC candidate
* use longer UDP timeout
* use DNS correlation for hostname attribution
* parse visible QUIC/TLS metadata where feasible
* apply normal UDP/domain/IP/port policy
* no TLS decryption
* no HTTP/3 request inspection
* audit as QUIC candidate when detected

Default behavior:

* QUIC support configurable
* no MITM
* no custom CA
* require hostname attribution for domain-based allow rules
* deny or require explicit IP/port allow rule when hostname attribution is unavailable
* fail closed only for unsupported broker mechanics, not lack of decryption

## Proxy Exposure Inside Sandbox

The broker should expose proxy configuration values that the caller can inject into the sandbox environment.

Environment variables:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `ALL_PROXY`
* `NO_PROXY`

Proxy listener options:

* localhost TCP listener inside sandbox network namespace
* broker-controlled synthetic gateway IP
* Unix socket is optional future support, not required

Recommended alpha behavior:

* broker listens on a sandbox-reachable TCP address/port
* caller injects proxy environment variables into the sandboxed process
* apps that honor proxy variables use proxy frontend
* apps that ignore proxy variables still go through transparent TUN
* both paths use the same policy engine and audit subsystem

## Avoiding Proxy Bypass

Proxy support must not create a bypass around policy.

Required behavior:

* transparent TUN traffic goes through policy engine
* transparent HTTP inspection goes through policy engine
* transparent HTTPS SNI/DNS attribution goes through policy engine
* HTTP proxy traffic goes through policy engine
* SOCKS proxy traffic goes through policy engine
* all egress goes through shared host egress backend
* audit records clearly identify frontend source and attribution source

If an app ignores proxy env vars, TUN policy still applies.

If an app uses proxy env vars, proxy policy receives richer metadata.

## Audit Subsystem

Audit logs are first-class output.

Minimum events:

* network session start
* broker start
* TUN configured
* proxy listener configured
* HTTP request allowed/denied
* HTTPS CONNECT allowed/denied
* transparent HTTP request allowed/denied
* TLS ClientHello SNI observed
* SNI/DNS mismatch denied
* hidden-SNI/ECH denied
* SOCKS CONNECT allowed/denied
* DNS query allowed/denied
* TCP connect allowed/denied
* TCP flow closed
* UDP flow created
* UDP packet denied
* UDP flow expired
* QUIC candidate flow created
* ICMP allowed/denied
* unsupported packet/request denied
* policy reload
* broker error
* network session exit

Each event should include:

* timestamp
* sandbox/session ID
* frontend type
* protocol
* source address/port where available
* destination address/port
* hostname where known
* hostname attribution source
* hostname attribution confidence
* origin where known
* decision
* rule ID or reason
* byte counts where applicable
* flow duration where applicable

Audit logging must support backpressure.

Network forwarding must not allow unbounded memory growth when audit output is slow.

## Integration Backends

The broker should support multiple integration backends.

### bwrap-Compatible Setup Backend

This backend uses bwrap for sandbox namespace/mount setup and runs `foxproxsetup` as the initial bwrap command. bwrap retains temporary `CAP_NET_ADMIN` for `foxproxsetup`; the helper creates/configures the TUN device, configures sandbox-side IP/route/DNS/proxy reachability, hands the TUN fd to the host broker, drops setup privileges, closes setup-only file descriptors, and execs the target app.

Responsibilities:

* construct or receive the bwrap command line
* include `--unshare-net`, user namespace setup, and temporary `--cap-add CAP_NET_ADMIN`
* make `/dev/net/tun` available to the setup helper
* start the host-side broker before the target app is released
* provide a setup control socket or inherited fd for TUN fd handoff
* run `foxproxsetup` as the bwrap command
* configure sandbox-side IP address and route from inside the sandbox network namespace
* configure broker DNS address
* configure proxy listener reachability
* return proxy environment values to the caller
* connect the TUN fd to the broker runtime
* clean up network resources when the broker session ends

Non-responsibilities:

* defining application filesystem policy beyond helper requirements
* applying final application seccomp before network setup completes
* keeping `CAP_NET_ADMIN` available after `foxproxsetup` execs the target app

A small bwrap fork can provide a setup-helper hook later. That hook runs a trusted helper during bwrap setup, before final capability drop/seccomp/app exec, and removes the need for the target command wrapper form.

### External Network Namespace Backend

This backend works with a caller-provided network namespace.

Responsibilities:

* receive namespace fd/path
* create/configure TUN in that namespace
* configure route/DNS/proxy reachability
* connect the TUN fd to the broker runtime

### Rootful Network Device Backend

This backend is for environments where the broker or launcher has host privileges.

Responsibilities:

* create network namespace if requested
* create/configure TUN device
* configure route/DNS/proxy reachability
* connect the TUN fd to the broker runtime

This backend is not alpha-required.

## bwrap-Compatible Network Setup

Expected alpha command shape:

* host launcher starts the host-side broker
* host launcher starts bwrap with `--unshare-user`, `--unshare-net`, temporary `--cap-add CAP_NET_ADMIN`, and access to `/dev/net/tun`
* bwrap command is `foxproxsetup -- target args...`
* `foxproxsetup` creates/configures TUN inside the bwrap network namespace
* `foxproxsetup` configures sandbox default route through TUN
* `foxproxsetup` configures sandbox DNS to point at the broker resolver
* `foxproxsetup` configures HTTP/SOCKS proxy listener reachability
* `foxproxsetup` sends the TUN fd to the host broker
* host broker owns host-side forwarding
* `foxproxsetup` drops `CAP_NET_ADMIN`, closes setup-only fds, and execs the target app
* caller injects proxy env vars if desired

The broker core does not depend on bwrap. The bwrap-compatible backend owns bwrap command construction, setup-helper conventions, and setup privilege lifecycle.

## Rust Module Sketch

Suggested crates/modules:

* `broker-core`

  * policy types
  * flow types
  * audit event types
  * config schema
  * normalized network events
  * attribution types
  * no Linux-specific code

* `broker-integrations`

  * bwrap-compatible netns backend
  * external netns backend
  * future rootful backend

* `broker-device`

  * TUN creation
  * TUN fd handling
  * namespace-aware device setup
  * future TAP frontend support

* `broker-frontends`

  * TUN frontend
  * HTTP proxy frontend
  * SOCKS5 frontend

* `broker-net`

  * network stack adapter
  * TCP/UDP/ICMP/DNS handling
  * flow manager

* `broker-inspect`

  * plaintext HTTP inspection
  * TLS ClientHello parsing
  * QUIC metadata classification
  * DNS correlation helpers
  * mismatch detection

* `broker-origin`

  * origin parsing
  * domain matching
  * CONNECT target parsing
  * HTTP request metadata extraction
  * hostname normalization

* `broker-policy`

  * rule evaluation
  * default policies
  * config loading
  * tests

* `broker-egress`

  * shared host TCP/UDP/DNS egress
  * proxy forwarding

* `broker-audit`

  * structured event emission
  * sinks
  * buffering/backpressure

* `broker-cli`

  * command-line interface
  * config paths
  * diagnostics
  * feature detection

## Dependency Strategy

Prefer fewer dependencies in the packet hot path.

Dependency categories:

* async runtime:

  * Tokio unless there is a strong reason not to

* TUN:

  * evaluate `tun-rs`, `tun`, `tokio-tun`

* network stack:

  * evaluate `smoltcp`
  * keep replaceable behind adapter trait

* HTTP proxy:

  * use maintained HTTP parsing/runtime crates
  * avoid custom HTTP parser unless needed

* SOCKS5:

  * use maintained crate if suitable
  * keep protocol handling isolated

* TLS ClientHello parsing:

  * use maintained parser if suitable
  * avoid implementing full TLS
  * extract only metadata needed for policy

* QUIC metadata:

  * best-effort parser/classifier
  * avoid full QUIC stack unless needed

* packet parsing:

  * only use maintained, auditable crates
  * avoid spreading parser crate types outside adapter layer

* config:

  * serde-compatible format is fine
  * keep config validation explicit

* logging:

  * structured logs
  * avoid unbounded queues

## Safety Rules

* unsafe code only in small, reviewed modules
* no unsafe in policy engine
* no unsafe in audit/event code
* no frontend-specific protocol objects in policy engine
* no raw C dependencies in initial Rust implementation unless justified
* fuzz packet-facing boundaries
* fuzz proxy parsers where possible
* fuzz TLS ClientHello parser inputs
* property-test policy decisions
* integration-test with real network namespaces

## Alpha Milestones

### Milestone 0: TUN Setup Proof

Required:

* bwrap command runs `foxproxsetup` with temporary `CAP_NET_ADMIN`
* `/dev/net/tun` is available to the setup helper
* setup helper creates a TUN device inside the sandbox network namespace
* setup helper assigns address/MTU and brings the interface up
* setup helper configures a route that sends test traffic through TUN
* broker or helper logs inbound IP packets from the TUN fd
* setup helper drops `CAP_NET_ADMIN` before target exec

Validation:

* ping, curl, or a small test program inside the sandbox causes packets to appear in TUN logs

### Milestone 1: Packet Write-Back Proof

Required:

* broker writes packets back to the TUN fd
* minimal packet synthesis exists for one simple path, such as ICMP echo reply
* checksums and source/destination reversal are correct for the proof path

Validation:

* sandbox `ping` can receive a synthetic reply through TUN

### Milestone 2: `smoltcp` TCP Forwarding Gate

Required:

* TUN fd feeds `smoltcp` or the selected userspace TCP/IP stack
* sandbox TCP connect attempts become userspace stream events
* broker opens host TCP sockets for allowed flows
* broker bridges bytes between sandbox TCP streams and host TCP sockets
* outbound packets are emitted back through TUN
* initial policy is minimal allow-all or deny-all

Validation:

* sandbox `curl http://example.com` works through unfiltered broker forwarding
* connection open/close/error events are logged

### Milestone 3: Minimal Broker Core

Required:

* normalized event model
* shared audit schema
* shared egress traits
* minimal config schema
* frontend abstraction
* minimal policy model with default allow/deny and IP/CIDR/port rules

### Milestone 4: UDP and DNS Foundation

Required:

* UDP pseudo-flow tracking
* unfiltered UDP forwarding proof
* DNS broker reachable from the sandbox
* direct external DNS denied by default
* DNS observations logged
* DNS cache shape suitable for later hostname attribution

### Milestone 5: Transparent Policy and Attribution

Required:

* hostname attribution model
* DNS-to-flow correlation for TUN traffic
* hostname/domain rules when attribution exists
* transparent plaintext HTTP Host/method/path inspection
* TLS ClientHello SNI parsing
* SNI/DNS mismatch handling
* hidden-SNI/ECH handling
* QUIC candidate classification
* clear audit differences between IP/port, DNS-correlated, HTTP Host/path, HTTPS SNI, and QUIC-candidate decisions

### Milestone 6: Explicit Proxy Networking

Required:

* HTTP proxy frontend
* HTTPS CONNECT support
* SOCKS5 TCP CONNECT support
* shared policy engine integration
* shared audit logging
* origin-aware allow/deny rules

Not in alpha scope:

* SOCKS UDP ASSOCIATE
* proxy authentication
* TLS MITM
* custom CA
* HTTP/3 semantic inspection

### Milestone 7: Robustness

Required:

* resource limits
* malformed packet handling
* malformed proxy request handling
* malformed TLS ClientHello handling
* fuzzing
* audit backpressure
* fail-closed unsupported paths
* cleanup robustness

## Success Criteria

The Rust broker is successful when:

* caller can attach broker networking to a sandbox network namespace
* broker can create/configure TUN inside that namespace
* apps without proxy support work through transparent TUN
* direct plaintext HTTP can be allowed/denied/logged by host/method/path
* direct HTTPS can be allowed/denied/logged by DNS attribution and SNI where available
* direct QUIC can be allowed/denied/logged by UDP policy, DNS attribution, and visible metadata where feasible
* apps with proxy support get richer HTTP(S) origin-aware policy
* HTTP requests can be allowed/denied/logged by origin and plaintext path
* HTTPS CONNECT destinations can be allowed/denied/logged by host/port
* SOCKS TCP destinations can be allowed/denied/logged
* TCP, UDP, DNS, ICMP, and QUIC-over-UDP are supported
* direct external DNS is blocked by default
* denied traffic is blocked and audited
* both proxy and TUN traffic use the same policy/audit backend
* no TLS MITM is required
* no custom CA is required
* direct host networking is impossible through the broker-controlled path
* broker core is not tied to bwrap
* unsupported edge cases fail closed
* future TAP support can be added as a frontend
