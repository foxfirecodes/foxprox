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

Supported alpha features:

* TUN-based transparent networking
* transparent hostname-aware HTTP/HTTPS filtering
* transparent DNS correlation
* plaintext HTTP Host/method/path inspection
* TLS ClientHello SNI parsing for direct HTTPS
* best-effort QUIC metadata classification
* HTTP proxy support
* HTTPS `CONNECT` support
* SOCKS5 TCP `CONNECT` support
* TCP forwarding
* UDP forwarding
* DNS handling
* ICMP basics
* QUIC-over-UDP support
* configurable UDP flow timeouts
* configurable default network policy
* structured audit logging
* bwrap-compatible network namespace integration
* backend design not hardwired to bwrap
* fail-closed behavior for unsupported edge cases

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

The broker must support attaching network mediation to an existing sandbox network namespace.

Initial device type:

* TUN

Initial namespace integration mode:

* bwrap-compatible network namespace attachment

The broker should not require bwrap specifically. It should support a generic model where another launcher/runtime provides:

* network namespace path or fd
* sandbox/session ID
* desired TUN device config
* desired broker listener config
* policy config
* audit config

The broker integration layer is responsible for:

* entering or targeting the sandbox network namespace only for network setup
* creating the TUN device in the sandbox network namespace
* configuring sandbox-side IP addressing
* configuring routes needed to send traffic through the TUN device
* configuring broker DNS address inside the namespace
* creating proxy listener addresses reachable from the sandbox
* passing or retaining the TUN fd needed by the broker
* returning network environment values to the caller when needed

The broker integration layer is not responsible for:

* creating the full sandbox
* choosing filesystem mounts
* launching the target application unless explicitly used as a thin wrapper mode
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

### bwrap-Compatible Network Namespace Backend

This backend is responsible only for broker/network setup against a network namespace associated with a bwrap-created sandbox.

Responsibilities:

* locate or receive the sandbox network namespace reference
* create/configure TUN inside that network namespace
* configure sandbox-side IP address and route
* configure broker DNS address
* configure proxy listener reachability
* return proxy environment values to the caller
* connect the TUN fd to the broker runtime
* clean up network resources when the broker session ends

Non-responsibilities:

* creating the bwrap sandbox
* choosing bwrap mount options
* applying filesystem policy
* applying syscall policy
* launching the target app unless explicitly used in a thin wrapper mode

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

Expected network-only interaction with a bwrap-created sandbox:

* sandbox already exists or is being created by an external launcher
* sandbox uses its own network namespace
* broker backend receives a namespace fd/path or an equivalent handle
* broker creates TUN inside that namespace
* sandbox default route points through TUN
* sandbox DNS points to broker resolver
* HTTP/SOCKS proxy listeners are reachable inside sandbox
* caller injects proxy env vars if desired
* broker owns host-side forwarding

The broker does not define the rest of the bwrap command.

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

### Milestone 1: Broker Core

Required:

* normalized event model
* hostname attribution model
* shared policy engine
* shared audit schema
* shared egress traits
* config schema
* frontend abstraction

### Milestone 2: Network Namespace + TUN Integration

Required:

* attach to caller-provided network namespace
* create/configure TUN
* configure sandbox-side IP/route/DNS for broker use
* expose proxy listener config
* return env/config values needed by caller

### Milestone 3: Transparent TUN Networking

Required:

* read/write IP packets
* TCP forwarding
* UDP forwarding
* DNS broker
* DNS correlation
* plaintext HTTP inspection
* TLS ClientHello SNI parsing
* ICMP basics
* QUIC-over-UDP classification
* audit logs

### Milestone 4: bwrap-Compatible Backend

Required:

* accept a network namespace reference associated with a bwrap-created sandbox
* create/configure TUN inside that namespace
* configure sandbox-side IP address
* configure sandbox-side default route through TUN
* configure sandbox DNS to use broker resolver
* configure HTTP/SOCKS proxy listener reachability
* return proxy environment values to the caller
* connect the TUN fd to broker runtime
* clean up broker-owned network resources when the session ends
* document expected caller responsibilities

Non-responsibilities:

* creating the bwrap sandbox
* defining the bwrap command
* choosing bind mounts
* applying filesystem policy
* applying Landlock policy
* applying seccomp policy
* launching the target application, except optional thin wrapper mode

Validation:

* works with a bwrap sandbox that already has its own network namespace
* sandbox can resolve DNS through broker
* sandbox can send TCP/UDP through broker-controlled TUN path
* sandbox can reach HTTP/SOCKS proxy listeners when configured
* broker teardown removes/cleans broker-owned network resources


### Milestone 5: Explicit Proxy Networking

Required:

* HTTP proxy frontend
* HTTPS CONNECT support
* SOCKS5 TCP CONNECT support
* shared policy engine integration
* shared audit logging
* origin-aware allow/deny rules

Deferred:

* SOCKS UDP ASSOCIATE
* proxy authentication
* TLS MITM
* custom CA
* HTTP/3 semantic inspection

### Milestone 6: Policy Hardening

Required:

* consistent decisions across TUN and proxy paths
* DNS-to-flow correlation for TUN traffic
* SNI/DNS mismatch handling
* hidden-SNI/ECH handling
* origin-based rules for proxy traffic
* clear audit differences between:

  * transparent IP/port decision
  * DNS-correlated decision
  * transparent HTTP Host/path decision
  * transparent HTTPS SNI decision
  * explicit HTTP origin decision
  * explicit HTTPS CONNECT decision
  * SOCKS destination decision

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
