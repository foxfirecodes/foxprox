# Transparent Network Broker Architecture

## Goal

Build a custom transparent userspace network broker that provides mediated network access for sandboxed applications that do not support proxy environment variables.

The broker should support:

* TCP
* UDP
* DNS
* ICMP
* QUIC over UDP
* audit logging
* configurable default policy
* fail-closed behavior for unsupported edge cases

The initial implementation should use TUN, not TAP. The architecture should keep Layer 2 concerns isolated so TAP can be added later without rewriting the policy and flow core.

## Non-Goals

Initial version does not support:

* TLS MITM
* custom CA installation
* full HTTPS URL/path visibility
* raw Ethernet semantics
* arbitrary non-IP protocols
* full LAN broadcast/multicast behavior
* transparent browser-origin policy
* slirp4netns or pasta as forwarding dependencies

## High-Level Design

Packet path:

* sandboxed app opens normal sockets
* sandbox kernel routes traffic through TUN interface
* broker reads IP packets from TUN
* broker parses packet
* broker applies policy
* broker forwards allowed traffic through host sockets
* broker writes response packets back to TUN
* denied traffic is logged and dropped/reset/rejected as appropriate

The sandboxed app sees normal networking.

The host sees only broker-owned sockets.

## Components

### Device Frontend

Initial frontend: TUN.

Responsibilities:

* create or receive TUN file descriptor
* read inbound IP packets from sandbox
* write outbound IP packets to sandbox
* normalize packets into internal packet representation
* expose no policy logic

Future frontend: TAP.

Responsibilities when added:

* parse Ethernet frames
* handle ARP
* handle IPv6 NDP
* extract IPv4/IPv6 packets
* wrap outbound IP packets into Ethernet frames
* drop unsupported EtherTypes

The policy core should not know whether packets came from TUN or TAP.

### Packet Core

Responsibilities:

* IPv4 parsing
* IPv6 parsing
* TCP parsing/flow handling
* UDP parsing/flow handling
* ICMP/ICMPv6 handling
* fragmentation policy
* packet validation
* checksum handling
* MTU handling
* error synthesis where useful

The packet core should expose normalized events:

* `tcp_connect_attempt`
* `tcp_flow_data`
* `udp_flow_packet`
* `dns_query`
* `icmp_message`
* `quic_candidate_flow`
* `unsupported_packet`

### Policy Engine

Responsibilities:

* make allow/deny decisions
* apply default policies
* apply user configuration
* produce structured audit records
* choose denial behavior

Policy inputs:

* sandbox identity
* executable identity where available
* protocol
* destination IP
* destination port
* DNS hostname when known
* SNI/QUIC metadata where safely available
* flow age
* byte counts
* rule source

Policy decisions:

* allow
* deny/drop
* deny/reset
* deny/ICMP unreachable
* require DNS resolution through broker
* classify as unsupported and fail closed

### TCP Forwarder

Responsibilities:

* maintain TCP flow state
* open host TCP sockets for allowed flows
* bridge sandbox TCP stream to host TCP stream
* synthesize TCP behavior needed by the TUN-facing side
* reset denied connections where appropriate
* log lifecycle events

Policy hooks:

* before connect
* after DNS correlation
* on suspicious destination change
* on flow close/error

### UDP Forwarder

Responsibilities:

* maintain UDP pseudo-flow state
* open host UDP sockets for allowed flows
* forward datagrams
* route replies back to sandbox
* expire idle mappings
* apply protocol-specific defaults

UDP flow key:

* source IP
* source port
* destination IP
* destination port
* protocol = UDP

Default UDP flow timeouts:

* DNS: 5–15 seconds
* generic UDP: 30–120 seconds
* QUIC: 2–5 minutes
* NTP-like one-shot traffic: short timeout
* broadcast/multicast: deny by default

These should be configurable.

UDP denial behavior:

* drop by default for generic UDP
* optionally synthesize ICMP unreachable
* log denial reason

### DNS Handler

Responsibilities:

* provide DNS service reachable from sandbox
* force sandbox DNS through broker-controlled resolver
* log DNS queries
* cache DNS results for policy correlation
* map hostname decisions to later TCP/UDP flows
* prevent direct external DNS unless explicitly allowed

Default DNS behavior:

* allow DNS only to broker resolver
* deny direct DNS to arbitrary external resolvers
* log hostname, query type, decision, and returned addresses
* configurable upstream resolver

### ICMP Handler

Responsibilities:

* support enough ICMP for normal networking
* support ping if allowed
* support ICMP errors needed for TCP/UDP behavior
* handle path MTU-related messages where possible
* deny unusual ICMP by default

Default ICMP behavior:

* allow essential ICMP errors
* configurable ping support
* deny unusual or unsupported ICMP types
* log denied ICMP

### QUIC Handling

QUIC runs over UDP, usually UDP/443.

Initial support:

* allow QUIC as UDP policy class
* configurable default allow/deny
* longer UDP flow timeout
* optional metadata extraction where safe and simple
* no TLS decryption
* no custom CA
* no full HTTP/3 request visibility

Default QUIC behavior:

* support UDP/443 flows
* classify as QUIC candidate
* apply domain/IP/port policy
* log as QUIC candidate when detected
* fail closed only on unsupported broker mechanics, not on lack of decryption

## Configurable Defaults

### TCP

Defaults:

* deny by default unless policy allows
* allow rules by host/IP/port
* log all connect attempts
* reset denied TCP connects where possible
* deny listening/bind-like behavior inside sandbox unless explicitly supported

### UDP

Defaults:

* deny by default unless policy allows
* DNS only through broker resolver
* QUIC supported and configurable
* deny multicast/broadcast by default
* deny LAN discovery by default
* per-protocol idle timeouts
* log flow creation, expiration, denial, and byte counts

### DNS

Defaults:

* broker resolver only
* log all queries
* cache hostname-to-address mappings
* deny direct external DNS
* configurable upstream resolver

### ICMP

Defaults:

* allow required errors
* ping configurable
* unsupported ICMP denied/logged

### QUIC

Defaults:

* configurable allow/deny
* UDP/443 recognized as QUIC candidate
* no MITM
* no custom CA
* longer idle timeout than generic UDP

## Interaction With bwrap

The launcher should:

* create or prepare network namespace
* create TUN device in the sandbox network namespace
* assign sandbox-side IP address
* configure route through TUN
* configure DNS to broker resolver
* start broker with TUN fd or namespace/device reference
* launch bwrap with `--unshare-net`
* apply mount namespace policy
* apply Landlock policy
* apply seccomp policy
* exec target application

The broker should not depend on bwrap-specific assumptions. It should only require:

* a network namespace target
* a TUN device or permission to create one
* routing/DNS configuration
* a sandbox identity label

## Non-bwrap Backend Support

The broker should support a generic mode for other launchers.

Possible backends:

* bwrap backend:

  * launcher uses bwrap
  * broker receives TUN fd or namespace path

* rootful namespace backend:

  * broker/launcher runs with privileges
  * creates network namespace directly
  * creates TUN device directly
  * launches target without bwrap

* external namespace backend:

  * caller provides namespace fd/path
  * broker attaches/configures TUN
  * caller handles process launch

Architecture rule:

* bwrap integration belongs in launcher/backend code
* broker core should not import or assume bwrap semantics
* broker should operate on abstract sandbox/session config

## TUN Setup Model

Preferred setup:

* launcher creates network namespace
* launcher creates TUN device inside namespace
* launcher configures:

  * interface address
  * route
  * MTU
  * DNS resolver target
* launcher passes TUN fd to broker
* broker drops unnecessary privileges after setup

Alternative setup:

* broker starts privileged or with needed capabilities
* broker creates/configures TUN
* broker drops privileges
* launcher starts sandbox

For minimal end-user setup, prefer user-namespace-compatible setup where possible.

## Layer 2 Future-Proofing

Design the broker around an L3-normalized core.

Do not let policy code depend on raw TUN packet layout.

Internal boundary:

* device frontend emits `InboundIpPacket`
* packet core handles IP/TCP/UDP/ICMP
* policy engine handles semantic flow events
* egress backend opens host sockets

Future TAP support should only add:

* Ethernet parser
* ARP responder
* IPv6 NDP responder
* MAC address management
* EtherType dispatch
* Ethernet frame wrapper for outbound packets

Unsupported Layer 2 packets should be dropped/logged by the TAP frontend before reaching the policy core.

## Audit Events

Minimum audit events:

* sandbox started
* broker started
* TUN configured
* DNS query allowed/denied
* TCP connect allowed/denied
* TCP flow closed
* UDP flow created
* UDP flow allowed/denied
* UDP flow expired
* QUIC candidate flow created
* ICMP allowed/denied
* unsupported packet/protocol denied
* policy reload
* sandbox exited

Each event should include:

* timestamp
* sandbox ID
* process/session ID where available
* protocol
* source address/port
* destination address/port
* hostname where known
* decision
* rule ID/reason
* byte counts where applicable

## Alpha Failure Policy

Fail closed for:

* unsupported IP protocol numbers
* malformed packets
* unsupported fragmentation cases
* direct DNS bypass attempts
* multicast/broadcast unless explicitly enabled
* unknown Layer 2 if TAP is later added
* unsupported ICMP types unless explicitly allowed

Fail early for:

* inability to create/configure TUN
* inability to isolate network namespace
* inability to start broker
* inability to apply required sandbox policy
* missing required kernel features
