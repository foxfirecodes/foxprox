# Future Zig Rewrite Stack and Requirements

## Status

This is a future side project only.

Do not rewrite the Rust implementation in Zig during the initial build.

Do not block Rust milestones on Zig design.

Do not introduce Zig into the production broker until the Rust implementation has proven the architecture and policy semantics.

## Purpose

A future Zig rewrite may be explored for:

* learning
* performance experiments
* simpler low-level Linux integration
* tighter C interop with mature TCP/IP libraries
* possible alternative broker implementation

The Zig version must be treated as experimental until it reaches feature parity with the Rust broker.

## Non-Goals

The Zig project must not:

* replace Rust before the Rust alpha is working
* fork policy behavior incompatibly
* reduce security guarantees
* skip audit logging
* hand-roll TCP from scratch
* bypass established test suites
* become the default implementation without explicit decision

## Candidate Stack

Primary candidate:

* Zig broker/control-plane
* lwIP as C TCP/IP stack
* Linux TUN frontend
* optional future TAP frontend
* Zig policy/audit/config layers

Possible responsibilities:

* Zig:

  * TUN setup
  * namespace/device orchestration
  * policy engine
  * audit logging
  * config parsing
  * host socket glue
  * lwIP adapter boundary
  * resource limits

* lwIP:

  * TCP state machine
  * UDP/IP handling
  * ICMP handling
  * checksums
  * timers
  * packet lifecycle

## Architecture Boundary

The Zig implementation must keep lwIP isolated.

Suggested boundary:

* `lwip_adapter.zig`

  * only module that directly touches lwIP C APIs
  * owns pbuf conversion
  * owns stack timers
  * converts stack events to broker events

* `tun_frontend.zig`

  * Linux TUN setup/read/write
  * no policy logic

* `policy.zig`

  * pure Zig
  * no C pointers
  * no packet mutation
  * deterministic rule evaluation

* `audit.zig`

  * structured logs
  * no C stack dependency

* `sandbox_backend/`

  * bwrap backend
  * future rootful/external netns backends

Rule:

* C networking state must not leak into policy/audit/config code.

## Required Feature Parity

Before the Zig broker can be considered a serious replacement, it must support:

* TUN-based transparent networking
* TCP forwarding
* UDP forwarding
* DNS handling
* ICMP basics
* QUIC-over-UDP support
* UDP flow timeouts
* configurable policy
* structured audit logs
* bwrap integration
* non-bwrap backend abstraction
* fail-closed unsupported edge cases
* seccomp/Landlock-compatible launch flow

## Required Policy Parity

The Zig version must implement the same policy semantics as Rust:

* TCP deny by default unless allowed
* UDP deny by default unless allowed
* DNS only through broker resolver by default
* direct external DNS denied
* QUIC configurable
* multicast/broadcast denied by default
* ICMP minimal allowlist
* unsupported protocols denied
* structured decision reasons
* rule IDs in audit events

## Required Audit Parity

The Zig broker must emit equivalent audit events:

* sandbox start
* broker start
* TUN configured
* DNS query allowed/denied
* TCP connect allowed/denied
* TCP flow closed
* UDP flow created
* UDP packet denied
* UDP flow expired
* QUIC candidate flow created
* ICMP allowed/denied
* unsupported packet denied
* policy reload
* broker error
* sandbox exit

Audit schema should remain compatible with the Rust implementation.

## Required Test Parity

The Zig version must pass the same black-box test suite as Rust.

Minimum tests:

* TCP allow
* TCP deny
* UDP allow
* UDP deny
* DNS allow
* DNS deny
* direct DNS bypass denied
* QUIC candidate flow
* UDP timeout expiration
* ICMP allowed/denied
* malformed packet denial
* unsupported protocol denial
* bwrap sandbox integration
* cleanup after target exit

Additional Zig-specific tests:

* lwIP adapter fuzzing
* pbuf lifetime tests
* memory leak checks
* sanitizer-enabled C dependency tests
* namespace integration tests

## Safety Requirements

The Zig version must:

* isolate all C interop
* avoid C pointers outside adapter modules
* document ownership of every packet buffer
* use sanitizers in CI for lwIP integration
* fuzz packet ingress paths
* enforce resource limits
* avoid unbounded queues
* fail closed on adapter errors

## Performance Requirements

The Zig version should be evaluated against Rust using the same benchmarks.

Benchmarks:

* TCP throughput
* TCP connection setup rate
* UDP packet throughput
* DNS query throughput
* QUIC-like UDP flow behavior
* audit logging overhead
* memory use under many flows
* latency under policy checks

Zig does not need to beat Rust to be useful, but it must not be significantly worse for normal alpha workloads.

## Migration Requirements

A Zig rewrite can only be considered after:

* Rust alpha works end-to-end
* policy semantics are stable
* audit schema is stable
* test suite is comprehensive
* Rust bottlenecks are understood
* Zig prototype passes feature parity tests
* maintainability tradeoff is explicitly reviewed

The Zig implementation should share:

* config schema
* audit schema
* policy model
* black-box tests
* documentation

It should not share:

* unsafe assumptions
* untested protocol behavior
* incompatible policy defaults

## Suggested Future Milestones

### Zig Spike 1: TUN + lwIP Smoke Test

* create TUN
* attach lwIP netif
* forward one TCP connection
* forward one UDP packet
* basic audit event

### Zig Spike 2: Policy Boundary

* normalized flow events
* pure Zig policy engine
* allow/deny decisions
* structured audit output

### Zig Spike 3: DNS/UDP/ICMP

* broker DNS
* UDP flow table
* ICMP basics
* timeouts

### Zig Spike 4: Rust Parity Test Suite

* run black-box tests against Zig broker
* compare behavior with Rust broker
* fix incompatibilities

### Zig Spike 5: Performance Review

* benchmark Rust vs Zig
* review code complexity
* review memory safety risk
* decide whether Zig remains side project or becomes supported backend

## Clear Instruction for Agents

Do not rewrite the Rust broker in Zig.

Do not replace Rust modules with Zig modules.

Do not introduce Zig into the main implementation path.

Only create Zig code under a clearly marked experimental/future directory if explicitly requested.

The current production implementation target is Rust.
