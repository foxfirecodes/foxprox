# foxprox

a WIP TUN device transparent network proxy/broker for policy-based sandboxing, primarily built for [sandfox](https://github.com/foxfirecodes/sandfox)

inspired by [passt/pasta](https://passt.top/passt/about/) and [slirp4netns](https://github.com/rootless-containers/slirp4netns)

## Usable alpha sandbox prototype

Build both binaries, then run an arbitrary command in a bwrap network namespace with a host-side foxprox broker owning the handed-off TUN fd:

```sh
cargo build -p foxprox-setup --bin foxproxsetup -p foxprox-cli --bin foxprox-lab

target/debug/foxprox-lab sandbox \
  --allow-all \
  --proxy-env \
  --timeout-secs 300 \
  -- \
  /usr/bin/python3 -c 'import socket; print(socket.gethostbyname("example.com"))'
```

The alpha launcher starts `bwrap --unshare-net`, runs `foxproxsetup` with temporary network setup capabilities, receives the TUN fd over a Unix handoff socket, drops setup privileges before target exec, and runs one long-lived broker loop until the target exits. Transparent TUN traffic, broker DNS, ICMP ping, UDP, QUIC candidates, transparent TCP/smoltcp byte bridging, HTTP/SOCKS proxy traffic, shared policy, host egress, and JSON-lines audit are wired through the prototype path.

Useful alpha options:

* `--allow-all` enables an initial permissive network policy for prototype use; omit it for deny-by-default.
* `--allow-ping` enables ICMP echo without enabling all traffic.
* `--dns-answer host=ipv4` adds a broker-local DNS answer and attribution entry.
* `--upstream-dns ip:port` forwards broker DNS misses to an upstream resolver; by default the launcher uses the first host `/etc/resolv.conf` nameserver when available. Use `--no-upstream-dns` for deterministic local-only runs.
* `--egress-map sandbox_ip=host_ip` maps sandbox-visible fixture IPs to host loopback/local addresses for tests.
* `--proxy-env` injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` for apps that honor proxy variables; apps that ignore them still traverse transparent TUN.
* `--audit-stdout` writes broker audit JSON lines to stdout instead of stderr.

This is an alpha network sandboxing prototype, not a full sandbox profile manager: filesystem mounts, seccomp, Landlock, PID/IPC policy, and product configuration UX remain caller/runtime responsibilities.

## Harness lab

The alpha harness is intentionally runnable without network namespace privileges for core behavior:

```sh
cargo test --all
cargo run -p foxprox-cli --bin foxprox-lab -- run all
cargo run -p foxprox-cli --bin foxprox-lab -- run stack
cargo run -p foxprox-cli --bin foxprox-lab -- run inspect
cargo run -p foxprox-cli --bin foxprox-lab -- run robustness
cargo run -p foxprox-cli --bin foxprox-lab -- run http-proxy-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run https-connect-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run socks5-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run proxy-deny-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run env-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run tun-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run setup-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run writeback-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-forward-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run udp-deny-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run dns-attribution-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-syn-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-synack-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run tcp-bridge-deny-smoke
cargo run -p foxprox-setup --bin foxproxsetup -- --print-plan
```

`foxprox-lab run all` emits deterministic JSON Lines audit records for policy, DNS attribution, proxy parsing, packet write-back, QUIC classification, transparent HTTP/TLS inspection, UDP pseudo-flow tracking, smoltcp TCP SYN/SYN-ACK stack gating, bounded audit backpressure, and fail-closed malformed/unsupported paths. `http-proxy-smoke` runs a local explicit HTTP proxy/origin/client fixture and verifies policy-gated forwarding by host-owned sockets. `https-connect-smoke` verifies explicit HTTPS `CONNECT` policy evaluation and byte tunneling to a local TCP fixture. `socks5-smoke` verifies SOCKS5 TCP `CONNECT` negotiation, policy evaluation, and byte tunneling to a local TCP fixture. `proxy-deny-smoke` verifies denied HTTP proxy behavior plus malformed/unsupported CONNECT and SOCKS requests fail closed before egress. `env-smoke` reports local `/dev/net/tun` and `bwrap` availability only; it does not prove the user has enough privileges to configure a real sandbox TUN device. `tun-smoke` is environment-dependent and attempts to create/configure a TUN device inside a `bwrap --unshare-net` namespace with temporary `CAP_NET_ADMIN` using `/usr/bin/ip`. `setup-smoke` runs the Rust `foxproxsetup` helper inside bwrap and verifies direct ioctl-based TUN setup without shelling out from the helper; build `foxproxsetup` first or set `FOXPROX_SETUP_HELPER`. `handoff-smoke` adds a host-side Unix socket receiver and verifies that `foxproxsetup` hands off a live TUN fd before dropping setup capabilities and execing the target. `writeback-smoke` runs a sandbox UDP probe and proves the host harness can read a packet from the handed-off TUN fd and write a synthetic reply back through it. `udp-forward-smoke` forwards the sandbox UDP probe through the reusable transparent UDP runtime, enforces an allow rule, sends through a host UDP socket to a local echo fixture, audits the decision, and returns the response over TUN. `udp-deny-smoke` uses the same runtime with default deny and verifies no egress call occurs. `dns-smoke` answers a sandbox DNS A query locally over TUN and records cache attribution. `dns-attribution-smoke` performs DNS and a subsequent UDP flow in one sandbox session to prove DNS-cache attribution can allow a domain-gated transparent flow. `tcp-syn-smoke` opens a sandbox TCP connection attempt, observes the SYN on the handed-off TUN fd, runs it through the transparent TCP policy/audit boundary, and proves allow-gated host TCP egress to a local fixture without yet completing TCP stream forwarding back to the sandbox. `tcp-synack-smoke` feeds that real sandbox SYN into the smoltcp IP-medium gate and writes the emitted SYN-ACK back to the TUN fd, proving the sandbox TCP handshake can be completed by smoltcp. `tcp-bridge-smoke` keeps smoltcp state across packets, inspects a transparent plaintext HTTP request, bridges sandbox TCP payload bytes through a local host TCP fixture, and writes the fixture response back through TUN. `tcp-bridge-deny-smoke` proves a default-denied TCP SYN does not enter smoltcp or host egress and receives a synthesized TCP RST.
