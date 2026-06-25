# Alpha Prototype Usage

This repository now includes a runnable alpha network prototype for a real Linux `bwrap` sandbox environment.

## Prerequisites

Run on Linux with:

```sh
command -v bwrap ip curl python3
ls /dev/net/tun
cargo build --workspace
```

The live smoke tests require unprivileged user namespaces, `bwrap`, and access to `/dev/net/tun`.

## Transparent bwrap TCP/HTTP/TLS one-shot

`foxprox-cli bwrap-tcp-once` starts a `bwrap` sandbox, runs `foxproxsetup` inside the setup phase with temporary `CAP_NET_ADMIN`, receives the TUN fd over a Unix socket, drops `CAP_NET_ADMIN` before the target command, and brokers one TCP flow through smoltcp.

Example HTTP request to an original destination address:

```sh
HOST_IP=$(ip -4 route get 8.8.8.8 | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
PORT=18080
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok' | nc -l "$HOST_IP" "$PORT" &

cargo run -p foxprox-cli -- bwrap-tcp-once \
  --bwrap /usr/bin/bwrap \
  --setup target/debug/foxproxsetup \
  --broker-socket /tmp/foxprox-alpha.sock \
  --tun-name fpxalpha0 \
  --address-cidr 10.150.0.2/24 \
  --mtu 1400 \
  --resolv-conf /tmp/foxprox-alpha-resolv.conf \
  --broker-dns 10.150.0.1 \
  --ip-program /usr/bin/ip \
  --listen-ip 10.150.0.1 \
  --listen-port "$PORT" \
  --sandbox alpha-demo \
  --max-packets 64 \
  --extra-bwrap-arg --dev-bind \
  --extra-bwrap-arg / \
  --extra-bwrap-arg / \
  -- \
  /usr/bin/curl --max-time 5 --silent --show-error "http://$HOST_IP:$PORT/"
```

When `--upstream IP:PORT` is omitted, the broker connects host egress to the original TCP destination from the sandbox SYN. Supplying `--upstream` keeps the deterministic test/demo override.

Stdout is JSON-lines audit only. On successful transparent HTTP traffic, expect records such as:

- `tcp_connect`
- `http_request`
- `tcp_flow_closed`

TLS ClientHello traffic is inspected before host egress and emits `tls_client_hello` with `hostname_attribution_source="tls_sni"`. DNS cache preseed entries can be supplied with repeatable `--dns-attribution HOST=IP`; TCP connect audit then records `hostname_attribution_source="dns_cache"`.

## Explicit proxy one-shot commands

The alpha also exposes explicit proxy frontends:

```sh
cargo run -p foxprox-cli -- http-proxy-once --listen 127.0.0.1:18080 --sandbox alpha-demo [--config policy.toml]
cargo run -p foxprox-cli -- http-connect-once --listen 127.0.0.1:18443 --sandbox alpha-demo [--config policy.toml]
cargo run -p foxprox-cli -- socks5-once --listen 127.0.0.1:19080 --sandbox alpha-demo [--config policy.toml]
```

Each command handles one client connection/request and emits the shared audit JSON format to stdout.

## Verification

Default verification:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Live bwrap/TUN evidence:

```sh
cargo test -p foxprox-cli --test live_bwrap_setup -- --ignored --nocapture
```

The live suite currently covers setup/fd handoff, ICMP write-back, UDP forwarding, DNS-over-TUN, smoltcp TCP forwarding, original-destination transparent egress, HTTP allow/deny audit, TLS SNI audit, and CLI JSON audit output.

## Current alpha boundary

This is an alpha prototype, not a production daemon. It intentionally proves narrow vertical slices:

- one transparent TCP flow per `bwrap-tcp-once` run;
- one explicit-proxy request/connection per proxy command;
- ignored live tests for privileged/bwrap/TUN behavior;
- reusable DNS attribution cache and CLI preseed seam, but no long-running DNS+TCP supervisor yet.

The remaining work is productionization: multi-flow scheduling, long-running supervision, polished profile UX, and continuous DNS-to-flow orchestration.
