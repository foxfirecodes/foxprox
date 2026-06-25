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

`foxprox-cli bwrap-tcp-once` starts a `bwrap` sandbox, runs `foxproxsetup` inside the setup phase with temporary `CAP_NET_ADMIN`, receives the TUN fd over a Unix socket, drops `CAP_NET_ADMIN` before the target command, and brokers DNS, UDP, and one TCP flow through the received TUN fd. TCP uses smoltcp; UDP uses original-destination host UDP egress with synthesized TUN responses.

Example HTTP request to an original destination address, with the sandbox resolver also wired through the broker for hostname-based targets:

```sh
HOST_IP=$(ip -4 route get 8.8.8.8 | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
PORT=18080
DNS_UPSTREAM=1.1.1.1:53
RESOLV_SOURCE=/tmp/foxprox-alpha-resolv.source
POLICY=/tmp/foxprox-alpha-policy.toml
: > "$RESOLV_SOURCE"
cat > "$POLICY" <<'TOML'
default_policy = "allow"

[dns]
broker_resolvers = ["10.150.0.1:53"]
deny_direct_external_dns = true
TOML
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok' | nc -l "$HOST_IP" "$PORT" &

cargo run -p foxprox-cli -- bwrap-tcp-once \
  --bwrap /usr/bin/bwrap \
  --setup target/debug/foxproxsetup \
  --broker-socket /tmp/foxprox-alpha.sock \
  --tun-name fpxalpha0 \
  --address-cidr 10.150.0.2/24 \
  --mtu 1400 \
  --resolv-conf /etc/resolv.conf \
  --broker-dns 10.150.0.1 \
  --dns-upstream "$DNS_UPSTREAM" \
  --ip-program /usr/bin/ip \
  --listen-ip 10.150.0.1 \
  --listen-port "$PORT" \
  --sandbox alpha-demo \
  --config "$POLICY" \
  --max-packets 64 \
  --extra-bwrap-arg --dev-bind \
  --extra-bwrap-arg / \
  --extra-bwrap-arg / \
  --extra-bwrap-arg --tmpfs \
  --extra-bwrap-arg /etc \
  --extra-bwrap-arg --bind \
  --extra-bwrap-arg "$RESOLV_SOURCE" \
  --extra-bwrap-arg /etc/resolv.conf \
  -- \
  /usr/bin/curl --ipv4 --max-time 5 --silent --show-error "http://$HOST_IP:$PORT/"
```

The `--tmpfs /etc` plus `--bind $RESOLV_SOURCE /etc/resolv.conf` pair avoids mutating the host resolver file while still letting `foxproxsetup` install a broker-controlled resolver for ordinary sandbox DNS lookups.

When `--dns-upstream IP:PORT` is supplied, DNS packets to `--broker-dns`:53 are handled inside the same launcher, audited, forwarded to the upstream resolver, and recorded into the DNS attribution cache before the later TCP flow. To exercise DNS in this command, use a hostname whose resolved address and port are reachable from the host. When `--upstream IP:PORT` is omitted, the broker connects host egress to the original TCP destination from the sandbox SYN. Supplying `--upstream` keeps the deterministic test/demo override.

Stdout is JSON-lines audit only. On successful transparent HTTP traffic, expect records such as:

- `tcp_connect`
- `http_request`
- `tcp_flow_closed`

TLS ClientHello traffic is inspected before host egress and emits `tls_client_hello` with `hostname_attribution_source="tls_sni"`. DNS answers observed through `--dns-upstream` or preseeded with repeatable `--dns-attribution HOST=IP` enrich later TCP connect audit with `hostname_attribution_source="dns_cache"`.

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

The live suite currently covers setup/fd handoff, ICMP write-back, UDP forwarding, DNS-over-TUN, smoltcp TCP forwarding, original-destination transparent TCP and UDP egress, DNS-to-TCP attribution in one real bwrap run, HTTP allow/deny audit, TLS SNI audit, and CLI JSON audit output.

## Current alpha boundary

This is an alpha prototype, not a production daemon. It intentionally proves narrow vertical slices:

- one transparent TCP flow per `bwrap-tcp-once` run, with DNS and UDP packets handled while that target runs;
- one explicit-proxy request/connection per proxy command;
- ignored live tests for privileged/bwrap/TUN behavior;
- DNS and TCP can run in the same one-shot launcher, but a long-running multi-flow supervisor is still future work.

The remaining work is productionization: multi-flow scheduling, long-running supervision, and polished profile UX.
