# foxprox

A WIP TUN-device transparent network proxy/broker for policy-based sandboxing, primarily built for [sandfox](https://github.com/foxfirecodes/sandfox).

Inspired by [passt/pasta](https://passt.top/passt/about/) and [slirp4netns](https://github.com/rootless-containers/slirp4netns).

## Alpha prototype

The current alpha includes a usable bwrap-based transparent sandbox launcher:

- `foxproxsetup` runs inside the sandbox network namespace, creates/configures a TUN device with temporary `CAP_NET_ADMIN`, sends the TUN fd back over a broker-owned Unix control socket, drops setup privilege escalation with `NO_NEW_PRIVS`, and execs the target.
- `foxprox` runs on the host, launches bwrap, authenticates the helper peer UID, receives exactly one TUN fd, runs a smoltcp broker over that fd, emits JSON audit events to stdout, injects broker DNS (`10.0.0.2`) into the sandbox resolver, and enforces deny-by-default policy.
- Transparent TCP and UDP are supported for configured IP/port destinations and optional sandbox-to-host endpoint maps.
- Broker-controlled DNS is supported with default-deny REFUSED responses, allow-listed domain forwarding to a configured upstream resolver, pending transaction correlation, and DNS attribution cache updates.

### Build

```sh
cargo build --workspace
```

### Example: curl a real site transparently

```sh
target/debug/foxprox \
  --allow-domain example.com \
  --dns-upstream 1.1.1.1:53 \
  -- \
  curl http://example.com/
```

The sandbox resolves `example.com` through broker-controlled DNS (`10.0.0.2`), then connects to the returned IP through the TUN route. The broker uses DNS attribution to allow the TCP connection and opens the host socket itself.

### Example: map sandbox TCP to a host service

```sh
# Host service listens on 127.0.0.1:8081; sandbox connects to 10.0.0.2:8080.
target/debug/foxprox \
  --tcp-map 10.0.0.2:8080=127.0.0.1:8081 \
  -- \
  curl http://10.0.0.2:8080/
```

### Example: map sandbox UDP to a host service

```sh
# Host UDP service listens on 127.0.0.1:9001; sandbox sends to 10.0.0.2:9000.
target/debug/foxprox \
  --udp-map 10.0.0.2:9000=127.0.0.1:9001 \
  -- \
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"ping", ("10.0.0.2", 9000)); print(s.recvfrom(16))'
```

### Example: allow DNS for one hostname

```sh
target/debug/foxprox \
  --allow-domain example.com:53 \
  --dns-upstream 1.1.1.1:53 \
  -- \
  python3 -c 'import socket; print(socket.gethostbyname("example.com"))'
```

Without a matching allow rule, sandbox DNS receives a bounded REFUSED response and the audit stream records `decision:"deny"` with `reason:"default_deny"`.

### Useful options

- `--allow-tcp IP:PORT`: allow transparent TCP egress to an IP/port directly.
- `--tcp-map SANDBOX_IP:PORT=HOST_IP:PORT`: listen inside the sandbox at `SANDBOX_IP:PORT`, but connect from the broker to `HOST_IP:PORT` after policy allow.
- `--allow-udp IP:PORT`: allow transparent UDP egress to an IP/port directly.
- `--udp-map SANDBOX_IP:PORT=HOST_IP:PORT`: listen inside the sandbox at `SANDBOX_IP:PORT`, but send from the broker to `HOST_IP:PORT` after policy allow.
- `--allow-domain HOST[:PORT]`: allow domain policy. Without a port, alpha listens transparently for common HTTP(S) ports 80 and 443 and allows broker DNS for that host. With a non-53 port, alpha also adds the DNS allow needed to resolve that host.
- `--dns-upstream IP:PORT`: upstream resolver used for allowed broker DNS queries.
- `--setup-helper PATH`: path to `foxproxsetup` when it is not adjacent to `foxprox`.
- `--max-runtime-ms N`: stop the broker after a bounded runtime.
- `-- COMMAND ARGS...`: target command executed inside bwrap after network setup.

## Security posture

Alpha behavior remains conservative:

- deny by default;
- fail closed for malformed/unsupported inputs;
- no TLS MITM or custom CA;
- direct DNS bypass prevention in core policy;
- auditable allow/deny/fail-closed decisions;
- exact one-fd setup handoff with peer UID validation;
- `foxprox-core` forbids unsafe code.
