# Live bwrap/TUN smoke test

The alpha live smoke test runs the proof broker on the host, starts `foxproxsetup` inside a new bubblewrap user/network namespace, creates a TUN device, and exercises real traffic through the TUN path. The smoke bwrap profile bind-mounts common host CA bundle locations, including `/etc/ssl`, `/etc/pki`, and `/etc/ca-certificates` when present.

## Requirements

Run on a Linux host with:

- `bwrap`
- `cargo` unless `--skip-build` is used
- `curl`
- `grep`
- `ip`
- `nc`
- `timeout`
- writable `/dev/net/tun`
- unprivileged user namespaces enabled
- outbound access to the selected smoke host and upstream DNS resolver

The script uses `bwrap --unshare-user --uid 0 --gid 0 --unshare-net --cap-add CAP_NET_ADMIN`. Mapping the sandbox user to uid/gid 0 inside the user namespace is required for the setup helper to configure links, addresses, routes, and the TUN device. Without it, commands such as `ip link set lo up` fail with `Operation not permitted`.

## Run

```sh
scripts/live-smoke-bwrap-tun.sh
```

Useful options:

```sh
scripts/live-smoke-bwrap-tun.sh --skip-build
scripts/live-smoke-bwrap-tun.sh --host example.com --upstream-dns 1.1.1.1:53
scripts/live-smoke-bwrap-tun.sh --out-dir .tmp/my-live-smoke
```

The output directory must be inside the repository because it contains the setup Unix socket that is bind-mounted into bwrap at `/work`.

## What it covers

The script runs two isolated broker/setup phases:

1. Direct transparent traffic:
   - broker DNS through the TUN path
   - transparent HTTP on TCP/80
   - transparent TLS/SNI inspection on TCP/443
   - UDP/443 classified as a QUIC candidate with DNS attribution
2. Explicit proxy bridge traffic:
   - setup-injected `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`
   - HTTP CONNECT through the TUN-reachable HTTP proxy bridge
   - absolute-form HTTP through the TUN-reachable HTTP proxy bridge
   - SOCKS5 CONNECT through the TUN-reachable SOCKS5 bridge

The script fails if the app commands fail or if broker logs do not contain the expected structured audit evidence, including `TunConfigured`, `DnsQuery`, `TransparentHttpRequest`, `TlsClientHello`, `QuicCandidateFlowCreated`, `HttpsConnect`, `HttpRequest`, and `SocksConnect`.

## `/etc/resolv.conf` expectation

`foxproxsetup --resolv-conf /etc/resolv.conf` rewrites the sandbox resolver file so DNS goes to the broker address. The smoke script creates a writable `/etc/resolv.conf` inside bwrap with `--bind-data` before launching `foxproxsetup`.

If you run the pieces manually, make sure the path passed to `--resolv-conf` is writable from inside the setup namespace. A read-only bind of the host `/etc/resolv.conf` will prevent DNS setup from completing.

## Current QUIC limit

Alpha QUIC support is intentionally limited to UDP policy and attribution. UDP/443 traffic is classified and audited as a QUIC candidate, and DNS cache entries are used for hostname attribution when available. The broker does not parse QUIC TLS ClientHello, decrypt HTTP/3, install CAs, or expose HTTP/3 URL/path metadata.
