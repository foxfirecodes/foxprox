# Controlled alpha runner and policy config

`foxprox run` is the controlled-alpha launcher. It starts the host broker, runs
`foxproxsetup` inside bwrap, hands the TUN fd back to the broker, injects proxy
environment variables when configured, and then runs the target command.

This is suitable for controlled production-like testing. It is not yet a polished
production hardening boundary: keep using bwrap/seccomp/mount policy appropriate
for your environment and review broker audit output.

## Quick start

```sh
cargo build --workspace

./target/debug/foxprox run \
  --config examples/controlled-alpha.toml \
  -- /usr/bin/curl -fsS https://example.com >/tmp/example.html
```

That command uses the injected HTTP CONNECT proxy because curl honors
`HTTPS_PROXY`. To force the transparent TUN path for curl during testing:

```sh
./target/debug/foxprox run \
  --config examples/controlled-alpha.toml \
  -- /usr/bin/curl --noproxy '*' -fsS https://example.com >/tmp/example.html
```

For an app that honors proxy variables, use the same launcher. With the example
config, `foxproxsetup` injects:

- `HTTP_PROXY=http://10.255.0.1:8080`
- `HTTPS_PROXY=http://10.255.0.1:8080`
- `ALL_PROXY=socks5h://10.255.0.1:1080`
- `NO_PROXY=localhost,127.0.0.1`

The broker emits JSON-lines audit records to stderr.

## Config shape

The config file is TOML. Unknown fields are rejected.

### `[sandbox]`

- `id`: audit/session label. Default: `foxprox-run`.
- `ifname`: TUN interface name inside the sandbox. Default: `foxprox0`.
- `setup_socket_host`: optional host setup socket path. Default:
  `/tmp/foxprox-<pid>/setup.sock`.
- `setup_socket_sandbox`: optional path passed to `foxproxsetup`. Default is the
  host setup socket path. The launcher auto-binds the socket directory into
  bwrap at the same path.
- `setup_helper_host`: optional host path to `foxproxsetup`. Default is a sibling
  binary next to the running `foxprox` executable.
- `resolv_conf`: resolver file that `foxproxsetup` rewrites inside bwrap.
  Default: `/etc/resolv.conf`.
- `keep_cap_net_raw`: keep ping capability after setup. Default: `false`.

### `[network]`

- `broker_ip`: broker/gateway IP in the sandbox network. Default: `10.255.0.1`.
- `sandbox_ip`: sandbox TUN IP. Default: `10.255.0.2`.
- `prefix_len`: prefix length. Default: `24`.
- `mtu`: TUN MTU. Default: `1500`.
- `upstream_dns`: host-side upstream DNS resolver. Default: `1.1.1.1:53`.
- `transparent_tcp_ports`: TCP ports accepted by the transparent TUN broker.
  Default: `[80, 443]`.
- `udp_forward_ports`: UDP ports forwarded by the broker. Default: `[443]`.
- `audit_queue_capacity`, `max_worker_threads`, `max_udp_flows`: resource limits.

The launcher automatically adds pre-inspection TCP allow rules for
`transparent_tcp_ports`. For HTTP/TLS ports, host egress still waits for the
later semantic HTTP Host/path or TLS SNI policy decision.

### `[proxy]`

- `http_port`: sandbox-reachable HTTP/CONNECT proxy port, or omit/`null` to
  disable. Default: `8080`.
- `socks5_port`: sandbox-reachable SOCKS5 proxy port, or omit/`null` to disable.
  Default: `1080`.
- `inject_env`: inject proxy environment variables into the target. Default:
  `true`.
- `no_proxy`: value for `NO_PROXY`/`no_proxy` when env injection is enabled.

### `[bwrap]`

- `program`: bwrap executable. Default: `bwrap`.
- `args`: optional full bwrap argument vector before the launcher adds the setup
  socket bind, setup helper bind, `--`, `foxproxsetup`, setup args, and target.
  Do not include `--`; the launcher adds the separator itself.

If `args` is omitted, the launcher uses a controlled default profile:

- new user and network namespaces
- uid/gid 0 inside the user namespace
- temporary `CAP_NET_ADMIN`
- read-only `/usr`, `/lib`, `/lib64`, `/etc/ssl`, `/etc/pki`,
  `/etc/ca-certificates`, `/etc/hosts`, and `/etc/nsswitch.conf` when present
- writable sandbox `/etc`, `/tmp`, and `/dev`
- `/dev/net/tun`
- `/proc`

### `[policy]`

Default policy is deny-by-default with direct DNS, broadcast/multicast, SNI/DNS
mismatch, and hidden-SNI guards enabled.

Supported policy fields:

- `default_action`: `deny-drop`, `deny-reset`, `deny-icmp-unreachable`, or
  `fail-closed`.
- `deny_direct_dns`, `deny_multicast_broadcast`, `deny_sni_dns_mismatch`,
  `deny_hidden_sni`: booleans.
- `broadcast_addresses`: additional IP addresses treated as broadcast.
- `[[policy.rules]]`: ordered first-match rules.

Rule fields:

- `id`: stable audit identifier.
- `effect`: `allow` or `deny`.
- `protocol`: `tcp`, `udp`, `dns`, `icmp`, `http`, `https-connect`, `tls`,
  `socks`, `quic`, or `unsupported`.
- `destination_cidr`: CIDR such as `93.184.216.34/32` or `2001:db8::/32`.
- `destination_ports`: single port (`443`) or inclusive range (`8000-8999`).
- `hostname`: exact hostname.
- `domain_suffix`: exact domain or subdomain match.
- `origin_scheme`: for HTTP-origin events, such as `http`.
- `http_methods`: list such as `["GET", "HEAD"]`.
- `http_path_prefix`: plaintext HTTP path/query prefix.
- `min_attribution`: `low`, `medium`, or `high`.

## Example policy intent

Transparent HTTPS to `example.com` needs a TLS semantic allow rule:

```toml
[[policy.rules]]
id = "allow-example-tls"
effect = "allow"
protocol = "tls"
domain_suffix = "example.com"
destination_ports = "443"
min_attribution = "high"
```

HTTP CONNECT proxy access to the same host needs an `https-connect` rule:

```toml
[[policy.rules]]
id = "allow-example-connect-proxy"
effect = "allow"
protocol = "https-connect"
domain_suffix = "example.com"
destination_ports = "443"
min_attribution = "high"
```

SOCKS5 TCP CONNECT needs a `socks` rule.

## Current limits

- No policy hot reload yet.
- No proxy authentication.
- No SOCKS UDP ASSOCIATE.
- QUIC is UDP/443 candidate classification plus DNS attribution, not QUIC TLS or
  HTTP/3 semantic inspection.
- Audit output currently goes to stderr.
