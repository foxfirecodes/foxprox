# foxprox

a WIP TUN device transparent network proxy/broker for policy-based sandboxing, primarily built for [sandfox](https://github.com/foxfirecodes/sandfox)

inspired by [passt/pasta](https://passt.top/passt/about/) and [slirp4netns](https://github.com/rootless-containers/slirp4netns)

## Alpha launcher

Build the alpha wrapper binaries:

```sh
cargo build -p foxprox-cli --bins
```

Run a command in a bwrap-created network namespace mediated by foxprox:

```sh
target/debug/foxprox -- curl http://example.com/
```

Inspect the sandbox TUN interface:

```sh
target/debug/foxprox -- /bin/sh -c 'ip addr show foxprox0; ip route; cat /etc/resolv.conf'
```

The wrapper starts `bwrap` with a network/user namespace and temporary `CAP_NET_ADMIN`, runs `foxproxsetup` inside the namespace to create/configure a TUN device, hands the TUN fd back to the host broker, drops setup capabilities, and execs the target command.

Useful launcher options:

```sh
target/debug/foxprox \
  --tun-name foxprox0 \
  --sandbox-ip 10.255.0.2 \
  --broker-ip 10.255.0.1 \
  --dns 10.255.0.1 \
  --mtu 1500 \
  -- curl http://example.com/
```

Useful alpha policy options:

```sh
# Reset/close a TLS connection after SNI inspection.
target/debug/foxprox --deny-host github.com -- curl https://github.com/

# Start from default deny, then allow TCP/443 and deny a domain suffix by TLS/proxy hostname.
target/debug/foxprox \
  --default-policy deny \
  --allow-tcp 443 \
  --deny-domain github.com \
  -- curl https://github.com/
```

Policy options can also be read from a simple line-oriented file with one option per line and `#` comments:

```conf
# foxprox-policy.conf
default-policy deny
allow-tcp 443
deny-action reset
deny-host github.com
```

```sh
target/debug/foxprox --policy foxprox-policy.conf -- curl https://github.com/
```

Supported policy flags include `--default-policy allow|deny`, `--deny-action reset|drop|icmp-unreachable`, `--allow-host`, `--deny-host`, `--allow-domain`, `--deny-domain`, `--allow-ip`, `--deny-ip`, `--allow-tcp`, `--deny-tcp`, `--allow-udp`, `--deny-udp`, ping, QUIC, and direct-DNS toggles.

This is an alpha network wrapper, not a complete filesystem/seccomp sandbox profile. It uses bwrap for the network namespace and keeps the broker core independent of bwrap-specific details.
