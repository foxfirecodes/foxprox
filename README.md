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

Useful options:

```sh
target/debug/foxprox \
  --tun-name foxprox0 \
  --sandbox-ip 10.255.0.2 \
  --broker-ip 10.255.0.1 \
  --dns 10.255.0.1 \
  --mtu 1500 \
  -- curl http://example.com/
```

This is an alpha network wrapper, not a complete filesystem/seccomp sandbox profile. It uses bwrap for the network namespace and keeps the broker core independent of bwrap-specific details.
