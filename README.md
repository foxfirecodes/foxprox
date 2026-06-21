# foxprox

a WIP TUN device transparent network proxy/broker for policy-based sandboxing, primarily built for [sandfox](https://github.com/foxfirecodes/sandfox)

inspired by [passt/pasta](https://passt.top/passt/about/) and [slirp4netns](https://github.com/rootless-containers/slirp4netns)

## Harness lab

The alpha harness is intentionally runnable without network namespace privileges for core behavior:

```sh
cargo test --all
cargo run -p foxprox-cli --bin foxprox-lab -- run all
cargo run -p foxprox-cli --bin foxprox-lab -- run env-smoke
cargo run -p foxprox-cli --bin foxprox-lab -- run tun-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run setup-smoke
cargo build -p foxprox-setup --bin foxproxsetup && cargo build -p foxprox-cli --bin foxprox-lab && target/debug/foxprox-lab run handoff-smoke
cargo run -p foxprox-setup --bin foxproxsetup -- --print-plan
```

`foxprox-lab run all` emits deterministic JSON Lines audit records for policy, DNS attribution, proxy parsing, packet write-back, QUIC classification, UDP pseudo-flow tracking, and fail-closed malformed/unsupported paths. `env-smoke` reports local `/dev/net/tun` and `bwrap` availability only; it does not prove the user has enough privileges to configure a real sandbox TUN device. `tun-smoke` is environment-dependent and attempts to create/configure a TUN device inside a `bwrap --unshare-net` namespace with temporary `CAP_NET_ADMIN` using `/usr/bin/ip`. `setup-smoke` runs the Rust `foxproxsetup` helper inside bwrap and verifies direct ioctl-based TUN setup without shelling out from the helper; build `foxproxsetup` first or set `FOXPROX_SETUP_HELPER`. `handoff-smoke` adds a host-side Unix socket receiver and verifies that `foxproxsetup` hands off a live TUN fd before dropping setup capabilities and execing the target.
