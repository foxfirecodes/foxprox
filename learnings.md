# Harness Lab Learnings

## 2026-06-21 — Initial environment

- `/dev/net/tun` and `bwrap` are installed in the local harness worktree environment, so environment-dependent namespace/TUN smoke commands can be offered. Their existence does not prove the current user can create/configure TUN devices inside a bwrap network namespace with `CAP_NET_ADMIN`.

## 2026-06-21 — Harness boundary

- Platform-independent alpha semantics can be verified without namespace privileges by routing normalized events through a shared policy engine, mock egress backend, structured audit records, and deterministic packet/proxy fixtures.
- `foxprox-lab run env-smoke` should remain a capability report, not a success claim for real bwrap/TUN setup, until a setup helper can actually create/configure a TUN device and hand its fd to the broker.

## 2026-06-21 — bwrap setup helper spawning limitation

- A `foxproxsetup` Rust binary launched directly as the bwrap command can start inside the namespace, but `std::process::Command::output()` from that helper failed with `ENOENT` when attempting to spawn both `/usr/bin/ip` and `/bin/sh`. The equivalent bwrap command that runs `/bin/sh -lc 'ip tuntap ...'` as the initial process succeeds. Treat shelling out from the setup helper as unreliable until investigated; direct TUN setup syscalls/netlink/ioctl are likely needed for the real helper.

## 2026-06-21 — Direct setup helper TUN path

- Direct ioctl-based TUN setup from the Rust `foxproxsetup` process succeeds inside the same `bwrap --unshare-user --unshare-net --cap-add CAP_NET_ADMIN` environment where spawning `/bin/sh` from the helper failed. Prefer direct `/dev/net/tun`, `TUNSETIFF`, `SIOCSIF*`, and route ioctls for setup-helper behavior; keep shell/IP-based smoke only as an independent environment comparison.
- A non-persistent TUN created with `TUNSETIFF` is tied to the open fd, so target execution must be gated on successful fd handoff to the host-side broker. `foxproxsetup` should fail closed rather than exec a target without `FOXPROX_SETUP_SOCKET`/`--handoff-env` being available.

## 2026-06-21 — Host-side setup fd handoff

- A bwrap-contained `foxproxsetup` can connect to a host Unix socket when the socket directory is explicitly bind-mounted into the sandbox and passed through `FOXPROX_SETUP_SOCKET`. `SCM_RIGHTS` fd passing preserves the non-persistent TUN device after the helper closes its local fd and execs/exits the target.

## 2026-06-21 — Packet write-back smoke constraints

- `ping` inside the bwrap target failed before sending traffic because the target lacked `CAP_NET_RAW`/setuid ping privileges after setup capability drop (`/usr/bin/ping: socket: Operation not permitted`). For unprivileged write-back smoke in this environment, a UDP socket probe is a better reusable pattern than ICMP ping. Keep ICMP synthesis covered by deterministic packet fixtures until a safe ping capability strategy is defined.

## 2026-06-21 — Transparent UDP runtime boundary

- Keep Linux fd handoff/read/write code in the CLI or future device crate, but keep packet parsing, policy-before-egress, audit generation, and UDP reply synthesis in platform-independent core runtime code. This makes environment smokes smaller and gives deterministic tests for allow/deny behavior before involving bwrap.

## 2026-06-21 — DNS smoke pattern

- A minimal raw DNS A query from sandbox Python is sufficient to prove broker-local DNS response and cache attribution over the handed-off TUN fd. This avoids depending on `/etc/resolv.conf` mutation or external upstream DNS while still exercising real UDP packets through the sandbox route.

## 2026-06-21 — Unix socket path limits in bwrap smokes

- Long handoff socket paths under the nested worktree can exceed `SUN_LEN` for Unix domain sockets. Use short names under the already-mounted `target/debug` directory (for example `fxdns-<pid>/s`) for new environment smokes that need host/sandbox Unix sockets.

## 2026-06-22 — smoltcp IP-medium gate pattern

- `smoltcp` 0.13 can be driven deterministically with a custom `Device` whose capabilities use `Medium::Ip` and `HardwareAddress::Ip`. This matches TUN-shaped IP packets and avoids Ethernet/TAP assumptions in the TCP stack gate.
- smoltcp validates TCP checksums for inbound SYN packets, so synthetic TCP fixtures need a correct IPv4 pseudo-header checksum; the earlier parser-only TCP fixtures with zero TCP checksums are not sufficient for stack-level tests.
