# Bubblewrap Fork Plan

Alpha bwrap setup runs foxprox as the initial bwrap command with temporary `CAP_NET_ADMIN`, e.g. `bwrap --unshare-user --uid 0 --gid 0 --unshare-net --cap-add CAP_NET_ADMIN -- foxproxsetup app ...`. `foxproxsetup` creates/configures the TUN device, configures routes/DNS/proxy reachability, hands the TUN fd to the host broker, drops `CAP_NET_ADMIN`, closes setup-only fds, and `exec`s the real app. Mapping to uid/gid 0 inside the user namespace is required for network setup commands such as `ip link set lo up`; without it, the helper lacks effective `CAP_NET_ADMIN` in the new network namespace.

A small bwrap fork (`foxwrap`) can add a setup hook that runs during bwrap setup, before final capability drop/seccomp/app exec. The desired feature is a trusted `--setup-helper HOST_PATH` option, possibly repeatable, that executes a helper inside the new user/network/mount namespaces but before the target application starts.

To make the helper reliably available, `foxwrap` should temporarily read-only bind the host helper to an internal reserved path such as `/.foxprox-setup/helper`, run it synchronously, then unmount it immediately after success. This avoids dependence on user-provided bind mounts and keeps the helper out of the final sandbox filesystem.

The fork should fail closed: if setup helper binding, execution, TUN handoff, or helper exit status fails, the target app is never executed. Setup-only capabilities and file descriptors must be dropped/closed before final app exec.

## Alpha live invocation notes

See `docs/live-smoke.md` and `scripts/live-smoke-bwrap-tun.sh` for a working live bwrap/TUN smoke invocation.

When using `foxproxsetup --resolv-conf PATH`, `PATH` must be writable inside the setup namespace because the helper rewrites it to point at the broker DNS address. For bwrap tests, create a sandbox-local file with `--bind-data FD /etc/resolv.conf` or an equivalent writable bind. A read-only bind of the host resolver file will fail closed before the target application is executed.

Explicit proxy environment injection is opt-in. Pass `--http-proxy`, `--https-proxy`, `--all-proxy`, and/or `--no-proxy` to `foxproxsetup` when the target application should see proxy variables after setup privilege drop.
