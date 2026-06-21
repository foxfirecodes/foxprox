# Bubblewrap Fork Plan

Alpha bwrap setup runs foxprox as the initial bwrap command with temporary `CAP_NET_ADMIN`, e.g. `bwrap --unshare-user --unshare-net --cap-add CAP_NET_ADMIN -- foxproxsetup app ...`. `foxproxsetup` creates/configures the TUN device, configures routes/DNS/proxy reachability, hands the TUN fd to the host broker, drops `CAP_NET_ADMIN`, closes setup-only fds, and `exec`s the real app.

A small bwrap fork (`foxwrap`) can add a setup hook that runs during bwrap setup, before final capability drop/seccomp/app exec. The desired feature is a trusted `--setup-helper HOST_PATH` option, possibly repeatable, that executes a helper inside the new user/network/mount namespaces but before the target application starts.

To make the helper reliably available, `foxwrap` should temporarily read-only bind the host helper to an internal reserved path such as `/.foxprox-setup/helper`, run it synchronously, then unmount it immediately after success. This avoids dependence on user-provided bind mounts and keeps the helper out of the final sandbox filesystem.

The fork should fail closed: if setup helper binding, execution, TUN handoff, or helper exit status fails, the target app is never executed. Setup-only capabilities and file descriptors must be dropped/closed before final app exec.
