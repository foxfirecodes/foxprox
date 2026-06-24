#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v bwrap >/dev/null 2>&1; then
  echo "error: bwrap not found in PATH" >&2
  exit 1
fi
if [[ ! -e /dev/net/tun ]]; then
  echo "error: /dev/net/tun is missing" >&2
  exit 1
fi

# Prove this host can create a rootless bwrap user+network namespace with
# CAP_NET_ADMIN and can open /dev/net/tun from inside that namespace. The
# ordering here matters: create a bwrap /dev, then dev-bind the host TUN node.
bwrap --unshare-user --uid 0 --gid 0 \
  --unshare-net \
  --cap-add CAP_NET_ADMIN \
  --ro-bind / / \
  --tmpfs /etc \
  --dev /dev \
  --dev-bind /dev/net/tun /dev/net/tun \
  --proc /proc \
  python3 - <<'PY'
import os
with open('/proc/self/status', 'r', encoding='utf-8') as status:
    cap_eff = next(line.split()[1] for line in status if line.startswith('CapEff:'))
if int(cap_eff, 16) & (1 << 12) == 0:
    raise SystemExit(f'CAP_NET_ADMIN missing inside bwrap: CapEff={cap_eff}')
fd = os.open('/dev/net/tun', os.O_RDWR)
os.close(fd)
PY

cargo test -p foxprox-cli --test bwrap_setup_e2e --all-features -- --ignored --nocapture
