#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/.tmp/live-smoke-$(date +%s)"
UPSTREAM_DNS="1.1.1.1:53"
SMOKE_HOST="example.com"
BUILD=1

usage() {
  cat <<'USAGE'
usage: scripts/live-smoke-bwrap-tun.sh [options]

Runs live bwrap/TUN smoke tests for the alpha proof-transparent path.

Options:
  --out-dir DIR        Directory for broker/sandbox logs (default: .tmp/live-smoke-<epoch>)
  --upstream-dns ADDR  Upstream DNS resolver for the broker (default: 1.1.1.1:53)
  --host HOST          Public HTTP/HTTPS host to fetch (default: example.com)
  --skip-build         Reuse existing target/debug binaries instead of cargo build
  -h, --help           Show this help

The output directory must be inside the repository because it contains the setup
Unix socket that is bind-mounted into bwrap at /work.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      [[ $# -ge 2 ]] || { echo "missing value for --out-dir" >&2; exit 2; }
      OUT_DIR="$2"
      shift 2
      ;;
    --upstream-dns)
      [[ $# -ge 2 ]] || { echo "missing value for --upstream-dns" >&2; exit 2; }
      UPSTREAM_DNS="$2"
      shift 2
      ;;
    --host)
      [[ $# -ge 2 ]] || { echo "missing value for --host" >&2; exit 2; }
      SMOKE_HOST="$2"
      shift 2
      ;;
    --skip-build)
      BUILD=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${OUT_DIR}" != /* ]]; then
  OUT_DIR="${ROOT}/${OUT_DIR}"
fi
case "${OUT_DIR}" in
  "${ROOT}"/*) ;;
  *) echo "--out-dir must be inside ${ROOT}" >&2; exit 2 ;;
esac

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

need bwrap
if [[ ${BUILD} -eq 1 ]]; then
  need cargo
fi
need curl
need grep
need ip
need nc
need timeout

if [[ ! -w /dev/net/tun ]]; then
  echo "/dev/net/tun is not writable by this user" >&2
  exit 1
fi

if [[ ${BUILD} -eq 1 ]]; then
  (cd "${ROOT}" && cargo build --workspace)
fi

FOXPROX="${ROOT}/target/debug/foxprox"
SETUP_IN_SANDBOX="/work/target/debug/foxproxsetup"
[[ -x "${FOXPROX}" ]] || { echo "missing executable ${FOXPROX}; run cargo build --workspace" >&2; exit 1; }
[[ -x "${ROOT}/target/debug/foxproxsetup" ]] || { echo "missing executable ${ROOT}/target/debug/foxproxsetup; run cargo build --workspace" >&2; exit 1; }

mkdir -p "${OUT_DIR}"
RESOLV_SEED="${OUT_DIR}/resolv.seed"
UPSTREAM_DNS_IP="${UPSTREAM_DNS%:*}"
printf 'nameserver %s\n' "${UPSTREAM_DNS_IP}" >"${RESOLV_SEED}"

BROKER_PID=""
stop_broker() {
  if [[ -n "${BROKER_PID}" ]]; then
    kill "${BROKER_PID}" 2>/dev/null || true
    wait "${BROKER_PID}" 2>/dev/null || true
    BROKER_PID=""
  fi
}
trap stop_broker EXIT

start_broker() {
  local phase_dir="$1"
  local sock="$2"
  rm -f "${sock}"
  "${FOXPROX}" proof-transparent \
    --setup-socket "${sock}" \
    --upstream-dns "${UPSTREAM_DNS}" \
    --tcp-port 80 \
    --tcp-forward-port 443 \
    --udp-forward-port 443 \
    --http-proxy-port 8080 \
    --http-proxy-allow-port 80 \
    --http-proxy-allow-port 443 \
    --socks5-proxy-port 1080 \
    --socks5-proxy-allow-port 80 \
    --socks5-proxy-allow-port 443 \
    --audit-queue-capacity 65536 \
    >"${phase_dir}/broker.log" 2>&1 &
  BROKER_PID=$!

  for _ in $(seq 1 100); do
    [[ -S "${sock}" ]] && return 0
    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
      echo "broker exited before creating setup socket" >&2
      cat "${phase_dir}/broker.log" >&2 || true
      exit 1
    fi
    sleep 0.1
  done
  echo "setup socket did not appear: ${sock}" >&2
  cat "${phase_dir}/broker.log" >&2 || true
  exit 1
}

run_in_bwrap() {
  local phase_dir="$1"
  local sock="$2"
  local setup_args="$3"
  local app_script="$4"
  local sandbox_sock="/work/${sock#${ROOT}/}"

  # The sandbox root intentionally has a writable /etc/resolv.conf. foxproxsetup
  # rewrites it to the broker DNS address before execing the test app.
  bwrap \
    --unshare-user --uid 0 --gid 0 --unshare-net --cap-add CAP_NET_ADMIN \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind "${ROOT}" /work \
    --dir /etc \
    --ro-bind-try /etc/ssl /etc/ssl \
    --ro-bind-try /etc/pki /etc/pki \
    --ro-bind-try /etc/ca-certificates /etc/ca-certificates \
    --ro-bind-try /etc/hosts /etc/hosts \
    --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf \
    --bind-data 3 /etc/resolv.conf \
    --dev /dev --dir /dev/net --dev-bind /dev/net/tun /dev/net/tun \
    --proc /proc --tmpfs /tmp --chdir /work \
    -- "${SETUP_IN_SANDBOX}" \
      --setup-socket "${sandbox_sock}" \
      --resolv-conf /etc/resolv.conf \
      ${setup_args} \
      -- /usr/bin/sh -lc "${app_script}" \
      3<"${RESOLV_SEED}" >"${phase_dir}/sandbox.log" 2>&1
}

require_log() {
  local pattern="$1"
  local file="$2"
  local description="$3"
  if ! grep -q -- "${pattern}" "${file}"; then
    echo "missing expected evidence (${description}) in ${file}" >&2
    tail -120 "${file}" >&2 || true
    exit 1
  fi
}

run_direct_phase() {
  local phase_dir="${OUT_DIR}/direct"
  local sock="${phase_dir}/setup.sock"
  mkdir -p "${phase_dir}"
  start_broker "${phase_dir}" "${sock}"
  run_in_bwrap "${phase_dir}" "${sock}" "" "
    set -eux
    /usr/bin/curl --noproxy '*' -fsS --max-time 20 http://${SMOKE_HOST} >/tmp/direct-http.out
    /usr/bin/curl -k --noproxy '*' -fsS --max-time 30 https://${SMOKE_HOST} >/tmp/direct-https.out
    /usr/bin/timeout 3 /usr/bin/sh -c '/usr/bin/printf q | /usr/bin/nc -u ${UPSTREAM_DNS_IP} 443' || true
    /usr/bin/test -s /tmp/direct-http.out
    /usr/bin/test -s /tmp/direct-https.out
  "
  stop_broker

  require_log '"kind":"TunConfigured"' "${phase_dir}/broker.log" "TUN configured audit"
  require_log '"kind":"DnsQuery"' "${phase_dir}/broker.log" "broker DNS audit"
  require_log '"kind":"TransparentHttpRequest"' "${phase_dir}/broker.log" "transparent HTTP audit"
  require_log '"kind":"TlsClientHello"' "${phase_dir}/broker.log" "transparent TLS audit"
  require_log '"kind":"QuicCandidateFlowCreated"' "${phase_dir}/broker.log" "UDP/443 QUIC candidate audit"
}

run_proxy_phase() {
  local phase_dir="${OUT_DIR}/proxy"
  local sock="${phase_dir}/setup.sock"
  mkdir -p "${phase_dir}"
  start_broker "${phase_dir}" "${sock}"
  run_in_bwrap "${phase_dir}" "${sock}" "--http-proxy http://10.255.0.1:8080 --https-proxy http://10.255.0.1:8080 --all-proxy socks5h://10.255.0.1:1080 --no-proxy localhost,127.0.0.1" "
    set -eux
    /usr/bin/env | /usr/bin/grep -E '^(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)='
    /usr/bin/curl -k -fsS --max-time 30 -x http://10.255.0.1:8080 https://${SMOKE_HOST} >/tmp/connect-proxy.out
    /usr/bin/sleep 1
    /usr/bin/curl -fsS --max-time 20 -x http://10.255.0.1:8080 http://${SMOKE_HOST} >/tmp/http-proxy.out
    /usr/bin/sleep 1
    /usr/bin/curl -fsS --max-time 20 --socks5-hostname 10.255.0.1:1080 http://${SMOKE_HOST} >/tmp/socks-http.out
    /usr/bin/test -s /tmp/connect-proxy.out
    /usr/bin/test -s /tmp/http-proxy.out
    /usr/bin/test -s /tmp/socks-http.out
  "
  stop_broker

  require_log '"kind":"ProxyListenerConfigured"' "${phase_dir}/broker.log" "proxy bridge listener audit"
  require_log '"kind":"HttpsConnect"' "${phase_dir}/broker.log" "HTTP CONNECT audit"
  require_log '"kind":"HttpRequest"' "${phase_dir}/broker.log" "HTTP proxy audit"
  require_log '"kind":"SocksConnect"' "${phase_dir}/broker.log" "SOCKS5 audit"
  require_log '^HTTP_PROXY=http://10.255.0.1:8080$' "${phase_dir}/sandbox.log" "setup HTTP_PROXY env"
  require_log '^HTTPS_PROXY=http://10.255.0.1:8080$' "${phase_dir}/sandbox.log" "setup HTTPS_PROXY env"
  require_log '^ALL_PROXY=socks5h://10.255.0.1:1080$' "${phase_dir}/sandbox.log" "setup ALL_PROXY env"
}

run_direct_phase
run_proxy_phase

cat <<EOF
live bwrap/TUN smoke passed
logs: ${OUT_DIR}
  direct broker: ${OUT_DIR}/direct/broker.log
  direct sandbox: ${OUT_DIR}/direct/sandbox.log
  proxy broker:  ${OUT_DIR}/proxy/broker.log
  proxy sandbox: ${OUT_DIR}/proxy/sandbox.log
EOF
