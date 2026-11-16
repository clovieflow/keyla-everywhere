#!/usr/bin/env bash
# Rotate Cloudflare WARP's tunnel keys while keeping a local SOCKS5 proxy.
#
# OpenCode Free limits usage per egress IP. WARP exposes one SOCKS5 endpoint
# (`127.0.0.1:40000` by default), so rotating the tunnel identity changes the
# egress address behind that same endpoint. Keyla then rotates the endpoint
# list per request; one endpoint is enough here because its IP changes.
#
# Run this on the same host as Keyla, after the WARP client is registered:
#   ./scripts/warp-rotate.sh
#   WARP_ROTATE_SECONDS=120 WARP_PROXY_PORT=40000 ./scripts/warp-rotate.sh
#
# Then configure Keyla:
#   KEYLA_OPENCODE_PROXY_URLS=socks5://127.0.0.1:40000
#
# The script only manages proxy mode; it does not route the host's traffic.
set -euo pipefail

INTERVAL="${WARP_ROTATE_SECONDS:-120}"
PORT="${WARP_PROXY_PORT:-40000}"
SOCKET="socks5://127.0.0.1:${PORT}"

if ! command -v warp-cli >/dev/null 2>&1; then
  echo "warp-cli is required (install the Cloudflare WARP client)" >&2
  exit 1
fi
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 30 ]; then
  echo "WARP_ROTATE_SECONDS must be an integer >= 30" >&2
  exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "WARP_PROXY_PORT must be a valid TCP port" >&2
  exit 2
fi

cleanup() {
  warp-cli disconnect >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

# Proxy mode keeps the tunnel local and exposes it as SOCKS5 instead of
# capturing the host's default route.
warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port "$PORT"
warp-cli --accept-tos connect

echo "warp proxy ready at ${SOCKET}; rotating every ${INTERVAL}s"

while true; do
  sleep "$INTERVAL"
  # Generate a fresh key pair and reconnect so the egress identity changes.
  warp-cli disconnect || true
  warp-cli --accept-tos tunnel rotate-keys
  warp-cli --accept-tos connect
  if command -v curl >/dev/null 2>&1; then
    egress="$(curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:${PORT}" \
      https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
      | awk -F= '$1 == "ip" { print $2; exit }' || true)"
    printf 'warp rotated at %s%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${egress:+ · egress $egress}"
  else
    printf 'warp rotated at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
done
