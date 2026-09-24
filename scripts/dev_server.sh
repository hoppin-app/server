#!/usr/bin/env bash
#
# dev_server.sh — start bootstrap.py for device testing, correctly.
#
# Does the four things that are easy to get wrong:
#   * listens on IPv4 *and* IPv6 (the default is IPv4 only, and an IPv6-only
#     phone then fails in a way that looks exactly like a firewall)
#   * TLS, never plaintext, so a tunnel or a forwarded port can't read traffic
#   * generates the certificate on first run and prints its pin
#   * prints every address a phone might need, and the server's public key
#
# Usage:
#   scripts/dev_server.sh              # dev mode, fixed code 123456
#   CODE=999111 scripts/dev_server.sh  # a different fixed code
#
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/venv/bin/python}"
CODE="${CODE:-123456}"
TLS_DIR="${TLS_DIR:-$ROOT/tls}"

if [[ ! -f "$TLS_DIR/cert.pem" || ! -f "$TLS_DIR/key.pem" ]]; then
    echo "No certificate yet — generating one (valid 825 days)…"
    ./server/gen_tls_cert.sh localhost "$TLS_DIR" 825
    echo
fi

echo "Pin for AppConfig.serverSPKISHA256Base64 (and the Developer screen):"
openssl x509 -in "$TLS_DIR/cert.pem" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64
echo

echo "Reach this server at:"
LAN4="$(ipconfig getifaddr en0 2>/dev/null || true)"
[[ -n "$LAN4" ]] && echo "  same Wi-Fi:      $LAN4:4443"
V6="$(ifconfig 2>/dev/null | awk '/inet6 2[0-9a-f]*:/ && /secured/ {print $2; exit}')"
[[ -n "$V6" ]] && echo "  IPv6 (anywhere): $V6:4443   (needs the router to allow inbound)"
PUB4="$(curl -s -m 4 https://api.ipify.org || true)"
[[ -n "$PUB4" ]] && echo "  IPv4 (anywhere): $PUB4:4443   (needs TCP 4443 forwarded to $LAN4)"
echo
echo "Verification code: $CODE"
echo

exec env HOPPIN_BIND='*' \
         HOPPIN_ENV=dev \
         HOPPIN_DEV_FIXED_CODE="$CODE" \
         HOPPIN_TLS_CERT="$TLS_DIR/cert.pem" \
         HOPPIN_TLS_KEY="$TLS_DIR/key.pem" \
         "$PYTHON" bootstrap.py
