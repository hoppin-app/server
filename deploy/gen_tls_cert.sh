#!/usr/bin/env bash
#
# gen_tls_cert.sh — generate a self-signed P-256 TLS certificate for the
# hoppin bootstrap server, and print the SPKI pin the iOS app must pin.
#
# Usage:
#   ./server/gen_tls_cert.sh [COMMON_NAME] [OUT_DIR] [DAYS]
#
#   COMMON_NAME  hostname or IP clients connect to (default: localhost)
#   OUT_DIR      where cert.pem / key.pem are written (default: ./tls)
#   DAYS         validity in days (default: 825, the max Apple accepts)
#
# Outputs:
#   $OUT_DIR/cert.pem   certificate  (HOPPIN_TLS_CERT)
#   $OUT_DIR/key.pem    private key  (HOPPIN_TLS_KEY, mode 600)
#   the base64 SHA-256 of the SubjectPublicKeyInfo DER -> AppConfig.serverSPKISHA256Base64
#
# NOTE: the pin is over the SubjectPublicKeyInfo, not the certificate. Re-issuing
# the certificate with the SAME key.pem keeps the pin stable, so you can renew
# without shipping an app update. Keep a backup keypair and ship BOTH pins.

set -euo pipefail

CN="${1:-localhost}"
OUT_DIR="${2:-./tls}"
DAYS="${3:-825}"

command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found" >&2; exit 1; }

mkdir -p "$OUT_DIR"
CERT="$OUT_DIR/cert.pem"
KEY="$OUT_DIR/key.pem"

# Subject Alternative Name: IP entry if CN parses as an IPv4 address, else DNS.
if [[ "$CN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="IP:$CN"
else
  SAN="DNS:$CN"
fi

echo "Generating self-signed P-256 certificate for CN=$CN (SAN=$SAN, ${DAYS}d)..."

openssl req -x509 \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$KEY" \
  -out "$CERT" \
  -days "$DAYS" \
  -nodes \
  -subj "/CN=$CN" \
  -addext "subjectAltName=$SAN" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  2>/dev/null

chmod 600 "$KEY"
chmod 644 "$CERT"

PIN="$(openssl x509 -in "$CERT" -pubkey -noout \
       | openssl pkey -pubin -outform DER \
       | openssl dgst -sha256 -binary \
       | openssl base64)"

FPR="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2)"
EXP="$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)"

cat <<EOF

  certificate : $CERT
  private key : $KEY   (mode 600 - never commit this)
  expires     : $EXP
  cert SHA256 : $FPR

  SPKI pin (base64 SHA-256 of SubjectPublicKeyInfo DER):

      $PIN

  Put it in the app:

      // HopChat-1/App/AppConfig.swift
      static let serverSPKISHA256Base64: [String] = [
          "$PIN",
          // "<backup key pin>",
      ]

  Run the server with:

      export HOPPIN_TLS_CERT="$(cd "$(dirname "$CERT")" && pwd)/$(basename "$CERT")"
      export HOPPIN_TLS_KEY="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"

EOF
