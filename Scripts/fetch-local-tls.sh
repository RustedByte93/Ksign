#!/bin/sh
# DEPRECATED, not used by `make`: fetches the public backloop.dev certificate (10-year validity, public private key).
# Apple rejects it with errSecCertificateValidityPeriodTooLong (-67901) when evaluated against an explicit anchor.
# Use Scripts/make-local-pki.sh instead. See LOCAL_INSTALLER.md.
# Fetches the *current* public self-signed backloop.dev certificate pack and
# stages it for bundling into the app.
#
# Source : https://backloop.dev/public/pack.json   (self-signed, valid to 2036)
# NOT    : https://backloop.dev/pack.json          (revoked 2026-07-31, expired 2026-10-29)
# NOT    : https://backloop.dev/backloop.dev-*.crt|pem  (these now return 404)
#
# Every step is fatal: if anything does not verify, the build fails instead of
# silently shipping a broken or legacy certificate.
#
# Usage: Scripts/fetch-local-tls.sh [output-dir]      (default: deps)
set -eu

OUT="${1:-deps}"
PACK_URL="https://backloop.dev/public/pack.json"
# SHA-256 fingerprint published on https://backloop.dev/public/
PINNED_FP="A6:EE:0D:5E:23:D0:2F:CC:F0:66:D6:03:BC:C9:C6:01:7B:B9:BD:62:E6:75:A3:EF:43:1D:D5:61:EB:36:CA:F1"
# Concrete hostname used by the installer. A literal "*.backloop.dev" is NOT a
# connectable hostname, so a real label under the wildcard is required.
HOSTNAME="ksign.backloop.dev"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading $PACK_URL"
curl -fsSL --retry 3 --max-time 60 -o "$TMP/pack.json" "$PACK_URL"

python3 - "$TMP" <<'PY'
import json, sys
tmp = sys.argv[1]
d = json.load(open(tmp + "/pack.json"))
if not d.get("public"):
    sys.exit("pack.json is not the public self-signed pack")
if d.get("domain") != "backloop.dev":
    sys.exit("unexpected domain in pack.json")
open(tmp + "/server.crt", "w").write(d["cert"].strip() + "\n")
open(tmp + "/server.pem", "w").write((d["key1"] + d["key2"]).strip() + "\n")
PY

echo "==> Verifying certificate"
FP="$(openssl x509 -in "$TMP/server.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
if [ "$FP" != "$PINNED_FP" ]; then
  echo "ERROR: fingerprint mismatch" >&2
  echo "  expected: $PINNED_FP" >&2
  echo "  got     : $FP" >&2
  exit 1
fi

# Not expired (checkend 0 => fail if already expired)
openssl x509 -in "$TMP/server.crt" -noout -checkend 0 >/dev/null \
  || { echo "ERROR: certificate expired" >&2; exit 1; }

# Self-signed leaf, not a CA, serverAuth, SAN covers the hostname
openssl x509 -in "$TMP/server.crt" -noout -text > "$TMP/cert.txt"
grep -q "CA:FALSE" "$TMP/cert.txt"                 || { echo "ERROR: not a leaf cert" >&2; exit 1; }
grep -q "TLS Web Server Authentication" "$TMP/cert.txt" || { echo "ERROR: no serverAuth EKU" >&2; exit 1; }
grep -q "DNS:\*\.backloop\.dev" "$TMP/cert.txt"    || { echo "ERROR: SAN lacks *.backloop.dev" >&2; exit 1; }

# Private key must match certificate
CERT_PUB="$(openssl x509 -in "$TMP/server.crt" -noout -pubkey | openssl sha256)"
KEY_PUB="$(openssl pkey -in "$TMP/server.pem" -pubout | openssl sha256)"
[ "$CERT_PUB" = "$KEY_PUB" ] || { echo "ERROR: private key does not match certificate" >&2; exit 1; }

mkdir -p "$OUT"
cp "$TMP/server.crt" "$OUT/server.crt"
cp "$TMP/server.pem" "$OUT/server.pem"
printf '%s\n' "$HOSTNAME" > "$OUT/commonName.txt"
chmod 600 "$OUT/server.pem"

echo "OK  fingerprint $FP"
echo "OK  staged in $OUT (server.crt, server.pem, commonName.txt -> $HOSTNAME)"

