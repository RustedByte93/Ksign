#!/bin/sh
# Generates the private PKI for Ksign's local HTTPS installer.
#
#   CA   : EC P-256, name-constrained to ksign.backloop.dev (it cannot vouch for any other site),
#          kept OUTSIDE the repo and OUTSIDE the IPA. Default: ~/.ksign-pki (mode 700).
#   Leaf : EC P-256, SAN = ksign.backloop.dev, serverAuth, CA:FALSE, short-lived (default 365 days;
#          Apple rejects TLS server certs valid for more than 825 days with errSecCertificateValidityPeriodTooLong).
#
# Output (default: deps/ — everything in deps/ is bundled into the app by the makefile):
#   server.crt              leaf certificate (PEM)
#   server.pem              leaf private key (PEM, PKCS#8)   <- ships inside the app, see LOCAL_INSTALLER.md
#   commonName.txt          ksign.backloop.dev
#   KsignLocalCA.crt        public CA certificate (PEM)
#   KsignLocalCA.cer        public CA certificate (DER)
#   KsignLocalCA.mobileconfig  unsigned configuration profile that installs the CA (public data only)
#
# Re-running with an existing CA = RENEWAL: a new leaf is issued under the same CA, so the phone keeps trusting it.
# Never commit or copy the CA key (ca.key). Never put it in deps/.
#
# Usage: Scripts/make-local-pki.sh [--out DIR] [--pki-dir DIR] [--leaf-days N] [--ephemeral]
#   --ephemeral   generate a throw-away CA, issue the leaf, then DESTROY the CA key. Nothing can ever
#                 issue another certificate for this CA; renewal needs a new CA and re-trusting it.
#   KSIGN_CA_KEY / KSIGN_CA_CERT  use an existing CA (e.g. from CI secrets written to a temp file).
set -eu

OUT="deps"
PKI_DIR="${KSIGN_PKI_DIR:-$HOME/.ksign-pki}"
LEAF_DAYS=365
EPHEMERAL=0
HOST="ksign.backloop.dev"
CA_DAYS=1825
MAX_LEAF_DAYS=825

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --pki-dir) PKI_DIR="$2"; shift 2 ;;
    --leaf-days) LEAF_DAYS="$2"; shift 2 ;;
    --ephemeral) EPHEMERAL=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$LEAF_DAYS" -le "$MAX_LEAF_DAYS" ] 2>/dev/null || { echo "ERROR: --leaf-days must be an integer <= $MAX_LEAF_DAYS" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
umask 077

CA_KEY="${KSIGN_CA_KEY:-}"
CA_CRT="${KSIGN_CA_CERT:-}"
if [ -z "$CA_KEY" ]; then
  if [ "$EPHEMERAL" = 1 ]; then
    CA_KEY="$TMP/ca.key"; CA_CRT="$TMP/ca.crt"
  else
    mkdir -p "$PKI_DIR"; chmod 700 "$PKI_DIR"
    CA_KEY="$PKI_DIR/ca.key"; CA_CRT="$PKI_DIR/ca.crt"
  fi
fi

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  echo "==> Creating new private CA (name-constrained to $HOST)"
  openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$CA_KEY"
  cat > "$TMP/ca.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:$HOST
EOF
  openssl req -new -key "$CA_KEY" -subj "/O=Ksign Local/CN=Ksign Local Installer CA" -out "$TMP/ca.csr"
  openssl x509 -req -in "$TMP/ca.csr" -signkey "$CA_KEY" -days "$CA_DAYS" -sha256 -extfile "$TMP/ca.ext" -out "$CA_CRT" 2>/dev/null
  chmod 600 "$CA_KEY"
else
  echo "==> Reusing existing CA: $CA_CRT (renewal; the phone keeps trusting it)"
  openssl x509 -in "$CA_CRT" -noout -checkend $((86400 * 30)) >/dev/null \
    || { echo "ERROR: CA expires within 30 days or is expired; remove it to create a new one (re-trust required)" >&2; exit 1; }
fi

echo "==> Issuing leaf for $HOST ($LEAF_DAYS days)"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$TMP/server.pem"
openssl req -new -key "$TMP/server.pem" -subj "/O=Ksign Local/CN=$HOST" -out "$TMP/server.csr"
cat > "$TMP/leaf.ext" <<EOF
subjectAltName=DNS:$HOST
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in "$TMP/server.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$TMP/ca.srl" \
  -days "$LEAF_DAYS" -sha256 -extfile "$TMP/leaf.ext" -out "$TMP/server.crt" 2>/dev/null

echo "==> Verifying"
openssl verify -CAfile "$CA_CRT" -purpose sslserver -verify_hostname "$HOST" "$TMP/server.crt" >/dev/null \
  || { echo "ERROR: leaf does not verify against the CA for $HOST" >&2; exit 1; }
openssl x509 -in "$TMP/server.crt" -noout -text > "$TMP/leaf.txt"
grep -q "CA:FALSE" "$TMP/leaf.txt" && grep -q "TLS Web Server Authentication" "$TMP/leaf.txt" \
  && grep -q "DNS:$HOST" "$TMP/leaf.txt" || { echo "ERROR: leaf extensions wrong" >&2; exit 1; }
[ "$(openssl x509 -in "$TMP/server.crt" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$TMP/server.pem" -pubout | openssl sha256)" ] \
  || { echo "ERROR: leaf key does not match leaf certificate" >&2; exit 1; }
# Leaf must not outlive the CA.
openssl x509 -in "$CA_CRT" -noout -checkend $((86400 * LEAF_DAYS)) >/dev/null \
  || { echo "ERROR: CA expires before the leaf would; use fewer --leaf-days or a new CA" >&2; exit 1; }

mkdir -p "$OUT"
cp "$TMP/server.crt" "$OUT/server.crt"
cp "$TMP/server.pem" "$OUT/server.pem"; chmod 600 "$OUT/server.pem"
printf '%s\n' "$HOST" > "$OUT/commonName.txt"
cp "$CA_CRT" "$OUT/KsignLocalCA.crt"
openssl x509 -in "$CA_CRT" -outform DER -out "$OUT/KsignLocalCA.cer"
chmod 644 "$OUT/server.crt" "$OUT/commonName.txt" "$OUT/KsignLocalCA.crt" "$OUT/KsignLocalCA.cer"

CA_B64="$(openssl base64 -A -in "$OUT/KsignLocalCA.cer")"
CA_FP="$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 | cut -d= -f2)"
CA_UUID="$(uuidgen)"; PROFILE_UUID="$(uuidgen)"
cat > "$OUT/KsignLocalCA.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>KsignLocalCA.cer</string>
			<key>PayloadContent</key>
			<data>$CA_B64</data>
			<key>PayloadDescription</key>
			<string>Trusts certificates for $HOST issued by this CA (name-constrained to that host).</string>
			<key>PayloadDisplayName</key>
			<string>Ksign Local Installer CA</string>
			<key>PayloadIdentifier</key>
			<string>com.ksign.localca.cert.$CA_UUID</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>$CA_UUID</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Lets Ksign install apps over local HTTPS ($HOST). SHA-256 of the CA: $CA_FP</string>
	<key>PayloadDisplayName</key>
	<string>Ksign Local Installer CA</string>
	<key>PayloadIdentifier</key>
	<string>com.ksign.localca.$PROFILE_UUID</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>$PROFILE_UUID</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
EOF
if command -v plutil >/dev/null 2>&1; then plutil -lint "$OUT/KsignLocalCA.mobileconfig" >/dev/null; fi
chmod 644 "$OUT/KsignLocalCA.mobileconfig"

# Safety: no CA key may ever land next to the app payload.
if ls "$OUT" | grep -qi 'ca\.key'; then echo "ERROR: CA key found in $OUT" >&2; exit 1; fi

echo "OK  CA SHA-256   : $CA_FP"
echo "OK  leaf SHA-256 : $(openssl x509 -in "$OUT/server.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "OK  leaf expires : $(openssl x509 -in "$OUT/server.crt" -noout -enddate | cut -d= -f2)"
if [ "$EPHEMERAL" = 1 ] && [ -z "${KSIGN_CA_KEY:-}" ]; then
  echo "OK  ephemeral CA key destroyed (renewal will require re-trusting a new CA)"
else
  echo "OK  CA key kept at $CA_KEY (never commit or bundle it)"
fi
echo "OK  staged in $OUT"
