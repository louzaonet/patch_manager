#!/bin/bash
# =============================================================================
# generate_certs.sh: Generate self-signed TLS certificates for Nginx
# =============================================================================
# Run this ONCE before starting Docker Compose:
#   cd docker && bash generate_certs.sh
#
# For production, replace the generated files with certificates from:
#   - Let's Encrypt (free, automated)
#   - Your internal CA
#   - A commercial CA
# =============================================================================

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)/nginx/certs"
DAYS=825  # self-signed, for testing; use ACME or your internal CA in production
HOSTNAME="${1:-patch-manager}"

mkdir -p "$CERT_DIR"

# Skip if certificates already exist
if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "Certificates already exist in $CERT_DIR"
    echo "   Delete them and re-run this script to regenerate."
    exit 0
fi

echo "Generating self-signed TLS certificate..."
echo "  Hostname: $HOSTNAME"
echo "  Valid for: $DAYS days"
echo ""

openssl req -x509 -nodes -newkey rsa:3072 \
    -days "$DAYS" \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=Local/L=Local/O=PatchManager/CN=$HOSTNAME" \
    -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo "Certificates generated:"
echo "   $CERT_DIR/server.crt"
echo "   $CERT_DIR/server.key"
echo ""
echo "For production, replace these with real certificates."
echo "For Let's Encrypt, see: https://certbot.eff.org/"
