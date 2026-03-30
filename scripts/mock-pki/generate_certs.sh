#!/bin/bash
# Generate mock PKI certificates for workforce simulation testing.
# Usage: ./generate_certs.sh [output_dir]

OUT_DIR="${1:-./certs}"
mkdir -p "$OUT_DIR"

echo "=== Generating Mock PKI ==="

# Root CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/ca-key.pem" \
  -out "$OUT_DIR/ca-cert.pem" \
  -days 365 \
  -subj "/CN=Mock GozerAI Root CA/O=GozerAI/C=US" 2>/dev/null
echo "[OK] Root CA"

# Device certificate
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/device-key.pem" \
  -out "$OUT_DIR/device-csr.pem" \
  -subj "/CN=device-001/O=GozerAI/C=US" 2>/dev/null

openssl x509 -req \
  -in "$OUT_DIR/device-csr.pem" \
  -CA "$OUT_DIR/ca-cert.pem" \
  -CAkey "$OUT_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$OUT_DIR/device-cert.pem" \
  -days 90 2>/dev/null
echo "[OK] Device certificate (CN=device-001)"

# Empty CRL
openssl ca -gencrl \
  -keyfile "$OUT_DIR/ca-key.pem" \
  -cert "$OUT_DIR/ca-cert.pem" \
  -out "$OUT_DIR/crl.pem" \
  -config /dev/null 2>/dev/null || {
  # Fallback: create empty CRL manually
  echo "    (CRL generation skipped — create manually or use openssl ca)"
}

echo ""
echo "Certificates in: $OUT_DIR"
echo "  ca-cert.pem    — Root CA certificate"
echo "  ca-key.pem     — Root CA private key"
echo "  device-cert.pem — Device certificate"
echo "  device-key.pem  — Device private key"
