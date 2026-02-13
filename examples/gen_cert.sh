#!/bin/bash
# Generate Ed25519 CA + server cert for localhost testing
set -e
DIR="$(dirname "$0")/certs"
mkdir -p "$DIR"

# Generate CA key and self-signed CA cert
openssl genpkey -algorithm ED25519 -out "$DIR/ca_key.pem"
openssl req -new -x509 -key "$DIR/ca_key.pem" -out "$DIR/ca_cert.pem" \
    -days 365 -subj "/CN=milli-quic Test CA"

# Generate server key
openssl genpkey -algorithm ED25519 -out "$DIR/server_key.pem"

# Generate server CSR and sign with CA
openssl req -new -key "$DIR/server_key.pem" -out "$DIR/server.csr" \
    -subj "/CN=localhost"
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca_cert.pem" -CAkey "$DIR/ca_key.pem" \
    -CAcreateserial -out "$DIR/server_cert.pem" -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Also create DER versions for milli-quic
openssl x509 -in "$DIR/server_cert.pem" -outform DER -out "$DIR/server_cert.der"
openssl pkcs8 -in "$DIR/server_key.pem" -topk8 -nocrypt -outform DER -out "$DIR/server_key.der"

# Clean up CSR
rm -f "$DIR/server.csr" "$DIR/ca_cert.srl"

echo "Certificates generated in $DIR/"
echo ""
echo "To trust in Firefox: Import $DIR/ca_cert.pem as a Certificate Authority"
echo "  Firefox -> Settings -> Privacy & Security -> Certificates -> View Certificates"
echo "  -> Authorities tab -> Import -> select ca_cert.pem -> Trust for websites"
