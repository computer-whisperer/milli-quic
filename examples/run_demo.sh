#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"

# Generate certs if needed
if [ ! -f "$CERT_DIR/server_cert.der" ]; then
    echo "Generating certificates..."
    "$SCRIPT_DIR/gen_cert.sh"
fi

echo ""
echo "=== milli-quic HTTP/3 Demo ==="
echo ""
echo "Firefox setup:"
echo "  1. Import CA cert: $CERT_DIR/ca_cert.pem"
echo "     Firefox -> Settings -> Privacy & Security -> Certificates"
echo "     -> View Certificates -> Authorities -> Import -> Trust for websites"
echo "  2. Navigate to: https://localhost:8443"
echo "  3. Reload the page -- Firefox will upgrade to HTTP/3"
echo "  4. Check DevTools (F12) -> Network -> Protocol column"
echo ""

# Build the server
echo "Building milli-quic h3_server..."
cargo build --example h3_server --manifest-path "$SCRIPT_DIR/../Cargo.toml" 2>&1

# Start the QUIC server in background
echo "Starting QUIC server on UDP :4433..."
"$SCRIPT_DIR/../target/debug/examples/h3_server" \
    --cert "$CERT_DIR/server_cert.der" \
    --key "$CERT_DIR/server_key.der" &
QUIC_PID=$!

# Start the TCP HTTPS server
echo "Starting HTTPS Alt-Svc server on TCP :8443..."
python3 "$SCRIPT_DIR/alt_svc_server.py" 8443 &
TCP_PID=$!

echo ""
echo "Both servers running. Press Ctrl+C to stop."

# Cleanup on exit
trap "kill $QUIC_PID $TCP_PID 2>/dev/null; echo 'Servers stopped.'" EXIT
wait
