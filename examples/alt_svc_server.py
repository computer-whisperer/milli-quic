#!/usr/bin/env python3
"""Minimal HTTPS server that advertises HTTP/3 via Alt-Svc header.

Usage:
    python3 alt_svc_server.py [port]

Serves HTTPS on TCP, advertising Alt-Svc: h3=":4433" so Firefox
discovers the milli-quic HTTP/3 server.
"""
import http.server
import ssl
import sys
import os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

class AltSvcHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Alt-Svc", 'h3=":4433"; ma=86400')
        self.end_headers()
        body = f"""\
<!DOCTYPE html>
<html>
<head><title>milli-quic demo</title></head>
<body>
<h1>milli-quic HTTP/3 Demo</h1>
<p>Protocol: HTTP/1.1 (TCP)</p>
<p>This page is served over TCP. The <code>Alt-Svc</code> header tells
your browser that HTTP/3 is available on UDP port 4433.</p>
<p>Reload the page — your browser should upgrade to HTTP/3 automatically.</p>
<p><small>Check DevTools → Network tab → Protocol column to verify.</small></p>
</body>
</html>"""
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        print(f"[tcp] {args[0]}")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    os.path.join(CERT_DIR, "ecdsa_server_cert.pem"),
    os.path.join(CERT_DIR, "ecdsa_server_key.pem"),
)

server = http.server.HTTPServer(("0.0.0.0", PORT), AltSvcHandler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(f"HTTPS Alt-Svc server listening on https://localhost:{PORT}")
print(f"Advertising Alt-Svc: h3=\":4433\"")
server.serve_forever()
