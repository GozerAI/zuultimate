#!/usr/bin/env python3
"""Mock PKI server — serves CRL and handles revocation requests."""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

CRL_PATH = "/pki/certs/crl.pem"
REVOKED_SERIALS: set[str] = set()


class PKIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/crl":
            self._serve_crl()
        elif self.path == "/health":
            self._json_response(200, {"status": "ok", "revoked_count": len(REVOKED_SERIALS)})
        elif self.path == "/revoked":
            self._json_response(200, {"revoked": list(REVOKED_SERIALS)})
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/revoke":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            serial = body.get("serial", "")
            if serial:
                REVOKED_SERIALS.add(serial)
                self._json_response(200, {"revoked": serial})
            else:
                self._json_response(400, {"error": "serial required"})
        else:
            self._json_response(404, {"error": "not found"})

    def _serve_crl(self):
        if os.path.exists(CRL_PATH):
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.end_headers()
            with open(CRL_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self._json_response(200, {"crl": "empty", "note": "No CRL file generated"})

    def _json_response(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    port = int(os.environ.get("PKI_PORT", "9999"))
    server = HTTPServer(("0.0.0.0", port), PKIHandler)
    print(f"Mock PKI server on port {port}")
    server.serve_forever()
