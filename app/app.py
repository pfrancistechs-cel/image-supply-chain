"""The application that gets built, signed and deployed. It shows what is inside the running image."""
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata

STARTED = time.time()


def info():
    try:
        urllib3 = metadata.version("urllib3")      # read from the package metadata, which is also what the SBOM lists
    except metadata.PackageNotFoundError:
        urllib3 = "not installed"
    return {"app": "shop", "version": os.environ.get("APP_VERSION", "dev"), "urllib3": urllib3,
            "image": os.environ.get("IMAGE_REF", "unknown"), "host": socket.gethostname(),
            "uptime_seconds": round(time.time() - STARTED, 1)}


PAGE = """<!doctype html><meta charset=utf-8><title>shop</title>
<body style="font-family:system-ui;max-width:640px;margin:3rem auto;padding:0 1rem">
<h1>shop v{version}</h1>
<p>This container was started by the supply-chain gate, from an image whose signature and SBOM were verified.</p>
<table cellpadding=6 border=1 style="border-collapse:collapse">
<tr><td>image</td><td><code>{image}</code></td></tr>
<tr><td>urllib3 inside</td><td>{urllib3}</td></tr>
<tr><td>host</td><td>{host}</td></tr></table></body>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, "ok\n", "text/plain")
        if self.path == "/info":
            return self.send(200, json.dumps(info()), "application/json")
        self.send(200, PAGE.format(**info()), "text/html; charset=utf-8")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
