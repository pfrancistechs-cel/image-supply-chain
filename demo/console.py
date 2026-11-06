"""Supply-chain console: what is in the registry, who signed it, what the gate decided, what is running. Standard library only."""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REGISTRY = os.environ.get("REGISTRY_URL", "http://registry:5000")
REPO = os.environ.get("REPO", "shop/app")
RESULTS = os.environ.get("RESULTS_DIR", "/results")
ACCEPT = ("application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,"
          "application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json")
NOPROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(path, method="GET"):
    req = urllib.request.Request(REGISTRY + path, method=method, headers={"Accept": ACCEPT})
    return NOPROXY.open(req, timeout=4)


def read_json(name, default):
    try:
        with open(os.path.join(RESULTS, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def registry_images():
    try:
        fetch("/v2/")
    except Exception:
        return None                     # the registry itself is down
    try:
        tags = json.load(fetch(f"/v2/{REPO}/tags/list")).get("tags") or []
    except Exception:
        tags = []                       # up, but nothing pushed yet (the repository does not exist: 404)
    plain = [t for t in tags if not t.endswith((".sig", ".att"))]
    rows = []
    for tag in sorted(plain):
        try:
            digest = fetch(f"/v2/{REPO}/manifests/{tag}", "HEAD").headers.get("Docker-Content-Digest", "")
        except Exception:
            digest = ""
        key = "sha256-" + digest.replace("sha256:", "")
        rows.append({"tag": tag, "digest": digest, "signed": key + ".sig" in tags, "sbom": key + ".att" in tags})
    return rows


def state():
    images = registry_images()
    return {"registry_up": images is not None, "images": images or [], "decisions": list(reversed(read_json("decisions.json", []))),
            "sbom": read_json("last-sbom.json", {"packages": [], "violations": []}), "app": read_json("app.json", None)}


PAGE = """<!doctype html><meta charset=utf-8><title>Supply chain console</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}
header{background:#18222d;color:#fff;padding:14px 22px}header h1{margin:0;font-size:18px}
main{display:grid;gap:16px;padding:16px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}
section{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px #0002}
h2{margin:0 0 8px;font-size:15px}table{border-collapse:collapse;width:100%;font-size:13px}
td,th{padding:5px 6px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}
.yes{color:#0a7a3c;font-weight:600}.no{color:#b42318;font-weight:600}code{font-size:12px}
.allow{background:#d1fadf;color:#05603a;padding:1px 6px;border-radius:4px}.deny{background:#fee4e2;color:#b42318;padding:1px 6px;border-radius:4px}
tr.bad td{background:#fff1f0}.muted{color:#667085}
</style>
<header><h1>Image supply chain: registry, signatures, SBOM, gate</h1></header>
<main>
<section><h2>Registry <span id=reg class=muted></span></h2><table id=images></table></section>
<section><h2>Running application</h2><div id=app class=muted>nothing deployed yet</div></section>
<section><h2>Gate decisions (newest first)</h2><table id=decisions></table></section>
<section><h2>SBOM of the last image the gate checked</h2><table id=sbom></table></section>
</main>
<script>
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const yn=v=>v?'<span class=yes>yes</span>':'<span class=no>no</span>';
const sh=d=>d?d.replace('sha256:','').slice(0,12):'-';
async function tick(){try{const s=await (await fetch('/api/state')).json();
document.getElementById('reg').textContent=s.registry_up?'(up)':'(DOWN)';
document.getElementById('images').innerHTML='<tr><th>tag</th><th>digest</th><th>signed</th><th>SBOM attested</th></tr>'+
 s.images.map(i=>`<tr><td>${esc(i.tag)}</td><td><code>${sh(i.digest)}</code></td><td>${yn(i.signed)}</td><td>${yn(i.sbom)}</td></tr>`).join('');
document.getElementById('app').innerHTML=s.app?`<b>${esc(s.app.tag)}</b> started ${esc(s.app.time)}<br><code>${esc(s.app.ref)}</code><br>Run by digest: it cannot change underneath.`:'nothing deployed yet';
document.getElementById('decisions').innerHTML='<tr><th>time</th><th>image</th><th>verdict</th><th>why</th></tr>'+
 s.decisions.map(d=>`<tr><td>${esc(d.time)}</td><td>${esc(d.tag)}<br><code>${sh(d.digest)}</code></td><td><span class=${d.verdict=='ALLOW'?'allow':'deny'}>${d.verdict}</span></td><td>${d.reasons.map(esc).join('<br>')}</td></tr>`).join('');
const bad=new Set(s.sbom.violations.map(v=>v.name+'@'+v.version));
document.getElementById('sbom').innerHTML='<tr><th>package</th><th>version</th></tr>'+
 s.sbom.packages.map(p=>`<tr class="${bad.has(p.name+'@'+p.version)?'bad':''}"><td>${esc(p.name)}</td><td>${esc(p.version)}</td></tr>`).join('');
}catch(e){document.getElementById('reg').textContent='(console cannot reach its API)'}}
tick();setInterval(tick,2500);
</script>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, b"ok\n", "text/plain")
        if self.path == "/api/state":
            return self.send(200, state())
        if self.path == "/":
            return self.send(200, PAGE.encode(), "text/html; charset=utf-8")
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8081"))), Handler).serve_forever()
