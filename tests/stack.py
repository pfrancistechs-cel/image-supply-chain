"""Test helper: the whole stack as local processes. The REAL registry, cosign and syft programs, the real console and
scripts; docker is replaced by tests/stubdocker.py. Skipped when the tools are not installed (as on the demo instance
before setup.sh, and in plain CI)."""
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS = ("cosign", "syft", "registry", "crane")
AVAILABLE = all(shutil.which(t) for t in TOOLS)
SKIP_REASON = "needs cosign, syft, registry (distribution) and crane in PATH; the demo instance only has cosign and syft"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Stack:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="sc")
        self.bin = os.path.join(self.tmp, "bin")
        self.results = os.path.join(self.tmp, "results")
        self.keys = os.path.join(self.tmp, "keys")
        for d in (self.bin, self.results, self.keys, os.path.join(self.tmp, "registry")):
            os.makedirs(d)
        self.ports = {k: free_port() for k in ("registry", "console", "app")}
        self.procs = []
        shim = os.path.join(self.bin, "docker")
        with open(shim, "w") as fh:
            fh.write(f'#!/bin/sh\nexec "{sys.executable}" "{os.path.join(ROOT, "tests", "stubdocker.py")}" "$@"\n')
        os.chmod(shim, 0o755)
        self.env = dict(os.environ, PYTHONUNBUFFERED="1", no_proxy="127.0.0.1,localhost", NO_PROXY="127.0.0.1,localhost",
                        STUB_DIR=self.tmp, PATH=self.bin + os.pathsep + os.environ["PATH"],
                        REGISTRY=f"localhost:{self.ports['registry']}", CONSOLE_URL=self.console_url,
                        APP_URL=f"http://127.0.0.1:{self.ports['app']}", APP_PORT=str(self.ports["app"]),
                        RESULTS_DIR=self.results, KEYS_DIR=self.keys)
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.env.pop(var, None)

    @property
    def console_url(self):
        return f"http://127.0.0.1:{self.ports['console']}"

    @property
    def registry_url(self):
        return f"http://127.0.0.1:{self.ports['registry']}"

    def spawn(self, cmd, env=None):
        self.procs.append(subprocess.Popen(cmd, env=env or self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True))

    def start(self, secs=30):
        cfg = os.path.join(self.tmp, "registry.yml")
        with open(cfg, "w") as fh:
            fh.write(f"version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: {self.tmp}/registry\n"
                     f"http:\n  addr: 127.0.0.1:{self.ports['registry']}\n")
        self.spawn(["registry", "serve", cfg])
        self.spawn([sys.executable, os.path.join(ROOT, "demo", "console.py")],
                   dict(self.env, PORT=str(self.ports["console"]), REGISTRY_URL=self.registry_url, REPO="shop/app",
                        RESULTS_DIR=self.results))
        end = time.time() + secs
        for url in (self.registry_url + "/v2/", self.console_url + "/healthz"):
            while True:
                try:
                    OPENER.open(url, timeout=2).read()
                    break
                except Exception:
                    if time.time() > end:
                        raise RuntimeError("not ready: " + url)
                    time.sleep(0.2)
        return self

    def script(self, *args, timeout=600):
        r = subprocess.run(["bash", os.path.join(ROOT, "scripts", args[0]), *args[1:]], env=self.env,
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr

    def get(self, url):
        return OPENER.open(url, timeout=5).read().decode()

    def stop(self):
        subprocess.run(["docker", "rm", "-f", "sc-app"], env=self.env, capture_output=True)
        for proc in self.procs:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.3)
        shutil.rmtree(self.tmp, ignore_errors=True)
