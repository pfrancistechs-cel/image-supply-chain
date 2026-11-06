#!/usr/bin/env python3
"""A stand-in for `docker`, for tests only. The registry, cosign and syft in the tests are the REAL programs; only docker
itself is replaced:

  build   -> makes an image layer (the app, a version marker, and one python dist-info per pinned requirement)
  push    -> pushes it to the real registry with `crane append`
  run     -> starts the app locally (python app/app.py) with the version of the image the digest points to
  rm -f   -> stops it
  compose -> pretends the two containers are running

What this cannot show: that the real Dockerfile builds (pip install, base image) and that the real daemon can push to localhost:5000."""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

STUB = os.environ.get("STUB_DIR", "")
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def path(*parts):
    p = os.path.join(STUB, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def safe(ref):
    return re.sub(r"[^A-Za-z0-9._-]", "_", ref)


def cmd_build(args):
    ref, build_args, dockerfile, context = None, {}, None, None
    it = iter(args)
    for a in it:
        if a == "-t":
            ref = next(it)
        elif a == "--build-arg":
            k, _, v = next(it).partition("=")
            build_args[k] = v
        elif a == "-f":
            dockerfile = next(it)
        elif a.startswith("-"):
            continue
        else:
            context = a
    reqs = build_args.get("REQS", "requirements.txt")
    version = build_args.get("APP_VERSION", "dev")
    work = tempfile.mkdtemp()
    site = os.path.join(work, "usr/local/lib/python3.12/site-packages")
    os.makedirs(os.path.join(work, "app"))
    shutil.copy(os.path.join(context, "app.py"), os.path.join(work, "app", "app.py"))
    with open(os.path.join(work, "app", "BUILD_VERSION"), "w") as fh:
        fh.write(version)
    with open(os.path.join(context, reqs)) as fh:
        for line in fh:
            if "==" in line:
                name, ver = line.strip().split("==")
                d = os.path.join(site, f"{name}-{ver}.dist-info")
                os.makedirs(d)
                with open(os.path.join(d, "METADATA"), "w") as m:
                    m.write(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n")
    layer = path("images", safe(ref) + ".tar")
    with tarfile.open(layer, "w") as tar:
        for root, dirs, files in sorted(os.walk(work)):
            dirs.sort()
            for f in sorted(files):
                full = os.path.join(root, f)
                info = tar.gettarinfo(full, os.path.relpath(full, work))
                info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                with open(full, "rb") as fh:
                    tar.addfile(info, fh)
    shutil.rmtree(work)
    with open(path("images", safe(ref) + ".json"), "w") as fh:
        json.dump({"version": version, "reqs": reqs}, fh)
    print("sha256:" + "0" * 64)
    return 0


def cmd_push(args):
    ref = [a for a in args if not a.startswith("-")][0]
    layer = path("images", safe(ref) + ".tar")
    if not os.path.exists(layer):
        sys.stderr.write(f"An image with the name {ref} does not exist locally\n")
        return 1
    r = subprocess.run(["crane", "append", "-f", layer, "-t", ref], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        return 1
    digest = subprocess.run(["crane", "digest", ref], capture_output=True, text=True).stdout.strip()
    with open(path("images", safe(ref) + ".json")) as fh:
        meta = json.load(fh)
    with open(path("digests", digest.replace(":", "_") + ".json"), "w") as fh:
        json.dump(meta, fh)
    print(digest)
    return 0


def cmd_run(args):
    name, host_port, env = None, None, {}
    it = iter(args)
    rest = []
    for a in it:
        if a == "--name":
            name = next(it)
        elif a == "-p":
            host_port = next(it).split(":")[0]
        elif a == "-e":
            k, _, v = next(it).partition("=")
            env[k] = v
        elif a == "--restart":
            next(it)
        elif a.startswith("-"):
            continue
        else:
            rest.append(a)
    ref = rest[0]
    digest = ref.split("@")[1] if "@" in ref else subprocess.run(["crane", "digest", ref], capture_output=True, text=True).stdout.strip()
    try:
        with open(path("digests", digest.replace(":", "_") + ".json")) as fh:
            meta = json.load(fh)
    except OSError:
        sys.stderr.write(f"Unable to find image '{ref}'\n")
        return 125
    app_env = dict(os.environ, PORT=host_port, APP_VERSION=meta["version"], **env)
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "app", "app.py")], env=app_env, start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(path("run", name + ".pid"), "w") as fh:
        fh.write(str(proc.pid))
    print("c" * 64)
    return 0


def cmd_rm(args):
    for name in [a for a in args if not a.startswith("-")]:
        p = path("run", name + ".pid")
        try:
            with open(p) as fh:
                os.killpg(int(fh.read()), signal.SIGKILL)
            time.sleep(0.2)
        except (OSError, ValueError):
            pass
        try:
            os.remove(p)
        except OSError:
            pass
    return 0


def main(argv):
    cmd, rest = (argv[0] if argv else ""), argv[1:]
    if cmd == "compose":
        if "ps" in rest and "-q" in rest:
            print("c1\nc2")
        return 0
    return {"build": cmd_build, "push": cmd_push, "run": cmd_run, "rm": cmd_rm}.get(cmd, lambda a: 0)(rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
