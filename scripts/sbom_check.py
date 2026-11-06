#!/usr/bin/env python3
"""Reads an SBOM and the deny policy. The SBOM comes from a cosign attestation (--attestation FILE: the output of
`cosign verify-attestation`) or a plain SPDX json file (--sbom FILE).

Prints one line per package problem. Writes --out (json: packages and violations) for the console.
Exit codes: 0 ok, 1 policy violation, 2 the SBOM is missing, unreadable or empty."""
import argparse
import base64
import json
import re
import sys


def load_attestation(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            envelope = json.loads(line)
            statement = json.loads(base64.b64decode(envelope["payload"]))
            predicate = statement.get("predicate")
            if isinstance(predicate, dict) and "Data" in predicate and isinstance(predicate["Data"], str):
                predicate = json.loads(predicate["Data"])        # older cosign wraps the document in {"Data": "..."}
            return predicate
    return None


def version_key(text):
    return tuple(int(n) for n in re.findall(r"\d+", text.split("+")[0].split("-")[0])[:4])


def packages_of(spdx):
    found = []
    for pkg in (spdx or {}).get("packages", []):
        name, version = pkg.get("name", ""), pkg.get("versionInfo", "")
        if not version or "/" in name or ":" in name:             # the image itself is listed as a package: skip it
            continue
        found.append({"name": name, "version": version})
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attestation")
    ap.add_argument("--sbom")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    try:
        if args.attestation:
            spdx = load_attestation(args.attestation)
        else:
            with open(args.sbom, encoding="utf-8") as fh:
                spdx = json.load(fh)
        with open(args.policy, encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError, KeyError) as exc:
        print(f"cannot read the SBOM or policy: {exc}")
        return 2
    packages = packages_of(spdx)
    if len(packages) < policy.get("min_packages", 1):
        print(f"the SBOM lists {len(packages)} packages: too few to trust")
        return 2
    violations = []
    for pkg in packages:
        for rule in policy.get("deny", []):
            if pkg["name"].lower() == rule["name"].lower() and version_key(pkg["version"]) < version_key(rule["below"]):
                violations.append({"name": pkg["name"], "version": pkg["version"], "rule": f"{rule['name']} < {rule['below']}",
                                   "why": rule["why"]})
                print(f"{pkg['name']} {pkg['version']} is denied ({rule['why']})")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"packages": packages, "violations": violations}, fh)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
