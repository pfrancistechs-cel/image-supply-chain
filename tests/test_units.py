"""No external tools needed: the SBOM checker, the console and the repo files."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CHECK = os.path.join(ROOT, "scripts", "sbom_check.py")
POLICY = os.path.join(ROOT, "policy", "deny.json")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import sbom_check  # noqa: E402


def sbom(*pkgs):
    return {"packages": [{"name": "localhost:5000/shop/app", "versionInfo": ""}] +
            [{"name": n, "versionInfo": v} for n, v in pkgs]}


def run(spdx, flag="--sbom", wrap=False):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        if wrap:    # the shape `cosign verify-attestation` prints: one DSSE envelope per line
            statement = {"predicateType": "https://spdx.dev/Document", "predicate": spdx}
            fh.write(json.dumps({"payloadType": "application/vnd.in-toto+json",
                                 "payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n")
        else:
            json.dump(spdx, fh)
    try:
        flag = "--attestation" if wrap else flag
        r = subprocess.run([sys.executable, CHECK, flag, fh.name, "--policy", POLICY], capture_output=True, text=True)
        return r.returncode, r.stdout
    finally:
        os.remove(fh.name)


class SbomChecker(unittest.TestCase):
    def test_clean_sbom_passes(self):
        self.assertEqual(run(sbom(("urllib3", "2.2.3"), ("certifi", "2024.8.30")))[0], 0)

    def test_old_urllib3_is_denied_with_a_reason(self):
        code, out = run(sbom(("urllib3", "1.26.4")))
        self.assertEqual(code, 1)
        self.assertIn("urllib3 1.26.4", out)
        self.assertIn("CVE-2023-43804", out)

    def test_boundary_version_is_allowed(self):
        self.assertEqual(run(sbom(("urllib3", "1.26.18")))[0], 0)
        self.assertEqual(run(sbom(("urllib3", "1.26.17")))[0], 1)

    def test_version_compare_is_numeric_not_textual(self):
        self.assertEqual(run(sbom(("urllib3", "1.26.100")))[0], 0)      # text order would say "100" < "18"
        self.assertEqual(run(sbom(("requests", "2.9.0")))[0], 1)        # text order would say "9" > "31"

    def test_name_match_ignores_case(self):
        self.assertEqual(run(sbom(("PyYAML", "5.3.1")))[0], 1)

    def test_empty_sbom_is_refused(self):
        self.assertEqual(run(sbom())[0], 2)
        self.assertEqual(run({})[0], 2)

    def test_unreadable_sbom_is_refused(self):
        r = subprocess.run([sys.executable, CHECK, "--sbom", "/nonexistent", "--policy", POLICY], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_attestation_envelope_is_unwrapped(self):
        self.assertEqual(run(sbom(("urllib3", "2.2.3")), wrap=True)[0], 0)
        self.assertEqual(run(sbom(("urllib3", "1.26.4")), wrap=True)[0], 1)

    def test_garbage_attestation_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("not json at all\n")
        try:
            r = subprocess.run([sys.executable, CHECK, "--attestation", fh.name, "--policy", POLICY], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
        finally:
            os.remove(fh.name)

    def test_image_itself_is_not_a_package(self):
        self.assertEqual([p["name"] for p in sbom_check.packages_of(sbom(("a", "1")))], ["a"])


class Files(unittest.TestCase):
    def test_policy_rules_are_complete(self):
        with open(POLICY) as fh:
            policy = json.load(fh)
        for rule in policy["deny"]:
            self.assertTrue({"name", "below", "why"} <= set(rule))

    def test_app_has_a_good_and_a_bad_requirement_file(self):
        with open(os.path.join(ROOT, "app", "requirements.txt")) as fh:
            self.assertEqual(run(sbom(tuple(fh.read().strip().split("=="))))[0], 0)
        with open(os.path.join(ROOT, "app", "requirements-bad.txt")) as fh:
            self.assertEqual(run(sbom(tuple(fh.read().strip().split("=="))))[0], 1)


if __name__ == "__main__":
    unittest.main()
