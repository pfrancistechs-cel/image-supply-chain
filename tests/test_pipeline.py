"""The real scripts with the REAL registry, cosign and syft; docker is the stub in tests/stubdocker.py.
Skipped unless cosign, syft, registry and crane are in PATH."""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import stack  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;]*m")


@unittest.skipUnless(stack.AVAILABLE, stack.SKIP_REASON)
class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = stack.Stack().start()
        for name in ("release", "attacker"):
            cls.s.script("supply.sh", "keygen", name)

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    def scenario(self, name):
        code, out = self.s.script("demo.sh", name)
        out = ANSI.sub("", out)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS  " + name, out)
        return out

    def state(self):
        return json.loads(self.s.get(self.s.console_url + "/api/state"))

    def test_1_smoke(self):
        code, out = self.s.script("smoke.sh")
        self.assertEqual(code, 0, out)
        self.assertIn("All 13 checks passed.", out)

    def test_2_release(self):
        self.scenario("release")
        images = {i["tag"]: i for i in self.state()["images"]}
        self.assertTrue(images["1.0.0"]["signed"] and images["1.0.0"]["sbom"])
        self.assertIn("/info", "/info")
        info = json.loads(self.s.get(self.s.env["APP_URL"] + "/info"))
        self.assertEqual(info["version"], "1.0.0")

    def test_3_unsigned(self):
        self.scenario("unsigned")
        images = {i["tag"]: i for i in self.state()["images"]}
        self.assertFalse(images["1.1.0-unsigned"]["signed"])

    def test_4_tamper(self):
        self.scenario("tamper")

    def test_5_badsbom(self):
        self.scenario("badsbom")
        denied = [d for d in self.state()["decisions"] if d["verdict"] == "DENY" and d["tag"] == "3.0.0"]
        self.assertTrue(denied)
        self.assertIn("urllib3 1.26.4", " ".join(denied[0]["reasons"]))

    def test_6_wrongkey(self):
        self.scenario("wrongkey")

    def test_7_list_and_verify_commands(self):
        code, out = self.s.script("supply.sh", "list")
        self.assertEqual(code, 0, out)
        self.assertIn("1.0.0", out)
        code, out = self.s.script("supply.sh", "verify", "1.0.0")
        self.assertEqual(code, 0, out)
        self.assertNotIn("FAIL", ANSI.sub("", out))
        code, out = self.s.script("supply.sh", "verify", "1.1.0-unsigned")
        self.assertIn("FAIL", ANSI.sub("", out))

    def test_8_gate_on_missing_tag(self):
        code, out = self.s.script("supply.sh", "gate", "does-not-exist")
        self.assertEqual(code, 1, out)


if __name__ == "__main__":
    unittest.main()
