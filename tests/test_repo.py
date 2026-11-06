import os
import stat
import subprocess
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = ["scripts/" + f for f in os.listdir(os.path.join(ROOT, "scripts")) if f.endswith(".sh")]


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class Repo(unittest.TestCase):
    def test_scripts_parse_and_are_executable(self):
        for rel in SCRIPTS + ["scripts/sbom_check.py"]:
            path = os.path.join(ROOT, rel)
            self.assertTrue(os.stat(path).st_mode & stat.S_IXUSR, rel + " is not executable")
            if rel.endswith(".sh"):
                self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0, rel)

    def test_required_files(self):
        for rel in ("docker-compose.yml", ".env.example", ".gitignore", ".gitattributes", "demo/console.py", "demo/Dockerfile",
                    "app/Dockerfile", "app/app.py", "policy/deny.json", "README.md", "STEPS.md", "DEMO.md", "DIAGRAM_PROMPT.md"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)

    def test_registry_and_ports_are_local_except_the_web_pages(self):
        text = read("docker-compose.yml")
        self.assertIn("127.0.0.1:5000:5000", text)
        self.assertIn('"8081:8081"', text)
        self.assertNotIn("0.0.0.0:5000", text)

    def test_keys_never_leave_the_machine(self):
        ignore = read(".gitignore")
        for pattern in ("keys/*.key", ".env"):
            self.assertIn(pattern, ignore)

    def test_gate_is_the_only_place_that_runs_the_app(self):
        for rel in SCRIPTS:
            if rel.endswith("lib.sh"):
                continue
            self.assertNotIn("$DOCKER run", read(rel), rel + " must not start the app: only the gate does")

    def test_app_is_started_by_digest(self):
        self.assertIn('ref="$(ref_of "$digest")"', read("scripts/lib.sh"))

    def test_demo_doc_is_brief(self):
        text = read("DEMO.md")
        self.assertLess(len(text.split()), 450)
        self.assertLess(len(text.splitlines()), 40)

    def test_chmod_is_documented(self):
        self.assertIn("chmod +x scripts/*.sh scripts/*.py", read("STEPS.md"))


if __name__ == "__main__":
    unittest.main()
