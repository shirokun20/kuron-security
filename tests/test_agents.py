import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AgentsTest(unittest.TestCase):
    def test_all_briefs_present(self):
        for n in (
            "researcher",
            "verifier-reachability",
            "verifier-impact",
            "verifier-defenses",
            "redactor",
            "patch-generator",
            "patch-verifier",
        ):
            p = ROOT / "agents" / f"{n}.md"
            self.assertTrue(p.exists(), n)
            self.assertLessEqual(len(p.read_text(encoding="utf-8").splitlines()), 60, n)

    def test_readonly_briefs_say_read_only(self):
        for n in (
            "researcher",
            "verifier-reachability",
            "verifier-impact",
            "verifier-defenses",
            "patch-verifier",
        ):
            text = (ROOT / "agents" / f"{n}.md").read_text(encoding="utf-8").lower()
            self.assertIn("read-only", text, n)
            self.assertIn("<untrusted_repository_data>", text, n)
        res_text = (ROOT / "agents" / "researcher.md").read_text(encoding="utf-8").lower()
        self.assertIn("never build", res_text)

    def test_redactor_schema_and_patch_generator_scratch(self):
        red = (ROOT / "agents" / "redactor.md").read_text(encoding="utf-8")
        self.assertIn("redaction.json", red)
        self.assertIn("not_cleaned", red)
        pg = (ROOT / "agents" / "patch-generator.md").read_text(encoding="utf-8").lower()
        self.assertIn("scratch", pg)
