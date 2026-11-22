import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DocsTest(unittest.TestCase):
    def test_versions_consistent(self):
        self.assertIn("version: 2.0.0", (ROOT / "SKILL.md").read_text(encoding="utf-8"))
        self.assertEqual(
            json.loads((ROOT / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))["version"],
            "2.0.0",
        )
        m = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(m["plugins"][0]["version"], "2.0.0")

    def test_skill_declares_labels_and_tiers(self):
        t = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for s in (
            "kuron-panel",
            "ad-hoc-panel",
            "unverified-single-pass",
            "personal",
            "bisnis",
            "enterprise",
        ):
            self.assertIn(s, t)
        for script in (
            "kuron_capabilities.py",
            "kuron_policy.py",
            "kuron_evidence.py",
            "kuron_products.py",
        ):
            self.assertIn(script, t)
        self.assertNotIn("adapter Claude Security", t)

    def test_jobs_and_readme_updated(self):
        for j in ("scan-codebase.md", "scan-changes.md", "suggest-patches.md"):
            jt = (ROOT / "jobs" / j).read_text(encoding="utf-8")
            self.assertIn("kuron_capabilities.py", jt, j)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for s in ("personal", "bisnis", "enterprise", "ad-hoc-panel", "unverified-single-pass"):
            self.assertIn(s, readme)
