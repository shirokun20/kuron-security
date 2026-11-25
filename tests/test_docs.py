import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DocsTest(unittest.TestCase):
    def test_versions_consistent(self):
        self.assertIn("version: 2.3.0", (ROOT / "SKILL.md").read_text(encoding="utf-8"))
        self.assertEqual(
            json.loads((ROOT / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))["version"],
            "2.3.0",
        )
        m = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(m["plugins"][0]["version"], "2.3.0")
        sarif = (ROOT / "scripts" / "kuron_sarif.py").read_text(encoding="utf-8")
        self.assertIn('SARIF_SEMANTIC_VERSION = "2.3.0"', sarif)

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
            "kuron_progress.py",
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
        self.assertIn("Live Scan Progress", readme)
        self.assertIn("progress.jsonl", readme)
        self.assertIn("flowchart TD", readme)
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("validate_projection", skill)
        self.assertIn("alternate-screen", skill)

    def test_readme_documents_public_historical_cve_proof(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for s in (
            "CVE-2023-32681",
            "psf/requests",
            "302225334678490ec66b3614a9dddb8a02c5f4fe",
            "74ea7cf7",
            "source -> guard -> sink",
            "requests/sessions.py:328",
            "## Trust Story",
            "## Limitations",
            "## Running Tests",
            "PYTHONPATH=scripts python3 -m unittest discover -s tests -p 'test_*.py' -v",
            "pytest -v",
        ):
            self.assertIn(s, readme)
        # 3/3 unanimous quorum everywhere; no 2/3 gate survives in the diagram.
        self.assertIn("3/3 unanimous TRUE_POSITIVE?", readme)
        self.assertIn("3/3 unanimous `TRUE_POSITIVE`", readme)
        self.assertNotIn(">= 2 TRUE_POSITIVE", readme)
        self.assertNotIn("no reserved-ID guard at :56", readme)
        for name in ("demo.gif", "demo-poster.png", "social-preview.png"):
            self.assertIn(f"docs/assets/{name}", readme)
            asset = ROOT / "docs" / "assets" / name
            self.assertTrue(asset.is_file(), f"missing asset {asset}")
            self.assertGreater(asset.stat().st_size, 0)

    def test_examples_are_public_and_leak_free(self):
        for name in (
            "KURON-SECURITY-RESULTS.md",
            "KURON-SECURITY-RESULTS.sarif",
            "F1.patch",
            "PATCHES.md",
        ):
            path = ROOT / "examples" / name
            self.assertTrue(path.is_file(), f"missing example {path}")
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("[REDACTED]", text)
            self.assertNotIn("learn_flutter", text)
        report = (ROOT / "examples" / "KURON-SECURITY-RESULTS.md").read_text(encoding="utf-8")
        self.assertIn("`3/3 TRUE_POSITIVE`", report)
        self.assertIn("CVE-2023-32681", report)
        self.assertIn("requests/sessions.py:328", report)

    def test_docs_match_hardened_behavior(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("python3 -c", skill)
        for phrase in (
            "Panel quorum",
            "Unanimous `TRUE_POSITIVE`",
            "Per-host enforcement matrix",
            "usage/policy error",
            "Exit codes",
            "stderr",
            "unverified-single-pass",
        ):
            self.assertIn(phrase, skill)
        self.assertIn("user-writable plugin cache", skill.lower())

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Relationship to `claude-security`", readme)
        self.assertIn("clean-room reimplementation", readme)
        self.assertIn("No** `sys.path` mutation", readme)

        products = (ROOT / "scripts" / "kuron_products.py").read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert", products)
        self.assertIn('"builder": "vendored"', products)
        self.assertIn("os.replace", products)
        self.assertIn("scan_secrets", products)
