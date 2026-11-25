import json
import tempfile
import unittest
from pathlib import Path
from kuron_redaction import RedactionError, enforce, scan_secrets, verdict


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def make_report(self, status="clean"):
        d = self.d / "report"
        d.mkdir(exist_ok=True)
        (d / "redaction.json").write_text(
            json.dumps({"status": status, "cleaned_files": []}), encoding="utf-8"
        )
        (d / "KURON-SECURITY-RESULTS.md").write_text("# report\n", encoding="utf-8")
        return d

    def test_clean_passes(self):
        d = self.make_report()
        self.assertEqual(verdict(str(d))["status"], "clean")
        enforce(str(d), ["KURON-SECURITY-RESULTS.md"])

    def test_not_cleaned_fails(self):
        with self.assertRaises(RedactionError):
            enforce(str(self.make_report("not_cleaned")), ["KURON-SECURITY-RESULTS.md"])

    def test_missing_verdict_fails(self):
        with self.assertRaises(RedactionError):
            enforce(str(self.d), ["KURON-SECURITY-RESULTS.md"])

    def test_missing_artifact_fails(self):
        d = self.make_report()
        with self.assertRaises(RedactionError):
            enforce(str(d), ["MISSING.sarif"])

    def test_patch_artifact_is_checked(self):
        d = self.make_report()
        (d / "F1.patch").write_text("password: not cleaned: literal\n", encoding="utf-8")
        with self.assertRaises(RedactionError):
            enforce(str(d), ["F1.patch"])

    def test_added_secret_patterns_detected(self):
        # Tokens are assembled at runtime: no static credential-like literal
        # ever appears in this file (GitHub Push Protection safe).
        tokens = {
            "anthropic-key": "sk" + "-ant-" + "A" * 40,
            "openai-key": "sk-" + "B" * 32,
            "google-api-key": "AIza" + "C" * 35,
            "gitlab-pat": "glpat-" + "D" * 24,
        }
        for name, token in tokens.items():
            with self.subTest(name=name):
                self.assertIn(name, scan_secrets("value=" + token))

    def test_added_secret_patterns_avoid_false_positives(self):
        samples = (
            "sk" + "-ant-" + "a" * 5,
            "sk-" + "a" * 5,
            "AIza" + "a" * 8,
            "glpat-" + "a" * 5,
            "a" * 40,
            "123e4567-e89b-12d3-a456-426614174000",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(scan_secrets(sample), [])
