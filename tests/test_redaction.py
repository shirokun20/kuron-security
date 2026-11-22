import json
import tempfile
import unittest
from pathlib import Path
from kuron_redaction import RedactionError, enforce, verdict


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
