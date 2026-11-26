import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kuron_redaction import (
    MAX_READ_BYTES,
    RedactionError,
    enforce,
    redact_report,
    redact_text,
    scan_secrets,
    verdict,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "kuron_redaction.py"


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(ROOT), capture_output=True, text=True, timeout=30,
        )

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

    def test_redact_text_replaces_secret_and_reports_name_only(self):
        token = "sk" + "-ant-" + "A" * 40
        original = "key=" + token + " tail"
        scrubbed, names = redact_text(original)
        self.assertEqual(scrubbed, "key=[REDACTED] tail")
        self.assertEqual(names, ["anthropic-key"])
        self.assertNotIn(token, scrubbed)
        self.assertNotIn(token, "".join(names))
        self.assertEqual(original, "key=" + token + " tail")  # input is not mutated

    def test_redact_text_is_deterministic_and_deduplicates_names(self):
        first_token = "AKIA" + "A" * 16
        second_token = "AKIA" + "B" * 16
        text = "a=" + first_token + " b=" + second_token
        first = redact_text(text)
        self.assertEqual(first, redact_text(text))
        self.assertEqual(first, ("a=[REDACTED] b=[REDACTED]", ["aws-access-key"]))
        self.assertNotIn(first_token, first[0])
        self.assertNotIn(second_token, first[0])

    def test_redact_text_preserves_clean_text(self):
        self.assertEqual(redact_text("nothing here"), ("nothing here", []))

    def test_redact_report_scrubs_artifact_and_writes_metadata_only(self):
        token = "ghp_" + "c" * 36
        report = self.d / "report"
        report.mkdir()
        artifact = report / "KURON-SECURITY-RESULTS.md"
        artifact.write_text("# report\nvalue: " + token + "\n", encoding="utf-8")
        payload = redact_report(str(report), [artifact.name])
        self.assertEqual(payload["status"], "clean")
        self.assertEqual(payload["cleaned_files"], [artifact.name])
        self.assertEqual(payload["matches"], [{"file": artifact.name, "patterns": ["github-token"]}])
        scrubbed = artifact.read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", scrubbed)
        self.assertNotIn(token, scrubbed)
        raw_verdict = (report / "redaction.json").read_text(encoding="utf-8")
        self.assertNotIn(token, raw_verdict)
        self.assertEqual(json.loads(raw_verdict)["status"], "clean")
        enforce(str(report), [artifact.name])

    def test_redact_report_is_byte_deterministic(self):
        token = "glpat-" + "e" * 24
        digests = []
        for name in ("one", "two"):
            report = self.d / name
            report.mkdir()
            (report / "findings.json").write_text(
                json.dumps({"snippet": "value=" + token}), encoding="utf-8"
            )
            redact_report(str(report))
            digests.append(
                (
                    (report / "redaction.json").read_bytes(),
                    (report / "findings.json").read_bytes(),
                )
            )
        self.assertEqual(digests[0], digests[1])
        self.assertNotIn(token.encode(), digests[0][0])
        self.assertNotIn(token.encode(), digests[0][1])

    def test_redact_report_fails_closed_on_bounded_read(self):
        token = "AKIA" + "E" * 16
        report = self.d / "report"
        report.mkdir()
        artifact = report / "KURON-SECURITY-RESULTS.md"
        artifact.write_text(token + "\n" + "x" * (MAX_READ_BYTES + 10), encoding="utf-8")
        payload = redact_report(str(report), [artifact.name])
        self.assertEqual(payload["status"], "not_cleaned")
        self.assertEqual(payload["truncated_files"], [artifact.name])
        self.assertNotIn("[REDACTED]", artifact.read_text(encoding="utf-8"))
        with self.assertRaises(RedactionError):
            enforce(str(report), [artifact.name])

    def test_cli_scrub_emits_no_raw_secret(self):
        token = "xoxb-" + "1234567890123"
        report = self.d / "report"
        report.mkdir()
        (report / "KURON-SECURITY-RESULTS.md").write_text(
            "token: " + token + "\n", encoding="utf-8"
        )
        proc = self.run_cli("scrub", str(report))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(token, proc.stdout)
        self.assertNotIn(token, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "clean")
        self.assertEqual(payload["matches"][0]["patterns"], ["slack-token"])
        self.assertNotIn(token, (report / "redaction.json").read_text(encoding="utf-8"))
        self.assertNotIn(token, (report / "KURON-SECURITY-RESULTS.md").read_text(encoding="utf-8"))

    def test_cli_scan_emits_only_file_line_and_pattern_names(self):
        token = "AIza" + "F" * 35
        target = self.d / "sample.py"
        target.write_text("ok = 1\nkey = \"" + token + "\"\n", encoding="utf-8")
        proc = self.run_cli("scan", str(target))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(token, proc.stdout)
        self.assertNotIn(token, proc.stderr)
        self.assertEqual(
            json.loads(proc.stdout),
            [{"file": "sample.py", "line": 2, "patterns": ["google-api-key"]}],
        )
        proc_dir = self.run_cli("scan", str(self.d))
        self.assertEqual(proc_dir.returncode, 0, proc_dir.stderr)
        self.assertNotIn(token, proc_dir.stdout)
        self.assertTrue(
            any(
                record["line"] == 2 and "google-api-key" in record["patterns"]
                for record in json.loads(proc_dir.stdout)
            )
        )
