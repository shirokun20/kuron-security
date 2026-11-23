import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from kuron_evidence import REQUIRED_TAINT_ROLES
from kuron_products import main, normalize


class ProductsTest(unittest.TestCase):
    def test_normalize_drops_invalid_evidence(self):
        raw = {"id": "F1", "file": "a.py", "line": 1, "snippet": "x", "taint_path": []}
        out = normalize(raw, 0)
        self.assertTrue(out is None or out.get("discard_reason"))

    def test_normalize_keeps_valid_evidence(self):
        raw = {
            "id": "F1",
            "file": "a.py",
            "line": 1,
            "cweId": "CWE-79",
            "taint_path": [
                {"role": r, "file": "a.py", "line": 1, "snippet": "x"}
                for r in REQUIRED_TAINT_ROLES
            ],
            "reachability": {"entrypoint": "a.py:1", "hops": [], "active_in_default_config": True},
            "independent_routes": ["static", "runtime"],
            "poc_trace": [
                {"file": "a.py", "line": 1, "action": "input"},
                {"file": "a.py", "line": 2, "action": "guard"},
                {"file": "a.py", "line": 3, "action": "sink"},
            ],
            "preconditions": [],
            "why_guard_fails": "value not covered",
            "cwe_class": "Base",
            "cwe_id": "CWE-79",
        }
        out = normalize(raw, 0)
        self.assertIsNotNone(out)
        self.assertFalse(out.get("discard_reason"))
        self.assertIn("evidence", out)
        self.assertIn("label", out)
        self.assertIn("discarded", out)

    def test_results_carry_label_and_discarded(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d)
            (report / "redaction.json").write_text(
                json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
            )
            (report / "findings.json").write_text(
                json.dumps([{"id": "BAD1", "file": "a.py", "line": 1, "taint_path": []}]),
                encoding="utf-8",
            )
            (report / "scan-meta.json").write_text(
                json.dumps({"mode": "scan", "label": "ad-hoc-panel"}), encoding="utf-8"
            )
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                rc = main(str(report), os.getcwd())
            self.assertEqual(rc, 0)
            stdout = stdout_buf.getvalue()
            stderr = stderr_buf.getvalue()
            self.assertNotIn("╭", stderr)
            self.assertTrue(stderr.isascii(), stderr)
            self.assertIn("SCAN SCORECARD", stderr)
            self.assertIn('"exit_code": 0', stdout)
            names = set(os.listdir(report))
            self.assertIn("KURON-SECURITY-RESULTS.md", names)
            self.assertIn("KURON-SECURITY-RESULTS.jsonl", names)
            self.assertIn("KURON-SECURITY-RESULTS.sarif", names)
            rev_files = [n for n in names if n.startswith("KURON-SECURITY-REVISION-")]
            self.assertTrue(rev_files)
            stamp = json.loads((report / rev_files[0]).read_text(encoding="utf-8"))
            self.assertEqual(stamp["label"], "ad-hoc-panel")
            self.assertEqual(stamp["verification"]["status"], "ad-hoc-panel")
            self.assertEqual(len(stamp["discarded"]), 1)
            self.assertIn("BAD1", stamp["discarded"][0]["id"])
