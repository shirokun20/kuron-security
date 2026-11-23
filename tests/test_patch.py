import json
import tempfile
import unittest
from pathlib import Path
from kuron_evidence import REQUIRED_TAINT_ROLES
from kuron_patch import check_claims, cmd_render
from kuron_redaction import RedactionError


class PatchTest(unittest.TestCase):
    def test_check_claims_rejects_missing_evidence(self):
        self.assertIsNotNone(check_claims({"id": "F1", "taint_path": []}))

    def test_check_claims_accepts_complete_evidence(self):
        f = {
            "id": "F1",
            "taint_path": [
                {"role": r, "file": "a.py", "line": 1, "snippet": "x"}
                for r in REQUIRED_TAINT_ROLES
            ],
            "independent_routes": ["static", "runtime"],
            "reachability": {"active_in_default_config": True},
            "poc_trace": [
                {"file": "a.py", "line": 1, "action": "input"},
                {"file": "a.py", "line": 2, "action": "guard"},
                {"file": "a.py", "line": 3, "action": "sink"},
            ],
            "preconditions": [],
            "why_guard_fails": "value not covered",
            "cwe_class": "Base",
            "cwe_id": "CWE-79",
            "untested": False,
            "attack_paths": [{"kind": "set_aside", "text": "guarded"}],
        }
        f["claims"] = {
            name: {
                "state": "CONFIDENT",
                "evidence": "a.py:1",
                "tool_check": {"command": "grep -n SINK a.py", "exit_code": 0},
            }
            for name in ("targeted", "no_new_vulnerability", "behaviour_unchanged")
        }
        self.assertIsNone(check_claims(f))

    def test_cmd_render_enforces_redaction_and_untested_label(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            report_dir = root / "KURON-SECURITY-20261122-000000"
            patch_dir = report_dir / ".kuron-security-run" / "patch-1"
            patches_dir = report_dir / "patches"
            patch_dir.mkdir(parents=True)
            patches_dir.mkdir(parents=True)

            (patch_dir / "F1.diff").write_text(
                "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x\n+y\n",
                encoding="utf-8",
            )
            unit = {
                "id": "F1",
                "status": "patch_written",
                "attempts": 1,
                "title": "Fix SQLi",
                "summary": "Use parameterized query",
                "untested": True,
                "tests_run": "not run",
                "taint_path": [
                    {"role": r, "file": "a.py", "line": 1, "snippet": "x"}
                    for r in REQUIRED_TAINT_ROLES
                ],
                "independent_routes": ["static", "runtime"],
                "reachability": {"active_in_default_config": True},
                "poc_trace": [
                    {"file": "a.py", "line": 1, "action": "input"},
                    {"file": "a.py", "line": 2, "action": "guard"},
                    {"file": "a.py", "line": 3, "action": "sink"},
                ],
                "preconditions": [],
                "why_guard_fails": "value not covered",
                "cwe_class": "Base",
                "cwe_id": "CWE-79",
                "panel_verdicts": {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "TRUE_POSITIVE"},
                "claims": {
                    "targeted": {"state": "CONFIDENT", "evidence": "a.py:1", "tool_check": {"command": "grep -n SINK a.py", "exit_code": 0}},
                    "no_new_vulnerability": {"state": "CONFIDENT", "evidence": "ok", "tool_check": {"command": "git diff --check", "exit_code": 0}},
                    "behaviour_unchanged": {"state": "CONFIDENT", "evidence": "ok", "tool_check": {"command": "git diff --stat", "exit_code": 0}},
                },
                "attack_paths": [{"kind": "set_aside", "text": "guarded"}],
            }
            (patch_dir / "patches.json").write_text(
                json.dumps({"label": "ad-hoc-panel", "units": [unit]}),
                encoding="utf-8",
            )

            # Without redaction.json -> fail closed
            with self.assertRaises(RedactionError):
                cmd_render(str(patch_dir), str(patches_dir), str(root), "HEAD")

            # With clean redaction.json -> passes and labels ad-hoc-panel + untested
            (patches_dir / "redaction.json").write_text(
                json.dumps({"status": "clean", "cleaned_files": ["F1.patch"]}),
                encoding="utf-8",
            )
            rc = cmd_render(str(patch_dir), str(patches_dir), str(root), "HEAD")
            self.assertEqual(rc, 0)
            patch_text = (patches_dir / "F1.patch").read_text(encoding="utf-8")
            self.assertIn("ad-hoc-panel", patch_text)
            self.assertIn("untested", patch_text)
