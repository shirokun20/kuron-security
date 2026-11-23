import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from kuron_patch import check_claims, cmd_prepare, cmd_render, main
from kuron_redaction import RedactionError

VALID_FINDING = {
    "id": "F1",
    "taint_path": [
        {"role": role, "file": "a.py", "line": 1, "snippet": "x"}
        for role in ("source", "guard", "sink")
    ],
    "reachability": {"active_in_default_config": True},
    "independent_routes": ["trace:static", "grep:source"],
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


def claim(command="grep -n SINK a.py"):
    return {
        "state": "CONFIDENT",
        "evidence": "a.py:1",
        "tool_check": {"command": command, "exit_code": 0},
    }


class PatchHardeningTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_self_attested_confident_without_tool_check_rejected(self):
        unit = dict(VALID_FINDING)
        unit["claims"] = {
            name: {"state": "CONFIDENT", "evidence": "a.py:1"}
            for name in ("targeted", "no_new_vulnerability", "behaviour_unchanged")
        }
        unit["untested"] = False
        unit["attack_paths"] = []
        err = check_claims(unit)
        self.assertIsNotNone(err)
        self.assertIn("tool_check", err)

    def test_verifiable_claims_accepted(self):
        unit = dict(VALID_FINDING)
        unit["claims"] = {name: claim() for name in
                          ("targeted", "no_new_vulnerability", "behaviour_unchanged")}
        unit["untested"] = False
        unit["attack_paths"] = []
        self.assertIsNone(check_claims(unit))

    def test_cmd_prepare_returns_zero(self):
        report = self.root / "KURON-SECURITY-20261122-000000"
        report.mkdir()
        (report / "findings.json").write_text(json.dumps([VALID_FINDING]), encoding="utf-8")

        def fake_git(args, cwd):
            if args[:2] == ["rev-parse", "--show-toplevel"]:
                return subprocess.CompletedProcess(args, 0, str(self.root) + "\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch("kuron_patch.git", side_effect=fake_git):
            rc = cmd_prepare(str(report), "all", str(self.root), "HEAD")
        self.assertEqual(rc, 0)
        self.assertTrue(list(report.glob(".kuron-security-run/patch-*/units.json")))

    def test_declined_unit_without_claims_does_not_crash(self):
        report = self.root / "KURON-SECURITY-20261122-000000"
        patch_dir = report / ".kuron-security-run" / "patch-1"
        patches_dir = report / "patches"
        patch_dir.mkdir(parents=True)
        patches_dir.mkdir(parents=True)
        (patch_dir / "patches.json").write_text(
            json.dumps({"label": "unverified-single-pass", "units": [
                {"id": "F1", "status": "declined", "attempts": 2,
                 "decline_reason": "not exploitable"}
            ]}),
            encoding="utf-8",
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(RedactionError):  # no verdict -> fail closed
                cmd_render(str(patch_dir), str(patches_dir), str(self.root), "HEAD")
        (patches_dir / "redaction.json").write_text(
            json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
        )
        with redirect_stderr(io.StringIO()):
            rc = cmd_render(str(patch_dir), str(patches_dir), str(self.root), "HEAD")
        self.assertEqual(rc, 0)

    def test_stale_cleanup_is_realpath_confined(self):
        report = self.root / "KURON-SECURITY-20261122-000000"
        patch_dir = report / ".kuron-security-run" / "patch-1"
        patches_dir = report / "patches"
        patch_dir.mkdir(parents=True)
        patches_dir.mkdir(parents=True)
        outside = self.root / "outside.patch"
        outside.write_text("sensitive\n", encoding="utf-8")
        (patches_dir / "F999.patch").write_text("stale", encoding="utf-8")
        try:
            (patches_dir / "F998.patch").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        (patch_dir / "patches.json").write_text(
            json.dumps({"label": "unverified-single-pass", "units": []}), encoding="utf-8"
        )
        (patches_dir / "redaction.json").write_text(
            json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
        )
        with redirect_stderr(io.StringIO()):
            rc = cmd_render(str(patch_dir), str(patches_dir), str(self.root), "HEAD")
        self.assertEqual(rc, 0)
        self.assertFalse((patches_dir / "F999.patch").exists())
        self.assertTrue((patches_dir / "F998.patch").is_symlink())
        self.assertTrue(outside.exists())

    def test_argparse_cli(self):
        with self.assertRaises(SystemExit) as clean:
            main(["--help"])
        self.assertEqual(clean.exception.code, 0)
        with self.assertRaises(SystemExit) as bad:
            main([])
        self.assertEqual(bad.exception.code, 2)

    def test_scorecard_is_ascii_on_stderr(self):
        report = self.root / "KURON-SECURITY-20261122-000000"
        patch_dir = report / ".kuron-security-run" / "patch-1"
        patches_dir = report / "patches"
        patch_dir.mkdir(parents=True)
        patches_dir.mkdir(parents=True)
        (patch_dir / "patches.json").write_text(
            json.dumps({"label": "unverified-single-pass", "units": []}), encoding="utf-8"
        )
        (patches_dir / "redaction.json").write_text(
            json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
        )
        err = io.StringIO()
        with redirect_stderr(err):
            rc = cmd_render(str(patch_dir), str(patches_dir), str(self.root), "HEAD")
        self.assertEqual(rc, 0)
        self.assertTrue(err.getvalue().isascii())
        self.assertNotIn("╭", err.getvalue())
