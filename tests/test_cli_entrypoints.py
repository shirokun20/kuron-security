"""End-to-end CLI smoke tests for all eight kuron_*.py scripts."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

VALID_FINDING = {
    "id": "F1",
    "taint_path": [
        {"role": role, "file": "a.py", "line": 1, "snippet": "x"}
        for role in ("source", "guard", "sink")
    ],
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
    "independent_routes": ["trace:static", "grep:source"],
}


def run(script, *args):
    """Run one script with a hard timeout so a CLI regression cannot hang CI."""
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30,
    )


class CliEntrypointsTest(unittest.TestCase):
    def test_help_for_all_scripts(self):
        for path in sorted(SCRIPTS.glob("kuron_*.py")):
            with self.subTest(script=path.name):
                proc = run(path.name, "--help")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("usage:", proc.stdout)

    def test_capabilities_probe_and_select_path(self):
        with tempfile.TemporaryDirectory() as d:
            caps = Path(d) / "caps.json"
            proc = run("kuron_capabilities.py", "probe", d, str(caps), "--harness", "codex")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["harness"], "codex")
            proc = run(
                "kuron_capabilities.py", "select-path", str(caps),
                "--tier", "personal", "--consent", "accept",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("label", json.loads(proc.stdout))

    def test_policy_validate_check_attestation(self):
        policy = str(ROOT / "policy" / "kuron-policy.yml")
        for args in (
            ("validate", policy),
            ("check", policy, "personal", "LOW", "a.py"),
            ("attestation", policy),
        ):
            with self.subTest(args=args):
                proc = run("kuron_policy.py", *args)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue(json.loads(proc.stdout))

    def test_progress_append_validate_detect(self):
        with tempfile.TemporaryDirectory() as d:
            proc = run(
                "kuron_progress.py", "append", d,
                '{"label": "probe", "trace_id": "trace-1"}',
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["seq"], 1)
            (Path(d) / "trace.jsonl").write_text(
                json.dumps({"trace_id": "trace-1"}) + "\n", encoding="utf-8"
            )
            proc = run("kuron_progress.py", "validate", d)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["ok"])
            proc = run("kuron_progress.py", "detect")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("mode", json.loads(proc.stdout))

    def test_evidence_validate_and_filter(self):
        with tempfile.TemporaryDirectory() as d:
            finding = Path(d) / "finding.json"
            findings = Path(d) / "findings.json"
            finding.write_text(json.dumps(VALID_FINDING), encoding="utf-8")
            findings.write_text(json.dumps([VALID_FINDING]), encoding="utf-8")
            proc = run("kuron_evidence.py", "validate", str(finding))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["ok"])
            proc = run("kuron_evidence.py", "filter", str(findings))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(json.loads(proc.stdout)["kept"]), 1)

    def test_trace_append_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            trace = Path(d) / "trace.jsonl"
            proc = run("kuron_trace.py", "append", str(trace), '{"event": "dispatch"}')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["appended"])
            proc = run(
                "kuron_trace.py", "verify",
                "grep -n XYZZY_NOT_PRESENT_12345 scripts/kuron_trace.py",
                "--cwd", str(ROOT), "--trace", str(trace),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(json.loads(proc.stdout)["trace_id"]), 12)

    def test_redaction_scan_and_enforce(self):
        proc = run("kuron_redaction.py", "scan", "--text", "nothing here")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), [])
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "redaction.json").write_text(
                json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
            )
            (Path(d) / "KURON-SECURITY-RESULTS.md").write_text("# report\n", encoding="utf-8")
            proc = run(
                "kuron_redaction.py", "enforce", d, "KURON-SECURITY-RESULTS.md"
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_patch_prepare_and_legacy_alias(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "KURON-SECURITY-20261122-000000"
            report.mkdir()
            (report / "findings.json").write_text(
                json.dumps([{"id": "F1"}]), encoding="utf-8"
            )
            for command in ("prepare", "--prepare"):
                with self.subTest(command=command):
                    proc = run(
                        "kuron_patch.py", command, str(report), "all",
                        "--repo-root", str(ROOT), "--base", "HEAD",
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertIn("F1", proc.stdout)

    def test_products_render(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d)
            (report / "redaction.json").write_text(
                json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
            )
            (report / "findings.json").write_text("[]", encoding="utf-8")
            (report / "scan-meta.json").write_text("{}", encoding="utf-8")
            proc = run("kuron_products.py", d, d)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('"exit_code": 0', proc.stdout)


if __name__ == "__main__":
    unittest.main()
