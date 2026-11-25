"""Phase 3 ecosystem regression: synthetic fixtures, no network, no LLM calls."""

from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kuron_evidence import CWE_BASE_CLASS_IDS, validate_finding
from kuron_policy import select_rulepacks
from kuron_products import main as products_main

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RULES = ROOT / "rules"
FIXTURES = ROOT / "tests" / "fixtures" / "ecosystem"
TP = {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "TRUE_POSITIVE"}
ARTIFACTS = (
    "KURON-SECURITY-RESULTS.md",
    "KURON-SECURITY-RESULTS.jsonl",
    "KURON-SECURITY-RESULTS.sarif",
    "KURON-SECURITY-REVISION-abc123def456.json",
)


def synthetic_finding(fid, cwe, title, file, line, snippet, severity):
    """One evidence-complete finding grounded in a synthetic fixture."""
    return {
        "id": fid,
        "cwe_id": cwe,
        "cwe_class": "Base",
        "title": title,
        "description": f"Synthetic {cwe} finding for offline regression.",
        "file": file,
        "line": line,
        "severity": severity,
        "taint_path": [
            {"role": role, "file": file, "line": line, "snippet": snippet}
            for role in ("source", "guard", "sink")
        ],
        "reachability": {"active_in_default_config": True},
        "poc_trace": [
            {"file": file, "line": line, "action": "read untrusted fixture value"},
            {"file": file, "line": line, "action": "guard absent or insufficient"},
            {"file": file, "line": line, "action": "reach the named sink"},
        ],
        "preconditions": ["target file is present in the synthetic fixture set"],
        "why_guard_fails": "the fixture shows no containment or scheme/address check",
        "independent_routes": ["trace:static", "grep:fixture"],
    }


TAURI_FINDING = synthetic_finding(
    "F1", "CWE-22", "Tauri archive path traversal",
    "tests/fixtures/ecosystem/tauri/src/import.rs", 7, "../../etc/passwd", "HIGH",
)
REDOS_FINDING = synthetic_finding(
    "F2", "CWE-1333", "Config DSL nested quantifier regex",
    "tests/fixtures/ecosystem/config-dsl/manifest.json", 4, "(a+)+$", "MEDIUM",
)
SSRF_FINDING = synthetic_finding(
    "F3", "CWE-918", "Extensions secondaryFetch SSRF",
    "tests/fixtures/ecosystem/extensions/fetcher.json", 5,
    "http://169.254.169.254/latest/meta-data/", "HIGH",
)
FINDINGS = (TAURI_FINDING, REDOS_FINDING, SSRF_FINDING)


def write_inputs(report: Path) -> None:
    report.mkdir(parents=True, exist_ok=True)
    (report / "redaction.json").write_text(
        json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
    )
    (report / "findings.json").write_text(json.dumps(list(FINDINGS)), encoding="utf-8")
    (report / "scan-meta.json").write_text(
        json.dumps(
            {
                "label": "kuron-panel",
                "tier": "personal",
                "scope": ["tests/fixtures/ecosystem"],
                "revision": {"commit": "abc123def456"},
                "panel_verdicts": {f["id"]: dict(TP) for f in FINDINGS},
            }
        ),
        encoding="utf-8",
    )


def run_products(report: Path) -> int:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = products_main(str(report), str(report))
    assert code in (0, 1), out.getvalue()
    return code


class RulepackContractTest(unittest.TestCase):
    def test_all_rulepacks_are_bounded_and_cwe_grounded(self):
        packs = sorted(RULES.glob("*.md"))
        self.assertTrue(packs)
        for name in ("tauri.md", "flutter.md", "config-dsl.md"):
            self.assertIn(RULES / name, packs)
        for path in packs:
            with self.subTest(rulepack=path.name):
                lines = path.read_text(encoding="utf-8").splitlines()
                self.assertLessEqual(len(lines), 120, path.name)
                cwes = set(re.findall(r"CWE-\d+", "\n".join(lines)))
                self.assertTrue(cwes, path.name)
                self.assertLessEqual(cwes, CWE_BASE_CLASS_IDS, path.name)

    def test_fixtures_stay_synthetic_and_small(self):
        files = [p for p in FIXTURES.rglob("*") if p.is_file()]
        self.assertTrue(files)
        self.assertLess(sum(p.stat().st_size for p in files), 50 * 1024)


class WiringTest(unittest.TestCase):
    def test_scan_deps_references_scripts_and_lockfiles(self):
        text = (ROOT / "jobs" / "scan-deps.md").read_text(encoding="utf-8")
        for token in (
            "kuron_capabilities.py", "kuron_policy.py", "kuron_trace.py",
            "kuron_redaction.py", "kuron_products.py", "kuron_evidence.py",
            "kuron_quorum.py", "Cargo.lock", "pubspec.lock", "pnpm-lock.yaml",
        ):
            with self.subTest(token=token):
                self.assertIn(token, text)

    def test_scan_codebase_quorum_and_rulepack_wiring(self):
        text = (ROOT / "jobs" / "scan-codebase.md").read_text(encoding="utf-8")
        self.assertIn("3/3 unanimous\n  TRUE_POSITIVE required", text)
        for stale in ("keep >=2", "2/3", "two-of-three", "two of three"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, text)
        for token in (
            "tauri.conf.json", "pubspec.yaml", "manifest.json",
            "rules/tauri.md", "rules/flutter.md", "rules/config-dsl.md",
            "kuron_policy.py select-rulepacks",
        ):
            with self.subTest(token=token):
                self.assertIn(token, text)

    def test_skill_registers_rulepacks_and_deps_job(self):
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for token in ("jobs/scan-deps.md", "rules/tauri.md", "rules/flutter.md",
                      "rules/config-dsl.md", "select-rulepacks"):
            with self.subTest(token=token):
                self.assertIn(token, text)


class DetectionTest(unittest.TestCase):
    def test_detection_on_synthetic_fixtures(self):
        cases = (
            ("tauri", "tauri"),
            ("flutter", "flutter"),
            ("config-dsl", "config-dsl"),
            ("extensions", "config-dsl"),
            ("deps", None),
        )
        for directory, expected in cases:
            with self.subTest(fixture=directory):
                result = select_rulepacks(str(FIXTURES / directory))
                self.assertFalse(result["scanned"]["truncated"])
                packs = result["selected"]
                self.assertEqual(packs == [expected], expected is not None)
                for signal in result["signals"]:
                    self.assertIn(signal["rulepack"], packs)
                    self.assertTrue(signal["path"])

    def test_cli_detection_matches_function_and_is_deterministic(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "kuron_policy.py"),
             "select-rulepacks", str(FIXTURES / "tauri")],
            cwd=str(ROOT), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), select_rulepacks(str(FIXTURES / "tauri")))


class OfflinePipelineTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.report = Path(self._td.name) / "report"
        write_inputs(self.report)

    def tearDown(self):
        self._td.cleanup()

    def test_three_findings_pass_evidence_contract(self):
        for finding in FINDINGS:
            with self.subTest(finding=finding["id"]):
                self.assertEqual(validate_finding(finding), (True, []))

    def test_products_keep_all_three_with_unanimous_panel(self):
        self.assertEqual(run_products(self.report), 1)  # HIGH findings kept
        jsonl = [
            json.loads(line)
            for line in (self.report / ARTIFACTS[1]).read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([r["id"] for r in jsonl], [f["id"] for f in FINDINGS])
        stamp = json.loads((self.report / ARTIFACTS[3]).read_text(encoding="utf-8"))
        self.assertEqual(stamp["findings"], 3)
        self.assertEqual(stamp["discarded"], [])
        self.assertTrue(all(r["panel_tally"]["unanimous_tp"] for r in jsonl))

    def test_sarif_codeflows_and_fingerprints_for_three_findings(self):
        self.assertEqual(run_products(self.report), 1)
        log = json.loads((self.report / ARTIFACTS[2]).read_text(encoding="utf-8"))
        results = log["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in results], ["CWE-22", "CWE-1333", "CWE-918"])
        for result in results:
            with self.subTest(rule=result["ruleId"]):
                digest = result["partialFingerprints"]["kuronPrimaryLocationHash"]
                self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")
                flows = result["codeFlows"][0]["threadFlows"][0]["locations"]
                self.assertEqual(
                    [loc["properties"]["role"] for loc in flows],
                    ["source", "guard", "sink"],
                )
                self.assertTrue(result["properties"]["panel_tally"]["unanimous_tp"])

    def test_markdown_advisory_cards_show_unanimous_verdicts(self):
        self.assertEqual(run_products(self.report), 1)
        text = (self.report / ARTIFACTS[0]).read_text(encoding="utf-8")
        self.assertEqual(text.count("`3/3 TRUE_POSITIVE`"), 3)
        for cwe in ("CWE-22", "CWE-1333", "CWE-918"):
            with self.subTest(cwe=cwe):
                self.assertIn(cwe, text)
        self.assertEqual(text.count("**poc_trace**"), 3)
        self.assertIn("**Flow:**", text)

    def test_products_are_byte_deterministic_offline(self):
        self.assertEqual(run_products(self.report), 1)
        other = Path(self._td.name) / "other"
        write_inputs(other)
        self.assertEqual(run_products(other), 1)
        for name in ARTIFACTS:
            with self.subTest(artifact=name):
                self.assertEqual(
                    (self.report / name).read_bytes(), (other / name).read_bytes()
                )


if __name__ == "__main__":
    unittest.main()
