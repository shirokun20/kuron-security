import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from kuron_products import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_POLICY,
    EXIT_REDACTION,
    PanelGateError,
    _apply_panel,
    compute_panel_tally,
    main,
)
from kuron_redaction import RedactionError


TP = {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "TRUE_POSITIVE"}
MAJORITY = {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "FALSE_POSITIVE"}


def make_finding(fid="F1", severity="LOW", verdicts=None, **extra):
    f = {
        "id": fid,
        "file": "a.py",
        "line": 1,
        "severity": severity,
        "cwe_id": "CWE-79",
        "title": "finding " + fid,
        "cwe_class": "Base",
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
        "independent_routes": ["trace:static", "grep:source"],
    }
    if verdicts is not None:
        f["panel_verdicts"] = verdicts
    f.update(extra)
    return f


class ProductsGatesTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.report = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def setup_report(self, findings, meta=None, status="clean"):
        (self.report / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
        (self.report / "scan-meta.json").write_text(json.dumps(meta or {}), encoding="utf-8")
        (self.report / "redaction.json").write_text(
            json.dumps({"status": status, "cleaned_files": []}), encoding="utf-8"
        )

    def run_main(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(str(self.report), str(self.report))
        return code, out.getvalue(), err.getvalue()

    # Phase 2 - real panel tally
    def test_tally_unanimous(self):
        t = compute_panel_tally(make_finding(verdicts=TP))
        self.assertTrue(t["ran"])
        self.assertTrue(t["unanimous_tp"])
        self.assertEqual((t["R"], t["I"], t["D"]), ("TP", "TP", "TP"))
        self.assertIn("3/3 TP", t["display"])

    def test_tally_majority_is_not_unanimous(self):
        t = compute_panel_tally(make_finding(verdicts=MAJORITY))
        self.assertTrue(t["ran"])
        self.assertFalse(t["unanimous_tp"])
        self.assertEqual(t["votes"], 2)

    def test_tally_missing_lens_did_not_run(self):
        t = compute_panel_tally(make_finding(verdicts={"R": "TRUE_POSITIVE"}))
        self.assertFalse(t["ran"])
        self.assertFalse(t["unanimous_tp"])

    def test_tally_accepts_list_form_and_aliases(self):
        f = make_finding(verdicts=[
            {"lens": "reachability", "verdict": True},
            {"lens": "impact", "verdict": "TP"},
            {"lens": "defenses", "verdict": "true_positive"},
        ])
        self.assertTrue(compute_panel_tally(f)["unanimous_tp"])

    def test_confidence_never_drives_tally(self):
        f = make_finding(confidence="HIGH")
        t = compute_panel_tally(f)
        self.assertFalse(t["ran"])
        self.assertFalse(t["unanimous_tp"])

    def test_apply_panel_refuses_unobserved_panel_label(self):
        with self.assertRaises(PanelGateError):
            _apply_panel([make_finding()], {}, "kuron-panel")

    def test_apply_panel_discards_non_unanimous(self):
        kept, rejected = _apply_panel([make_finding(verdicts=MAJORITY)], {}, "ad-hoc-panel")
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("quorum failed", rejected[0]["discard_reason"])

    def test_apply_panel_keeps_unanimous(self):
        kept, rejected = _apply_panel([make_finding(verdicts=TP)], {}, "kuron-panel")
        self.assertEqual(len(kept), 1)
        self.assertEqual(rejected, [])

    # Exit codes and gating
    def test_exit_zero_for_low_only(self):
        self.setup_report([make_finding()])
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_CLEAN)
        self.assertEqual(json.loads(out.strip())["exit_code"], 0)
        self.assertTrue(err.isascii())
        self.assertNotIn("╭", err)

    def test_exit_one_for_high_finding(self):
        self.setup_report([make_finding(severity="HIGH")])
        code, out, _ = self.run_main()
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(json.loads(out.strip())["reason"], "high/critical findings kept")

    def test_exit_two_for_unobserved_panel_claim(self):
        self.setup_report([make_finding()], {"label": "kuron-panel"})
        code, out, _ = self.run_main()
        self.assertEqual(code, EXIT_POLICY)
        self.assertIn("observed R/I/D", json.loads(out.strip())["reason"])
        self.assertEqual(list(self.report.glob("KURON-SECURITY-RESULTS.*")), [])

    def test_exit_three_for_redaction_failure(self):
        self.setup_report([make_finding()], status="not_cleaned")
        code, out, _ = self.run_main()
        self.assertEqual(code, EXIT_REDACTION)
        self.assertEqual(list(self.report.glob("KURON-SECURITY-RESULTS.*")), [])

    def test_independent_secret_scan_blocks_and_cleans_staging(self):
        secret = "AKIA" + "A" * 16
        self.setup_report([make_finding(snippet=secret)])
        code, out, _ = self.run_main()
        self.assertEqual(code, EXIT_REDACTION)
        self.assertIn("aws-access-key", json.loads(out.strip())["reason"])
        self.assertEqual(list(self.report.glob(".staging-*")), [])
        self.assertEqual(list(self.report.glob("KURON-SECURITY-RESULTS.*")), [])

    def test_secret_scan_variety(self):
        from kuron_redaction import scan_secrets

        self.assertIn("github-token", scan_secrets("token ghp_" + "a" * 36))
        self.assertIn("github-fine-grained-pat", scan_secrets("github_pat_" + "a" * 45))
        self.assertIn("slack-token", scan_secrets("xoxb-123456789012"))
        self.assertIn("private-key", scan_secrets("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertEqual(scan_secrets("nothing here"), [])

    # Phase 1 - no dynamic plugin import / deterministic vendored builder
    def test_no_sys_path_mutation_or_plugin_import(self):
        self.setup_report([make_finding(verdicts=TP)], {"label": "kuron-panel"})
        before = list(sys.path)
        code, _, _ = self.run_main()
        self.assertEqual(code, EXIT_CLEAN)
        self.assertEqual(sys.path, before)
        self.assertNotIn("lib", sys.modules)

    def test_sarif_rules_and_stamp_builder(self):
        self.setup_report([make_finding(verdicts=TP)], {"label": "kuron-panel"})
        code, _, _ = self.run_main()
        self.assertEqual(code, EXIT_CLEAN)
        sarif = json.loads((self.report / "KURON-SECURITY-RESULTS.sarif").read_text())
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["$schema"].endswith("sarif-2.1.0.json"))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "CWE-79")
        self.assertEqual(sarif["runs"][0]["properties"]["builder"], "vendored")
        stamp = json.loads(next(self.report.glob("KURON-SECURITY-REVISION-*.json")).read_text())
        self.assertEqual(stamp["builder"], "vendored")

    def test_default_label_is_unverified_single_pass(self):
        self.setup_report([make_finding()], {})
        code, _, _ = self.run_main()
        self.assertEqual(code, EXIT_CLEAN)
        stamp = json.loads(next(self.report.glob("KURON-SECURITY-REVISION-*.json")).read_text())
        self.assertEqual(stamp["label"], "unverified-single-pass")
