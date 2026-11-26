"""Strict OASIS SARIF 2.1.0 validation of generated Kuron products.

Full Draft-07 validation runs when ``jsonschema`` is installed (CI installs it).
A dependency-free structural validator always runs so ``unittest`` stays green
offline; the full check is explicitly skipped in that case.
"""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from kuron_products import main

try:
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover - exercised only on zero-dep machines
    Draft7Validator = None

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "tests" / "fixtures" / "sarif-schema-2.1.0.json"
SARIF_NAME = "KURON-SECURITY-RESULTS.sarif"

TP = {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "TRUE_POSITIVE"}
FINDING = {
    "id": "F1",
    "file": "svc.py",
    "line": 9,
    "severity": "HIGH",
    "cwe_id": "CWE-79",
    "cwe_class": "base",
    "title": "XSS via untrusted input",
    "reachability": {"active_in_default_config": True},
    "panel_verdicts": dict(TP),
    "taint_path": [
        {"role": "source", "file": "input.py", "line": 1, "snippet": "request.args"},
        {"role": "guard", "file": "svc.py", "line": 4, "snippet": "clean()"},
        {"role": "sink", "file": "svc.py", "line": 9, "snippet": "render()"},
    ],
    "poc_trace": [
        {"file": "input.py", "line": 1, "action": "input"},
        {"file": "svc.py", "line": 4, "action": "guard"},
        {"file": "svc.py", "line": 9, "action": "sink"},
    ],
    "preconditions": [],
    "why_guard_fails": "encoded brackets bypass clean()",
    "independent_routes": ["trace:static", "grep:sink"],
}
PATCH_DIFF = """--- a/svc.py
+++ b/svc.py
@@ -7,3 +7,4 @@ def render():
 context
-    return markup(raw)
+    return markup(escape(raw))
+    done
"""


def structural_errors(log: dict) -> list[str]:
    """Dependency-free checks covering the fields Phase 2 adds to SARIF."""
    errors: list[str] = []
    if log.get("version") != "2.1.0":
        errors.append("version must be 2.1.0")
    if not str(log.get("$schema", "")).endswith("sarif-2.1.0.json"):
        errors.append("$schema must reference SARIF 2.1.0")
    runs = log.get("runs") or []
    if len(runs) != 1:
        return errors + ["expected exactly one run"]
    run = runs[0]
    driver = (run.get("tool") or {}).get("driver") or {}
    if driver.get("name") != "Kuron Security":
        errors.append("driver.name missing")
    if driver.get("semanticVersion") != "2.3.2":
        errors.append("driver.semanticVersion must be 2.3.2")
    for result in run.get("results") or []:
        if not (result.get("message") or {}).get("text"):
            errors.append("result.message.text missing")
        if not result.get("locations"):
            errors.append("result.locations missing")
        digest = (result.get("partialFingerprints") or {}).get(
            "kuronPrimaryLocationHash", ""
        )
        if len(digest) != 64:
            errors.append("kuronPrimaryLocationHash must be sha256 hex")
        expected = hashlib.sha256(
            f"{result.get('ruleId')}|{FINDING['file']}|{FINDING['line']}".encode("utf-8")
        ).hexdigest()
        if digest != expected:
            errors.append("kuronPrimaryLocationHash is not deterministic")
        flows = result.get("codeFlows") or []
        if not flows or not flows[0]["threadFlows"][0]["locations"]:
            errors.append("taint_path was not rendered as codeFlows/threadFlows")
        for fix in result.get("fixes") or []:
            changes = fix.get("artifactChanges") or []
            if not changes or not changes[0].get("replacements"):
                errors.append("fixes[] need artifactChanges with replacements")
    return errors


class SarifSchemaStrictTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.report = Path(self._td.name)
        (self.report / "redaction.json").write_text(
            json.dumps({"status": "clean", "cleaned_files": []}), encoding="utf-8"
        )
        (self.report / "findings.json").write_text(json.dumps([FINDING]), encoding="utf-8")
        (self.report / "scan-meta.json").write_text(
            json.dumps({"label": "kuron-panel", "revision": {"commit": "abc123"}}),
            encoding="utf-8",
        )
        (self.report / "patches").mkdir()
        (self.report / "patches" / "F1.patch").write_text(PATCH_DIFF, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.code = main(str(self.report), str(self.report))
        self.assertEqual(self.code, 1, out.getvalue())

    def tearDown(self):
        self._td.cleanup()

    def log(self) -> dict:
        return json.loads((self.report / SARIF_NAME).read_text(encoding="utf-8"))

    def test_vendored_schema_is_the_full_oasis_schema(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "http://json-schema.org/draft-07/schema#")
        self.assertIn("Static Analysis Results Format (SARIF)", schema["title"])
        for name in ("result", "fix", "codeFlow", "threadFlow", "toolComponent"):
            self.assertIn(name, schema["definitions"])
        self.assertGreater(SCHEMA_PATH.stat().st_size, 50000)

    def test_generated_sarif_has_all_phase_two_fields(self):
        log = self.log()
        result = log["runs"][0]["results"][0]
        self.assertEqual(log["runs"][0]["tool"]["driver"]["semanticVersion"], "2.3.2")
        self.assertEqual(len(result["codeFlows"][0]["threadFlows"][0]["locations"]), 3)
        self.assertEqual(len(result["partialFingerprints"]), 1)
        self.assertTrue(result["fixes"][0]["artifactChanges"][0]["replacements"])
        self.assertEqual(structural_errors(log), [])

    def test_structural_validator_stays_dependency_free(self):
        self.assertEqual(structural_errors(self.log()), [])

    @unittest.skipIf(Draft7Validator is None, "jsonschema not installed; full Draft-07 check skipped")
    def test_full_draft07_schema_validation(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        errors = sorted(Draft7Validator(schema).iter_errors(self.log()), key=lambda e: list(e.path))
        self.assertEqual(
            errors, [], [(list(e.path), e.message) for e in errors]
        )

    @unittest.skipIf(Draft7Validator is None, "jsonschema not installed; full Draft-07 check skipped")
    def test_empty_results_also_validate(self):
        (self.report / "findings.json").write_text("[]", encoding="utf-8")
        # A label requiring a panel is fine with zero findings.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(str(self.report), str(self.report)), 0)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(list(Draft7Validator(schema).iter_errors(self.log())), [])


if __name__ == "__main__":
    unittest.main()
