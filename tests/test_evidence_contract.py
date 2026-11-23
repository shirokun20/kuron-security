import copy
import unittest

from kuron_evidence import (
    CWE_BASE_CLASS_IDS,
    filter_findings,
    validate_finding,
)

BASE = {
    "id": "F1",
    "taint_path": [
        {"role": role, "file": "a.py", "line": 0, "snippet": "x"}
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


def reasons(f):
    ok, why = validate_finding(f)
    return ok, why


class EvidenceContractTest(unittest.TestCase):
    def test_base_valid_including_line_zero(self):
        ok, why = reasons(BASE)
        self.assertTrue(ok, why)
        self.assertIn("CWE-79", CWE_BASE_CLASS_IDS)

    def test_poc_trace_step_count_bounds(self):
        for steps in (BASE["poc_trace"][:2], BASE["poc_trace"] + [BASE["poc_trace"][0]] * 5):
            f = copy.deepcopy(BASE)
            f["poc_trace"] = steps
            ok, why = reasons(f)
            self.assertFalse(ok)
            self.assertTrue(any("3-7" in r for r in why))

    def test_poc_trace_requires_preconditions_and_why(self):
        for key in ("preconditions", "why_guard_fails"):
            f = copy.deepcopy(BASE)
            del f[key]
            ok, why = reasons(f)
            self.assertFalse(ok)
            self.assertTrue(any(key in r for r in why))

    def test_poc_trace_steps_require_file_line_action(self):
        f = copy.deepcopy(BASE)
        f["poc_trace"][0] = {"file": "a.py", "action": "input"}
        ok, why = reasons(f)
        self.assertFalse(ok)
        self.assertTrue(any("poc_trace[0]" in r for r in why))

    def test_cwe_class_rejects_unknown(self):
        f = copy.deepcopy(BASE)
        f["cwe_class"] = "CWE-999999"
        ok, why = reasons(f)
        self.assertFalse(ok)
        self.assertTrue(any("cwe_class" in r for r in why))

    def test_cwe_class_accepts_known_id_and_kind(self):
        f = copy.deepcopy(BASE)
        f["cwe_class"] = "CWE-89"
        self.assertTrue(reasons(f)[0])
        f["cwe_class"] = "Class"
        self.assertTrue(reasons(f)[0])
        f["cwe_class"] = "Base"
        f["cwe_id"] = "not-an-id"
        self.assertFalse(reasons(f)[0])

    def test_active_in_default_config_must_be_true_not_omitted(self):
        f = copy.deepcopy(BASE)
        del f["reachability"]["active_in_default_config"]
        ok, why = reasons(f)
        self.assertFalse(ok)
        self.assertTrue(any("exactly True" in r for r in why))

    def test_method_families_not_just_distinct_strings(self):
        f = copy.deepcopy(BASE)
        f["independent_routes"] = ["grep:one", "grep:two"]
        ok, why = reasons(f)
        self.assertFalse(ok)
        self.assertTrue(any("families" in r for r in why))

    def test_two_families_accepted(self):
        f = copy.deepcopy(BASE)
        f["independent_routes"] = ["trace:one", "lens-reachability"]
        self.assertTrue(reasons(f)[0])

    def test_filter_discards_with_reason(self):
        bad = copy.deepcopy(BASE)
        bad["id"] = "BAD"
        bad["reachability"]["active_in_default_config"] = False
        kept, discarded = filter_findings([BASE, bad])
        self.assertEqual([f["id"] for f in kept], ["F1"])
        self.assertEqual([f["id"] for f in discarded], ["BAD"])
        self.assertTrue(discarded[0]["discard_reason"])
