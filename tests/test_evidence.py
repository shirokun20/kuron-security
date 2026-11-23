import unittest
from kuron_evidence import REQUIRED_TAINT_ROLES, filter_findings, validate_finding

BASE = {
    "id": "F1",
    "taint_path": [
        {"role": r, "file": "a.py", "line": 1, "snippet": "x"}
        for r in REQUIRED_TAINT_ROLES
    ],
    "reachability": {
        "entrypoint": "a.py:1",
        "hops": [],
        "active_in_default_config": True,
    },
    "independent_routes": ["static", "runtime"],
    "poc_trace": [
        {"file": "a.py", "line": 1, "action": "input arrives"},
        {"file": "a.py", "line": 2, "action": "guard evaluated"},
        {"file": "a.py", "line": 3, "action": "sink reached"},
    ],
    "preconditions": ["default config"],
    "why_guard_fails": "the guard does not cover this value",
    "cwe_class": "Base",
    "cwe_id": "CWE-79",
}


class EvidenceTest(unittest.TestCase):
    def test_complete_finding_kept(self):
        self.assertEqual(validate_finding(BASE), (True, []))
        kept, discarded = filter_findings([BASE])
        self.assertEqual(kept, [BASE])
        self.assertEqual(discarded, [])

    def test_missing_guard_dropped(self):
        f = dict(BASE, taint_path=[BASE["taint_path"][0], BASE["taint_path"][2]])
        ok, reasons = validate_finding(f)
        self.assertFalse(ok)
        self.assertTrue(any("guard" in r for r in reasons))

    def test_dead_path_dropped_with_reason(self):
        f = dict(
            BASE,
            reachability={**BASE["reachability"], "active_in_default_config": False},
        )
        kept, discarded = filter_findings([f])
        self.assertEqual(kept, [])
        self.assertEqual(len(discarded), 1)
        self.assertTrue(discarded[0]["discard_reason"])

    def test_single_route_dropped(self):
        f = dict(BASE, independent_routes=["static"])
        ok, reasons = validate_finding(f)
        self.assertFalse(ok)
        self.assertTrue(any("independent_routes" in r for r in reasons))

    def test_collects_multiple_reasons(self):
        f = {
            "id": "F2",
            "taint_path": [],
            "reachability": {"active_in_default_config": False},
            "independent_routes": [],
        }
        ok, reasons = validate_finding(f)
        self.assertFalse(ok)
        self.assertGreaterEqual(len(reasons), 3)
