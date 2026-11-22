import tempfile
import unittest
from pathlib import Path
from kuron_policy import attestation, check, validate


class PolicyTest(unittest.TestCase):
    def test_validate_reads_version_and_sha(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.yml"
            p.write_text(
                "version: 1\nprofiles:\n  enterprise:\n    block:\n"
                "      - severity: CRITICAL\n        path: 'tests/*'\n",
                encoding="utf-8",
            )
            out = validate(str(p))
            self.assertEqual(out["version"], 1)
            self.assertEqual(len(out["sha256"]), 64)
            self.assertIn("enterprise", out["profile_rules"])

    def test_check_blocks_critical_in_tests(self):
        policy = {
            "version": 1,
            "sha256": "a" * 64,
            "profile_rules": {
                "enterprise": {"block": [{"severity": "CRITICAL", "path": "tests/*"}]}
            },
        }
        self.assertEqual(check(policy, "enterprise", "CRITICAL", "tests/a.dart"), "block")
        self.assertEqual(check(policy, "personal", "CRITICAL", "tests/a.dart"), "allow")
        self.assertEqual(check(policy, "enterprise", "HIGH", "src/a.dart"), "allow")

    def test_attestation_is_deterministic(self):
        policy = {"version": 1, "sha256": "b" * 64, "profile_rules": {}}
        self.assertEqual(
            attestation(policy),
            {"policy_version": 1, "policy_sha256": "b" * 64},
        )

    def test_repo_default_policy_is_valid(self):
        repo_policy = Path(__file__).resolve().parents[1] / "policy" / "kuron-policy.yml"
        out = validate(str(repo_policy))
        self.assertEqual(out["version"], 1)
        self.assertEqual(
            set(out["profile_rules"].keys()), {"personal", "bisnis", "enterprise"}
        )
