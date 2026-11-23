import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kuron_policy import PolicyError, _match_path, check, validate

VALID = (
    "version: 1\n"
    "profiles:\n"
    "  personal:\n"
    "    block: []\n"
    "  enterprise:\n"
    "    effort: high\n"
    "    block:\n"
    "      - severity: CRITICAL\n"
    "        path: 'src/**'\n"
)


class StrictPolicyTest(unittest.TestCase):
    def write(self, text):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "policy.yml"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_valid_policy(self):
        out = validate(self.write(VALID))
        self.assertEqual(out["version"], 1)
        self.assertEqual(len(out["sha256"]), 64)
        self.assertEqual(out["profile_rules"]["enterprise"]["block"][0]["path"], "src/**")

    def test_missing_file_raises_policy_error(self):
        with self.assertRaises(PolicyError):
            validate("/no/such/policy.yml")

    def test_non_int_version(self):
        with self.assertRaises(PolicyError):
            validate(self.write(VALID.replace("version: 1", "version: one")))

    def test_comments_rejected(self):
        with self.assertRaises(PolicyError):
            validate(self.write(VALID + "# trailing comment\n"))
        with self.assertRaises(PolicyError):
            validate(self.write("version: 1 # inline\nprofiles:\n  personal:\n    block: []\n"))

    def test_nested_map_rejected(self):
        bad = VALID.replace("    effort: high\n", "    effort:\n      nested: value\n")
        with self.assertRaises(PolicyError):
            validate(self.write(bad))

    def test_unknown_tier_and_key_rejected(self):
        for text in (
            VALID.replace("  personal:", "  unknown:"),
            VALID.replace("    effort: high\n", "    mystery: high\n"),
        ):
            with self.subTest(text=text), self.assertRaises(PolicyError):
                validate(self.write(text))

    def test_unknown_severity_and_scalar_block_rejected(self):
        for text in (
            VALID.replace("severity: CRITICAL", "severity: URGENT"),
            VALID.replace("block: []", "block: [foo]"),
        ):
            with self.subTest(text=text), self.assertRaises(PolicyError):
                validate(self.write(text))

    def test_enterprise_deny_default(self):
        policy = validate(self.write(VALID))
        self.assertEqual(check(policy, "enterprise", "LOW", "anything.py"), "block")
        self.assertEqual(check(policy, "personal", "LOW", "anything.py"), "allow")

    def test_unknown_tier_in_check_raises(self):
        policy = validate(self.write(VALID))
        with self.assertRaises(PolicyError):
            check(policy, "ghost", "LOW", "x")

    def test_glob_semantics_recursive_and_single_segment(self):
        policy = validate(self.write(VALID))
        self.assertEqual(check(policy, "enterprise", "CRITICAL", "src/auth/deep/x.py"), "block")
        with mock.patch("kuron_policy.os.name", "posix"):
            self.assertTrue(_match_path("src/a/b.py", "src/**"))
            self.assertFalse(_match_path("tests/sub/a.py", "tests/*"))
        with mock.patch("kuron_policy.os.name", "nt"):
            self.assertTrue(_match_path("src\\a\\b.py", "src/**"))

    def test_repo_policy_still_valid(self):
        repo = Path(__file__).resolve().parents[1] / "policy" / "kuron-policy.yml"
        out = validate(str(repo))
        self.assertEqual(set(out["profile_rules"]), {"personal", "bisnis", "enterprise"})
