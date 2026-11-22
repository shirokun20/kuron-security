import json
import tempfile
import unittest
from pathlib import Path
from kuron_capabilities import CapabilityError, probe, select_path


class CapabilityTest(unittest.TestCase):
    def test_probe_writes_all_keys(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "capabilities.json"
            caps = probe(d, str(out), harness="agy")
            self.assertEqual(
                set(caps),
                {
                    "harness",
                    "agent_types",
                    "tools",
                    "has_git",
                    "has_network",
                    "plugin_briefs_available",
                    "shell_git_dialect",
                },
            )
            self.assertEqual(caps["harness"], "agy")
            self.assertEqual(json.loads(out.read_text()), caps)

    def test_select_path_kuron_panel(self):
        caps = {
            "harness": "omp",
            "agent_types": ["security-reviewer", "explore"],
            "tools": ["read", "write", "subagent", "git"],
            "has_git": True,
            "has_network": False,
            "plugin_briefs_available": True,
            "shell_git_dialect": "posix",
        }
        res = select_path(caps, "enterprise", consent=None)
        self.assertEqual(res["label"], "kuron-panel")
        self.assertEqual(res["tier"], "enterprise")
        self.assertEqual(res["backend"], "omp")
        self.assertIn("security-reviewer", res["agent_types_used"])

    def test_select_path_ad_hoc_panel_requires_consent(self):
        caps = {
            "harness": "agy",
            "agent_types": ["self", "research"],
            "tools": ["read", "write", "define_subagent", "git"],
            "has_git": True,
            "has_network": False,
            "plugin_briefs_available": False,
            "shell_git_dialect": "posix",
        }
        with self.assertRaises(CapabilityError):
            select_path(caps, "personal", consent=None)
        res = select_path(caps, "personal", consent="accept")
        self.assertEqual(res["label"], "ad-hoc-panel")

    def test_select_path_single_pass_requires_consent(self):
        caps = {
            "harness": "cli",
            "agent_types": [],
            "tools": ["read", "write"],
            "has_git": False,
            "has_network": False,
            "plugin_briefs_available": False,
            "shell_git_dialect": "posix",
        }
        with self.assertRaises(CapabilityError):
            select_path(caps, "personal", consent="decline")
        res = select_path(caps, "personal", consent="accept")
        self.assertEqual(res["label"], "unverified-single-pass")

    def test_enterprise_aborts_when_capabilities_insufficient(self):
        caps = {
            "harness": "cli",
            "agent_types": [],
            "tools": ["read", "write"],
            "has_git": False,
            "has_network": False,
            "plugin_briefs_available": False,
            "shell_git_dialect": "posix",
        }
        with self.assertRaises(CapabilityError):
            select_path(caps, "enterprise", consent="accept")
