import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kuron_capabilities import (
    CapabilityError,
    plugin_brief_paths,
    plugin_script_paths,
    probe,
    select_path,
)

PANEL_CAPS = {
    "harness": "omp",
    "agent_types": ["security-reviewer", "explore"],
    "tools": ["read", "subagent", "git"],
    "has_git": True,
    "plugin_briefs_available": True,
    "plugin_briefs_sha256": "a" * 64,
    "panel_launch_observed": True,
    "capability_sources": {"panel_launch_observed": "observed", "has_git": "observed"},
}


def caps(**changes):
    return {**PANEL_CAPS, **changes}


class CapabilityProvenanceTest(unittest.TestCase):
    def test_probe_attaches_source_per_capability(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "capabilities.json"
            data = probe(d, str(out), harness="omp", panel_launch_observed=True)
            sources = data["capability_sources"]
            self.assertEqual(data["sources"], sources)
            self.assertEqual(sources["harness"], "observed")
            self.assertEqual(sources["agent_types"], "assumed")
            self.assertEqual(sources["has_network"], "assumed")
            self.assertEqual(sources["shell_git_dialect"], "observed")
            self.assertIn(sources["has_git"], ("observed", "assumed"))

    def test_harness_source_is_declared_from_env(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict("os.environ", {"KURON_HARNESS": "agy"}):
                data = probe(d, str(Path(d) / "c.json"))
            self.assertEqual(data["capability_sources"]["harness"], "declared")

    def test_panel_requires_observed_launch(self):
        data = caps(panel_launch_observed=False)
        self.assertNotEqual(select_path(data, "personal", "accept")["label"], "kuron-panel")

    def test_panel_requires_observed_source(self):
        data = caps(capability_sources={"panel_launch_observed": "assumed"})
        self.assertNotEqual(select_path(data, "personal", "accept")["label"], "kuron-panel")

    def test_panel_requires_hash_present_briefs(self):
        data = caps(plugin_briefs_sha256=None)
        self.assertNotEqual(select_path(data, "personal", "accept")["label"], "kuron-panel")

    def test_observed_panel_yields_kuron_panel(self):
        res = select_path(caps(), "enterprise", None)
        self.assertEqual(res["label"], "kuron-panel")
        self.assertEqual(res["panel_source"], "observed")

    def test_unified_plugin_path_helpers(self):
        self.assertIsInstance(plugin_brief_paths(), list)
        self.assertIsInstance(plugin_script_paths(), list)

    def test_enterprise_still_requires_git(self):
        with self.assertRaises(CapabilityError):
            select_path(caps(has_git=False), "enterprise", "accept")
