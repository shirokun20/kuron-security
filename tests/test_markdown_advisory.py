"""Full Security Advisory Card contract, including untrusted-text escaping."""

import tempfile
import unittest
from pathlib import Path

from kuron_markdown import METER_WIDTH, _md, _meter_filled, render_document, render_markdown

TP = {"R": "TRUE_POSITIVE", "I": "TRUE_POSITIVE", "D": "TRUE_POSITIVE"}


def finding(**overrides):
    out = {
        "id": "F1",
        "file": "svc.py",
        "line": 9,
        "severity": "HIGH",
        "cwe_id": "CWE-79",
        "title": "XSS via untrusted input",
        "description": "Untrusted value reaches the HTML sink without escaping.",
        "panel_verdicts": dict(TP),
        "taint_path": [
            {"role": "source", "file": "input.py", "line": 1, "snippet": "request.args"},
            {"role": "guard", "file": "svc.py", "line": 4, "snippet": "clean()"},
            {"role": "sink", "file": "svc.py", "line": 9, "snippet": "render()"},
        ],
        "poc_trace": [
            {"file": "input.py", "line": 1, "action": "input"},
            {"file": "svc.py", "line": 4, "action": "guard evaluated"},
            {"file": "svc.py", "line": 9, "action": "sink reached"},
        ],
        "why_guard_fails": "clean() skips encoded angle brackets",
    }
    out.update(overrides)
    return out


def patches():
    return {"F1": {"path": "patches/F1.patch", "status": "patch_written", "text": "diff"}}


class AdvisoryCardTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.report = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def document(self, finding_obj=None, patch_map=None):
        return render_document(
            "kuron-panel",
            "abc123",
            {},
            [finding_obj or finding()],
            [],
            {},
            patches() if patch_map is None else patch_map,
        )

    def test_card_contains_all_advisory_sections(self):
        doc = self.document()
        self.assertIn("## Kept Findings", doc)
        self.assertIn("> [!WARNING]", doc)
        self.assertIn("| Severity | CWE | Sink (`file:line`) | Panel Verdict | Patch Status |", doc)
        self.assertIn("`3/3 TRUE_POSITIVE`", doc)
        self.assertIn("`patches/F1.patch` (ready)", doc)
        self.assertIn("**Flow:**", doc)
        for role in ("source", "guard", "sink"):
            self.assertIn(f"`{role}`", doc)
        self.assertIn("```mermaid", doc)
        self.assertIn("**poc_trace**", doc)
        self.assertIn("**why_guard_fails**", doc)
        self.assertIn("> clean\\(\\) skips encoded angle brackets", doc)
        self.assertIn("<details>", doc)
        self.assertIn("| `R` (Reachability) | `TP` |", doc)
        self.assertIn("| `I` (Impact) | `TP` |", doc)
        self.assertIn("| `D` (Defenses) | `TP` |", doc)

    def test_flow_is_one_line_and_trace_steps_render(self):
        doc = self.document()
        flow = next(line for line in doc.splitlines() if line.startswith("**Flow:**"))
        self.assertIn("`source` (`input.py:1`) -> `guard` (`svc.py:4`) -> `sink` (`svc.py:9`)", flow)
        self.assertIn("- `input.py:1` — input", doc)
        self.assertIn("- `svc.py:9` — sink reached", doc)

    def test_poc_trace_object_form_renders_without_keyerror(self):
        # SKILL documents the object form; the renderer used to slice the dict
        # directly and raised KeyError: slice(None, 64, None).
        obj_finding = finding(
            poc_trace={
                "steps": [
                    {"file": "input.py", "line": 1, "action": "input"},
                    {"file": "svc.py", "line": 4, "action": "guard evaluated"},
                    {"file": "svc.py", "line": 9, "action": "sink reached"},
                ],
                "preconditions": ["authenticated user", "debug mode enabled"],
                "why_guard_fails": "nested guard bypass",
            },
            preconditions=None,
            why_guard_fails=None,
        )
        doc = self.document(obj_finding)
        self.assertIn("- `input.py:1` — input", doc)
        self.assertIn("- `svc.py:9` — sink reached", doc)
        self.assertIn("- authenticated user", doc)
        self.assertIn("> nested guard bypass", doc)

    def test_poc_trace_string_form_renders_without_keyerror(self):
        doc = self.document(finding(poc_trace="single free-text step"))
        self.assertIn("- single free-text step", doc)

    def test_patch_status_none_when_no_patch(self):
        doc = self.document(patch_map={})
        self.assertIn("| none |", doc)
        self.assertNotIn("patches/F1.patch", doc)

    def test_panel_verdicts_missing_lens_shown_as_unknown(self):
        doc = self.document(finding(panel_verdicts={"R": "TRUE_POSITIVE"}))
        self.assertIn("| `R` (Reachability) | `TP` |", doc)
        self.assertIn("| `I` (Impact) | `?` |", doc)
        self.assertIn("| `D` (Defenses) | `?` |", doc)

    def test_markdown_injection_is_escaped(self):
        hostile = finding(
            title="[click](http://evil) # inject\n```\n> callout",
            description="<script>alert(1)</script> | col",
            why_guard_fails="![img](http://evil/x) ~~strike~~",
        )
        doc = self.document(hostile)
        self.assertNotIn("[click](http://evil)", doc)
        self.assertNotIn("<script>", doc)
        self.assertNotIn("```\n> callout", doc)
        self.assertIn("\\[click\\]\\(http://evil\\)", doc)
        self.assertIn("\\<script\\>", doc)
        self.assertIn("\\| col", doc)
        self.assertIn("\\!\\[img\\]\\(http://evil/x\\)", doc)

    def test_mermaid_injection_is_escaped(self):
        hostile = finding(
            taint_path=[
                {"role": "source", "file": 'evil.py"]; alert(1); //', "line": 1},
                {"role": "guard", "file": "svc.py", "line": 4},
                {"role": "sink", "file": "svc.py", "line": 9},
            ]
        )
        doc = self.document(hostile)
        graph = doc.split("```mermaid", 1)[1].split("```", 1)[0]
        source_line = next(line for line in graph.splitlines() if line.startswith("  S["))
        self.assertIn("flowchart LR", graph)
        self.assertTrue(source_line.startswith('  S["source: '))
        self.assertNotIn("alert(1)", source_line)
        self.assertNotIn(";", source_line)
        self.assertNotIn("\\", source_line)

    def test_render_markdown_writes_product(self):
        render_markdown(str(self.report), "kuron-panel", "abc123", {}, [finding()], [], {}, patches())
        text = (self.report / "KURON-SECURITY-RESULTS.md").read_text(encoding="utf-8")
        self.assertIn("> [!WARNING]", text)
        self.assertIn("**poc_trace**", text)

    def test_ascii_meter_fix_still_intact(self):
        self.assertEqual(METER_WIDTH, 20)
        self.assertEqual(_meter_filled(1, 8), 3)  # half-up, not banker's rounding
        self.assertEqual(_meter_filled(5, 5), METER_WIDTH)

    def test_md_helper_is_deterministic(self):
        self.assertEqual(_md("a | b"), "a \\| b")
        self.assertEqual(_md("x\ny\tz"), "x y z")


if __name__ == "__main__":
    unittest.main()
