import io
import json
import tempfile
import unittest
from pathlib import Path

from kuron_progress import (
    ProgressRenderer,
    append_event,
    detect_terminal,
    elapsed_text,
    progress_line,
    sanitize,
    validate_projection,
)


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class ProgressTest(unittest.TestCase):
    def test_detect_non_tty_is_file_mode(self):
        info = detect_terminal(io.StringIO(), env={"TERM": "xterm"})
        self.assertEqual(info["mode"], "file")
        self.assertFalse(info["tty"])

    def test_detect_ci_overrides_tty(self):
        info = detect_terminal(FakeTty(), env={"TERM": "xterm", "CI": "1"})
        self.assertEqual(info["mode"], "file")

    def test_detect_dumb_terminal_falls_back_to_append(self):
        info = detect_terminal(FakeTty(), env={"TERM": "dumb"})
        self.assertEqual(info["mode"], "append")

    def test_sanitize_strips_ansi_and_control_chars(self):
        self.assertEqual(sanitize("a\x1b[31mb\x00c\n d"), "abc d")

    def test_elapsed_text(self):
        self.assertEqual(elapsed_text(0), "0s")
        self.assertEqual(elapsed_text(95000), "1m35s")

    def test_append_event_assigns_seq_and_ts(self):
        with tempfile.TemporaryDirectory() as d:
            first = append_event(d, {"phase": "Research", "status": "working"})
            second = append_event(d, {"phase": "Panel", "status": "done"})
            self.assertEqual((first["seq"], second["seq"]), (1, 2))
            self.assertEqual(first["trace_id"], "local-1")
            self.assertTrue(first["ts"].endswith("+00:00"))
            lines = (Path(d) / "progress.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 2)

    def test_progress_line_is_ascii_and_clamped(self):
        line = progress_line(
            {"label": "kuron-panel", "phase": "2", "phase_total": "3",
             "done": 22, "total": 48, "elapsed_ms": 134000,
             "message": "\x1b[31m🛡️ " + "x" * 200},
            width=40,
        )
        self.assertTrue(line.isascii(), line)
        self.assertLessEqual(len(line), 39)
        self.assertIn("22/48", line)

    def test_file_mode_keeps_stream_clean(self):
        stream = io.StringIO()
        renderer = ProgressRenderer(stream=stream, mode="file", min_interval_ms=0)
        renderer.render({"phase": "1", "done": 1, "total": 2})
        self.assertEqual(stream.getvalue(), "")
        renderer.finish("scan complete")
        self.assertIn("scan complete", stream.getvalue())

    def test_append_mode_writes_each_line(self):
        stream = io.StringIO()
        renderer = ProgressRenderer(stream=stream, mode="append", min_interval_ms=0)
        renderer.render({"phase": "1", "done": 1, "total": 2})
        renderer.render({"phase": "2", "done": 2, "total": 2})
        self.assertEqual(len(stream.getvalue().strip().splitlines()), 2)

    def test_live_mode_throttles_and_clears(self):
        stream = io.StringIO()
        renderer = ProgressRenderer(stream=stream, mode="live", min_interval_ms=60000)
        renderer.render({"phase": "1", "done": 1, "total": 2})
        renderer.render({"phase": "1", "done": 2, "total": 2})
        self.assertEqual(stream.getvalue().count("\r\x1b[2K"), 1)
        renderer.finish("scan complete")
        self.assertTrue(stream.getvalue().endswith("scan complete\n"))

    def test_validate_projection_requires_trace_event(self):
        with tempfile.TemporaryDirectory() as d:
            append_event(d, {"trace_id": "t-1", "phase": "Research"})
            ok, missing = validate_projection(d)
            self.assertFalse(ok)
            self.assertEqual(missing, ["t-1"])
            (Path(d) / "trace.jsonl").write_text(json.dumps({"trace_id": "t-1"}) + "\n")
            ok, missing = validate_projection(d)
            self.assertTrue(ok)
            self.assertEqual(missing, [])
