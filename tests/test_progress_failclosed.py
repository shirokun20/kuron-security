import json
import tempfile
import unittest
from pathlib import Path

from kuron_progress import append_event, progress_line, validate_projection


class ProgressFailClosedTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_missing_progress_fails_closed(self):
        ok, missing = validate_projection(str(self.d))
        self.assertFalse(ok)
        self.assertEqual(missing, ["no progress events"])

    def test_empty_progress_fails_closed(self):
        (self.d / "progress.jsonl").write_text("", encoding="utf-8")
        ok, missing = validate_projection(str(self.d))
        self.assertFalse(ok)
        self.assertEqual(missing, ["empty progress stream"])

    def test_empty_trace_id_fails_closed(self):
        append_event(str(self.d), {"phase": "Research"})
        (self.d / "trace.jsonl").write_text("", encoding="utf-8")
        ok, missing = validate_projection(str(self.d))
        self.assertFalse(ok)
        self.assertIn("<missing trace_id>", missing)

    def test_missing_trace_file_fails_closed(self):
        append_event(str(self.d), {"trace_id": "t-1"})
        ok, missing = validate_projection(str(self.d))
        self.assertFalse(ok)
        self.assertEqual(missing, ["t-1"])

    def test_real_trace_id_passes(self):
        append_event(str(self.d), {"trace_id": "t-1"})
        (self.d / "trace.jsonl").write_text(json.dumps({"trace_id": "t-1"}) + "\n")
        self.assertEqual(validate_projection(str(self.d)), (True, []))

    def test_no_synthetic_local_ids(self):
        rec = append_event(str(self.d), {"phase": "Research"})
        self.assertEqual(rec["trace_id"], "")
        text = (self.d / "progress.jsonl").read_text()
        self.assertNotIn("local-", text)

    def test_lock_serializes_sequence(self):
        for _ in range(5):
            append_event(str(self.d), {"phase": "x"})
        seqs = [json.loads(line)["seq"] for line in (self.d / "progress.jsonl").read_text().splitlines()]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])
        self.assertTrue((self.d / ".progress.lock").exists())

    def test_default_label_is_unverified_single_pass(self):
        line = progress_line({})
        self.assertIn("unverified-single-pass", line)
