import json
import os
import tempfile
import unittest
from pathlib import Path
from kuron_trace import ALLOWLIST, CommandNotAllowed, append, verify_command


class TraceTest(unittest.TestCase):
    def test_allowlist_exact(self):
        self.assertEqual(
            ALLOWLIST,
            ("git show", "git grep", "grep", "nl", "sed -n", "sg"),
        )

    def test_append_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "trace.jsonl"
            append(str(t), {"event": "dispatch", "worker": "r1"})
            self.assertEqual(json.loads(t.read_text().strip())["worker"], "r1")

    def test_verify_command_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(CommandNotAllowed):
                verify_command("rm -rf /", d, str(Path(d) / "t.jsonl"))
            with self.assertRaises(CommandNotAllowed):
                verify_command("grep foo bar.py; rm -rf /", d, str(Path(d) / "t.jsonl"))
            with self.assertRaises(CommandNotAllowed):
                verify_command("grep foo bar.py | cat", d, str(Path(d) / "t.jsonl"))

    def test_verify_command_captures_exit_code_and_logs(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "t.jsonl"
            r = verify_command("grep -n XYZZY_NOT_PRESENT_12345 scripts/kuron_trace.py", os.getcwd(), str(t))
            self.assertNotEqual(r["exit_code"], 0)
            self.assertEqual(len(r["trace_id"]), 12)
            logged = json.loads(t.read_text().strip())
            self.assertEqual(logged["trace_id"], r["trace_id"])
            self.assertEqual(logged["exit_code"], r["exit_code"])
