import json
import os
import tempfile
import unittest
from pathlib import Path

from kuron_trace import (
    MAX_OUTPUT_BYTES,
    CommandNotAllowed,
    _git_isolated_env,
    _validate_command,
    verify_command,
)


class TraceHardeningTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # #1 - arbitrary Python expression slot is gone
    def test_python_c_rejected(self):
        for cmd in (
            'python3 -c "import os; print(os.environ)"',
            "python3 -c 'print(1)'",
        ):
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    # #2 - sed e/w and unsafe flags
    def test_sed_exec_and_write_scripts_rejected(self):
        (self.root / "f.txt").write_text("x\n", encoding="utf-8")
        unsafe = [
            "sed -n '1e id' f.txt",
            "sed -n 'e id' f.txt",
            "sed -n 'w /tmp/pwn' f.txt",
            "sed -n '1,5w /tmp/pwn' f.txt",
            "sed -n 's/x/y/w /tmp/pwn' f.txt",
            "sed -n 's/x/y/e' f.txt",
            "sed -n '/err/e' f.txt",
        ]
        for cmd in unsafe:
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    def test_sed_validator_bypass_payloads_rejected(self):
        (self.root / "f.txt").write_text("x\n", encoding="utf-8")
        bypasses = [
            "sed -n '1!e' f.txt",
            "sed -n '1!e id' f.txt",
            "sed -n '1!w' f.txt",
            "sed -n '1!w /tmp/pwn' f.txt",
            "sed -n '0~2w' f.txt",
            "sed -n '0~2w /tmp/pwn' f.txt",
            "sed -n '/a/!w' f.txt",
            "sed -n '/a/!w /tmp/pwn' f.txt",
            "sed -n '/a/Me' f.txt",
            "sed -n '/a/Me id' f.txt",
        ]
        for cmd in bypasses:
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    def test_sed_safe_script_accepted(self):
        (self.root / "f.txt").write_text("x\n", encoding="utf-8")
        argv = _validate_command("sed -n '1,5p' f.txt", str(self.root))
        self.assertEqual(argv, ["sed", "-n", "1,5p", "f.txt"])

    def test_sed_in_place_and_script_file_rejected(self):
        for cmd in (
            "sed -n -i 's/x/y/' f.txt",
            "sed -n -f script.sed f.txt",
            "sed -n --in-place 's/x/y/' f.txt",
        ):
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    # #2 - git grep pager / external command
    def test_git_grep_pager_flags_rejected(self):
        for cmd in (
            "git grep -O sh foo",
            "git grep --open-files-in-pager sh foo",
            "git grep --pager sh foo",
            "git grep --ext-command sh foo",
        ):
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    def test_grep_recursive_flags_rejected(self):
        for cmd in ("grep -r x .", "grep -R x .", "grep --recursive x ."):
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    # #2 - path confinement
    def test_absolute_path_outside_root_rejected(self):
        with self.assertRaises(CommandNotAllowed):
            _validate_command(f"grep -n x {self.root}/../outside.txt", str(self.root))
        with self.assertRaises(CommandNotAllowed):
            _validate_command("nl /etc/passwd", str(self.root))

    def test_relative_traversal_rejected(self):
        with self.assertRaises(CommandNotAllowed):
            _validate_command("nl ../../etc/passwd", str(self.root))

    def test_git_show_colon_path_confined(self):
        _validate_command("git show HEAD:f.txt", str(self.root))
        with self.assertRaises(CommandNotAllowed):
            _validate_command("git show HEAD:../../etc/passwd", str(self.root))

    def test_safe_commands_accepted(self):
        for cmd in (
            "git show --stat HEAD",
            "git grep -n -I needle",
            "grep -n needle f.txt",
            "nl -ba f.txt",
        ):
            with self.subTest(cmd=cmd):
                self.assertIsInstance(_validate_command(cmd, str(self.root)), list)

    # ast-grep: read-only queries only
    def test_sg_readonly_queries_accepted(self):
        for cmd in (
            "sg run -p 'foo($X)' --lang python f.txt",
            "sg scan --pattern foo --lang py --json f.txt",
            "sg scan --pattern=foo --json=compact --globs '*.py'",
        ):
            with self.subTest(cmd=cmd):
                self.assertIsInstance(_validate_command(cmd, str(self.root)), list)

    def test_sg_mutation_interactive_and_path_escapes_rejected(self):
        for cmd in (
            "sg run -p foo -r f.txt",
            "sg run -p foo --rewrite 'bar' f.txt",
            "sg run -p foo -U f.txt",
            "sg run -p foo --update-all f.txt",
            "sg run -p foo -i f.txt",
            "sg run -p foo --interactive f.txt",
            "sg run -p foo --debug-query f.txt",
            "sg run f.txt",
            "sg scan --lang py f.txt",
            "sg run -p foo ../../etc/passwd",
            "sg scan --pattern foo /etc/passwd",
        ):
            with self.subTest(cmd=cmd), self.assertRaises(CommandNotAllowed):
                _validate_command(cmd, str(self.root))

    # #2 - environment isolation
    def test_git_config_isolated_across_platforms(self):
        env = _git_isolated_env()
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_SYSTEM"], os.devnull)

    # #2 - output bound
    def test_output_is_capped_and_marked(self):
        (self.root / "big.txt").write_text("MATCH\n" * 60000, encoding="utf-8")
        result = verify_command(
            "grep -n MATCH big.txt", str(self.root), str(self.root / "trace.jsonl")
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(
            len(result["raw_output"].encode("utf-8", errors="replace")),
            MAX_OUTPUT_BYTES,
        )
        logged = json.loads((self.root / "trace.jsonl").read_text().strip())
        self.assertTrue(logged["truncated"])

    def test_small_output_not_marked_truncated(self):
        (self.root / "f.txt").write_text("hello\n", encoding="utf-8")
        result = verify_command(
            "grep -n hello f.txt", str(self.root), str(self.root / "trace.jsonl")
        )
        self.assertFalse(result["truncated"])
        self.assertIn("hello", result["raw_output"])
