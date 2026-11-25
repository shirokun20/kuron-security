#!/usr/bin/env python3
"""Trace ledger and read-only allowlisted verification command runner for Kuron Security v2.

Security boundary: only a fixed set of read-only commands is accepted, every
argument is validated against a per-command flag policy, path-like arguments are
realpath-confined to the scan root, git is launched with isolated configuration,
and captured output is bounded. This module is the enforcement layer that binds
on every harness, regardless of whether agent frontmatter ``tools:`` is honored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# "python3 -c" was removed deliberately: an expression slot is arbitrary code
# execution and cannot be constrained by a token filter (shell=False ignores it).
ALLOWLIST: tuple[str, ...] = (
    "git show",
    "git grep",
    "grep",
    "nl",
    "sed -n",
    "sg",
)

_FORBIDDEN_SHELL_TOKENS = (";", "&&", "|", ">", "<", "`", "$(")
MAX_OUTPUT_BYTES = 256 * 1024

# ast-grep is accepted only as a read-only query: run/scan subcommands, query
# flags, and realpath-confined paths. Rewrite/interactive/debug-query flags are
# denied explicitly rather than silently ignored.
_SG_SUBCOMMANDS = ("run", "scan")
_SG_VALUE_FLAGS = frozenset({"--pattern", "-p", "--lang", "-l", "--globs"})
_SG_BOOL_FLAGS = frozenset({"--json"})
_SG_PREFIXES = ("--pattern=", "--json=", "--globs=")
_SG_DENY = frozenset(
    {
        "--rewrite", "-r", "-U", "--update-all", "-i", "--interactive",
        "--debug-query",
    }
)

# Per-command argv policy. ``flags`` are exact allowed switches; ``prefixes``
# are allowed switches that carry an attached value (``--format=...``); ``deny``
# is checked first and documents the dangerous switches that must never pass.
_COMMAND_SPECS: dict[str, dict] = {
    "git show": {
        "flags": frozenset(
            {
                "--stat",
                "--shortstat",
                "--numstat",
                "--summary",
                "--name-only",
                "--name-status",
                "--no-patch",
                "-s",
                "--oneline",
                "--no-color",
                "--abbrev-commit",
                "--decorate",
                "--no-decorate",
                "--no-renames",
                "--find-renames",
                "--first-parent",
                "--full-history",
            }
        ),
        "prefixes": ("--format=", "--pretty=", "--abbrev=", "--max-count=", "-L", "-n"),
        "deny": frozenset({"--output", "--output=", "--save", "--ext-diff", "--exec"}),
        "max_args": 12,
        "confine_colon_paths": True,
    },
    "git grep": {
        "flags": frozenset(
            {
                "-n",
                "-I",
                "-i",
                "-E",
                "-F",
                "-P",
                "-w",
                "-v",
                "-c",
                "-o",
                "-l",
                "-L",
                "-e",
                "-f",
                "--no-color",
                "--color=never",
                "--fixed-strings",
                "--extended-regexp",
                "--perl-regexp",
                "--ignore-case",
                "--line-number",
                "--files-with-matches",
                "--untracked",
            }
        ),
        "prefixes": ("--color=", "--max-count=", "--thread"),
        "deny": frozenset(
            {
                "-O",
                "--open-files-in-pager",
                "--pager",
                "--ext-command",
                "--no-index",
                "--no-pager",
            }
        ),
        "max_args": 16,
        "confine_colon_paths": False,
    },
    "grep": {
        "flags": frozenset(
            {
                "-n",
                "-i",
                "-I",
                "-E",
                "-F",
                "-w",
                "-v",
                "-c",
                "-o",
                "-l",
                "-L",
                "-a",
                "-e",
                "-f",
                "--no-color",
                "--color=never",
                "--text",
                "--binary-files=without-match",
            }
        ),
        "prefixes": ("--include=", "--exclude=", "--exclude-dir=", "--color=", "--binary-files="),
        "deny": frozenset(
            {
                "-r",
                "-R",
                "--recursive",
                "--dereference-recursive",
                "--devices",
                "-D",
                "-d",
                "--directories",
            }
        ),
        "max_args": 16,
        "confine_colon_paths": False,
    },
    "nl": {
        "flags": frozenset(
            {"-ba", "-bt", "-bn", "-bc", "-nln", "-nrn", "-nrz", "-p"}
        ),
        "prefixes": ("-w", "-s", "-v"),
        "deny": frozenset(),
        "max_args": 12,
        "confine_colon_paths": False,
    },
    "sed -n": {
        "flags": frozenset(),
        "prefixes": (),
        "deny": frozenset(),
        "max_args": 12,
        "confine_colon_paths": False,
    },
    "sg": {
        "flags": _SG_BOOL_FLAGS,
        "prefixes": _SG_PREFIXES,
        "deny": _SG_DENY,
        "max_args": 16,
        "confine_colon_paths": False,
    },
}


class CommandNotAllowed(Exception):
    """Raised when a verification command violates the read-only allowlist."""


def append(trace_path: str, event: dict) -> None:
    """Append a single JSON event line to trace.jsonl."""
    p = Path(trace_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=False) + "\n")


def _confine_path(token: str, root: str) -> None:
    """Reject any path-like token whose realpath escapes the realpath'd scan root."""
    root_real = os.path.realpath(root)
    candidate = token if os.path.isabs(token) else os.path.join(root_real, token)
    resolved = os.path.realpath(candidate)
    if resolved != root_real and not resolved.startswith(root_real + os.sep):
        raise CommandNotAllowed(
            f"Path {token!r} escapes the scan root ({root_real})"
        )


_SED_PRINT_ONLY = re.compile(r"^[0-9]+(,[0-9]+)?p$")


def _sed_script_safe(script: str) -> bool:
    """Return True if a sed script is strictly a print-range command (e.g. '1,5p' or '42p').

    Any other command, addressing form, substitution, execution (e), or file write (w)
    is rejected by default to prevent validator bypasses.
    """
    return bool(_SED_PRINT_ONLY.match(script.strip()))


def _validate_sg_argv(rest: list[str], root: str) -> None:
    """Validate an ast-grep query: read-only flags, bounded args, confined paths."""
    if not rest or rest[0] not in _SG_SUBCOMMANDS:
        raise CommandNotAllowed("sg requires the read-only 'run' or 'scan' subcommand")
    args = rest[1:]
    spec = _COMMAND_SPECS["sg"]
    if len(args) > spec["max_args"]:
        raise CommandNotAllowed(f"Too many arguments for 'sg' (max {spec['max_args']})")
    has_pattern = False
    idx = 0
    while idx < len(args):
        token = args[idx]
        idx += 1
        if token in _SG_DENY or token.split("=", 1)[0] in _SG_DENY:
            raise CommandNotAllowed(f"Flag {token!r} is explicitly denied for 'sg'")
        if token in _SG_VALUE_FLAGS:
            if idx >= len(args):
                raise CommandNotAllowed(f"Flag {token!r} requires a value")
            value = args[idx]
            idx += 1
            if value in _SG_DENY or value.split("=", 1)[0] in _SG_DENY:
                raise CommandNotAllowed(f"Flag {token!r} requires a safe value")
            if token in ("--pattern", "-p"):
                has_pattern = True
            continue
        if token in _SG_BOOL_FLAGS or token.startswith(_SG_PREFIXES):
            if token.startswith("--pattern="):
                has_pattern = True
            continue
        if token.startswith("-"):
            raise CommandNotAllowed(f"Flag {token!r} is not allowed for 'sg'")
        _confine_path(token, root)
    if not has_pattern:
        raise CommandNotAllowed("sg requires --pattern/-p for a read-only query")


def _validate_argv(argv: list[str], prefix: str, root: str) -> None:
    spec = _COMMAND_SPECS[prefix]
    rest = argv[len(prefix.split()) :]
    if len(rest) > spec["max_args"]:
        raise CommandNotAllowed(
            f"Too many arguments for '{prefix}' (max {spec['max_args']})"
        )
    if prefix == "sg":
        _validate_sg_argv(rest, root)
        return
    if prefix == "sed -n":
        if len(rest) < 2:
            raise CommandNotAllowed("sed -n requires a script and at least one file")
        script = rest[0]
        if script.startswith("-"):
            raise CommandNotAllowed("sed script flags are not allowed")
        if not _sed_script_safe(script):
            raise CommandNotAllowed(
                "sed script contains a shell-exec (e) or write (w/W) command"
            )
        for token in rest[1:]:
            if token.startswith("-") and token != "-":
                raise CommandNotAllowed(f"Flag {token!r} is not allowed for sed -n")
            _confine_path(token, root)
        return

    after_dashdash = False
    non_flag_count = 0
    for token in rest:
        if token == "--" and not after_dashdash:
            after_dashdash = True
            continue
        if not after_dashdash and token.startswith("-") and token != "-":
            if token in spec["deny"]:
                raise CommandNotAllowed(
                    f"Flag {token!r} is explicitly denied for '{prefix}'"
                )
            if any(token.startswith(p) for p in spec["deny"]):
                raise CommandNotAllowed(
                    f"Flag {token!r} is explicitly denied for '{prefix}'"
                )
            if token in spec["flags"]:
                continue
            if any(token.startswith(p) for p in spec["prefixes"]):
                continue
            raise CommandNotAllowed(f"Flag {token!r} is not allowed for '{prefix}'")
        non_flag_count += 1
        if spec["confine_colon_paths"] and ":" in token and not os.path.isabs(token):
            _rev, subpath = token.split(":", 1)
            if subpath:
                _confine_path(subpath, root)
        else:
            _confine_path(token, root)
    if non_flag_count == 0:
        raise CommandNotAllowed(f"'{prefix}' requires a pattern/path argument")


def _validate_command(command: str, root: str) -> list[str]:
    for tok in _FORBIDDEN_SHELL_TOKENS:
        if tok in command:
            raise CommandNotAllowed(f"Forbidden shell metacharacter '{tok}' in command")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise CommandNotAllowed(f"Malformed command syntax: {exc}") from exc
    if not argv:
        raise CommandNotAllowed("Empty command")

    matched: str | None = None
    for prefix in ALLOWLIST:
        prefix_tokens = prefix.split()
        if argv[: len(prefix_tokens)] == prefix_tokens:
            matched = prefix
            break
    if matched is None:
        raise CommandNotAllowed(f"Command '{argv[0]}' is not in read-only ALLOWLIST")
    _validate_argv(argv, matched, root)
    return argv


def _git_isolated_env() -> dict[str, str]:
    """Isolate git configuration from user/system files on every platform."""
    env = dict(os.environ)
    null = os.devnull  # /dev/null on POSIX, NUL on Windows
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = null
    env["GIT_CONFIG_SYSTEM"] = null
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def verify_command(command: str, cwd: str, trace_path: str) -> dict:
    """Execute an allowlisted read-only command, log to trace.jsonl, and return evidence dict.

    ``cwd`` is the scan root: every path-like argument is confined to its
    realpath. Output is capped at MAX_OUTPUT_BYTES with an explicit truncation
    marker so evidence never floods the trace ledger.
    """
    argv = _validate_command(command, cwd)
    proc = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=15,
        cwd=cwd,
        env=_git_isolated_env(),
    )
    data = (proc.stdout + proc.stderr).encode("utf-8", errors="replace")
    truncated = len(data) > MAX_OUTPUT_BYTES
    if truncated:
        data = data[:MAX_OUTPUT_BYTES]
    raw_output = data.decode("utf-8", errors="replace")
    trace_id = hashlib.sha256((command + raw_output).encode("utf-8")).hexdigest()[:12]
    result = {
        "command": command,
        "raw_output": raw_output,
        "exit_code": proc.returncode,
        "trace_id": trace_id,
        "truncated": truncated,
    }
    append(trace_path, {"event": "verify_command", **result})
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kuron Security read-only trace runner")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("append", help="append one JSON trace event")
    a.add_argument("trace_path")
    a.add_argument("event_json")
    v = sub.add_parser("verify", help="run an allowlisted read-only command")
    v.add_argument("command")
    v.add_argument("--cwd", required=True)
    v.add_argument("--trace", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "append":
            event = json.loads(args.event_json)
            if not isinstance(event, dict):
                raise ValueError("event_json must be a JSON object")
            append(args.trace_path, event)
            result = {"appended": True}
        else:
            result = verify_command(args.command, args.cwd, args.trace)
    except (CommandNotAllowed, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
