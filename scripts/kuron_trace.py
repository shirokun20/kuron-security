#!/usr/bin/env python3
"""Trace ledger and read-only allowlisted verification command runner for Kuron Security v2."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

ALLOWLIST: tuple[str, ...] = (
    "git show",
    "git grep",
    "grep",
    "nl",
    "sed -n",
    "python3 -c",
)

_FORBIDDEN_SHELL_TOKENS = (";", "&&", "|", ">", "<", "`", "$(")


class CommandNotAllowed(Exception):
    """Raised when a verification command violates the read-only allowlist."""


def append(trace_path: str, event: dict) -> None:
    """Append a single JSON event line to trace.jsonl."""
    p = Path(trace_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=False) + "\n")


def _validate_command(command: str) -> list[str]:
    for tok in _FORBIDDEN_SHELL_TOKENS:
        if tok in command:
            raise CommandNotAllowed(f"Forbidden shell metacharacter '{tok}' in command")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise CommandNotAllowed(f"Malformed command syntax: {exc}") from exc
    if not argv:
        raise CommandNotAllowed("Empty command")

    allowed = False
    for prefix in ALLOWLIST:
        prefix_tokens = prefix.split()
        if argv[: len(prefix_tokens)] == prefix_tokens:
            allowed = True
            break
    if not allowed:
        raise CommandNotAllowed(f"Command '{argv[0]}' is not in read-only ALLOWLIST")
    return argv


def verify_command(command: str, cwd: str, trace_path: str) -> dict:
    """Execute an allowlisted read-only command, log to trace.jsonl, and return evidence dict."""
    argv = _validate_command(command)
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    proc = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=15,
        cwd=cwd,
        env=env,
    )
    raw_output = proc.stdout + proc.stderr
    trace_id = hashlib.sha256((command + raw_output).encode("utf-8")).hexdigest()[:12]
    result = {
        "command": command,
        "raw_output": raw_output,
        "exit_code": proc.returncode,
        "trace_id": trace_id,
    }
    append(trace_path, {"event": "verify_command", **result})
    return result
