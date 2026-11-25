#!/usr/bin/env python3
"""Fail-closed redaction gate for Kuron Security v2."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class RedactionError(Exception):
    """Raised when redaction verdict is missing, not clean, or an artifact is unredacted."""


# Independent stdlib secret scan: this is deliberately separate from the
# agent-written redaction.json verdict, which is trusted only as a claim.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # Anthropic keys are checked first so the openai pattern can exclude them.
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    (
        "google-api-key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    ),
    (
        "gitlab-pat",
        re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    ),
)


def scan_secrets(text: str) -> list[str]:
    """Return the names of secret patterns found in ``text`` (empty means clean)."""
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def verdict(report_dir: str) -> dict:
    """Read redaction.json from report_dir and return {status, cleaned_files}."""
    vpath = Path(report_dir) / "redaction.json"
    if not vpath.exists():
        raise RedactionError(f"Missing redaction verdict file: {vpath}")
    try:
        data = json.loads(vpath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RedactionError(f"Invalid redaction.json: {exc}") from exc
    if not isinstance(data, dict) or "status" not in data:
        raise RedactionError("redaction.json must be a JSON object with 'status'")
    return {
        "status": data.get("status"),
        "cleaned_files": list(data.get("cleaned_files") or []),
    }


def enforce(report_dir: str, artifacts: list[str]) -> None:
    """Fail closed if redaction status != 'clean', any artifact is missing, or 'not cleaned:' appears."""
    v = verdict(report_dir)
    if v["status"] != "clean":
        raise RedactionError(f"Redaction failed: status is '{v['status']}' (expected 'clean')")

    base = Path(report_dir)
    for name in artifacts:
        p = base / name
        if not p.exists():
            raise RedactionError(f"Expected redacted artifact missing: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
        if "not cleaned:" in text:
            raise RedactionError(f"Unredacted marker 'not cleaned:' found in {p}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kuron Security redaction gate")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="list secret pattern names found in text or a file")
    s.add_argument("path", nargs="?")
    s.add_argument("--text")
    e = sub.add_parser("enforce", help="fail closed on an unredacted report")
    e.add_argument("report_dir")
    e.add_argument("artifacts", nargs="*")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            if (args.path is None) == (args.text is None):
                print("error: provide exactly one of path or --text", file=sys.stderr)
                return 2
            text = (
                args.text if args.text is not None
                else Path(args.path).read_text(encoding="utf-8", errors="replace")
            )
            result = scan_secrets(text)
        else:
            enforce(args.report_dir, args.artifacts)
            result = {"ok": True}
    except (OSError, RedactionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
