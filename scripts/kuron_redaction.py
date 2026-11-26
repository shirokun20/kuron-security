#!/usr/bin/env python3
"""Fail-closed redaction gate for Kuron Security v2.

Secret handling here is deterministic Python stdlib work. Raw credential
literals are never returned, printed, or sent to a model: callers receive only
pattern names, file paths, and line numbers.
"""

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

# Bounded resource limits for every on-disk operation in this module.
MAX_READ_BYTES = 256 * 1024
MAX_SCAN_FILES = 256
REDACTION_MARKER = "[REDACTED]"
ARTIFACT_SUFFIXES = (".md", ".json", ".jsonl", ".sarif", ".patch", ".txt")


def scan_secrets(text: str) -> list[str]:
    """Return the names of secret patterns found in ``text`` (empty means clean)."""
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def redact_text(text: str) -> tuple[str, list[str]]:
    """Replace secret matches with ``[REDACTED]`` and list the matched names.

    The returned names are deduplicated and ordered by first match position; the
    raw matched value is never included in either return value.
    """
    if not isinstance(text, str):
        raise TypeError("redact_text expects str")
    matches: list[tuple[int, int, int, str]] = []
    for position, (name, pattern) in enumerate(SECRET_PATTERNS):
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end(), position, name))
    if not matches:
        return text, []

    first_seen: dict[str, int] = {}
    for start, _end, position, name in sorted(matches, key=lambda m: (m[0], m[2])):
        first_seen.setdefault(name, start)
    names = [name for name, _ in sorted(first_seen.items(), key=lambda item: (item[1], item[0]))]

    # Merge overlapping matches so no part of a credential survives redaction.
    merged: list[list[int]] = []
    for start, end, _position, _name in sorted(matches, key=lambda m: (m[0], m[1])):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(REDACTION_MARKER)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), names


def _read_bounded(path: Path) -> tuple[str, bool]:
    """Read at most ``MAX_READ_BYTES`` bytes via a context manager.

    Returns ``(text, truncated)``; decoding is replace-only so binary content
    cannot raise or leak raw bytes into model context.
    """
    with path.open("rb") as handle:
        raw = handle.read(MAX_READ_BYTES + 1)
    truncated = len(raw) > MAX_READ_BYTES
    return raw[:MAX_READ_BYTES].decode("utf-8", errors="replace"), truncated


def _report_files(base: Path, artifacts: list[str] | None) -> tuple[list[Path], bool]:
    """Resolve the artifact list deterministically with a hard file-count cap."""
    if artifacts is None:
        candidates = sorted(
            p for p in base.iterdir()
            if p.is_file() and p.name != "redaction.json" and p.suffix in ARTIFACT_SUFFIXES
        )
    else:
        candidates = sorted((base / name for name in artifacts), key=str)
    truncated = len(candidates) > MAX_SCAN_FILES
    return candidates[:MAX_SCAN_FILES], truncated


def redact_report(report_dir: str, artifacts: list[str] | None = None) -> dict:
    """Scrub report artifacts offline and write deterministic ``redaction.json``.

    Only status, cleaned file names, and matched pattern metadata are recorded;
    no raw credential value is written to disk or returned to the caller.
    """
    base = Path(report_dir)
    base.mkdir(parents=True, exist_ok=True)
    files, walk_truncated = _report_files(base, artifacts)
    cleaned: list[str] = []
    matches: list[dict] = []
    truncated_files: list[str] = []
    unresolved_files: list[str] = []
    missing_files: list[str] = []

    for path in files:
        if not path.is_file():
            missing_files.append(path.name)
            continue
        text, truncated = _read_bounded(path)
        if truncated:
            # Never write a partial file back: fail closed instead.
            truncated_files.append(path.name)
            continue
        scrubbed, names = redact_text(text)
        if "not cleaned:" in text:
            unresolved_files.append(path.name)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(scrubbed)
        cleaned.append(path.name)
        if names:
            matches.append({"file": path.name, "patterns": names})

    status = "clean" if not (
        truncated_files or unresolved_files or missing_files or walk_truncated
    ) else "not_cleaned"
    payload = {
        "status": status,
        "cleaned_files": sorted(cleaned),
        "matches": matches,
        "missing_files": sorted(missing_files),
        "truncated_files": sorted(truncated_files),
        "unresolved_files": sorted(unresolved_files),
        "walk_truncated": walk_truncated,
    }
    (base / "redaction.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def scan_target(target: str) -> list[dict]:
    """Scan a file or directory, returning only ``file``, ``line``, and pattern names."""
    root = Path(target)
    if root.is_dir():
        found = sorted(p for p in root.rglob("*") if p.is_file())
        files = found[:MAX_SCAN_FILES]
        display = lambda p: str(p.relative_to(root))
    elif root.is_file():
        files = [root]
        display = lambda p: p.name
    else:
        raise RedactionError(f"scan target does not exist: {root}")

    records: list[dict] = []
    for path in files:
        text, _truncated = _read_bounded(path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            names = scan_secrets(line)
            if names:
                records.append({"file": display(path), "line": line_number, "patterns": names})
    return records


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
    s = sub.add_parser(
        "scan", help="scan a file or directory; emit file:line + pattern names only"
    )
    s.add_argument("path", nargs="?")
    s.add_argument("--text", help="scan inline text (legacy, emits pattern names only)")
    sc = sub.add_parser(
        "scrub", help="scrub report artifacts offline and write redaction.json"
    )
    sc.add_argument("report_dir")
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
            if args.text is not None:
                result: dict | list = scan_secrets(args.text)
            else:
                result = scan_target(args.path)
        elif args.command == "scrub":
            result = redact_report(args.report_dir)
        else:
            enforce(args.report_dir, args.artifacts)
            result = {"ok": True}
    except (OSError, RedactionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    if args.command == "scrub" and result["status"] != "clean":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
