#!/usr/bin/env python3
"""Fail-closed redaction gate for Kuron Security v2."""

from __future__ import annotations

import json
from pathlib import Path


class RedactionError(Exception):
    """Raised when redaction verdict is missing, not clean, or an artifact is unredacted."""


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
