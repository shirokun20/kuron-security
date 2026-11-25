#!/usr/bin/env python3
"""Deterministic SARIF 2.1.0 builder for Kuron Security findings.

Vendored clean-room; no plugin-cache imports, no runtime dependencies. Adds
stable primary-location fingerprints, taint-path code flows and optional
patch-derived fixes on top of the original rule/result shape.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

from kuron_quorum import compute_panel_tally

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_SEMANTIC_VERSION = "2.3.1"

_MAX_TAINT_STEPS = 64
_MAX_PATCH_LINES = 2000
_MAX_TEXT = 2048
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _line(value) -> int:
    try:
        return max(int(value) if value is not None else 1, 1)
    except (TypeError, ValueError):
        return 1


def _safe_uri(value) -> str:
    """Keep patch/file paths relative, POSIX and bounded."""
    text = str(value or "").strip().replace("\\", "/")
    return "/".join(seg for seg in text.split("/") if seg not in ("", ".", ".."))[:200]


def _location_fingerprint(rule_id: str, record: dict) -> str:
    """sha256(ruleId|file|symbol_or_line) - stable across reordering."""
    file = str(record.get("file") or "")
    symbol = record.get("symbol") or record.get("function") or record.get("line")
    raw = f"{rule_id}|{file}|{symbol if symbol is not None else ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _code_flows(record: dict) -> list[dict]:
    """Model taint_path[] as one threadFlow of ordered source/guard/sink steps."""
    steps = record.get("taint_path") or []
    if not isinstance(steps, list):
        return []
    locations: list[dict] = []
    for step in steps[:_MAX_TAINT_STEPS]:
        if not isinstance(step, dict):
            continue
        physical = {
            "artifactLocation": {"uri": _safe_uri(step.get("file"))},
            "region": {"startLine": _line(step.get("line"))},
        }
        snippet = str(step.get("snippet") or "")[:_MAX_TEXT]
        if snippet:
            physical["region"]["snippet"] = {"text": snippet}
        location: dict = {"physicalLocation": physical}
        action = str(step.get("action") or "")[:_MAX_TEXT]
        if action:
            location["message"] = {"text": action}
        locations.append(
            {
                "location": location,
                "kinds": ["taint"],
                "properties": {"role": str(step.get("role") or "")[:64]},
            }
        )
    return [{"threadFlows": [{"locations": locations}]}] if locations else []


def _diff_changes(text: str, file_hint: str = "") -> list[dict]:
    """Convert a bounded unified diff into SARIF artifactChanges (per hunk)."""
    hunks: list[dict] = []
    uri = _safe_uri(file_hint)
    current = None
    for raw in text.splitlines()[:_MAX_PATCH_LINES]:
        if raw.startswith("+++ "):
            candidate = raw[4:].split("\t", 1)[0].strip()
            if candidate and candidate != "/dev/null":
                uri = _safe_uri(candidate[2:] if candidate.startswith("b/") else candidate)
        elif raw.startswith("@@"):
            if current:
                hunks.append(current)
            match = _HUNK_RE.match(raw)
            if not match:
                current = None
                continue
            start = max(1, int(match.group(1)))
            count = max(1, int(match.group(2) or 1))
            current = {
                "uri": uri,
                "start": start,
                "end": start + count - 1,
                "added": [],
            }
        elif current is not None and raw.startswith("+") and not raw.startswith("+++"):
            current["added"].append(raw[1:][:_MAX_TEXT])
    if current:
        hunks.append(current)

    changes: list[dict] = []
    seen: set[tuple] = set()
    for hunk in hunks:
        if not hunk["uri"] or (hunk["uri"], hunk["start"]) in seen:
            continue
        seen.add((hunk["uri"], hunk["start"]))
        inserted = "\n".join(hunk["added"])
        changes.append(
            {
                "artifactLocation": {"uri": hunk["uri"]},
                "replacements": [
                    {
                        "deletedRegion": {
                            "startLine": hunk["start"],
                            "endLine": hunk["end"],
                        },
                        "insertedContent": {
                            "text": inserted + ("\n" if inserted else "")
                        },
                    }
                ],
            }
        )
    return changes


def _sarif_fix(record: dict, patches: dict | None) -> dict | None:
    if not isinstance(patches, dict):
        return None
    fid = str(record.get("id") or "")
    info = patches.get(fid)
    if not isinstance(info, dict):
        return None
    changes = _diff_changes(str(info.get("text") or ""), str(record.get("file") or ""))
    if not changes:
        return None
    return {
        "description": {"text": f"Patch for {fid}"},
        "artifactChanges": changes,
        "properties": {
            "path": str(info.get("path") or ""),
            "status": str(info.get("status") or ""),
        },
    }


def _build_sarif_log(
    records: list[dict],
    label: str,
    att: dict,
    discarded_count: int = 0,
    patches: dict | None = None,
) -> dict:
    """Deterministic SARIF 2.1.0 with one rule descriptor per used ruleId."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for r in records:
        rule_id = str(r.get("cwe_id") or r.get("cweId") or r.get("id") or "KURON")
        level = (
            "error"
            if str(r.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            else "warning"
        )
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {
                    "text": str(r.get("title") or r.get("description") or rule_id)
                },
                "fullDescription": {
                    "text": str(r.get("description") or r.get("title") or rule_id)
                },
                "defaultConfiguration": {"level": level},
            }
        tally = r.get("panel_tally") or compute_panel_tally(r)
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": str(r.get("title") or r.get("description") or r.get("id"))
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _safe_uri(r.get("file"))},
                        "region": {"startLine": _line(r.get("line"))},
                    }
                }
            ],
            "partialFingerprints": {
                "kuronPrimaryLocationHash": _location_fingerprint(rule_id, r)
            },
            "properties": {
                "id": r.get("id"),
                "severity": r.get("severity"),
                "label": label,
                "panel_tally": {
                    "R": tally.get("R"),
                    "I": tally.get("I"),
                    "D": tally.get("D"),
                    "ran": tally.get("ran"),
                    "unanimous_tp": tally.get("unanimous_tp"),
                },
            },
        }
        flows = _code_flows(r)
        if flows:
            result["codeFlows"] = flows
        fix = _sarif_fix(r, patches)
        if fix:
            result["fixes"] = [fix]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kuron Security",
                        "semanticVersion": SARIF_SEMANTIC_VERSION,
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {
                    "engine": "kuron-security",
                    "builder": "vendored",
                    "verification": label,
                    "attestation": att,
                    "discarded_count": discarded_count,
                },
            }
        ],
    }


build_sarif_log = _build_sarif_log
# Backwards-compatible name for callers/tests that used the old private helper.
_fallback_sarif_log = _build_sarif_log


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a SARIF 2.1.0 log from findings")
    parser.add_argument("findings", help="JSON file holding a list of findings")
    parser.add_argument("--label", default="unverified-single-pass")
    args = parser.parse_args(argv)
    with open(args.findings, encoding="utf-8") as fh:
        records = json.load(fh)
    print(json.dumps(_build_sarif_log(records, args.label, {}), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli())
