#!/usr/bin/env python3
"""Scan input intake: load, normalize, validate and dedupe findings.

Kept verbatim from the original products orchestrator so the JSONL contract,
discard reasons and exit codes are unchanged. Clean-room, stdlib-only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from kuron_capabilities import select_path
from kuron_evidence import validate_finding
from kuron_policy import attestation as policy_attestation
from kuron_policy import validate as validate_policy

VALID_LABELS = ("kuron-panel", "ad-hoc-panel", "unverified-single-pass")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def load_raw(path: str, default=None):
    if not os.path.exists(path):
        return [] if default is None else default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(raw: dict, index: int, default_label: str = "unverified-single-pass") -> dict | None:
    out = dict(raw)
    out.setdefault("id", f"F{index + 1}")
    if "cwe_id" not in out and "cweId" in out:
        out["cwe_id"] = out["cweId"]
    if "description" not in out and "rationale" in out:
        out["description"] = out["rationale"]
    if "exploit_scenario" not in out and "exploitScenario" in out:
        out["exploit_scenario"] = out["exploitScenario"]

    evidence = dict(out.get("evidence") or {})
    for key in (
        "taint_path",
        "reachability",
        "poc_trace",
        "verification",
        "independent_routes",
        "cwe_class",
        "preconditions",
        "why_guard_fails",
    ):
        if key in out and key not in evidence:
            evidence[key] = out[key]
    out["evidence"] = evidence

    # Fail closed: a missing or malformed label never asserts a panel ran.
    label = out.get("label") or default_label
    if label not in VALID_LABELS:
        label = default_label
    out["label"] = label
    out.setdefault("discarded", [])

    candidate = {**out, **evidence}
    ok, reasons = validate_finding(candidate)
    if not ok:
        out["discard_reason"] = "; ".join(reasons)
    return out


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (
            f.get("file", ""),
            f.get("line", 0),
            f.get("cwe_id") or f.get("cweId") or "",
        )
        if key not in merged:
            merged[key] = dict(f)
        else:
            existing = merged[key]
            old_sev = str(existing.get("severity", "LOW")).upper()
            new_sev = str(f.get("severity", "LOW")).upper()
            if SEVERITY_RANK.get(new_sev, 0) > SEVERITY_RANK.get(old_sev, 0):
                existing["severity"] = new_sev
            routes = list(
                dict.fromkeys(
                    list(existing.get("independent_routes") or [])
                    + list(f.get("independent_routes") or [])
                )
            )
            existing["independent_routes"] = routes
    return list(merged.values())


def _resolve_label(meta: dict) -> str:
    explicit = meta.get("label")
    if explicit in VALID_LABELS:
        return explicit
    caps = meta.get("capabilities")
    if isinstance(caps, dict):
        try:
            selected = select_path(
                caps,
                meta.get("tier") or "personal",
                meta.get("consent"),
            )
            return selected["label"]
        except Exception:
            return "unverified-single-pass"
    return "unverified-single-pass"


def _resolve_attestation(meta: dict) -> dict:
    if isinstance(meta.get("attestation"), dict):
        return meta["attestation"]
    policy_path = meta.get("policy_path")
    if policy_path and os.path.exists(policy_path):
        return policy_attestation(validate_policy(policy_path))
    return {}


def discover_patches(report_dir: str, findings: list[dict]) -> dict[str, dict]:
    """Map finding id -> on-disk patch metadata (bounded, symlink-safe).

    Only ``patches/<id>.patch`` files are trusted; self-reported patch fields in
    a finding are deliberately ignored so the advisory card shows real status.
    """
    patches_dir = os.path.join(report_dir, "patches")
    out: dict[str, dict] = {}
    if not os.path.isdir(patches_dir):
        return out
    root = os.path.realpath(patches_dir)
    try:
        with os.scandir(patches_dir) as entries:
            scanned = 0
            for entry in entries:
                scanned += 1
                if scanned > 512 or len(out) >= 256:  # cut-loop guard
                    break
                stem, ext = os.path.splitext(entry.name)
                if ext != ".patch" or not stem.startswith("F"):
                    continue
                if os.path.realpath(entry.path) != os.path.join(root, entry.name):
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                with open(entry.path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(65536)  # bounded patch text
                out[stem] = {
                    "id": stem,
                    "path": f"patches/{entry.name}",
                    "status": "patch_written",
                    "text": text,
                }
    except OSError:
        return out
    return out


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize and validate raw findings")
    parser.add_argument("findings", help="JSON file holding a list of raw findings")
    args = parser.parse_args(argv)
    with open(args.findings, encoding="utf-8") as fh:
        raw = json.load(fh)
    label = "unverified-single-pass"
    out = [normalize(r, i, label) for i, r in enumerate(raw) if isinstance(r, dict)]
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli())
