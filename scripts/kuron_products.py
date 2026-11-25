#!/usr/bin/env python3
"""Kuron Security v2 product orchestrator: findings.json + scan-meta.json -> products.

Clean-room, stdlib-only and deterministic. Products are rendered into a staging
directory, pass the redaction gate and an independent secret scan there, and are
only then promoted atomically. Verifier lens verdicts (not self-reported
confidence) decide whether a finding survives the panel and what badge it gets.

Rendering is split into focused modules: kuron_intake (input), kuron_evidence
(validation), kuron_quorum (panel), kuron_sarif and kuron_markdown (products).
All legacy symbols are re-exported here for 100% backward compatibility.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import uuid
from pathlib import Path

from kuron_evidence import filter_findings
from kuron_intake import (
    VALID_LABELS,
    SEVERITY_RANK,
    _dedupe_findings,
    _resolve_attestation,
    _resolve_label,
    discover_patches,
    load_raw,
    normalize,
)
from kuron_markdown import (
    METER_WIDTH,
    _ascii,
    _ascii_tally,
    _meter_filled,
    _print_scorecard,
    render_document,
    render_markdown as _render_markdown_impl,
)
from kuron_quorum import (
    LENS_CODES,
    PANEL_LABELS,
    UNANIMOUS_THRESHOLD,
    PanelGateError,
    _apply_panel,
    compute_panel_tally,
)
from kuron_redaction import RedactionError, enforce, scan_secrets
from kuron_sarif import (
    SARIF_SCHEMA,
    SARIF_SEMANTIC_VERSION,
    _build_sarif_log,
    _fallback_sarif_log,
    build_sarif_log,
)
from kuron_trace import append as trace_append

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_POLICY = 2
EXIT_REDACTION = 3


def _render_markdown(report_dir, label, tag, meta, kept, discarded, att, patches=None):
    """Legacy call signature; delegates to the advisory card renderer."""
    return _render_markdown_impl(
        report_dir, label, tag, meta, kept, discarded, att, patches
    )


def _status(code: int, reason: str) -> int:
    """Emit one machine-readable status line on stdout and return the exit code."""
    print(json.dumps({"exit_code": code, "reason": _ascii(reason, 200)}, sort_keys=True))
    return code


def main(report_dir: str, scan_root: str) -> int:
    try:
        raw_findings = load_raw(os.path.join(report_dir, "findings.json"), default=[])
        meta = load_raw(os.path.join(report_dir, "scan-meta.json"), default={})
    except (OSError, ValueError) as exc:
        return _status(EXIT_POLICY, f"cannot read scan inputs: {exc}")
    if not isinstance(raw_findings, list) or not isinstance(meta, dict):
        return _status(EXIT_POLICY, "findings.json must be a list and scan-meta.json an object")

    revision = meta.get("revision") or {}
    label = _resolve_label(meta)
    if label not in VALID_LABELS:
        return _status(EXIT_POLICY, f"unsupported verification label {label!r}")
    try:
        att = _resolve_attestation(meta)
    except Exception as exc:
        return _status(EXIT_POLICY, f"invalid policy attestation: {exc}")

    normalized = [normalize(r, i, label) for i, r in enumerate(raw_findings) if isinstance(r, dict)]
    kept, discarded = filter_findings(
        [{**n, **n.get("evidence", {})} for n in normalized]
    )
    kept = _dedupe_findings(kept)
    try:
        kept, panel_rejected = _apply_panel(kept, meta, label)
    except PanelGateError as exc:
        return _status(EXIT_POLICY, str(exc))
    discarded.extend(panel_rejected)

    records = kept
    jsonl_lines = [json.dumps({**item, "label": label}, ensure_ascii=True) for item in records]
    patches = discover_patches(report_dir, records)
    log = _build_sarif_log(
        records, label, att, discarded_count=len(discarded), patches=patches
    )

    commit = revision.get("commit")
    tag = (commit or "unversioned")[:12]
    if revision.get("dirty"):
        tag += "-dirty"
    rev_name = f"KURON-SECURITY-REVISION-{tag}.json"

    stamp = {
        "engine": "kuron-security",
        "builder": "vendored",
        "verification": {"status": label},
        "label": label,
        "attestation": att,
        "mode": str(meta.get("mode", "scan")),
        "scope": list(meta.get("scope") or ()),
        "effort": meta.get("effort"),
        "commit": commit,
        "dirty": revision.get("dirty"),
        "findings": len(records),
        "discarded": [
            {"id": d.get("id"), "discard_reason": d.get("discard_reason")}
            for d in discarded
        ],
        "coverage": meta.get("coverage")
        or {
            "skippedComponents": [],
            "over-cap": [],
            "collapsed-shape": [],
            "lostResearchers": [],
        },
    }

    md_name = "KURON-SECURITY-RESULTS.md"
    jsonl_name = "KURON-SECURITY-RESULTS.jsonl"
    sarif_name = "KURON-SECURITY-RESULTS.sarif"
    artifacts = [md_name, jsonl_name, sarif_name, rev_name]
    promotion = artifacts + ["trace.jsonl"]

    staging = Path(report_dir) / f".staging-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        redaction_src = Path(report_dir) / "redaction.json"
        if redaction_src.exists():
            shutil.copy2(redaction_src, staging / "redaction.json")

        _render_markdown_impl(str(staging), label, tag, meta, records, discarded, att, patches)
        with (staging / jsonl_name).open("w", encoding="utf-8") as fh:
            for line in jsonl_lines:
                fh.write(line + "\n")
        with (staging / sarif_name).open("w", encoding="utf-8") as fh:
            json.dump(log, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        with (staging / rev_name).open("w", encoding="utf-8") as fh:
            json.dump(stamp, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        trace_append(
            str(staging / "trace.jsonl"),
            {
                "event": "render_products",
                "label": label,
                "kept": len(records),
                "discarded": len(discarded),
                "attestation": att,
                "builder": "vendored",
            },
        )

        enforce(str(staging), artifacts)
        for name in promotion:
            found = scan_secrets((staging / name).read_text(encoding="utf-8", errors="replace"))
            if found:
                raise RedactionError(
                    f"independent secret scan failed in {name}: {', '.join(sorted(set(found)))}"
                )
        for name in promotion:
            os.replace(staging / name, Path(report_dir) / name)
    except RedactionError as exc:
        return _status(EXIT_REDACTION, f"redaction gate failed: {exc}")
    except OSError as exc:
        return _status(EXIT_POLICY, f"artifact rendering failed: {exc}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    severities = {str(r.get("severity", "LOW")).upper() for r in records}
    if severities & {"HIGH", "CRITICAL"}:
        code, reason = EXIT_FINDINGS, "high/critical findings kept"
    else:
        code, reason = EXIT_CLEAN, "no high/critical findings kept"
    _print_scorecard(label, tag, meta, records, discarded, rev_name)
    return _status(code, reason)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render Kuron Security scan products")
    parser.add_argument("report_dir")
    parser.add_argument("scan_root")
    args = parser.parse_args(argv)
    return main(args.report_dir, args.scan_root)


if __name__ == "__main__":
    sys.exit(cli())
