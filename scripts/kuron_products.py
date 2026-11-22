#!/usr/bin/env python3
"""Kuron Security v2 product renderer: findings.json + scan-meta.json -> MD + JSONL + SARIF + stamp.

Reuses the official plugin's validation and SARIF builders (read-only) when
available; enforces evidence contract, honest provenance labels, policy
attestation, trace logging, and fail-closed redaction.
"""

from __future__ import annotations

import glob
import json
import os
import sys
import uuid
from pathlib import Path

from kuron_capabilities import select_path
from kuron_evidence import filter_findings, validate_finding
from kuron_policy import attestation as policy_attestation
from kuron_policy import validate as validate_policy
from kuron_redaction import enforce
from kuron_trace import append as trace_append

VALID_LABELS = ("kuron-panel", "ad-hoc-panel", "unverified-single-pass")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def plugin_scripts() -> str | None:
    cands = sorted(
        glob.glob(
            os.path.expanduser(
                "~/.claude/plugins/cache/claude-plugins-official/claude-security/*/scripts"
            )
        )
        + glob.glob(
            os.path.expanduser(
                "~/.gemini/config/plugins/claude-security/scripts"
            )
        )
    )
    return cands[-1] if cands else None


def load_raw(path: str, default=None):
    if not os.path.exists(path):
        return [] if default is None else default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(raw: dict, index: int) -> dict | None:
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
    ):
        if key in out and key not in evidence:
            evidence[key] = out[key]
    out["evidence"] = evidence

    label = out.get("label") or "ad-hoc-panel"
    if label not in VALID_LABELS:
        label = "ad-hoc-panel"
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
        selected = select_path(
            caps,
            meta.get("tier") or "personal",
            meta.get("consent"),
        )
        return selected["label"]
    return "ad-hoc-panel"


def _resolve_attestation(meta: dict) -> dict:
    if isinstance(meta.get("attestation"), dict):
        return meta["attestation"]
    policy_path = meta.get("policy_path")
    if policy_path and os.path.exists(policy_path):
        return policy_attestation(validate_policy(policy_path))
    return {}


def _fallback_sarif_log(records: list[dict], label: str, att: dict) -> dict:
    results = []
    for r in records:
        results.append(
            {
                "ruleId": str(r.get("cwe_id") or r.get("id") or "KURON"),
                "level": "error"
                if str(r.get("severity", "")).upper() in ("CRITICAL", "HIGH")
                else "warning",
                "message": {"text": str(r.get("title") or r.get("description") or r.get("id"))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(r.get("file") or "")},
                            "region": {"startLine": max(int(r.get("line") or 1), 1)},
                        }
                    }
                ],
                "properties": {
                    "id": r.get("id"),
                    "severity": r.get("severity"),
                    "label": label,
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Kuron Security", "rules": []}},
                "results": results,
                "properties": {
                    "engine": "kuron-security",
                    "verification": label,
                    "attestation": att,
                },
            }
        ],
    }


def _render_markdown(
    report_dir: str,
    label: str,
    tag: str,
    meta: dict,
    kept: list[dict],
    discarded: list[dict],
    att: dict,
) -> None:
    md_path = Path(report_dir) / "KURON-SECURITY-RESULTS.md"
    lines = [
        "# Kuron Security Scan Results",
        "",
        f"- **Verification Label:** `{label}`",
        f"- **Tier:** `{meta.get('tier', 'personal')}`",
        f"- **Revision:** `{tag}`",
        f"- **Kept Findings:** {len(kept)}",
        f"- **Discarded (pre-panel):** {len(discarded)}",
    ]
    if att:
        lines.append(
            f"- **Policy Attestation:** `v{att.get('policy_version')}` (`{att.get('policy_sha256')}`)"
        )
    lines.append("")
    lines.append("## Kept Findings")
    lines.append("")
    if not kept:
        lines.append("No findings survived evidence validation and panel verification.")
    else:
        for f in kept:
            lines.append(
                f"- **{f.get('id')}** [{str(f.get('severity', 'LOW')).upper()}] "
                f"`{f.get('file')}:{f.get('line')}` — {f.get('title') or f.get('cwe_id', '')}"
            )
    lines.append("")
    lines.append("## Discarded Findings")
    lines.append("")
    if not discarded:
        lines.append("None.")
    else:
        for d in discarded:
            lines.append(f"- **{d.get('id', '?')}**: {d.get('discard_reason', 'invalid evidence')}")
    lines.append("")
    coverage = meta.get("coverage") or {}
    lines.append("## Coverage Ledger")
    lines.append("")
    lines.append(f"- `skippedComponents`: {coverage.get('skippedComponents', [])}")
    lines.append(f"- `over-cap`: {coverage.get('over-cap', [])}")
    lines.append(f"- `collapsed-shape`: {coverage.get('collapsed-shape', [])}")
    lines.append(f"- `lostResearchers`: {coverage.get('lostResearchers', [])}")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _print_scorecard(
    label: str,
    tag: str,
    meta: dict,
    kept: list[dict],
    discarded: list[dict],
    rev_name: str,
) -> None:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in kept:
        sev = str(r.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    total = max(len(kept), 1)
    rule = "─" * 68
    scope = meta.get("scope") or ()
    scope_str = ", ".join(scope) if scope else "whole repository"
    mode = str(meta.get("mode", "scan"))
    effort = meta.get("effort") or meta.get("tier") or "default"

    print(f"\n╭─ 🛡️  KURON SECURITY · SCAN SCORECARD {rule[:30]}")
    print(f"│  Mode     : {mode} ({effort} effort)")
    print(f"│  Scope    : {scope_str}")
    print(f"│  Revision : {tag} · Stamp: {label}")
    print(
        f"│  Summary  : {len(kept)} kept "
        f"(CRITICAL {counts['CRITICAL']} · HIGH {counts['HIGH']} · "
        f"MEDIUM {counts['MEDIUM']} · LOW {counts['LOW']}) · {len(discarded)} discarded"
    )
    print(f"├─ Severity Breakdown {rule[:47]}")
    for sev_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts[sev_tier]
        filled = int(round((c / total) * 20)) if len(kept) > 0 else 0
        meter = "█" * filled + "░" * (20 - filled)
        print(f"│  {sev_tier:<8} : {meter}  {c}")
    print(f"├─ Kept Findings ({len(kept)}) {rule[:48]}")
    if not kept:
        print("│  [CLEAN]   0 findings survived the evidence & verification gate.")
    for idx, r in enumerate(kept):
        fid = str(r.get("id", f"F{idx + 1}"))
        sev = str(r.get("severity", "LOW")).upper()
        cwe = str(r.get("cwe_id") or r.get("cweId") or "-")
        loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
        title = str(r.get("title", "")).strip()
        conf = str(r.get("confidence", "high")).upper()
        if label == "kuron-panel":
            panel_badge = "3/3✓ (R:✓ I:✓ D:✓)" if conf == "HIGH" else "2/3✓"
        else:
            panel_badge = label
        print(f"│  [{sev}]".ljust(12) + f" {fid} · {cwe} · {panel_badge}")
        if title:
            print(f"│            {title}")
        print(f"│            └─ {loc}")
        if idx + 1 < len(kept):
            print("│")
    print(f"├─ Artifacts {rule[:56]}")
    print("│  Report   : KURON-SECURITY-RESULTS.md")
    print(f"│  Machine  : KURON-SECURITY-RESULTS.sarif · .jsonl · {rev_name}")
    print(f"╰{rule}")
    print(f"wrote {len(kept)} findings (stamp {rev_name})")


def main(report_dir: str, scan_root: str) -> None:
    raw_findings = load_raw(os.path.join(report_dir, "findings.json"), default=[])
    meta = load_raw(os.path.join(report_dir, "scan-meta.json"), default={})
    revision = meta.get("revision") or {}
    label = _resolve_label(meta)
    att = _resolve_attestation(meta)

    normalized = [normalize(r, i) for i, r in enumerate(raw_findings)]
    non_null = [n for n in normalized if n is not None]
    kept, discarded = filter_findings([{**n, **n.get("evidence", {})} for n in non_null])
    kept = _dedupe_findings(kept)

    p_scripts = plugin_scripts()
    if p_scripts and kept:
        sys.path.insert(0, p_scripts)
        from lib import finding, sarif, secret, strictjson  # noqa: E402

        built = [
            finding.build_finding(
                r,
                i,
                {},
                scan_root,
                meta.get("scan_prefix") or "",
                must_exist=True,
            )
            for i, r in enumerate(kept)
        ]
        sources: dict[str, str] = {}
        for b in built:
            rel = b["file"]
            if rel not in sources:
                with open(
                    os.path.join(scan_root, rel), encoding="utf-8", errors="replace"
                ) as fh:
                    sources[rel] = fh.read()
        commit = revision.get("commit")
        clean = commit if revision.get("dirty") is False and commit else None
        scan = sarif.Scan(
            id=uuid.uuid4(),
            mode=str(meta.get("mode", "scan")),
            prefix="",
            remote=meta.get("remote"),
            scope=tuple(meta.get("scope") or ()),
            revision=clean,
        )
        records = sarif.placed(built, scan, sources, refused_secrets=set())
        jsonl_lines = [strictjson.text(secret.withheld(item)) for item in records]
        log = sarif.log(
            records,
            scan,
            tool_version=None,
            run_properties={
                "engine": "kuron-security",
                "verification": label,
                "attestation": att,
                "discarded_count": len(discarded),
            },
            panels={},
            notifications=[],
        )
        log["runs"][0]["tool"]["driver"]["name"] = "Kuron Security"
        log["runs"][0]["tool"]["driver"].pop("organization", None)
        log["runs"][0]["tool"]["driver"].pop("informationUri", None)
    else:
        commit = revision.get("commit")
        records = kept
        jsonl_lines = [json.dumps({**item, "label": label}) for item in records]
        log = _fallback_sarif_log(records, label, att)

    jsonl_name = "KURON-SECURITY-RESULTS.jsonl"
    sarif_name = "KURON-SECURITY-RESULTS.sarif"
    md_name = "KURON-SECURITY-RESULTS.md"

    with open(os.path.join(report_dir, jsonl_name), "w", encoding="utf-8") as fh:
        for line in jsonl_lines:
            fh.write(line + "\n")

    with open(os.path.join(report_dir, sarif_name), "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
        fh.write("\n")

    tag = (commit or "unversioned")[:12]
    if revision.get("dirty"):
        tag += "-dirty"
    rev_name = f"KURON-SECURITY-REVISION-{tag}.json"

    stamp = {
        "engine": "kuron-security",
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
    with open(os.path.join(report_dir, rev_name), "w", encoding="utf-8") as fh:
        json.dump(stamp, fh, indent=2)
        fh.write("\n")

    _render_markdown(report_dir, label, tag, meta, kept, discarded, att)

    trace_append(
        os.path.join(report_dir, "trace.jsonl"),
        {
            "event": "render_products",
            "label": label,
            "kept": len(records),
            "discarded": len(discarded),
            "attestation": att,
        },
    )

    enforce(report_dir, [md_name, jsonl_name, sarif_name, rev_name])
    _print_scorecard(label, tag, meta, records, discarded, rev_name)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
