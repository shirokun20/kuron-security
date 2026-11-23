#!/usr/bin/env python3
"""Kuron Security v2 product renderer: findings.json + scan-meta.json -> MD + JSONL + SARIF + stamp.

Clean-room, stdlib-only and deterministic. Products are rendered into a staging
directory, pass the redaction gate and an independent secret scan there, and are
only then promoted atomically. Verifier lens verdicts (not self-reported
confidence) decide whether a finding survives the panel and what badge it gets.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import uuid
from pathlib import Path

from kuron_capabilities import select_path
from kuron_evidence import filter_findings, validate_finding
from kuron_policy import attestation as policy_attestation
from kuron_policy import validate as validate_policy
from kuron_progress import sanitize
from kuron_redaction import RedactionError, enforce, scan_secrets
from kuron_trace import append as trace_append

VALID_LABELS = ("kuron-panel", "ad-hoc-panel", "unverified-single-pass")
PANEL_LABELS = ("kuron-panel", "ad-hoc-panel")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_POLICY = 2
EXIT_REDACTION = 3

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LENS_ALIASES = {
    "r": "R",
    "reach": "R",
    "reachable": "R",
    "reachability": "R",
    "i": "I",
    "impact": "I",
    "exploitability": "I",
    "d": "D",
    "def": "D",
    "defense": "D",
    "defenses": "D",
    "guard": "D",
}
_TRUE_POSITIVE = {"true_positive", "true-positive", "tp", "true", "yes", "1"}
_FALSE_POSITIVE = {"false_positive", "false-positive", "fp", "false", "no", "0"}


class PanelGateError(Exception):
    """Raised when a panel label is claimed without observed lens verdicts."""


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


def _normalize_verdict(value) -> str | None:
    if value is True:
        return "TP"
    if value is False:
        return "FP"
    text = str(value or "").strip().lower()
    if text in _TRUE_POSITIVE:
        return "TP"
    if text in _FALSE_POSITIVE:
        return "FP"
    return None


def compute_panel_tally(finding: dict, meta: dict | None = None) -> dict:
    """Aggregate observed R/I/D lens verdicts; never trust self-reported confidence.

    Verdicts are read from the finding's ``panel_verdicts`` / ``lens_verdicts`` /
    ``verdicts`` / ``panel`` field, or from ``meta['panel_verdicts'][id]``. They
    may be a {lens: verdict} mapping or a list of {"lens","verdict"} objects.
    """
    meta = meta or {}
    raw = None
    for key in ("panel_verdicts", "lens_verdicts", "verdicts", "panel"):
        candidate = finding.get(key)
        if isinstance(candidate, (dict, list)):
            raw = candidate
            break
    if raw is None:
        by_id = meta.get("panel_verdicts")
        fid = str(finding.get("id") or "")
        if isinstance(by_id, dict) and fid in by_id:
            raw = by_id[fid]

    normalized: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            lens = _LENS_ALIASES.get(
                str(item.get("lens") or item.get("role") or "").strip().lower()
            )
            verdict = _normalize_verdict(item.get("verdict"))
            if lens and verdict:
                normalized[lens] = verdict
    elif isinstance(raw, dict):
        for key, value in raw.items():
            lens = _LENS_ALIASES.get(str(key).strip().lower())
            verdict = _normalize_verdict(value)
            if lens and verdict:
                normalized[lens] = verdict

    r, i, d = normalized.get("R"), normalized.get("I"), normalized.get("D")
    ran = all(value is not None for value in (r, i, d))
    unanimous = ran and all(value == "TP" for value in (r, i, d))

    def mark(value: str | None) -> str:
        return "\u2713" if value == "TP" else ("\u2717" if value == "FP" else "?")

    display = f"R:{mark(r)} I:{mark(i)} D:{mark(d)}"
    if unanimous:
        display += " (3/3 TP)"
    return {
        "R": r,
        "I": i,
        "D": d,
        "ran": ran,
        "unanimous_tp": unanimous,
        "votes": sum(1 for v in (r, i, d) if v == "TP"),
        "display": display,
    }


def _apply_panel(
    kept: list[dict], meta: dict, label: str
) -> tuple[list[dict], list[dict]]:
    """Keep only unanimously-TRUE_POSITIVE findings; refuse unobserved panel claims."""
    survivors: list[dict] = []
    rejected: list[dict] = []
    for finding in kept:
        tally = compute_panel_tally(finding, meta)
        finding["panel_tally"] = tally
        if label in PANEL_LABELS and not tally["ran"]:
            raise PanelGateError(
                f"{finding.get('id', '?')}: label '{label}' requires observed R/I/D "
                "lens verdicts; refusing to claim a panel that did not run"
            )
        if tally["ran"] and not tally["unanimous_tp"]:
            rejected.append(
                {
                    **finding,
                    "discard_reason": (
                        f"panel quorum failed ({tally['display']}); unanimous "
                        "TRUE_POSITIVE across R/I/D required"
                    ),
                }
            )
        else:
            survivors.append(finding)
    return survivors, rejected


def _build_sarif_log(
    records: list[dict], label: str, att: dict, discarded_count: int = 0
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
        raw_line = r.get("line")
        try:
            start_line = max(int(raw_line) if raw_line is not None else 1, 1)
        except (TypeError, ValueError):
            start_line = 1
        tally = r.get("panel_tally") or compute_panel_tally(r)
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": str(r.get("title") or r.get("description") or r.get("id"))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(r.get("file") or "")},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
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
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kuron Security",
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


# Backwards-compatible name for callers/tests that used the old private helper.
_fallback_sarif_log = _build_sarif_log


def _ascii(value: object, limit: int = 80) -> str:
    """ASCII-only, sanitized text for scorecards (no cp1252 console crashes)."""
    return sanitize(value, limit).encode("ascii", "replace").decode("ascii")


def _ascii_tally(finding: dict) -> str:
    tally = finding.get("panel_tally") or compute_panel_tally(finding)

    def mark(value: str | None) -> str:
        return "Y" if value == "TP" else ("N" if value == "FP" else "?")

    text = "R:{} I:{} D:{}".format(
        mark(tally.get("R")), mark(tally.get("I")), mark(tally.get("D"))
    )
    if tally.get("unanimous_tp"):
        text += " [3/3 TP]"
    elif tally.get("ran"):
        text += f" [{tally.get('votes', 0)}/3 TP]"
    else:
        text += " [no panel]"
    return text


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
            tally = f.get("panel_tally") or compute_panel_tally(f)
            lines.append(
                f"- **{f.get('id')}** [{str(f.get('severity', 'LOW')).upper()}] "
                f"`{f.get('file')}:{f.get('line')}` — {f.get('title') or f.get('cwe_id', '')} "
                f"({tally['display']})"
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
    stream=None,
) -> None:
    """Human scorecard: ASCII only, written to stderr so stdout stays machine-clean."""
    stream = stream if stream is not None else sys.stderr
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in kept:
        sev = str(r.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    total = max(len(kept), 1)
    rule = "-" * 68
    scope = meta.get("scope") or ()
    scope_str = ", ".join(scope) if scope else "whole repository"
    mode = str(meta.get("mode", "scan"))
    effort = meta.get("effort") or meta.get("tier") or "default"

    def emit(text: str) -> None:
        print(_ascii(text, 200), file=stream)

    emit(f"\n+- KURON SECURITY - SCAN SCORECARD {rule[:30]}")
    emit(f"|  Mode     : {mode} ({effort} effort)")
    emit(f"|  Scope    : {scope_str}")
    emit(f"|  Revision : {tag} | Stamp: {label}")
    emit(
        f"|  Summary  : {len(kept)} kept "
        f"(CRITICAL {counts['CRITICAL']} | HIGH {counts['HIGH']} | "
        f"MEDIUM {counts['MEDIUM']} | LOW {counts['LOW']}) | {len(discarded)} discarded"
    )
    emit(f"+- Severity Breakdown {rule[:44]}")
    for sev_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts[sev_tier]
        filled = int(round((c / total) * 20)) if kept else 0
        meter = "#" * filled + "." * (20 - filled)
        emit(f"|  {sev_tier:<8} : [{meter}] {c}")
    emit(f"+- Kept Findings ({len(kept)}) {rule[:45]}")
    if not kept:
        emit("|  [CLEAN]   0 findings survived the evidence & verification gate.")
    for idx, r in enumerate(kept):
        fid = str(r.get("id", f"F{idx + 1}"))
        sev = str(r.get("severity", "LOW")).upper()
        cwe = str(r.get("cwe_id") or r.get("cweId") or "-")
        loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
        title = str(r.get("title", "")).strip()
        emit(f"|  [{sev}] {fid} - {cwe} - {_ascii_tally(r)}")
        if title:
            emit(f"|            {title}")
        emit(f"|            -> {loc}")
        if idx + 1 < len(kept):
            emit("|")
    emit(f"+- Artifacts {rule[:54]}")
    emit("|  Report   : KURON-SECURITY-RESULTS.md")
    emit(f"|  Machine  : KURON-SECURITY-RESULTS.sarif - .jsonl - {rev_name}")
    emit(f"+{rule}")
    emit(f"wrote {len(kept)} findings (stamp {rev_name})")


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
    log = _build_sarif_log(records, label, att, discarded_count=len(discarded))

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

        _render_markdown(str(staging), label, tag, meta, records, discarded, att)
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
