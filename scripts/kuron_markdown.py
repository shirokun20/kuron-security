#!/usr/bin/env python3
"""Security Advisory Card renderer and ASCII scan scorecard.

All repository-supplied text is treated as untrusted: it is sanitized and
escaped before entering Markdown tables, callouts or Mermaid labels, so a
finding cannot inject headings, links, code fences or graph syntax.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

from kuron_progress import sanitize
from kuron_quorum import compute_panel_tally

METER_WIDTH = 20
_MD_UNSAFE = re.compile(r"([\\`*_\[\]()#|<>!~{}])")
_MERMAID_UNSAFE = re.compile(r"[\"\[\]{}()<>|`#\\~$;]")


def _ascii(value: object, limit: int = 80) -> str:
    """ASCII-only, sanitized text for scorecards (no cp1252 console crashes)."""
    return sanitize(value, limit).encode("ascii", "replace").decode("ascii")


def _meter_filled(count: int, total: int, width: int = METER_WIDTH) -> int:
    """Scale count/total to a bounded cell count with integer half-up rounding.

    ``round()`` is banker's rounding (2.5 -> 2) and float division drifts; the
    integer form below keeps every /20 bar on the same, predictable scale.
    """
    if count <= 0 or total <= 0:
        return 0
    return min(width, max(0, (count * width * 2 + total) // (2 * total)))


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

    total = len(kept)
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
        filled = _meter_filled(c, total)
        meter = "#" * filled + "." * (METER_WIDTH - filled)
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


def _md(value: object, limit: int = 160) -> str:
    """Escape untrusted repository text before it enters Markdown."""
    return _MD_UNSAFE.sub(r"\\\1", sanitize(value, limit))


def _mermaid_label(value: object, limit: int = 100) -> str:
    """Strip graph syntax and HTML-escape a label used inside Mermaid quotes."""
    text = _MERMAID_UNSAFE.sub(" ", sanitize(value, limit))
    return html.escape(text, quote=True)[:limit]


def _taint_nodes(finding: dict) -> dict[str, tuple[str, str]]:
    """Pick the first source/guard/sink step of the evidence taint path."""
    nodes: dict[str, tuple[str, str]] = {}
    for step in (finding.get("taint_path") or [])[:64]:
        if not isinstance(step, dict):
            continue
        role = str(step.get("role") or "").strip().lower()
        if role in ("source", "guard", "sink") and role not in nodes:
            nodes[role] = (str(step.get("file") or "?"), str(step.get("line") or "?"))
    return nodes


def _patch_status(finding: dict, patches: dict) -> str:
    info = patches.get(str(finding.get("id") or "")) if isinstance(patches, dict) else None
    if not isinstance(info, dict):
        return "none"
    return f"`{_md(info.get('path'), 120)}` (ready)"


def _advisory_card(finding: dict, label: str, patches: dict) -> list[str]:
    tally = finding.get("panel_tally") or compute_panel_tally(finding)
    severity = str(finding.get("severity", "LOW")).upper()
    cwe = str(finding.get("cwe_id") or finding.get("cweId") or "-")
    fid = str(finding.get("id") or "?")
    sink = f"{finding.get('file', '?')}:{finding.get('line', '?')}"
    verdict = (
        "`3/3 TRUE_POSITIVE`"
        if tally.get("unanimous_tp")
        else f"`{tally.get('votes', 0)}/3 TP`"
    )
    nodes = _taint_nodes(finding)
    flow = " -> ".join(
        f"`{role}` (`{_md(nodes[role][0], 80)}:{_md(nodes[role][1], 16)}`)"
        if role in nodes
        else f"`{role}` (none)"
        for role in ("source", "guard", "sink")
    )

    lines = [
        f"### {_md(fid, 40)} — {_md(finding.get('title') or finding.get('description') or cwe, 160)}",
        "",
        "> [!WARNING]",
        f"> **{_md(severity, 16)} · {_md(cwe, 40)} · {_md(fid, 40)}** — "
        f"{_md(finding.get('description') or finding.get('exploit_scenario') or finding.get('title') or '', 200)}",
        "",
        "| Severity | CWE | Sink (`file:line`) | Panel Verdict | Patch Status |",
        "|---|---|---|---|---|",
        f"| `{_md(severity, 16)}` | `{_md(cwe, 40)}` | `{_md(sink, 120)}` | "
        f"{verdict} (`{_md(label, 40)}`) | {_patch_status(finding, patches)} |",
        "",
        f"**Flow:** {flow}",
        "",
        "```mermaid",
        "flowchart LR",
        f'  S["source: {_mermaid_label(nodes.get("source", ("?", "?"))[0])}"]',
        f'  G["guard: {_mermaid_label(nodes.get("guard", ("?", "?"))[0])}"]',
        f'  K["sink: {_mermaid_label(nodes.get("sink", ("?", "?"))[0])}"]',
        "  S --> G --> K",
        "```",
        "",
        "| Lens | Verdict |",
        "|---|---|",
    ]
    names = {"R": "Reachability", "I": "Impact", "D": "Defenses"}
    for code in ("R", "I", "D"):
        value = tally.get(code) or "?"
        lines.append(f"| `{code}` ({names[code]}) | `{_md(value, 8)}` |")
    lines.extend(
        [
            "",
            "<details>",
            "<summary>Proof trace &amp; guard analysis</summary>",
            "",
            "**poc_trace**",
            "",
        ]
    )
    for step in (finding.get("poc_trace") or [])[:64]:
        if isinstance(step, dict):
            where = f"{step.get('file', '?')}:{step.get('line', '?')}"
            lines.append(
                f"- `{_md(where, 120)}` — {_md(step.get('action') or step.get('text') or '', 160)}"
            )
        else:
            lines.append(f"- {_md(step, 160)}")
    lines.extend(
        [
            "",
            "**why_guard_fails**",
            "",
            f"> {_md(finding.get('why_guard_fails') or 'not recorded', 400)}",
            "",
            "</details>",
            "",
        ]
    )
    return lines


def render_document(
    label: str,
    tag: str,
    meta: dict,
    kept: list[dict],
    discarded: list[dict],
    att: dict,
    patches: dict | None = None,
) -> str:
    """Render the full report as text (Advisory Cards + discarded + coverage)."""
    patches = patches or {}
    lines = [
        "# Kuron Security Scan Results",
        "",
        f"- **Verification Label:** `{_md(label, 40)}`",
        f"- **Tier:** `{_md(meta.get('tier', 'personal'), 40)}`",
        f"- **Revision:** `{_md(tag, 40)}`",
        f"- **Kept Findings:** {len(kept)}",
        f"- **Discarded (pre-panel):** {len(discarded)}",
    ]
    if att:
        lines.append(
            f"- **Policy Attestation:** `v{_md(att.get('policy_version'), 40)}` "
            f"(`{_md(att.get('policy_sha256'), 80)}`)"
        )
    lines.extend(["", "## Kept Findings", ""])
    if not kept:
        lines.append("No findings survived evidence validation and panel verification.")
    for finding in kept:
        lines.extend(_advisory_card(finding, label, patches))
    lines.extend(["", "## Discarded Findings", ""])
    if not discarded:
        lines.append("None.")
    for item in discarded:
        lines.append(
            f"- **{_md(item.get('id', '?'), 40)}**: "
            f"{_md(item.get('discard_reason', 'invalid evidence'), 240)}"
        )
    coverage = meta.get("coverage") or {}
    lines.extend(["", "## Coverage Ledger", ""])
    for key in ("skippedComponents", "over-cap", "collapsed-shape", "lostResearchers"):
        lines.append(f"- `{key}`: {_md(str(coverage.get(key, [])), 400)}")
    return "\n".join(lines) + "\n"


def render_markdown(
    report_dir: str,
    label: str,
    tag: str,
    meta: dict,
    kept: list[dict],
    discarded: list[dict],
    att: dict,
    patches: dict | None = None,
) -> None:
    path = Path(report_dir) / "KURON-SECURITY-RESULTS.md"
    path.write_text(
        render_document(label, tag, meta, kept, discarded, att, patches), encoding="utf-8"
    )


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render Security Advisory Cards")
    parser.add_argument("findings", help="JSON file holding a list of findings")
    parser.add_argument("--label", default="unverified-single-pass")
    args = parser.parse_args(argv)
    with open(args.findings, encoding="utf-8") as fh:
        kept = json.load(fh)
    print(render_document(args.label, "unversioned", {}, kept, [], {}), end="")
    return 0


if __name__ == "__main__":
    sys.exit(cli())
