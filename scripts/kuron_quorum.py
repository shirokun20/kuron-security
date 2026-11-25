#!/usr/bin/env python3
"""Panel quorum: aggregate observed R/I/D lens verdicts (3/3 unanimous).

Verdicts come from the finding's panel_verdicts / lens_verdicts / verdicts /
panel field, or from meta['panel_verdicts'][id]. Self-reported confidence is
never consulted. A panel label cannot be claimed without observed verdicts.
Clean-room, stdlib-only, deterministic.
"""

from __future__ import annotations

import argparse
import json
import sys

PANEL_LABELS = ("kuron-panel", "ad-hoc-panel")
LENS_CODES = ("R", "I", "D")
UNANIMOUS_THRESHOLD = 3  # all three lenses must vote TRUE_POSITIVE: 3/3, not 2/3

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
    """Aggregate observed lens verdicts; never trust self-reported confidence."""
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
        for item in raw[:64]:  # cut-loop guard: bounded verdict list
            if not isinstance(item, dict):
                continue
            lens = _LENS_ALIASES.get(
                str(item.get("lens") or item.get("role") or "").strip().lower()
            )
            verdict = _normalize_verdict(item.get("verdict"))
            if lens and verdict:
                normalized[lens] = verdict
    elif isinstance(raw, dict):
        for key, value in list(raw.items())[:64]:
            lens = _LENS_ALIASES.get(str(key).strip().lower())
            verdict = _normalize_verdict(value)
            if lens and verdict:
                normalized[lens] = verdict

    r, i, d = normalized.get("R"), normalized.get("I"), normalized.get("D")
    ran = all(value is not None for value in (r, i, d))
    unanimous = ran and sum(1 for value in (r, i, d) if value == "TP") == UNANIMOUS_THRESHOLD

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


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute the observed R/I/D panel tally")
    parser.add_argument("finding", help="JSON file holding one finding")
    parser.add_argument("meta", nargs="?", help="optional scan-meta.json with panel_verdicts")
    args = parser.parse_args(argv)
    with open(args.finding, encoding="utf-8") as fh:
        finding = json.load(fh)
    meta = {}
    if args.meta:
        with open(args.meta, encoding="utf-8") as fh:
            meta = json.load(fh)
    print(json.dumps(compute_panel_tally(finding, meta), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli())
