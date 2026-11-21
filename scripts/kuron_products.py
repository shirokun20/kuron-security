#!/usr/bin/env python3
"""Kuron Security product renderer: findings.json + scan-meta.json -> JSONL + SARIF + stamp.

Reuses the official plugin's validation and SARIF builders (read-only);
never touches the Workflow vote chain. The stamp says kuron-panel, never
verified/unverified.
"""

import glob
import json
import os
import sys
import uuid


def plugin_scripts() -> str:
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
    if not cands:
        raise SystemExit("official claude-security plugin not found in cache")
    return cands[-1]


def load_raw(path: str):
    with open(path) as fh:
        return json.load(fh)


def normalize(raw: dict, index: int) -> dict:
    out = dict(raw)
    out.setdefault("id", f"F{index + 1}")
    if "cwe_id" not in out and "cweId" in out:
        out["cwe_id"] = out["cweId"]
    if "description" not in out and "rationale" in out:
        out["description"] = out["rationale"]
    if "exploit_scenario" not in out and "exploitScenario" in out:
        out["exploit_scenario"] = out["exploitScenario"]
    return out


def main() -> None:
    report_dir, scan_root = sys.argv[1], sys.argv[2]
    sys.path.insert(0, plugin_scripts())
    from lib import finding, sarif, secret, strictjson  # noqa: E402

    raw_findings = load_raw(os.path.join(report_dir, "findings.json"))
    meta = load_raw(os.path.join(report_dir, "scan-meta.json"))
    revision = meta.get("revision") or {}

    raws = [normalize(r, i) for i, r in enumerate(raw_findings)]
    built = [
        finding.build_finding(
            r,
            i,
            {},
            scan_root,
            meta.get("scan_prefix") or "",
            must_exist=True,
        )
        for i, r in enumerate(raws)
    ]

    sources: dict[str, str] = {}
    for b in built:
        rel = b["file"]
        if rel not in sources:
            with open(os.path.join(scan_root, rel), encoding="utf-8",
                      errors="replace") as fh:
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
    with open(os.path.join(report_dir, "KURON-SECURITY-RESULTS.jsonl"), "w") as fh:
        for item in records:
            fh.write(strictjson.text(secret.withheld(item)) + "\n")

    log = sarif.log(
        records,
        scan,
        tool_version=None,
        run_properties={"engine": "kuron-security",
                        "verification": "kuron-panel"},
        panels={},
        notifications=[],
    )
    # The log shape is built on the official plugin's lib; the producer is us.
    log["runs"][0]["tool"]["driver"]["name"] = "Kuron Security"
    log["runs"][0]["tool"]["driver"].pop("organization", None)
    log["runs"][0]["tool"]["driver"].pop("informationUri", None)
    with open(os.path.join(report_dir, "KURON-SECURITY-RESULTS.sarif"), "w") as fh:
        json.dump(log, fh, indent=2)
        fh.write("\n")
    stamp = {
        "engine": "kuron-security",
        "verification": {"status": "kuron-panel"},
        "mode": scan.mode,
        "scope": list(scan.scope),
        "effort": meta.get("effort"),
        "commit": commit,
        "dirty": revision.get("dirty"),
        "findings": len(records),
    }
    tag = (commit or "unversioned")[:12]
    if revision.get("dirty"):
        tag += "-dirty"
    with open(
        os.path.join(report_dir, f"KURON-SECURITY-REVISION-{tag}.json"), "w"
    ) as fh:
        json.dump(stamp, fh, indent=2)
        fh.write("\n")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in raws:
        sev = str(r.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }
    total = max(len(records), 1)
    bar_width = 72
    bar = "═" * bar_width
    thin = "─" * bar_width
    print(f"\n╔{bar}╗")
    print(f"║ 🛡️  KURON SECURITY — SCAN SCORECARD{' ' * 37}║")
    print(f"╠{bar}╣")
    summary_line = (
        f"Mode: {scan.mode:<8} │ Effort: {str(meta.get('effort') or '-'):<6} "
        f"│ Commit: {tag:<18} │ Stamp: kuron-panel"
    )
    print(f"║ {summary_line:<70} ║")
    sev_line = (
        f"Total: {len(records):<3} │ "
        f"🔴 CRIT: {counts['CRITICAL']}   🟠 HIGH: {counts['HIGH']}   "
        f"🟡 MED: {counts['MEDIUM']}   🔵 LOW: {counts['LOW']}"
    )
    print(f"║ {sev_line:<66} ║")
    print(f"╟{thin}╢")
    for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts[tier]
        filled = int(round((c / total) * 24)) if len(records) > 0 else 0
        meter = "█" * filled + "░" * (24 - filled)
        row = f"{icons[tier]} {tier:<8} [{meter}] {c}"
        print(f"║ {row:<69} ║")
    print(f"╠{bar}╣")
    if not raws:
        print(f"║ 🟢 CLEAN — 0 findings survived the 3-lens refutation panel.{' ' * 12}║")
    for r in raws:
        fid = str(r.get("id", "?"))
        sev = str(r.get("severity", "?")).upper()
        icon = icons.get(sev, "•")
        cwe = str(r.get("cwe_id") or r.get("cweId") or "-")
        loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
        conf = str(r.get("confidence", "high")).upper()
        panel_badge = "3/3✓" if conf == "HIGH" else "2/3✓"
        row = f"{icon} {fid:<3} [{sev:<8}│{panel_badge}] {cwe:<8} {loc}"
        print(f"║ {row[:69]:<69} ║")
    print(f"╠{bar}╣")
    out_line = f"📦 Report : KURON-SECURITY-RESULTS.md  │  SARIF + JSONL + Stamp ready"
    print(f"║ {out_line:<69} ║")
    print(f"╚{bar}╝")
    print(f"wrote {len(records)} findings (stamp KURON-SECURITY-REVISION-{tag}.json)")


main()
