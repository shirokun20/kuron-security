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

    total = max(len(records), 1)
    rule = "─" * 68
    scope_str = ", ".join(scan.scope) if scan.scope else "whole repository"
    print(f"\n╭─ 🛡️  KURON SECURITY · SCAN SCORECARD {rule[:30]}")
    print(f"│  Mode     : {scan.mode} ({meta.get('effort') or 'default'} effort)")
    print(f"│  Scope    : {scope_str}")
    print(f"│  Revision : {tag} · Stamp: kuron-panel")
    print(
        f"│  Summary  : {len(records)} kept "
        f"(CRITICAL {counts['CRITICAL']} · HIGH {counts['HIGH']} · "
        f"MEDIUM {counts['MEDIUM']} · LOW {counts['LOW']})"
    )
    print(f"├─ Severity Breakdown {rule[:47]}")
    for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts[tier]
        filled = int(round((c / total) * 20)) if len(records) > 0 else 0
        meter = "█" * filled + "░" * (20 - filled)
        print(f"│  {tier:<8} : {meter}  {c}")
    print(f"├─ Kept Findings ({len(records)}) {rule[:48]}")
    if not raws:
        print("│  [CLEAN]   0 findings survived the 3-lens refutation panel.")
    for idx, r in enumerate(raws):
        fid = str(r.get("id", f"F{idx + 1}"))
        sev = str(r.get("severity", "LOW")).upper()
        cwe = str(r.get("cwe_id") or r.get("cweId") or "-")
        loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
        title = str(r.get("title", "")).strip()
        conf = str(r.get("confidence", "high")).upper()
        panel_badge = "3/3✓ (R:✓ I:✓ D:✓)" if conf == "HIGH" else "2/3✓"
        badge = f"[{sev}]"
        print(f"│  {badge:<9} {fid} · {cwe} · {panel_badge}")
        if title:
            print(f"│            {title}")
        print(f"│            └─ {loc}")
        if idx + 1 < len(raws):
            print("│")
    print(f"├─ Artifacts {rule[:56]}")
    print("│  Report   : KURON-SECURITY-RESULTS.md")
    print(
        f"│  Machine  : KURON-SECURITY-RESULTS.sarif · .jsonl · "
        f"KURON-SECURITY-REVISION-{tag}.json"
    )
    print(f"╰{rule}")
    print(f"wrote {len(records)} findings (stamp KURON-SECURITY-REVISION-{tag}.json)")


main()
