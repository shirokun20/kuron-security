#!/usr/bin/env python3
"""Evidence contract validator and pre-panel filter for Kuron Security v2."""

from __future__ import annotations

REQUIRED_TAINT_ROLES = ("source", "guard", "sink")


def validate_finding(f: dict) -> tuple[bool, list[str]]:
    """Validate evidence contract on a finding; return (ok, all_reasons)."""
    reasons: list[str] = []

    taint_path = f.get("taint_path")
    if not isinstance(taint_path, list) or not taint_path:
        reasons.append("taint_path missing or empty (requires source, guard, sink)")
    else:
        seen_roles: set[str] = set()
        for idx, hop in enumerate(taint_path):
            if not isinstance(hop, dict):
                reasons.append(f"taint_path[{idx}] is not an object")
                continue
            role = hop.get("role")
            if role in REQUIRED_TAINT_ROLES:
                seen_roles.add(role)
            if not hop.get("file") or not hop.get("line"):
                reasons.append(f"taint_path[{idx}] ({role or 'unknown'}) missing file or line")
        for role in REQUIRED_TAINT_ROLES:
            if role not in seen_roles:
                reasons.append(f"taint_path missing required role '{role}'")

    reachability = f.get("reachability")
    if not isinstance(reachability, dict):
        reasons.append("reachability missing")
    else:
        if reachability.get("active_in_default_config") is False:
            reasons.append("reachability inactive in default config (dead path)")
        if reachability.get("admin_only") is True:
            reasons.append("reachability is admin_only")
        if reachability.get("test_fixture") is True:
            reasons.append("reachability is test_fixture")

    routes = f.get("independent_routes")
    if not isinstance(routes, list) or len(set(routes)) < 2:
        reasons.append("independent_routes requires at least 2 distinct route IDs")

    return (len(reasons) == 0, reasons)


def filter_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition findings into (kept, discarded) without mutating kept findings."""
    kept: list[dict] = []
    discarded: list[dict] = []
    for f in findings:
        ok, reasons = validate_finding(f)
        if ok:
            kept.append(f)
        else:
            discarded.append({**f, "discard_reason": "; ".join(reasons)})
    return kept, discarded
