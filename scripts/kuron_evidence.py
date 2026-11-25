#!/usr/bin/env python3
"""Evidence contract validator and pre-panel filter for Kuron Security v2."""

from __future__ import annotations

import argparse
import json
import re
import sys

REQUIRED_TAINT_ROLES = ("source", "guard", "sink")

# Vendored subset of CWE Base and Class IDs commonly seen in security findings.
# Kept as a stdlib frozenset so no dependency (PyYAML, cwe data package) is needed.
CWE_BASE_CLASS_IDS: frozenset[str] = frozenset(
    {
        "CWE-20", "CWE-22", "CWE-23", "CWE-59", "CWE-73", "CWE-74", "CWE-77",
        "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-98",
        "CWE-113", "CWE-116", "CWE-119", "CWE-120", "CWE-125", "CWE-129",
        "CWE-132", "CWE-134", "CWE-190", "CWE-191", "CWE-200", "CWE-209",
        "CWE-284", "CWE-285", "CWE-287", "CWE-288", "CWE-290", "CWE-306",
        "CWE-307", "CWE-311", "CWE-319", "CWE-347", "CWE-352", "CWE-354",
        "CWE-362", "CWE-367", "CWE-377", "CWE-378", "CWE-400", "CWE-401",
        "CWE-404", "CWE-407", "CWE-409", "CWE-410", "CWE-416", "CWE-426",
        "CWE-441", "CWE-444", "CWE-451", "CWE-470", "CWE-476", "CWE-494",
        "CWE-502", "CWE-522", "CWE-532", "CWE-552", "CWE-565", "CWE-601",
        "CWE-602", "CWE-611", "CWE-639", "CWE-640", "CWE-641", "CWE-665",
        "CWE-668", "CWE-674", "CWE-681", "CWE-697", "CWE-706", "CWE-732",
        "CWE-770", "CWE-772", "CWE-776", "CWE-777", "CWE-798", "CWE-806",
        "CWE-829", "CWE-833", "CWE-835", "CWE-862", "CWE-863", "CWE-901",
        "CWE-908", "CWE-918", "CWE-921", "CWE-922", "CWE-926", "CWE-929",
        "CWE-937", "CWE-939", "CWE-943", "CWE-913", "CWE-1188",
        "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-1236",
        "CWE-1321", "CWE-1336", "CWE-1333",
    }
)
VALID_CWE_CLASS_KINDS = frozenset({"base", "class"})

_FAMILY_PREFIXES = (
    ("trace:", "trace"),
    ("grep:", "grep"),
    ("git:", "git"),
    ("git-show", "git"),
    ("git-grep", "git"),
    ("lens-", "lens"),
    ("lens:", "lens"),
    ("panel:", "lens"),
)


def _route_family(route: object) -> str:
    """Map a route ID to its verification method family, not just its string."""
    text = str(route).strip().lower()
    for prefix, family in _FAMILY_PREFIXES:
        if text.startswith(prefix):
            return family
    if text in ("static", "static-grep", "source"):
        return "static"
    if text in ("runtime", "dynamic", "command-verify", "command", "script"):
        return "runtime"
    return text.split(":", 1)[0].split("-", 1)[0] or text


def _validate_poc(f: dict, reasons: list[str]) -> None:
    poc = f.get("poc_trace")
    steps = preconditions = why = None
    if isinstance(poc, dict):
        steps = poc.get("steps")
        preconditions = poc.get("preconditions", f.get("preconditions"))
        why = poc.get("why_guard_fails", f.get("why_guard_fails"))
    elif isinstance(poc, list):
        steps = poc
        preconditions = f.get("preconditions")
        why = f.get("why_guard_fails")
    elif poc is not None:
        reasons.append("poc_trace must be a list of 3-7 steps or an object with steps")

    if isinstance(steps, list):
        if not 3 <= len(steps) <= 7:
            reasons.append("poc_trace requires 3-7 static steps")
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                reasons.append(f"poc_trace[{idx}] is not an object")
                continue
            if not step.get("file") or step.get("line") is None or not step.get("action"):
                reasons.append(f"poc_trace[{idx}] missing file/line/action")
    elif poc is not None and not isinstance(poc, dict):
        pass
    else:
        reasons.append("poc_trace steps missing")

    if not isinstance(preconditions, list):
        reasons.append("poc_trace requires preconditions[]")
    if not str(why or "").strip():
        reasons.append("poc_trace requires why_guard_fails")


def _validate_cwe(f: dict, reasons: list[str]) -> None:
    value = f.get("cwe_class")
    if value is None or not str(value).strip():
        reasons.append("cwe_class missing (expected a CWE Base/Class ID or kind)")
        return
    text = str(value).strip()
    if text.lower() in VALID_CWE_CLASS_KINDS:
        cwe_id = str(f.get("cwe_id") or f.get("cweId") or "").strip().upper()
        if not re.fullmatch(r"CWE-[0-9]+", cwe_id):
            reasons.append("cwe_class kind requires a valid cwe_id")
        return
    if text.upper() not in CWE_BASE_CLASS_IDS:
        reasons.append(f"cwe_class {text!r} is not a known CWE Base/Class ID")


def validate_finding(f: dict) -> tuple[bool, list[str]]:
    """Validate the full evidence contract on a finding; return (ok, all_reasons)."""
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
            # line: 0 is a legitimate value; only a missing line is invalid.
            if not hop.get("file") or hop.get("line") is None:
                reasons.append(f"taint_path[{idx}] ({role or 'unknown'}) missing file or line")
        for role in REQUIRED_TAINT_ROLES:
            if role not in seen_roles:
                reasons.append(f"taint_path missing required role '{role}'")

    reachability = f.get("reachability")
    if not isinstance(reachability, dict):
        reasons.append("reachability missing")
    else:
        if reachability.get("active_in_default_config") is not True:
            reasons.append("reachability.active_in_default_config must be exactly True")
        if reachability.get("admin_only") is True:
            reasons.append("reachability is admin_only")
        if reachability.get("test_fixture") is True:
            reasons.append("reachability is test_fixture")

    _validate_poc(f, reasons)
    _validate_cwe(f, reasons)

    routes = f.get("independent_routes")
    if not isinstance(routes, list) or len({_route_family(r) for r in routes}) < 2:
        reasons.append("independent_routes requires at least 2 distinct verification method families")

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kuron Security evidence contract")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("validate", "validate one finding from a JSON file"),
        ("filter", "partition a JSON list of findings"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.path, encoding="utf-8") as fh:
            data = json.load(fh)
        if args.command == "validate":
            ok, reasons = validate_finding(data)
            result = {"ok": ok, "reasons": reasons}
        else:
            if not isinstance(data, list):
                raise ValueError("findings file must be a JSON list")
            kept, discarded = filter_findings(data)
            result = {"kept": kept, "discarded": discarded}
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
