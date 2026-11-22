#!/usr/bin/env python3
"""Minimal versioned policy validator and SHA-256 attestation for Kuron Security v2."""

from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path


def _unquote(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return val[1:-1]
    return val


def _parse_policy_yaml(text: str) -> tuple[int, dict]:
    version = 1
    profile_rules: dict[str, dict] = {}
    in_profiles = False
    current_tier: str | None = None
    in_block = False
    current_item: dict | None = None

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if indent == 0:
            in_profiles = False
            current_tier = None
            in_block = False
            current_item = None
            if stripped.startswith("version:"):
                version = int(_unquote(stripped.split(":", 1)[1]))
            elif stripped == "profiles:":
                in_profiles = True
            continue

        if not in_profiles:
            continue

        if indent == 2 and stripped.endswith(":"):
            current_tier = stripped[:-1].strip()
            profile_rules.setdefault(current_tier, {"block": []})
            in_block = False
            current_item = None
            continue

        if current_tier is None:
            continue

        if indent == 4:
            current_item = None
            if stripped == "block:":
                in_block = True
            elif stripped == "block: []":
                in_block = False
                profile_rules[current_tier]["block"] = []
            elif ":" in stripped:
                in_block = False
                k, v = stripped.split(":", 1)
                profile_rules[current_tier][k.strip()] = _unquote(v)
            continue

        if in_block and indent >= 6:
            if stripped.startswith("- "):
                current_item = {}
                profile_rules[current_tier]["block"].append(current_item)
                rest = stripped[2:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    current_item[k.strip()] = _unquote(v)
            elif current_item is not None and ":" in stripped:
                k, v = stripped.split(":", 1)
                current_item[k.strip()] = _unquote(v)

    return version, profile_rules


def validate(path: str) -> dict:
    """Read and validate a kuron-policy.yml file and compute its SHA-256."""
    raw_bytes = Path(path).read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    version, profile_rules = _parse_policy_yaml(raw_bytes.decode("utf-8"))
    return {
        "version": version,
        "sha256": sha256,
        "profile_rules": profile_rules,
    }


def check(policy: dict, tier: str, severity: str, path: str) -> str:
    """Return 'block' if a rule for tier matches severity and path glob, else 'allow'."""
    rules = (policy.get("profile_rules") or {}).get(tier) or {}
    sev_upper = str(severity).upper()
    for rule in rules.get("block") or []:
        rule_sev = str(rule.get("severity", "*")).upper()
        rule_path = str(rule.get("path", "*"))
        if (rule_sev == "*" or rule_sev == sev_upper) and fnmatch.fnmatch(path, rule_path):
            return "block"
    return "allow"


def attestation(policy: dict) -> dict:
    """Return deterministic policy attestation for trace and revision stamp."""
    return {
        "policy_version": policy.get("version"),
        "policy_sha256": policy.get("sha256"),
    }
