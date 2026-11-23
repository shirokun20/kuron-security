#!/usr/bin/env python3
"""Strict, stdlib-only versioned policy validator and SHA-256 attestation.

The bundled policy format is a fixed, small subset of YAML: integer ``version``,
``profiles:`` with exactly the known tiers, scalar profile keys, and ``block``
as either ``[]`` or a list of ``{severity, path}`` mappings. Anything outside
that shape is rejected with a typed PolicyError rather than silently mis-parsed.

When PyYAML happens to be installed, its safe parser may be used as an opt-in
validation pass via ``parse_with_pyyaml``; it is never required at runtime.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

ALLOWED_TIERS = ("personal", "bisnis", "enterprise")
_ALLOWED_TOP = frozenset({"version", "profiles"})
_ALLOWED_PROFILE = frozenset({"effort", "isolation", "four_eyes", "block"})
_ALLOWED_RULE = frozenset({"severity", "path"})
_ALLOWED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "*"})
_INT_RE = re.compile(r"[+-]?\d+\Z")


class PolicyError(Exception):
    """Raised for any malformed, unsupported, or out-of-shape policy input."""


def _unquote(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return val[1:-1]
    return val


def _fail(line: int | None, message: str) -> "None":
    prefix = f"line {line}: " if line is not None else ""
    raise PolicyError(prefix + message)


def _parse_policy_yaml(text: str) -> tuple[int, dict]:
    version: int | None = None
    profiles: dict[str, dict] = {}
    mode: str | None = None
    tier: str | None = None
    rule: dict | None = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        if "\t" in raw:
            _fail(lineno, "tabs are not allowed in the strict policy subset")
        if "#" in raw:
            _fail(lineno, "comments are not supported in the strict policy subset")
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if not stripped.endswith(":") and ":" not in stripped:
            _fail(lineno, "expected a 'key: value' mapping")

        if indent == 0:
            key, value = stripped.split(":", 1)
            key, value = key.strip(), value.strip()
            if key not in _ALLOWED_TOP:
                _fail(lineno, f"unknown top-level key {key!r}")
            if key == "version":
                if not _INT_RE.fullmatch(value):
                    _fail(lineno, "version must be an integer")
                version = int(value)
                mode = None
            else:  # profiles:
                if value:
                    _fail(lineno, "'profiles' must be a mapping")
                mode = "profiles"
            tier = rule = None
            continue

        if mode is None:
            _fail(lineno, "unexpected indented line outside a top-level mapping")

        if indent == 2:
            if not stripped.endswith(":") or ":" in stripped[:-1]:
                _fail(lineno, "expected a tier mapping such as 'enterprise:'")
            name = stripped[:-1].strip()
            if name not in ALLOWED_TIERS:
                _fail(lineno, f"unknown tier {name!r}; expected one of {ALLOWED_TIERS}")
            tier = name
            profiles.setdefault(tier, {"block": []})
            mode = "tier"
            rule = None
            continue

        if tier is None:
            _fail(lineno, "profile key without a tier")

        if indent == 4:
            if mode == "block" and rule is not None and ":" in stripped:
                key, value = stripped.split(":", 1)
                key = key.strip()
                if key not in _ALLOWED_RULE:
                    _fail(lineno, f"unknown block-rule key {key!r}")
                rule[key] = _unquote(value)
                continue
            if stripped == "block:":
                mode = "block"
                rule = None
                continue
            if stripped == "block: []":
                profiles[tier]["block"] = []
                mode = "tier"
                rule = None
                continue
            if stripped.startswith("block:"):
                _fail(lineno, "'block' must be [] or a list of mappings")
            if ":" not in stripped:
                _fail(lineno, "expected a scalar profile key")
            key, value = stripped.split(":", 1)
            key, value = key.strip(), value.strip()
            if key not in _ALLOWED_PROFILE - {"block"}:
                _fail(lineno, f"unknown profile key {key!r}")
            if not value:
                _fail(lineno, "nested maps are not supported in the strict policy subset")
            profiles[tier][key] = _unquote(value)
            mode = "tier"
            rule = None
            continue

        if indent >= 6:
            if mode != "block":
                _fail(lineno, "unexpected nested list outside 'block'")
            if not stripped.startswith("- "):
                # Continuation field of the current block item (e.g. "path: ...").
                if rule is None or ":" not in stripped:
                    _fail(lineno, "block items must start with '- '")
                key, value = stripped.split(":", 1)
                if key.strip() not in _ALLOWED_RULE:
                    _fail(lineno, f"unknown block-rule key {key.strip()!r}")
                rule[key.strip()] = _unquote(value)
                continue
            rest = stripped[2:].strip()
            if ":" not in rest:
                _fail(lineno, "block item must be a mapping")
            key, value = rest.split(":", 1)
            key = key.strip()
            if key not in _ALLOWED_RULE:
                _fail(lineno, f"unknown block-rule key {key!r}")
            rule = {key: _unquote(value)}
            profiles[tier]["block"].append(rule)
            continue

        _fail(lineno, f"unsupported indentation ({indent})")

    if version is None:
        _fail(None, "missing integer 'version'")
    if not profiles:
        _fail(None, "policy defines no profiles")

    for name, profile in profiles.items():
        block = profile.get("block")
        if not isinstance(block, list):
            _fail(None, f"profile {name!r} block must be a list")
        for item in block:
            if not isinstance(item, dict) or set(item) != _ALLOWED_RULE:
                _fail(None, f"profile {name!r} has a malformed block rule: {item!r}")
            severity = str(item["severity"]).strip().upper()
            if severity not in _ALLOWED_SEVERITIES:
                _fail(None, f"unknown severity {item['severity']!r} in profile {name!r}")
            item["severity"] = severity
            path = str(item["path"]).strip()
            if not path or "\x00" in path or os.path.isabs(path):
                _fail(None, f"invalid block path {item['path']!r} in profile {name!r}")
            item["path"] = _unquote(path)
    return version, profiles


def parse_with_pyyaml(text: str) -> dict | None:
    """Optional cross-check with PyYAML when installed; never required at runtime."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else None


def validate(path: str) -> dict:
    """Read and strictly validate a kuron-policy.yml file and compute its SHA-256."""
    try:
        raw_bytes = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path!r}: {exc}") from exc
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file must be UTF-8: {exc}") from exc
    version, profile_rules = _parse_policy_yaml(text)
    return {
        "version": version,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "profile_rules": profile_rules,
    }


def _match_path(path: str, pattern: str) -> bool:
    """Portable PurePath glob matching with '**' meaning 'any descendants'."""
    path_cls = PureWindowsPath if os.name == "nt" else PurePosixPath
    normalized = str(path_cls(path)).replace("\\", "/")
    pattern = str(pattern)
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        if normalized == prefix:
            return True
        if normalized.startswith(prefix + "/"):
            return True
        return path_cls(normalized).match(pattern)
    return path_cls(normalized).match(pattern)


def check(policy: dict, tier: str, severity: str, path: str) -> str:
    """Return 'block' for a matching rule (or any path in deny-default tiers).

    Enterprise is deny-by-default: absent an explicit allow rule, any path is
    blocked. Personal/bisnis remain allow-by-default for their documented use.
    """
    if tier not in ALLOWED_TIERS:
        raise PolicyError(f"unknown tier {tier!r}; expected one of {ALLOWED_TIERS}")
    rules = (policy.get("profile_rules") or {}).get(tier) or {}
    sev_upper = str(severity).upper()
    for rule in rules.get("block") or []:
        rule_sev = str(rule.get("severity", "*")).upper()
        rule_path = str(rule.get("path", "*"))
        if (rule_sev == "*" or rule_sev == sev_upper) and _match_path(path, rule_path):
            return "block"
    if tier == "enterprise":
        return "block"
    return "allow"


def attestation(policy: dict) -> dict:
    """Return deterministic policy attestation for trace and revision stamp."""
    return {
        "policy_version": policy.get("version"),
        "policy_sha256": policy.get("sha256"),
    }
