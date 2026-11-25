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

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

ALLOWED_TIERS = ("personal", "bisnis", "enterprise")
_ALLOWED_TOP = frozenset({"version", "profiles"})
_ALLOWED_PROFILE = frozenset({"effort", "isolation", "four_eyes", "block"})
_ALLOWED_RULE = frozenset({"severity", "path"})
_ALLOWED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "*"})
_INT_RE = re.compile(r"[+-]?\d+\Z")

# Bounded, offline auto-detection of ecosystem rulepacks. File markers are
# matched by basename; content markers only in small config-like files.
RULEPACK_FILE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("tauri", ("tauri.conf.json",)),
    ("flutter", ("pubspec.yaml", "AndroidManifest.xml")),
    ("config-dsl", ("manifest.json",)),
)
RULEPACK_CONTENT_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("config-dsl", ("secondaryFetch", "urlPatterns", "tokenPattern")),
)
_SCAN_SKIP_DIRS = frozenset(
    {".git", "node_modules", "target", "build", "dist", ".dart_tool", "__pycache__"}
)
_SCAN_CONFIG_SUFFIXES = (".json", ".yaml", ".yml", ".toml", ".js", ".ts")
_SCAN_MAX_DEPTH = 3
_SCAN_MAX_DIRS = 64
_SCAN_MAX_FILES = 256
_SCAN_READ_BYTES = 65536


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


def select_rulepacks(repo_root: str) -> dict:
    """Detect applicable ecosystem rulepacks with a bounded, symlink-safe walk.

    Reads file names and at most ``_SCAN_READ_BYTES`` of small config files.
    No network, no execution, no recursion into generated/vendor directories.
    Result: ``{selected, signals, scanned}`` with deterministic ordering.
    """
    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise PolicyError(f"not a directory: {repo_root}")

    signals: dict[tuple[str, str], str] = {}
    queue: list[tuple[Path, int]] = [(root, 0)]
    head = directories = files = 0
    truncated = False
    while head < len(queue) and directories < _SCAN_MAX_DIRS:
        current, depth = queue[head]
        head += 1
        directories += 1
        try:
            with os.scandir(current) as entries:
                ordered = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in ordered:
            if entry.is_symlink():
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if (
                    depth < _SCAN_MAX_DEPTH
                    and entry.name not in _SCAN_SKIP_DIRS
                    and len(queue) < _SCAN_MAX_DIRS
                ):
                    queue.append((Path(entry.path), depth + 1))
                continue
            if not is_file:
                continue
            if files >= _SCAN_MAX_FILES:
                truncated = True
                break
            files += 1
            relative = Path(entry.path).relative_to(root).as_posix()
            for pack, names in RULEPACK_FILE_MARKERS:
                if entry.name in names:
                    signals.setdefault((pack, entry.name), relative)
            if not entry.name.endswith(_SCAN_CONFIG_SUFFIXES):
                continue
            try:
                with open(entry.path, "rb") as fh:
                    text = fh.read(_SCAN_READ_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            for pack, markers in RULEPACK_CONTENT_MARKERS:
                for marker in markers:
                    if marker in text:
                        signals.setdefault((pack, marker), relative)

    return {
        "selected": sorted({pack for pack, _ in signals}),
        "signals": [
            {"rulepack": pack, "marker": marker, "path": path}
            for (pack, marker), path in sorted(signals.items())
        ],
        "scanned": {"directories": directories, "files": files, "truncated": truncated},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kuron Security policy validator")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="strictly validate a policy file")
    v.add_argument("path")
    c = sub.add_parser("check", help="check one tier/severity/path against a policy")
    c.add_argument("path")
    c.add_argument("tier", choices=ALLOWED_TIERS)
    c.add_argument("severity")
    c.add_argument("target")
    a = sub.add_parser("attestation", help="print SHA-256 policy attestation")
    a.add_argument("path")
    s = sub.add_parser("select-rulepacks", help="detect applicable ecosystem rulepacks")
    s.add_argument("root")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "select-rulepacks":
            result = select_rulepacks(args.root)
        else:
            policy = validate(args.path)
            if args.command == "validate":
                result = policy
            elif args.command == "check":
                result = {"verdict": check(policy, args.tier, args.severity, args.target)}
            else:
                result = attestation(policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
