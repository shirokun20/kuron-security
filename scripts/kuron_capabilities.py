#!/usr/bin/env python3
"""Runtime capability probe and verification path selection for Kuron Security v2.

Every capability carries a provenance source: ``observed`` (measured this run),
``declared`` (the caller/environment asserted it), or ``assumed`` (inferred from
a static table or binary-name sniff). Only observed evidence may justify the
strongest provenance label.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import shutil
from pathlib import Path

VALID_TIERS = ("personal", "bisnis", "enterprise")
VALID_SOURCES = ("observed", "declared", "assumed")

# One set of plugin path roots shared by every consumer in this module.
PLUGIN_ROOT_GLOBS: tuple[str, ...] = (
    "~/.claude/plugins/cache/claude-plugins-official/claude-security/*",
    "~/.gemini/config/plugins/claude-security",
)

HARNESS_DEFAULTS = {
    "agy": {
        "agent_types": ["self", "research", "image-generator", "flutter_a11y_agent"],
        "tools": ["read", "write", "subagent", "define_subagent", "ask"],
    },
    "claude-code": {
        "agent_types": ["security-reviewer", "general-purpose", "Explore"],
        "tools": ["read", "write", "subagent", "ask"],
    },
    "opencode": {
        "agent_types": ["security-reviewer", "general", "explore"],
        "tools": ["read", "write", "subagent", "ask"],
    },
    "omp": {
        "agent_types": ["security-reviewer", "explore"],
        "tools": ["read", "write", "subagent", "ask"],
    },
    "muse": {
        "agent_types": ["security-reviewer", "research"],
        "tools": ["read", "write", "subagent", "ask"],
    },
}


class CapabilityError(Exception):
    """Raised when requested tier or verification path cannot be satisfied."""


def _expand(pattern: str) -> list[str]:
    return sorted(glob.glob(os.path.expanduser(pattern)))


def plugin_brief_paths() -> list[str]:
    """All discovered official agent briefs, from every known plugin cache root."""
    found: set[str] = set()
    for root in _expand(PLUGIN_ROOT_GLOBS[0]):
        found.update(_expand(os.path.join(root, "agents", "*.md")))
    found.update(_expand(os.path.join(PLUGIN_ROOT_GLOBS[1], "agents", "*.md")))
    return sorted(found)


def plugin_script_paths() -> list[str]:
    """All discovered official script directories (reported only, never imported)."""
    found: set[str] = set()
    for root in _expand(PLUGIN_ROOT_GLOBS[0]):
        scripts = os.path.join(root, "scripts")
        if os.path.isdir(scripts):
            found.add(scripts)
    gemini_scripts = os.path.join(PLUGIN_ROOT_GLOBS[1], "scripts")
    if os.path.isdir(os.path.expanduser(gemini_scripts)):
        found.add(os.path.expanduser(gemini_scripts))
    return sorted(found)


def _has_plugin_briefs() -> bool:
    return bool(plugin_brief_paths())


def _briefs_digest(paths: list[str]) -> str | None:
    """Hash brief contents so a panel claim can be tied to observed files."""
    if not paths:
        return None
    digest = hashlib.sha256()
    for path in paths:
        digest.update(os.path.basename(path).encode("utf-8", errors="replace"))
        try:
            digest.update(Path(path).read_bytes())
        except OSError:
            return None
    return digest.hexdigest()


def _detect_harness(harness: str | None) -> tuple[str, str]:
    """Return (harness, source) where source is observed/declared/assumed."""
    if harness:
        return harness, "observed"
    env_harness = os.environ.get("KURON_HARNESS", "").strip()
    if env_harness:
        return env_harness, "declared"
    for candidate, name in (
        ("omp", "omp"),
        ("claude", "claude-code"),
        ("opencode", "opencode"),
        ("agy", "agy"),
        ("muse", "muse"),
    ):
        if shutil.which(candidate):
            return name, "assumed"
    return "unknown", "observed"


def probe(
    root: str,
    out_path: str,
    harness: str | None = None,
    panel_launch_observed: bool = False,
) -> dict:
    """Probe capabilities without executing agent commands and write capabilities.json.

    ``panel_launch_observed`` must be supplied by the caller only after a real
    subagent panel launch succeeds during this run. It is never inferred from
    a binary name or a file-existence check.
    """
    detected_harness, harness_source = _detect_harness(harness)
    defaults = HARNESS_DEFAULTS.get(
        detected_harness, {"agent_types": [], "tools": ["read", "write"]}
    )
    tools = list(defaults["tools"])
    has_git = shutil.which("git") is not None
    if has_git and "git" not in tools:
        tools.append("git")

    network_env = os.environ.get("KURON_NETWORK", "").strip().lower()
    has_network = network_env in ("1", "true", "yes")
    briefs = plugin_brief_paths()
    plugin_briefs_available = bool(briefs)
    briefs_sha256 = _briefs_digest(briefs)
    panel_observed = bool(panel_launch_observed) and plugin_briefs_available and bool(briefs_sha256)
    shell_git_dialect = "posix" if os.name == "posix" else os.name

    sources = {
        "harness": harness_source,
        "agent_types": "assumed",
        "tools": "assumed",
        "has_git": "observed" if has_git else "assumed",
        "has_network": "declared" if network_env else "assumed",
        "plugin_briefs_available": "observed",
        "plugin_briefs_sha256": "observed" if briefs_sha256 else "assumed",
        "panel_launch_observed": "observed" if panel_observed else "assumed",
        "shell_git_dialect": "observed",
    }

    caps = {
        "harness": detected_harness,
        "agent_types": list(defaults["agent_types"]),
        "tools": tools,
        "has_git": has_git,
        "has_network": has_network,
        "plugin_briefs_available": plugin_briefs_available,
        "plugin_briefs_sha256": briefs_sha256,
        "panel_launch_observed": panel_observed,
        "shell_git_dialect": shell_git_dialect,
        "capability_sources": sources,
        "sources": sources,
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(caps, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return caps


def _source_of(caps: dict, name: str) -> str:
    for key in ("capability_sources", "sources"):
        mapping = caps.get(key)
        if isinstance(mapping, dict) and name in mapping:
            return str(mapping[name])
    return "assumed"


def select_path(caps: dict, tier: str, consent: str | None) -> dict:
    """Deterministically select verification path and label from capabilities and tier."""
    if tier not in VALID_TIERS:
        raise CapabilityError(f"Unknown tier '{tier}'; expected one of {VALID_TIERS}")

    agent_types = list(caps.get("agent_types") or [])
    tools = list(caps.get("tools") or [])
    has_briefs = bool(caps.get("plugin_briefs_available", False))
    panel_observed = bool(caps.get("panel_launch_observed", False))
    backend = str(caps.get("harness") or "unknown")
    has_git = bool(caps.get("has_git", False))

    has_subagent = (
        "subagent" in tools
        or "define_subagent" in tools
        or any(a in agent_types for a in ("security-reviewer", "research", "general"))
    )

    observed_panel = (
        panel_observed
        and has_briefs
        and bool(caps.get("plugin_briefs_sha256"))
        and _source_of(caps, "panel_launch_observed") == "observed"
    )
    if "security-reviewer" in agent_types and observed_panel:
        label = "kuron-panel"
        agent_types_used = ["security-reviewer"]
    elif has_subagent:
        label = "ad-hoc-panel"
        used = [a for a in ("research", "security-reviewer") if a in agent_types]
        if not used:
            used = ["define_subagent"] if "define_subagent" in tools else ["subagent"]
        agent_types_used = used
    else:
        label = "unverified-single-pass"
        agent_types_used = []

    if tier == "enterprise":
        if not has_git or label == "unverified-single-pass":
            raise CapabilityError(
                "Enterprise tier requires git worktree isolation and a multi-lens subagent panel"
            )
    elif tier == "bisnis":
        if not has_git:
            raise CapabilityError("Bisnis tier requires git for per-scan worktree isolation")

    if label in ("ad-hoc-panel", "unverified-single-pass") and consent != "accept":
        raise CapabilityError(
            f"Verification path '{label}' provides lower assurance than kuron-panel; explicit consent='accept' required"
        )

    return {
        "tier": tier,
        "label": label,
        "backend": backend,
        "agent_types_used": agent_types_used,
        "panel_source": "observed" if label == "kuron-panel" else _source_of(caps, "agent_types"),
    }
