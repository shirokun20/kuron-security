#!/usr/bin/env python3
"""Runtime capability probe and verification path selection for Kuron Security v2."""

from __future__ import annotations

import glob
import json
import os
import shutil
from pathlib import Path

VALID_TIERS = ("personal", "bisnis", "enterprise")

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


def _detect_harness(harness: str | None) -> str:
    if harness:
        return harness
    env_harness = os.environ.get("KURON_HARNESS", "").strip()
    if env_harness:
        return env_harness
    for candidate, name in (
        ("omp", "omp"),
        ("claude", "claude-code"),
        ("opencode", "opencode"),
        ("agy", "agy"),
        ("muse", "muse"),
    ):
        if shutil.which(candidate):
            return name
    return "unknown"


def _has_plugin_briefs() -> bool:
    pattern = os.path.expanduser(
        "~/.claude/plugins/cache/claude-plugins-official/claude-security/*/agents/scan-researcher.md"
    )
    return bool(glob.glob(pattern))


def probe(root: str, out_path: str, harness: str | None = None) -> dict:
    """Probe runtime capabilities without executing agent commands and write capabilities.json."""
    detected_harness = _detect_harness(harness)
    defaults = HARNESS_DEFAULTS.get(
        detected_harness, {"agent_types": [], "tools": ["read", "write"]}
    )
    tools = list(defaults["tools"])
    has_git = shutil.which("git") is not None
    if has_git and "git" not in tools:
        tools.append("git")

    has_network = os.environ.get("KURON_NETWORK", "").lower() in ("1", "true", "yes")
    plugin_briefs_available = _has_plugin_briefs()
    shell_git_dialect = "posix" if os.name == "posix" else os.name

    caps = {
        "harness": detected_harness,
        "agent_types": list(defaults["agent_types"]),
        "tools": tools,
        "has_git": has_git,
        "has_network": has_network,
        "plugin_briefs_available": plugin_briefs_available,
        "shell_git_dialect": shell_git_dialect,
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(caps, indent=2) + "\n", encoding="utf-8")
    return caps


def select_path(caps: dict, tier: str, consent: str | None) -> dict:
    """Deterministically select verification path and label from capabilities and tier."""
    if tier not in VALID_TIERS:
        raise CapabilityError(f"Unknown tier '{tier}'; expected one of {VALID_TIERS}")

    agent_types = list(caps.get("agent_types") or [])
    tools = list(caps.get("tools") or [])
    has_briefs = bool(caps.get("plugin_briefs_available", False))
    backend = str(caps.get("harness") or "unknown")
    has_git = bool(caps.get("has_git", False))

    has_subagent = (
        "subagent" in tools
        or "define_subagent" in tools
        or any(a in agent_types for a in ("security-reviewer", "research", "general"))
    )

    if "security-reviewer" in agent_types and has_briefs:
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
    }
