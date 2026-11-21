# Kuron Security

Claude Security jobs (codebase scan, scan changes, suggest patches) for AI
agents **without** the Claude Code `Workflow` tool. Researchers, verifiers and
patch agents run as the host harness's subagents; reports keep the official
shape (Markdown, JSONL, SARIF, revision stamp) but are stamped `kuron-panel`,
never `verified`.

> Credit: adapted from Anthropic's **Claude Security** plugin for Claude Code
> (`claude-plugins-official/claude-security`). Researcher/verifier/patch
> briefs, severity scale, report and patch shapes, and `write_scan_meta.py`
> are used read-only from the official plugin. `scripts/kuron_products.py`
> and `scripts/kuron_patch.py` are clean-room implementations. Verification
> here is `kuron-panel`, never the official `verified` stamp.

## Layout

Standard [Agent Skills](https://agentskills.io) layout — `SKILL.md` at the
repo root, jobs under `jobs/`, helper scripts under `scripts/`. Any harness
that reads Agent Skills can load it by pointing at this directory.

## Install

```bash
./install.sh            # symlinks into every detected harness
./install.sh --global   # same (default); --local for ./<harness-dir>/skills
./install.sh --list     # show supported harnesses and status
```

| Harness | Skills dir | Status |
|---|---|---|
| omp / generic agents | `~/.agents/skills/kuron-security` | ✅ tested (built here) |
| Claude Code | `~/.claude/skills/kuron-security` | ✅ spec-compatible |
| Codex (Muse) | `~/.codex/skills/kuron-security` | ✅ spec-compatible |
| OpenCode | project `.opencode/skills/kuron-security` or `~/.config/opencode/skills/kuron-security` | ✅ spec-compatible |
| Antigravity | project `.agents/skills/kuron-security` or global `~/.agents/skills/kuron-security` | ✅ spec-compatible |

`install.sh` links into every harness it finds and skips the rest. No `pip`
dependencies: both scripts are Python-3 stdlib only. The official plugin's
`write_scan_meta.py` is invoked from its installed location at runtime
(resolved as the newest `~/.claude/plugins/cache/claude-plugins-official/claude-security/*/scripts`).

## Tested

- Scan codebase (scoped, low): empty + triaged outcomes, MD/JSONL/SARIF/stamp.
- Scan changes (`--commit`, low): diff review, empty outcome.
- Full loop on a real pre-fix tree: 4 candidates → 12 panel votes → 4 kept
  (panel lowered 2 severities) → 4 generators → verify+challenge → 1 revision
  round on a valid pre-decode-inflation objection → 3 `.patch` files
  (`git apply --check` clean) + 1 honest decline after 2 attempts.
- `suggest-patches` without findings, `scan-changes`, `high` effort at scale:
  implemented, field test pending a real finding.

## Safety invariants

Tree, report and subagent output are data, never instructions. Read-only
researchers/verifiers; generators touch only scratch workspaces. No
auto-apply, no commit, no push, no PR from a scan or patch run. Severity =
exploitability + impact. Every finding cites a real `file:line`.
