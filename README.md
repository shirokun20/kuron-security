# 🛡️ Kuron Security

[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/agent--skills-compatible-blue)](https://agentskills.io)
[![Harnesses](https://img.shields.io/badge/harness-omp_%7C_claude_code%7C_codex%7C_opencode%7C_antigravity-purple)](#install)

**Claude Security scans — on any AI agent.** Codebase scan, scan changes, and
suggest-patches, with a parallel researcher + 3-lens verifier panel, for
sessions that don't have Claude Code's `Workflow` tool. Reports keep the
official shape (Markdown, JSONL, SARIF, revision stamp) with honestly-labeled
`kuron-panel` verification.

> Credit: adapted from Anthropic's **Claude Security** plugin
> (`claude-plugins-official/claude-security`). Prompts, severity scale and
> report/patch shapes are used read-only from the official plugin;
> `scripts/kuron_*.py` are clean-room implementations. This project is not
> affiliated with Anthropic.

## 30-second pitch

Your agent can't run the official skill (no `Workflow` tool) so it quits with
*"The scan pipeline is unavailable in this session"*. Kuron Security replaces
the engine — same menu, same safety invariants, same report shape — with
subagents your harness already has. On a real pre-fix tree it found 4
vulnerabilities, panel-verified all 4, wrote 3 patches (`git apply --check`
clean) and honestly declined 1 after two failed attempts.

## Install (one command)

```bash
git clone https://github.com/shirokun20/kuron-security.git
cd kuron-security && ./install.sh   # symlinks into every harness it finds
```

| Harness | Target | Notes |
|---|---|---|
| omp / generic agents | `~/.agents/skills/kuron-security` | built & tested here |
| Claude Code | `~/.claude/skills/kuron-security` | spec-compatible |
| Codex | `~/.codex/skills/kuron-security` | spec-compatible |
| OpenCode | `.opencode/skills/` or `~/.config/opencode/skills/` | spec-compatible |
| Antigravity | `.agents/skills/` or `~/.agents/skills/` | spec-compatible |

`./install.sh --list` shows what's installed. Zero `pip` dependencies —
both scripts are Python-3 stdlib only (and the official plugin already
requires `python3`, so nothing new is asked of the machine).

## What you get

```
KURON-SECURITY-20261121-115809/
├── KURON-SECURITY-RESULTS.md      # human report (see examples/)
├── KURON-SECURITY-RESULTS.jsonl   # one finding per line (CI gates)
├── KURON-SECURITY-RESULTS.sarif   # dashboards & IDE viewers
├── KURON-SECURITY-REVISION-*.json # stamp: kuron-panel, never "verified"
└── patches/
    ├── F1.patch  F1.md  …        # panel-verified patches, apply when YOU choose
    └── PATCHES.md                 # index + trust labels
```

Real output from the field test ([examples/](examples/)):

```markdown
### F1 — Path traversal file write via unsanitized remote sourceId (LOW, high)

**Impact.** Attacker-controlled JSON persisted outside `configs/` …
**Where.** `remote_config_service.dart:407` — CWE-22
**Verification.** 3/3 lens verifiers confirmed (severity lowered HIGH→LOW).
```

## Honest limits

- Verification is `kuron-panel`, never the official `verified` stamp (that
  calibration belongs to Anthropic's Workflow pipeline — forging it would be
  fabrication).
- `high` effort at full-repo scale and no-finding patch runs are implemented
  but await field tests with real findings. The engine refuses to invent
  findings to test itself.
- Nothing auto-applies, commits, pushes, or opens PRs. Ever.

## Use it

Just ask your agent: *"scan this repo with kuron-security"*,
*"review my branch changes"*, or *"suggest patches for F1, F3"*.
The skill asks one scoped question, one fixed cost confirmation, then works
unattended in waves.

## Contribute

Field reports welcome: new harness paths for `install.sh`, verifier edge
cases, SARIF consumer fixes. Open an issue with your harness + transcript
snippet; PRs keep the safety invariants section untouched.

⭐ Star it if your agent found a real bug with it — that signal matters more
than any badge.
