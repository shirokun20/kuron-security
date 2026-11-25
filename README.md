# 🛡️ Kuron Security

[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Agent Skills 2026](https://img.shields.io/badge/agent--skills-2026_compatible-blue)](https://agentskills.io)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-informational)](#what-you-get)
[![Release](https://img.shields.io/github/v/release/shirokun20/kuron-security)](https://github.com/shirokun20/kuron-security/releases)
[![skills.sh](https://img.shields.io/badge/skills.sh-kuron--security-blue)](https://www.skills.sh/shirokun20/kuron-security/kuron-security)
[![agentskill.sh](https://img.shields.io/badge/agentskill.sh-listed-brightgreen)](https://agentskill.sh/@shirokun20/kuron-security)
[![skillsmd](https://img.shields.io/badge/skillsmd-submitted-lightgrey)](https://skillsmd.dev/)
[![Sponsor](https://img.shields.io/badge/sponsor-shirokun20-ff69b4)](https://github.com/sponsors/shirokun20)
[![M8ven Score](https://m8ven.ai/badge/mcp/shirokun20-kuron-security-tpuyxk?v=0aec0d41ce52a4e726c51b56795d86fe)](https://m8ven.ai/mcp/shirokun20-kuron-security-tpuyxk?s=readme)

**Run Anthropic's Claude Security pipeline on any 2026 AI coding agent — no proprietary `Workflow` tool required.**

> [!IMPORTANT]
> If you run official `claude-security` outside Claude Code's internal `Workflow` runtime, it halts before reading a single file:
> ```text
> The scan pipeline is unavailable in this session (it needs the Workflow tool)...
> ```
> **Kuron Security** replaces that locked engine with waves of standard subagents your 2026 harness already has (**Antigravity 2.0**, **omp**, **OpenCode**, **Codex**, **Claude Code**, **muse**). All briefs are vendored clean-room in `agents/`, the SARIF/MD/JSONL renderer is vendored and deterministic, and no runtime code or brief is imported from an official plugin cache. It adds capability probing, taint-chain evidence contracts, **ASCII scorecards**, **Mermaid source-to-sink attack graphs**, and **honest provenance labels** (`kuron-panel`, `ad-hoc-panel`, `unverified-single-pass`). See [Relationship to `claude-security`](#relationship-to-claude-security).

---

## Why Kuron Security vs. a generic `"audit my code"` prompt?

| Capability | Generic AI Prompt (`"find security bugs"`) | Official `claude-security` Plugin | 🛡️ **Kuron Security (`v2.2.1` · 2026)** |
|---|---|---|---|
| **Harnesses supported** | Any chat | Claude Code (`Workflow` tool only) | **Antigravity · omp · OpenCode · Codex · Claude Code** |
| **False-positive filtering** | ❌ Single LLM guesses & pads | ✅ 3-lens verifier panel | ✅ **3-lens adversarial panel (`REACHABILITY` · `IMPACT` · `DEFENSES`)** |
| **Severity calibration** | ❌ Frequently inflates to `HIGH`/`CRITICAL` | ✅ Clamped to lowest confirming voter | ✅ **Automatic panel severity downgrade + visual meter** |
| **Attack-path visualization** | ❌ Prose wall | ❌ Prose only | ✅ **Per-finding Mermaid Source-to-Sink graph + `<details>` audit trail** |
| **Patch verification** | ❌ Edits your working tree directly | ✅ Scratch clone + verifier + attacker | ✅ **Isolated scratch clone + 3-claim verifier + fresh attacker challenge** |
| **Machine outputs** | ❌ Chat text only | ✅ MD + JSONL + SARIF + stamp | ✅ **MD + JSONL + SARIF 2.1.0 + honest provenance stamp** |

---

## Operating Tiers & Honest Provenance Labels (`v2.2.1`)

### Three Operating Tiers

| Tier | Effort & Shape | Isolation | Artifacts & Review |
|---|---|---|---|
| `personal` | Low/medium, scoped focus | Local worktree | MD + JSONL + SARIF + stamp; optional human review |
| `bisnis` | Medium (high on sensitive areas) | Enforced sandbox, worktree per scan | All 4 artifacts + mandatory redaction + HIGH/CRITICAL review before patch |
| `enterprise` | High, full top-level coverage | Ephemeral worktree per run, deny-default sandbox, SHA-256 attested `policy/kuron-policy.yml` | Immutable `trace.jsonl`, four-eyes review on CRITICAL before patch |

### Honest Provenance Labels

| Label | When Used | Example |
|---|---|---|
| `kuron-panel` | Specialist `security-reviewer` + official briefs ran | Full 3-lens specialist panel |
| `ad-hoc-panel` | 3 isolated read-only replacement lenses ran (requires user consent) | Antigravity `define_subagent` / `research` |
| `unverified-single-pass` | No subagents available; single pass + deterministic read-only script check (requires user consent) | CLI-only harness |

---

## Quickstart (30 seconds)

### Option A — Universal 1-liner via `skills.sh` (installs to 20+ agents)

```bash
npx skills add shirokun20/kuron-security --skill kuron-security -g -y
```

Automatically detects and installs into **Antigravity, Claude Code, Codex, Cursor, OpenCode, Cline, Amp, Windsurf, Copilot, and 15+ other agents**.

### Option B — Claude Code / omp Plugin Marketplace

```text
/plugin marketplace add shirokun20/kuron-security
/plugin install kuron-security@kuron-security
```

| Harness (2026) | Global / Workspace Target | Install Command |
|---|---|---|
| **Antigravity (AGY 2.0)** | `~/.gemini/config/skills` or `<repo>/.agents/skills` | `npx skills add shirokun20/kuron-security -a antigravity` |
| **omp** | `~/.agents/skills` | `npx skills add shirokun20/kuron-security -g` |
| **Claude Code** | `~/.claude/skills` (or `.claude-plugin/plugin.json`) | `npx skills add shirokun20/kuron-security -a claude-code` |
| **Codex** | `~/.codex/skills` | `npx skills add shirokun20/kuron-security -a codex` |
| **OpenCode** | `~/.config/opencode/skills` or `<repo>/.opencode/skills` | `npx skills add shirokun20/kuron-security -a opencode` |

### Trigger prompts (copy & paste)

```text
Scan lib/core/services with Kuron Security at low effort.
```
```text
Scan this branch's changes against main with Kuron Security.
```
```text
Suggest patches for all findings in the latest Kuron Security report.
```

---

## How the 3-Phase Adversarial Pipeline Works

```mermaid
flowchart TD
    subgraph Phase1["🔍 Phase 1: Read-Only Discovery"]
        R1["Component × Lens Researchers"] --> C["Raw Candidates (C1..Cn)<br/>Exact file:line + verbatim snippet + CWE"]
    end

    subgraph Phase2["⚖️ Phase 2: 3-Lens Adversarial Refutation (Default: FALSE_POSITIVE)"]
        C --> L1["Lens 1: REACHABILITY<br/>Attacker-controlled entry?"]
        C --> L2["Lens 2: IMPACT<br/>Real worst-case gain?"]
        C --> L3["Lens 3: DEFENSES<br/>Upstream guard exists?"]
        L1 & L2 & L3 --> Gate{"≥ 2 TRUE_POSITIVE?"}
        Gate -->|"No (< 2 votes)"| Drop["❌ Dropped as False Positive"]
        Gate -->|"Yes (clamp to lowest severity)"| Kept["✅ Kept Findings (F1..Fn)<br/>Scorecard + Mermaid Graph + SARIF 2.1.0"]
    end

    subgraph Phase3["🔧 Phase 3: Isolated Scratch Patching"]
        Kept --> Gen["Patch Generator<br/>(Detached Scratch Clone at PATCH BASE)"]
        Gen --> Ver["Independent Patch Verifier<br/>(TARGETED · NO_NEW_VULN · BEHAVIOUR)"]
        Gen --> Atk["Fresh Attacker Researcher<br/>(Hunts bypasses in staged diff)"]
        Ver & Atk --> PGate{"3/3 CONFIDENT & 0 Bypasses?"}
        PGate -->|"1st Objection"| Rev["1x Revision Round"] --> Gen
        PGate -->|"2nd Objection"| Dec["⛔ Honest Decline Note"]
        PGate -->|"Pass"| Patch["📦 Ready-to-Apply F<n>.patch<br/>(git apply --check verified)"]
    end
```

---

## Live Scan Progress

Progress is an event stream first, a display second. Every phase, wave, and
agent transition is appended to `<run dir>/progress.jsonl` with a `trace_id`
that must exist in `trace.jsonl`, so the display is only a projection of real
recorded events — never a cosmetic guess.

`scripts/kuron_progress.py` writes a single ASCII line to **stderr** when a real
TTY is available:

```text
[KURON] 22/48 | phase 2/3 | 2m14s | kuron-panel
```

When the harness captures output, runs in CI, or has no usable terminal, it
falls back to plain milestone lines or to the event file alone. stdout stays
clean for JSONL, SARIF, and the final scorecard. There is no alternate-screen
and no keyboard handling, which is why this works in omp, agy, muse, opencode,
Claude Code, and Orca alike. An interactive drill-down view can be added later
as an optional renderer without changing the event contract.

## What You Get (Visual Output Preview)

### 1. Alignment-Safe Open-Rail CLI Scorecards

Every scan and patch run prints an ASCII open-rail scorecard on **stderr** (`+-`, `|`, `+-`) — cp1252-safe, zero ragged borders, and stdout stays machine-clean. The examples below use box-drawing characters for illustration; the live renderer is ASCII-only:

```text
╭─ 🛡️  KURON SECURITY · SCAN SCORECARD ──────────────────────────────
│  Mode     : scan (low effort)
│  Scope    : lib/core/config/remote_config_service.dart, lib/core/services/source_installer_service.dart
│  Revision : b977b4e5736d · Stamp: kuron-panel
│  Summary  : 3 kept (CRITICAL 0 · HIGH 0 · MEDIUM 1 · LOW 2)
├─ Severity Breakdown ───────────────────────────────────────────────
│  CRITICAL : ░░░░░░░░░░░░░░░░░░░░  0
│  HIGH     : ░░░░░░░░░░░░░░░░░░░░  0
│  MEDIUM   : ███████░░░░░░░░░░░░░  1
│  LOW      : █████████████░░░░░░░  2
├─ Kept Findings (3) ────────────────────────────────────────────────
│  [MEDIUM]  F1 · CWE-20 · 3/3✓ (R:✓ I:✓ D:✓)
│            Reserved config identifiers ('app', 'tags') not blocked during source config installation
│            └─ lib/core/config/remote_config_service.dart:455
│
│  [LOW]     F2 · CWE-409 · 3/3✓ (R:✓ I:✓ D:✓)
│            Unbounded ZIP decompression (zip bomb) in source package inspection and extraction
│            └─ lib/core/services/source_installer_service.dart:469
│
│  [LOW]     F3 · CWE-400 · 3/3✓ (R:✓ I:✓ D:✓)
│            Unbounded remote icon download and disk persistence in source installer
│            └─ lib/core/services/source_installer_service.dart:958
├─ Artifacts ────────────────────────────────────────────────────────
│  Report   : KURON-SECURITY-RESULTS.md
│  Machine  : KURON-SECURITY-RESULTS.sarif · .jsonl · KURON-SECURITY-REVISION-b977b4e5736d.json
╰────────────────────────────────────────────────────────────────────
```

```text
╭─ 🔧 KURON SECURITY · PATCH SCORECARD ──────────────────────────────
│  Base     : b977b4e5736d · Written: 1 · Declined: 0 · Skipped: 0
├─ Units (1) ────────────────────────────────────────────────────────
│  [READY]    F1 · Reserved config identifiers ('app', 'tags') not blocked during source config installation
│             Gate  : TARGETED ✓ │ NO_NEW_VULN ✓ │ BEHAVIOUR_UNCHANGED ✓ (attempts=1)
│             Check : git apply --check (clean)
│             Apply : git apply KURON-SECURITY-20261121-125051/patches/F1.patch
╰────────────────────────────────────────────────────────────────────
```

### 2. GitHub Security Advisory Card (`KURON-SECURITY-RESULTS.md` + `F1.patch`)

Each finding is presented as an instant-triage **Security Advisory Card** combining a 1-row metadata header, a **Source-to-Sink Mermaid graph**, a **syntax-highlighted `diff` preview**, and an expandable **3-Lens Panel Audit Table**:

#### `F1` — Reserved config identifiers (`'app'`, `'tags'`) not blocked during source config installation

| Severity | Confidence | Weakness | Sink (`file:line`) | Panel Verdict | Patch Status |
|---|---|---|---|---|---|
| 🟡 **`MEDIUM`** | **`HIGH`** | `CWE-20` (Improper Input Validation) | `remote_config_service.dart:455` | ✅ **`3/3 TRUE_POSITIVE`** (`kuron-panel`) | 🔧 **`F1.patch` ready** (`apply=clean`) |

```mermaid
flowchart TD
  A["INPUT — source: 'app'<br/>source_installer_service.dart:407"]
  B["TRUST BOUNDARY<br/>_validateSourceId passes<br/>remote_config_service.dart:67"]
  C["IMPACT — next startup overrides _appConfig<br/>remote_config_service.dart:645"]
  A -->|"sourceId = 'app'"| B
  B -->|"config + registry write<br/>:431 / :455"| C
  A -. "no reserved-ID guard at :56" .-> C
  classDef impact fill:#5b1a1a,stroke:#ff6b6b,color:#fff;
  class C impact;
```

> [!WARNING]
> **Impact & Exploit Scenario:** An untrusted source manifest or ZIP package claiming `"source": "app"` writes `configs/app-config.json` and registers `'app'` in `installed_source_ids` (because `_bundledSourceIds` only checks `{'[REDACTED]'}`). On the next startup, `_restoreInstalledSourcesFromCache` loads `app-config.json` into `_appConfig`, hijacking global settings including `storage.folders.backup` (passed to `path.join` in `DownloadBloc`/`DownloadService`) while remaining invisible in the installed-sources UI.

```diff
--- a/lib/core/config/remote_config_service.dart
+++ b/lib/core/config/remote_config_service.dart
@@ -56,15 +56,22 @@ class RemoteConfigService {
   static const Set<String> _bundledSourceIds = {'[REDACTED]'};
+  static const Set<String> reservedConfigIds = {'app', 'tags', ..._bundledSourceIds};
+
+  static bool isReservedConfigId(String sourceId) =>
+      reservedConfigIds.contains(sourceId.trim().toLowerCase());
 
   static void _validateSourceId(String sourceId) {
-    if (!_sourceIdPattern.hasMatch(sourceId)) {
+    if (!_sourceIdPattern.hasMatch(sourceId) || isReservedConfigId(sourceId)) {
       throw FormatException('Invalid sourceId: "$sourceId"');
     }
   }
```

<details>
<summary>🔬 <b>3-Lens Adversarial Panel Audit Trail (3/3 Confirmed · Click to expand)</b></summary>

| Lens | Verdict | Rated Severity | Decisive Code Evidence (`file:line`) |
|---|---|---|---|
| **1. `REACHABILITY`** | ✅ `TRUE_POSITIVE` | `MEDIUM` | `_installSourceFromLink` (`settings_source_install.dart:446`) / `_installSourceFromZip` (`line 560`) → `installCandidates` (`source_installer_service.dart:738`) → `applySourceConfigFromJson` (`remote_config_service.dart:394`) → `markSourceInstalled('app')` (`line 455`) → `_loadFromFile('app')` (`line 645`). |
| **2. `IMPACT`** | ✅ `TRUE_POSITIVE` | `MEDIUM` | `_appConfig` controls global `AppLimits`, `AppDurations`, and `AppStorage.backupFolderName` (`app_constants.dart:95-96`), which flows unvalidated into `path.join(baseDownloadPath, backupFolderName, ...)` (`download_bloc.dart:1223`, `download_service.dart:590`). |
| **3. `DEFENSES`** | ✅ `TRUE_POSITIVE` | `MEDIUM` | Neither `_validateSourceId` (`remote_config_service.dart:66`) nor `SourceConfig.fromJson` (`config_models.g.dart:28`, which ignores unknown keys) blocks `'app'` or `'tags'`. |

</details>

### 3. Self-Contained Report Bundle

```text
KURON-SECURITY-20261121-125051/
├── .gitignore                               # contains "*" so artifacts never leak into git commits
├── KURON-SECURITY-RESULTS.md                # visual human triage report (see examples/)
├── KURON-SECURITY-RESULTS.jsonl             # strict JSONL for CI gates
├── KURON-SECURITY-RESULTS.sarif             # SARIF 2.1.0 for GitHub Code Scanning & IDEs
├── KURON-SECURITY-REVISION-b977b4e5736d.json # revision & honest provenance verification stamp
└── patches/                                 # F1.patch, F1.md, PATCHES.md, patches.jsonl
```

---

## Field-Tested Matrix (November 2026)

| Harness | Mode | Real-world 2026 Verification Result |
|---|---|---|
| **Antigravity (`AGY 2.0`)** | Native subagents | Scanned post-fix `HEAD` (`b977b4e5`) → confirmed all 3 `CWE-22` path-traversal fixes held, discovered **new `MEDIUM` (`CWE-20`) reserved-ID hijack** (`"source": "app"` overwriting `_appConfig`) + 2 resource-exhaustion findings (**9/9 panel votes**), then generated & verified `F1.patch` (`3/3 CONFIDENT`, `git apply` clean, `5/5` unit tests passing). |
| **omp** | Native subagents | Scanned pre-fix tree (`2e726ac`) → **4 candidates, 12 panel votes, 4 kept** (2 severities downgraded by panel) → **3 clean `.patch` files** (`git apply --check` clean) + **1 honest decline** after 2 rounds (caught spoofable ZIP central-directory headers). |
| **OpenCode** (`opencode run`) | Headless CLI | Found planted SQLi candidate; panel conservatively rejected `1/3` (missing route context in isolated fixture — zero false-positive promotion) and emitted full MD/JSONL/SARIF bundle. |
| **Claude Code / Codex** | Subagent skill | Spec-compatible (`Agent Skills` format); ready for field runs. |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Official `claude-security` plugin not in cache | No action needed: `agents/` provides all briefs and `kuron_products.py` includes a built-in, deterministic SARIF 2.1.0 builder. Nothing is loaded from a plugin cache at runtime. Install the official plugin separately only if you want to compare `kuron-panel` behavior. |
| `python3: command not found` | Install Python 3 (`brew install python` on macOS, `apt install python3` on Debian/Ubuntu). Standard library only — zero `pip` dependencies. |
| Verifier "reviewed the wrong tree" | Always pass absolute `SCAN_ROOT` / `WORKSPACE` paths in subagent briefs. |
| `git apply --check` fails on a generated patch | Your working tree moved after the scan; the patch is anchored to the recorded `PATCH BASE` commit in `F<n>.md`. |

---

## Support & Sponsor

Kuron Security is maintained in public, free to install, and free to fork. If it saves you time or catches a real bug, the most useful things you can do are:

- **Star the repo** and install it with `npx skills add shirokun20/kuron-security --skill kuron-security -g -y` — skills.sh indexes from real installs, so this is how the skill becomes discoverable to other agents.
- **Report a false positive or a missed bug** with the `file:line` and the project language in an issue. Field reports are the fastest way to improve the evidence contract and the 3-lens panel.
- **Add a harness** you actually use. See `CONTRIBUTING.md` — the capability adapter is designed so a new harness is a small, testable addition.
- **Sponsor the work** at [github.com/sponsors/shirokun20](https://github.com/sponsors/shirokun20). Funds go to maintenance, more harness coverage, larger real-world scan fixtures, and keeping the audit trail and SARIF output standards-compliant. No feature is gated behind sponsorship — ever.

## Relationship to `claude-security`

Kuron Security is an **independent, clean-room reimplementation** of the
*workflow shape* described by Anthropic's `claude-security` plugin (read-only
discovery → three-lens adversarial verification → isolated patching →
MD/JSONL/SARIF artifacts). It is not affiliated with or endorsed by Anthropic.

| Aspect | What Kuron Security does |
|---|---|
| Agent briefs | Vendored clean-room in `agents/`. They are our own text, not copies of official briefs. |
| Python scripts | Original stdlib-only implementation in `scripts/kuron_*.py`. **No** `sys.path` mutation, no import of `lib.finding`, `lib.sarif`, `lib.secret`, or `lib.strictjson` from a user-writable plugin cache. |
| SARIF output | Built in-repo (`builder: vendored` in the revision stamp) with one `rules[]` descriptor per used `ruleId` and a pinned SARIF 2.1.0 schema URL. No vendor output is renamed or stripped of attribution. |
| Official plugin | Optional and **external**. It is treated as a reference for `kuron-panel` parity only; its presence is recorded as `observed` capability evidence but its code is never executed or imported. |
| Licensing | Kuron Security is MIT (see `LICENSE`). The official `claude-security` plugin carries its own license; this project does not redistribute its code. Where concepts or terminology overlap, they are attributed to the upstream project rather than presented as Kuron-authored. |
| Provenance labels | `kuron-panel` requires an observed multi-lens launch plus hash-present briefs; otherwise `ad-hoc-panel` (explicit consent) or `unverified-single-pass`. A `3/3` badge is computed from real R/I/D verdicts, never from a self-reported confidence field. |

This section replaces earlier wording that suggested official briefs were
"reused when present and matching" — that behavior was removed because an
unverified, user-writable import path and silent driver renaming could not
honor a clean-room or deterministic-artifact guarantee.

## Safety Invariants & Attribution

- **Honest labeling**: Every scan and patch product carries an honest provenance label (`kuron-panel`, `ad-hoc-panel`, or `unverified-single-pass`, plus `untested` on untested patches), never any `verified` or `panel-verified` stamp.
- **Zero unasked mutations**: Researchers and verifiers are strictly read-only. Patch generators touch only isolated scratch clones. Nothing is ever auto-applied, committed, pushed, or opened as a PR without your explicit request.
- **Indirect prompt-injection quarantine**: All scanned code and diffs are fenced inside `<untrusted_repository_data>` delimiters with control characters stripped; repository text attempting to steer scanner behavior is flagged as a `CWE-74` finding and never executed.
- **Credit**: All briefs are vendored clean-room in `agents/`; `scripts/kuron_*.py` are clean-room 2026 implementations. The official `claude-security` plugin is an external reference only, never imported at runtime. Not affiliated with Anthropic — see [Relationship to `claude-security`](#relationship-to-claude-security).

⭐ **Star this repo if your agent caught a real vulnerability with it!**
