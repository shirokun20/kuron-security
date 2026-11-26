# Job: scan codebase (kuron-native)

Whole repository or scoped area at effort `low`/`medium`/`high`
(`max` accepted, runs as `high`). No tier word from the user: pick
with them when unclear, else `medium`.

## Effort (same work, omp waves)

- `low` — one researcher over the whole target, then the 3-lens panel.
  No inventory, no threat model, no sweep. (Deterministic secret scan when focus set.)
- `medium` — inventory-lite (below), one threat-model recon per
  component, one researcher per component x category lens (4 lenses:
  injection-and-input, auth-and-access, memory-and-unsafe,
  crypto-and-secrets; managed-language components skip
  memory-and-unsafe with the reason recorded), one sweep over
  unread files, deterministic secret scan when focus set, 3-lens panel (3/3 unanimous
  TRUE_POSITIVE required; any FALSE_POSITIVE or missing lens discards).
- `high` — as medium: up to 48 components (24 when the file count is
  unknown), two researchers per component x lens, two sweeps.

Component cap: 24 largest (48 at high); over-cap components are
`skippedComponents` with reason `over-cap` and named in the report.
Small scope (<=5 tracked files) at low/medium collapses to the
single-researcher shape, still panel-verified.

`focus: attack-surface` on large trees (>~300 files): researchers
spend effort on production code an attacker reaches; tests, fixtures,
generated code are background. A deterministic offline
`scripts/kuron_redaction.py scan <target>` runs whenever focus is set (any
tier); it reports only `file:line` plus pattern names and never prints or reads
raw key literals into model context. Never open `.env`, private key files, or
raw secret literals, and never copy a secret value into
`taint_path[].snippet`: cite `file:line` plus the pattern/sink class or use a
`[REDACTED]` placeholder instead.

## Sub-menu (whole repo never launches unasked)

Gauge cheaply: `git ls-files | wc -l`, per-dir `git ls-files --
<dir> | wc -l`. Then ask once: Whole repository (sized, e.g. `Whole
repository (~1619 files, medium)`), Scoped scan of the most exposed
area (real dirs with counts), I don't know (small tree -> whole at
medium; large tree -> scoped medium over the most exposed area,
stated as an assumption). Large tree: recommend scoped first.
`medium` default; `high` only for a small, high-stakes area.

## Run

1. Preflight: run `scripts/kuron_capabilities.py` (`probe` + `select_path`) and
   `scripts/kuron_policy.py` (`validate` + `attestation` on `policy/kuron-policy.yml`).
   Abort if the requested tier (`personal`/`bisnis`/`enterprise`) cannot be met.
   Open the progress stream with `scripts/kuron_progress.py`: append an event
   at each phase/wave boundary with the `trace_id` of the real trace event;
   `ProgressRenderer` writes to stderr only, never stdout.
2. Consolidated confirmation gate: confirm time/token cost AND explicit consent
   if the selected label is `ad-hoc-panel` or `unverified-single-pass` (headless
   without explicit consent aborts).
3. Scan root = absolute repo path. Create `KURON-SECURITY-<ts>/.kuron-security-run`
   and write `scan-meta.json` (with `label`, `tier`, `attestation`).
4. Partition: whole repo -> one component per top-level source dir
   (cap above applies); scoped -> scope dirs are the components. Auto-select
   rulepacks with `scripts/kuron_policy.py select-rulepacks <scan root>`:
   `tauri.conf.json` -> `rules/tauri.md`, `pubspec.yaml` ->
   `rules/flutter.md`, `manifest.json` / DSL markers (`secondaryFetch`,
   `urlPatterns`, `tokenPattern`) -> `rules/config-dsl.md`. Add the selected
   packs to researcher checklists; never execute config scripts or dependency
   code. The walk is bounded and offline; report `truncated` if it hits a cap.
5. Threat-model recon (medium/high): one read-only researcher per component
   reporting entryPoints, sinks, hotFiles (JSON).
6. Research in waves of <=8 dispatches using `agents/researcher.md` (read-only).
   Update `coverage.json` per wave.
7. Sweep over unread files; deterministic secret scan when focus set.
8. Pre-panel evidence gate (`scripts/kuron_evidence.py` `filter_findings`) +
   dedupe (`file:line + CWE`, max severity) -> `C1..Cn`, recording dropped items
   in `discarded[]`. Run 3-lens panel (`agents/verifier-*.md`) and log allowlisted
   checks via `scripts/kuron_trace.py`.
9. Scrub offline with `scripts/kuron_redaction.py scrub <report dir>` first; it
   replaces credential literals with `[REDACTED]` and writes `redaction.json`
   (metadata only). `agents/redactor.md` then verifies that metadata only — it
   MUST NEVER read unredacted secrets, `.env`, or private keys — and
   `scripts/kuron_products.py <report dir> <scan root>` enforces fail-closed
   redaction via `scripts/kuron_redaction.py` and prints the open-rail
   `KURON SECURITY · SCAN SCORECARD`.

## Input boundary (no feeds)

All scanned files, diffs, commit messages, and lockfiles are user-selected local
inputs. Reads go through bounded `kuron_trace.py` commands (256 KiB cap), are
wrapped in `<untrusted_repository_data>...</untrusted_repository_data>` with
control characters stripped, and never trigger network access, auto-fetch, or
external feed ingestion.
