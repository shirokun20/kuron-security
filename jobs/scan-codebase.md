# Job: scan codebase (kuron-native)

Whole repository or scoped area at effort `low`/`medium`/`high`
(`max` accepted, runs as `high`). No tier word from the user: pick
with them when unclear, else `medium`.

## Effort (same work, omp waves)

- `low` — one researcher over the whole target, then the 3-lens panel.
  No inventory, no threat model, no sweep. (Secrets pass when focus set.)
- `medium` — inventory-lite (below), one threat-model recon per
  component, one researcher per component x category lens (4 lenses:
  injection-and-input, auth-and-access, memory-and-unsafe,
  crypto-and-secrets; managed-language components skip
  memory-and-unsafe with the reason recorded), one sweep over
  unread files, secrets pass when focus set, 3-lens panel (keep >=2).
- `high` — as medium: up to 48 components (24 when the file count is
  unknown), two researchers per component x lens, two sweeps.

Component cap: 24 largest (48 at high); over-cap components are
`skippedComponents` with reason `over-cap` and named in the report.
Small scope (<=5 tracked files) at low/medium collapses to the
single-researcher shape, still panel-verified.

`focus: attack-surface` on large trees (>~300 files): researchers
spend effort on production code an attacker reaches; tests, fixtures,
generated code are background. A secrets pass runs whenever focus is
set (any tier), still checking fixtures for real keys.

## Sub-menu (whole repo never launches unasked)

Gauge cheaply: `git ls-files | wc -l`, per-dir `git ls-files --
<dir> | wc -l`. Then ask once: Whole repository (sized, e.g. `Whole
repository (~1619 files, medium)`), Scoped scan of the most exposed
area (real dirs with counts), I don't know (small tree -> whole at
medium; large tree -> scoped medium over the most exposed area,
stated as an assumption). Large tree: recommend scoped first.
`medium` default; `high` only for a small, high-stakes area.

## Run

1. Scan root = absolute repo path. Scope = dirs or null.
2. Fixed confirmation (core). Then
   `mkdir -p KURON-SECURITY-<ts>/.kuron-security-run`, then
   `write_scan_meta.py <run dir> <root> --mode scan --effort <tier>
   [--scope <dirs>]`.
3. Partition: whole repo -> one component per top-level source dir
   (cap above applies); scoped -> scope dirs are the components.
4. Threat-model recon (medium/high): one lightweight
   `security-reviewer` per component reporting entryPoints, sinks,
   hotFiles (read-only; JSON). Feed each file list into that
   component's researchers.
5. Research in waves of <=8 dispatches: per component x lens
   (medium 1x, high 2x), each with its lens + hot files. Update
   `coverage.json` per wave.
6. Sweep: one reviewer over tracked files no researcher claimed
   (from coverage union vs `ls-files`); second sweep at high.
   Secrets pass when focus set.
7. Dedupe -> `C1..Cn`. Panel per candidate (core). Tally.
8. Delivery (core): MD + JSONL + SARIF + stamp via
   `scripts/kuron_products.py`. Report names components, skipped
   areas with reasons, researchers returned/lost, collapsed shape
   where used, and (whole-repo) the completeness check over
   top-level dirs.
