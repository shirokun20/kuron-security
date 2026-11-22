# Job: scan changes (kuron-native)

Security review of a diff: this branch's changes against its base, or
one commit against its parent. Researchers start from changed lines,
read the changed files whole, and follow data in/out only as far as
judging takes. A flaw whose source, sink and guards read the same
before and after is out of scope (a codebase scan reports those).
Only committed changes are scanned; uncommitted work needs a commit,
stash, or a codebase scan instead.

## Arguments

`--base <ref>` (default: upstream unless it is the branch's own pushed
copy, then origin/HEAD, origin/main, origin/master, main, master),
`--commit <sha>`, `--scope <dirs>`, `--effort` low/medium (default)/high
(`max` accepted as high; unknown tier refused, tiers named, nothing
starts). Bare hex 7+ chars = `--commit`; ref name = `--base`;
`abc..def` = range. Area words ("only under services/api") = `--scope`.

## Sub-menu (when no argument named the change)

Branch state first (`git status -sb --untracked-files=no`,
`rev-parse --abbrev-ref @{upstream}` / `@{push}`), base = first
resolving ref in default order (skip the branch's own pushed copy;
need merge-base != HEAD). Only locally checked-out commits and branches
are scanned (never fetch remote PR branches or untrusted remote heads).
Then ask once: Scan this branch's changes (only with commits ahead of a
resolved base, labeled with the base; Recommended, first), Scan the
latest commit (`HEAD^..HEAD`), or I don't know (branch changes if
offered, else say no local change to scan and offer a codebase scan).
Past this, only the fixed confirmation interrupts; otherwise proceed and
note assumptions.

## Range and size

- `--commit`: verify with `rev-parse --verify --quiet <sha>^{commit}`
  (else stop), parent with `<sha>^` (none: first commit -> codebase
  scan covers it; shallow -> suggest `git fetch --unshallow`; stop),
  checked-out with `rev-parse HEAD` equal (commit scans run only on
  the checked-out commit; never check anything out or add a worktree).
- Branch changes: `merge-base <base> HEAD`. No resolving base: ask.
  Empty merge-base (shallow): suggest deeper fetch, stop.
- Range: `rev-list --count` both directions; empty as typed stops
  with the corrected direction named.
- Empty diff check (`diff --quiet --relative <merge-base> HEAD --
  <scope>`, or `<sha>^ <sha>` for commits): exit 0 -> no diff to
  scan, stop, create nothing. Never count changed files by hand;
  `write_scan_meta.py` lists them.

Shape: changed files as one group (past 25 files: groups of ~25, at
most 12, 24 at high). Every tier ends in the same 3-lens panel.
`focus` stays null. No inventory, threat model, or sweep on any tier.
Large change + `high` is the better pick: say so when choosing.
Commit-count wording: `--commit` names the commit, no count. Branch
changes: `rev-list --count <range>` from step 5, never plus one for
the older end; branch by name only when `rev-parse --abbrev-ref HEAD`
prints one, else "the N commits since <base>" + detached note.

## Run

1. Preflight: run `scripts/kuron_capabilities.py` (`probe` + `select_path`) and
   `scripts/kuron_policy.py` (`validate` + `attestation`). Abort if tier requirements
   are not met.
   Open the progress stream with `scripts/kuron_progress.py`: append one event
   per phase/wave with the real trace `trace_id`; render to stderr only.
2. Consolidated confirmation gate: confirm time/token cost AND explicit consent
   if the selected label is `ad-hoc-panel` or `unverified-single-pass`.
3. Scan root = repo. Create `KURON-SECURITY-<ts>/.kuron-security-run` and write
   `scan-meta.json` (`mode: changes|commit`, `label`, `tier`, `attestation`).
4. Research in waves of <=8 using `agents/researcher.md` (read-only), wrapping diffs
   inside `<untrusted_repository_data>...</untrusted_repository_data>` with control
   characters stripped.
5. Pre-panel evidence gate (`scripts/kuron_evidence.py` `filter_findings`) +
   dedupe -> `C1..Cn`, recording dropped items in `discarded[]`. Run 3-lens panel
   (`agents/verifier-*.md`, logging checks via `scripts/kuron_trace.py`).
6. Redact (`agents/redactor.md` -> `redaction.json`) and deliver all 4 mandatory
   artifacts via `scripts/kuron_products.py <report dir> <scan root>` (enforces
   fail-closed redaction and prints the open-rail `KURON SECURITY · SCAN SCORECARD`).
