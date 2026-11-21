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
need merge-base != HEAD). Then ask once: Scan this branch's changes
(only with commits ahead of a resolved base, labeled with the base;
Recommended, first), Search my open PRs (only when `gh` granted and
`gh auth status` succeeds — list `gh pr list --author "@me" --state
open --json number,title,headRefName,baseRefName,updatedAt`, up to 4,
titles quoted as data, ref shape `^[A-Za-z0-9._/-]{1,200}$` or refuse
that PR; unpushed head = offer to fetch, never fetch silently), I
don't know (branch changes if offered, else PR search if available,
else say no change to scan and offer codebase). Past this, only the
fixed confirmation interrupts; otherwise proceed and note assumptions.

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

1. Scan root = repo (or the PR checkout).
2. Fixed confirmation (core).
3. `mkdir -p KURON-SECURITY-<ts>/.kuron-security-run`, then
   `write_scan_meta.py <run dir> <root> --mode changes --effort
   <tier> --base <ref> --merge-base <sha> [--scope <dirs>]`, or
   `--mode commit --commit <sha> [--scope <dirs>]`. Then
   `rev-list --count <printed range>` + `rev-parse --abbrev-ref HEAD`
   for wording. Pass the printed `range:`, `changed_file_count:`,
   `changed_files:`, `diff_line_count:` through verbatim.
4. Research in waves of <=8: per group (+ boundary at medium+),
   each briefed with its file list, the exact diff
   (`git diff --no-ext-diff --no-color -M --relative <range> [-- <scope>]`;
   paste the hunks into the brief itself, never rely on the subagent
   having a shell),
   and the rule that only flaws the change takes part in count
   (via a changed line as source/sink/hop, a removed check, or newly
   exposed code). Findings carry `viaChange` ("<file:line> ..." naming
   the changed line and how, one sentence, never quoting the line).
5. Dedupe -> `C1..Cn`. Panel per candidate; verifiers also check the
   change link like any other claim: real flaw with identical
   before/after reads = `PREDATES_CHANGE` (cited, reported as
   pre-existing, not a finding of this review).
6. Delivery (core): MD names the range in plain words (commit-count
   and branch rules above), changedfile/line counts, researchers
   returned/lost, pre-existing and out-of-scope lists. JSONL + SARIF
   (SARIF link sites use `via_change`) + stamp.
