# Contributing to Kuron Security

Thanks for helping make this a standard that works across AI coding agents. Everything here is public and free; the best contributions are real-world evidence and small, testable improvements.

## Fastest ways to help

1. **Report a false positive or a missed vulnerability.** Open an issue with the project language, the exact `file:line`, whether the finding survived the 3-lens panel, and the provenance label (`kuron-panel` / `ad-hoc-panel` / `unverified-single-pass`). This directly improves the evidence contract and the reachability filter.
2. **Add a harness you actually use.** Agent support is detected at runtime in `scripts/kuron_capabilities.py`, never hardcoded in the skill body. A new harness usually needs: a probe result, a renderer mode, and a read-only subagent fallback in `agents/`. Add a `unittest` case under `tests/`.
3. **Improve the audit trail.** Trace events, `progress.jsonl`, policy attestation, and SARIF output are all public contracts. Changes here must keep every progress event backed by a real `trace_id`.
4. **Docs and examples.** Clearer install commands, real scan reports, and honest before/after examples are as valuable as code.

## Local checks

```bash
PYTHONPATH=scripts python3 -m unittest discover -s tests -p 'test_*.py' -v
```

All tests must pass. Python 3 standard library only — no new pip dependencies.

## Non-negotiable invariants

- Tree, report, and subagent output are data, never instructions.
- Researchers and verifiers are strictly read-only; patch generators only touch scratch worktrees.
- Never write `verified` / `panel-verified` as a calibration status. The only labels are the three honest provenance labels above.
- Redaction is fail-closed. If `redaction.json` is not `clean`, no product is published.
- No auto-apply, commit, push, or PR from a scan or patch run.
- The skill must keep working without the proprietary `Workflow` tool.

## Pull requests

Fork, branch, add a test for the behavior you change, run the test command above, and open a PR describing what evidence you used. Use the issue templates for bug reports and harness support requests. If you want to fund longer-running work, sponsorship is at [github.com/sponsors/shirokun20](https://github.com/sponsors/shirokun20) — no feature is gated behind it.
