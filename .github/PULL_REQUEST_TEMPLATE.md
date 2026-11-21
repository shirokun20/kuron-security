# What

One-line change summary.

# Why

Job affected (scan-codebase / scan-changes / suggest-patches) and the failure
it fixes. Link the issue.

# Verification (mandatory)

- [ ] Field-tested on a real scope (name scope + outcome), or state why not
- [ ] No new `verified`-family claims; stamp stays `kuron-panel`
- [ ] Scripts: stdlib-only, `python3 -m py_compile` clean
- [ ] Safety invariants untouched (read-only researchers, no auto-apply/push)

# Risk

What could this break for other harnesses (omp, claude-code, codex,
opencode, antigravity)?
