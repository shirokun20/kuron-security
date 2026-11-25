# Patches

This example is a **public, historical, already-patched CVE**: CVE-2023-32681 in
`psf/requests` at pre-fix commit `302225334678490ec66b3614a9dddb8a02c5f4fe`.
The diff in `F1.patch` is the published upstream fix from commit
[`74ea7cf7`](https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5),
which adds the missing `scheme.startswith('https')` guard in
`Session.rebuild_proxies`.

- **F1** — `patches/F1.patch` — `git apply --check` clean against the pre-fix checkout. Review-only: no patch test or application was executed by this scan example. The SARIF fix record in `KURON-SECURITY-RESULTS.sarif` is derived from this exact diff.

Apply in a scratch clone only: `git apply examples/F1.patch`. Kuron Security never
applies, commits, pushes, or opens a PR without an explicit user request.
