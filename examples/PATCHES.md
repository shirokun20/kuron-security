# Patches

- F1: patch written (kuron-panel, review-only: no covering test) — Path traversal file write via unsanitized remote sourceId into configs directory
- F2: patch written (kuron-panel, review-only: no covering test) — Path traversal arbitrary file delete via unsanitized remote sourceId on uninstall
- F3: patch written (kuron-panel, review-only: no covering test) — Path traversal file write via unsanitized remote sourceId in icon cache persistence
- F4: no patch — Second objection stands: declared central-directory sizes are attacker-controlled (zeroed, zip64-sentinel skipped, lying offsets return null), so the pre-decode scan passes and decodeBytes still inflates a real bomb before post-decode checks run. Only bounded streaming inflation fully closes this; the patch raises the bar (catches honest-huge archives) but cannot guarantee it with this decode API. No patch written after 2 attempts.

Apply: `git apply <report>/patches/F<n>.patch` per file.
