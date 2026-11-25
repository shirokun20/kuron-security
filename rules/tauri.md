# Rulepack: Tauri desktop apps

Read-only checklist for Tauri projects. When `tauri.conf.json` is detected by
`kuron_policy.py select-rulepacks`, apply these checks to the scoped files.
Never build, run, or download anything from the target project.

## 1. Webview CSP (`tauri.conf.json`)

- Find `app > security > csp`; confirm a `default-src 'self'` baseline.
- Reject `'unsafe-inline'`, `'unsafe-eval'`, `data:`, or a wildcard in
  `script-src` unless the finding names the exact injection source that requires
  it (CWE-79).
- `dangerousDisableAssetCspModification: true` removes the injected nonce/hash:
  treat as a finding only with an attacker-controlled HTML sink.
- Missing `csp` is a gap, not a finding by itself; record it as coverage.

## 2. Updater signature placeholder

- Inspect `plugins > updater > pubkey` (and Tauri v1 `updater > pubkey`).
- A placeholder such as `YOUR_PUBKEY`, `""`, or a short/non-base64 value means
  signature verification is not configured: report with the exact line (CWE-494,
  CWE-798).
- Confirm endpoints are HTTPS. Never fetch the endpoint or the pubkey.

## 3. Capability scope (`capabilities/*.json`)

- Read each capability file; list `permissions` entries with `fs:allow-*`,
  `shell:allow-*`, `http:allow-*`, or `*` wildcards (CWE-732, CWE-284).
- `fs:allow-read`/`fs:allow-write` scope `["**"]`, `"$HOME/**"`, or an absolute
  root is over-broad: report only when a reachable window has a matching
  attacker-influenced path argument.
- Check that `windows` binds the capability to the intended window label; an
  unbound or `["*"]` binding applies it everywhere.

## 4. Command authorization (`#[tauri::command]`)

- Enumerate `#[tauri::command]` functions. For each privileged action
  (file write, process spawn, network fetch, secret read), require an explicit
  caller check: `app.handle()`, window label, origin verification, or a state
  guard.
- A command that accepts a raw path/URL from `invoke()` with no containment or
  allowlist is missing authorization (CWE-862, CWE-20).
- Verify the corresponding `invoke_handler!` registration; an unregistered
  command is dead code, not a live finding.

## 5. Secret handling (`secrets.rs`)

- Find reads of API keys/tokens and their sinks: `println!`, `tracing::debug!`,
  `emit`, IPC return values, telemetry, or `tauri.conf.json` itself.
- Secrets baked into the binary or config are exposed to any local user
  (CWE-798, CWE-200); logging a secret is exposure via logs (CWE-532).
- Prefer OS keychain / `keyring` + runtime injection; only report when a real
  secret value or a concrete sink is visible.

## 6. Archive path traversal

- In `src/import.rs` and any `lopdf`/Flate decompression path, trace the entry
  name from the archive header to `std::fs::write`, `File::create`, or an
  unzip target join.
- `out_dir.join(entry_name)` without canonicalization + prefix containment
  accepts `../../etc/passwd` (CWE-22). Decompressed PDF streams used as file
  names are the same class of sink.
- Require a taint chain: archive entry -> guard (or absent guard) -> filesystem
  sink before promoting the finding.

## Evidence to attach

`source` = archive entry / IPC argument; `guard` = containment check or its
absence; `sink` = filesystem write or privileged command. One static route plus
one independent route (grep or trace) per finding. No code execution.
