# Rulepack: Flutter / Dart apps

Read-only checklist for Flutter projects. When `pubspec.yaml` or
`AndroidManifest.xml` is detected by `kuron_policy.py select-rulepacks`, apply
these checks. Never run the app, an emulator, or package manager scripts.

## 1. Exported Android components

- Read `android/app/src/main/AndroidManifest.xml`. For every `<activity>`,
  `<service>`, `<receiver>`, or `<provider>` with an `<intent-filter>`, require
  an explicit `android:exported="true"` (needed for launchers/deep links) or
  `"false"` for internal components (CWE-926).
- An exported component with a custom action and no permission is reachable by
  any installed app: report with the component name and the missing guard
  (CWE-862, CWE-20).

## 2. Deep links and intent injection

- Trace incoming `android.intent.data` / `getIntent().getData()` into Dart
  (`uni_links`, `go_router`, `Navigator.pushNamed`).
- Unvalidated host/path, or a deep link that selects a privileged route or
  forwards a URL to a WebView, is intent injection / open redirect (CWE-601).
- Require an allowlist of hosts + schemes and a check before navigation; record
  the exact validation gap.

## 3. Secret storage

- Mark uses of `shared_preferences`, plain files, or `flutter_secure_storage`
  without platform options as sensitive sinks (CWE-922, CWE-311).
- Check `flutter_secure_storage` options: Keychain accessibility and
  `EncryptedSharedPreferences` / Keystore must not be downgraded to plaintext;
  no secrets in `debugPrint`, logs, or analytics payloads (CWE-532).
- A finding needs a concrete secret read/write and a concrete weaker sink;
  a plain dependency listing alone is not a finding.

## 4. WebView JS bridges

- Find `WebView(javascriptMode: ...)` / `addJavaScriptChannel` / `javascriptChannels`
  and native `'postMessage'` handlers.
- JS enabled on attacker-controlled URLs plus a channel that exposes native
  methods is script injection into the bridge (CWE-79); unvalidated
  `evaluateJavascript()` input is code injection (CWE-94).
- Require URL allowlisting + channel message validation. Note `javascriptMode:
  JavaScriptMode.disabled` as the safe default; do not report disabled bridges.

## 5. Archive extraction (`archive` package)

- Trace `ArchiveFile.name` into `File(...).writeAsBytes` or an extraction target.
- A name joined to the destination without canonicalization + containment
  accepts `../../etc/passwd`: zip-slip (CWE-22).
- Include the entry-name source and filesystem sink in the taint chain; never
  extract a fixture archive.

## 6. Resource and leak checks

- For long-lived streams (`http.Client` responses, `StreamSubscription`,
  `Timer`, isolates), verify cancellation on dispose: `CancelToken.cancel()`,
  `subscription.cancel()`, `controller.close()` (CWE-772).
- A request started in `initState` with no `CancelToken` and no dispose path
  leaks work and can deliver a response after unmount (CWE-400). Report only
  when a concrete lifecycle gap is visible in the widget.
- Bounded scans: inspect the named files, not the whole SDK or generated build
  output.

## Evidence to attach

`source` = exported intent / archive entry / bridge message; `guard` =
allowlist, permission, or containment check (or its absence); `sink` =
navigation, native call, filesystem write, or un-cancelled resource. Two
independent verification routes per finding; no runtime execution.
