#!/usr/bin/env python3
"""Kuron Security patch products: clean-room implementation of the behavior
described in the official patch-spec.md. No official code is copied.

  kuron_patch.py --prepare <report dir> <selection> --repo-root <dir> --base <sha>
  kuron_patch.py --render <patch dir> <patches dir> <repo root> --base <sha>

Report dirs are KURON-SECURITY-<timestamp>; stamps say kuron-panel.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

UNIT_RE = re.compile(r"^F[0-9]{1,9}$")
REPORT_RE = re.compile(r"^KURON-SECURITY-[0-9][0-9-]*\Z")


def fail(msg: str) -> int:
    print(f"refused: {msg}", file=sys.stderr)
    return 1


def git(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "-C", cwd, *args], capture_output=True, text=True, env=env
    )


def load_json(path: str):
    with open(path) as fh:
        return json.load(fh)


def load_findings(report_dir: str) -> list[dict]:
    fjson = os.path.join(report_dir, "findings.json")
    if os.path.exists(fjson):
        return load_json(fjson)
    fjsonl = os.path.join(report_dir, "KURON-SECURITY-RESULTS.jsonl")
    if os.path.exists(fjsonl):
        with open(fjsonl) as fh:
            return [json.loads(line) for line in fh if line.strip()]
    raise FileNotFoundError(
        f"neither findings.json nor KURON-SECURITY-RESULTS.jsonl found in {report_dir}"
    )


def cmd_prepare(report_dir: str, selection: str, repo_root: str, base: str) -> int:
    name = os.path.basename(os.path.normpath(report_dir))
    if not REPORT_RE.match(name):
        return fail(f"{name!r} is not a KURON-SECURITY-<timestamp> report directory")
    r = git(["rev-parse", "--show-toplevel"], cwd=repo_root)
    if r.returncode != 0 or os.path.realpath(r.stdout.strip()) != os.path.realpath(
        repo_root
    ):
        return fail("repo-root is not a repository top level")
    if git(["rev-parse", "--verify", "--quiet", base + "^{commit}"], cwd=repo_root).returncode:
        return fail(f"base {base!r} names no commit")

    findings = load_findings(report_dir)
    by_id = {f["id"]: f for f in findings}
    if selection == "all":
        units = [f["id"] for f in findings]
    elif selection == "high":
        units = [f["id"] for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    else:
        units = [s for s in selection.split(",") if s]
        for u in units:
            if not UNIT_RE.match(u):
                return fail(f"{u!r} is not a finding id")
            if u not in by_id:
                return fail(f"nothing to patch: no finding {u} in report")
    if not units:
        return fail(f"nothing to patch: no finding matches {selection!r}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    patch_dir = os.path.join(report_dir, ".kuron-security-run", f"patch-{ts}")
    findings_dir = os.path.join(patch_dir, "findings")
    os.makedirs(findings_dir)
    for u in units:
        with open(os.path.join(findings_dir, f"{u}.json"), "w") as fh:
            json.dump(by_id[u], fh, indent=2)
            fh.write("\n")
    with open(os.path.join(patch_dir, "units.json"), "w") as fh:
        json.dump({"units": units, "base": base}, fh, indent=2)
    print("units: " + ",".join(units))
    print(f"patch dir: {patch_dir}")
def check_claims(unit: dict) -> str | None:
    for claim in ("targeted", "no_new_vulnerability", "behaviour_unchanged"):
        got = (unit.get("claims") or {}).get(claim, {})
        if got.get("state") != "CONFIDENT":
            return f"{unit['id']}: claim {claim} is not CONFIDENT"
    if "untested" not in unit or "attack_paths" not in unit:
        return f"{unit['id']}: missing untested or attack_paths"
    for p in unit["attack_paths"]:
        if p.get("kind") not in ("opened", "still_reachable", "set_aside") or not p.get(
            "text"
        ):
            return f"{unit['id']}: bad attack path"
    return None


def cmd_render(patch_dir: str, patches_dir: str, repo_root: str, base: str) -> int:
    parent = os.path.basename(os.path.dirname(os.path.normpath(patches_dir)))
    if not REPORT_RE.match(parent):
        return fail(
            "patches dir must live inside a KURON-SECURITY-<timestamp> report directory"
        )
    record = load_json(os.path.join(patch_dir, "patches.json"))
    units = record.get("units", [])
    patches_display = os.path.normpath(patches_dir)
    ids = set()
    for u in units:
        if not UNIT_RE.match(u.get("id", "")):
            return fail(f"bad unit id {u.get('id')!r}")
        if u.get("status") not in ("patch_written", "declined", "skipped_stale"):
            return fail(f"{u['id']}: unknown status")
        if u["status"] != "skipped_stale":
            if not isinstance(u.get("attempts"), int) or u["attempts"] < (
                1 if u["status"] == "patch_written" else 0
            ):
                return fail(f"{u['id']}: bad attempts")
        ids.add(u["id"])
        if u["status"] == "patch_written":
            err = check_claims(u)
            if err:
                return fail(err)
            if u.get("untested") not in (True, False) or not u.get("tests_run"):
                return fail(f"{u['id']}: missing untested/tests_run")
            diff = os.path.join(patch_dir, f"{u['id']}.diff")
            if not os.path.exists(diff) or "diff --git" not in open(
                diff, errors="replace"
            ).read():
                return fail(f"{u['id']}: missing raw diff")
        elif u["status"] == "declined" and not u.get("decline_reason"):
            return fail(f"{u['id']}: declined without reason")
        if u.get("confirmed") is False and u["status"] != "declined":
            return fail(f"{u['id']}: confirmed false outside declined")
    for stale in sorted(os.listdir(patches_dir)) if os.path.isdir(patches_dir) else []:
        if UNIT_RE.match(os.path.splitext(stale)[0]) and os.path.splitext(stale)[
            0
        ] not in ids:
            if stale.endswith((".patch", ".md")):
                os.remove(os.path.join(patches_dir, stale))
                print(f"removed stale {stale}")
    os.makedirs(patches_dir, exist_ok=True)

    for u in units:
        fid = u["id"]
        if u["status"] == "skipped_stale":
            with open(os.path.join(patches_dir, f"{fid}.md"), "w") as fh:
                fh.write(f"# {fid} — skipped (stale)\n\n{u.get('decline_reason','')}\n")
            continue
        if u["status"] == "declined":
            lines = [
                f"# {fid} — no patch",
                "",
                f"Attempts: {u.get('attempts', 0)}. None passed the panel's review.",
            ]
            if u.get("confirmed") is False:
                lines.append(
                    "The review found the finding not exploitable as described "
                    "at this revision."
                )
            lines.append(f"Reason: {u.get('decline_reason','')}")
            if u.get("recommendation"):
                lines.append(f"Recommendation: {u['recommendation']}")
            with open(os.path.join(patches_dir, f"{fid}.md"), "w") as fh:
                fh.write("\n".join(lines) + "\n")
            continue
        raw = open(os.path.join(patch_dir, f"{fid}.diff"), errors="replace").read()
        c = u["claims"]
        header = [
            f"# Patch for {fid}: {u.get('title','')}",
            "# Trust label: kuron-panel (reviewed by an independent patch reviewer plus a fresh diff challenger; not the official verified stamp).",
            f"# TARGETED ({c['targeted']['evidence']})",
            f"# NO_NEW_VULNERABILITY ({c['no_new_vulnerability']['evidence']})",
            f"# BEHAVIOUR_UNCHANGED ({c['behaviour_unchanged']['evidence']})",
        ]
        if u.get("untested"):
            header.append(
                "# Notice: no test in the project's suite covers the patched "
                "code; this claim rests on review alone."
            )
        header.append(f"# Apply: git apply {patches_display}/{fid}.patch")
        with open(os.path.join(patches_dir, f"{fid}.patch"), "w") as fh:
            fh.write("\n".join(header) + "\n" + raw)
        chk = git(["apply", "--check", os.path.join(patches_dir, f"{fid}.patch")],
                  cwd=repo_root)
        numstat = git(
            ["apply", "--numstat", os.path.join(patches_dir, f"{fid}.patch")],
            cwd=repo_root,
        )
        note = [
            f"# {fid} — patch",
            "",
            f"Summary: {u.get('summary','')}",
            f"Trust: kuron-panel (independent patch reviewer + diff challenger)."
            + (" Review-only: no covering test." if u.get("untested") else ""),
            f"Tests: {u.get('tests_run','')}",
            f"Reviewed paths: {', '.join(u.get('reviewed_paths', []))}",
            f"Apply check: {'clean' if chk.returncode == 0 else 'FAILED — tree moved under these files; patch still built against ' + base}",
            "Diffstat:",
            "```",
            (numstat.stdout.strip() or "(empty)"),
            "```",
            f"Apply: `git apply {patches_display}/{fid}.patch`",
        ]
        with open(os.path.join(patches_dir, f"{fid}.md"), "w") as fh:
            fh.write("\n".join(note) + "\n")
        u["apply_check"] = "clean" if chk.returncode == 0 else "failed"
        u["diffstat"] = numstat.stdout.strip()

    index = ["# Patches", ""]
    for u in units:
        if u["status"] == "patch_written":
            index.append(
                f"- {u['id']}: patch written (kuron-panel"
                + (", review-only: no covering test" if u.get("untested") else "")
                + f") — {u.get('title','')}"
            )
        elif u["status"] == "declined":
            index.append(f"- {u['id']}: no patch — {u.get('decline_reason','')}")
        else:
            index.append(f"- {u['id']}: skipped (stale)")
    index += ["", "Apply: `git apply <report>/patches/F<n>.patch` per file."]
    with open(os.path.join(patches_dir, "PATCHES.md"), "w") as fh:
        fh.write("\n".join(index) + "\n")
    with open(os.path.join(patches_dir, "patches.jsonl"), "w") as fh:
        for u in units:
            fh.write(
                json.dumps(
                    {k: u.get(k) for k in (
                        "id", "status", "base", "title", "summary", "claims",
                        "untested", "tests_run", "reviewed_paths",
                        "attack_paths", "attempts", "confirmed", "diffstat",
                        "apply_check", "decline_reason", "recommendation",
                    )}
                )
                + "\n"
            )
    report_dir = os.path.dirname(os.path.normpath(patches_dir))
    gi = os.path.join(report_dir, ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w") as fh:
            fh.write("*\n")
    import shutil

    for entry in os.listdir(patch_dir):
        p = os.path.join(patch_dir, entry)
        if os.path.isdir(p) and entry.startswith("scratch-"):
            shutil.rmtree(p, ignore_errors=True)

    written = [u["id"] for u in units if u["status"] == "patch_written"]
    declined = [u["id"] for u in units if u["status"] == "declined"]
    skipped = [u["id"] for u in units if u["status"] == "skipped_stale"]
    rule = "─" * 68
    print(f"\n╭─ 🔧 KURON SECURITY · PATCH SCORECARD {rule[:30]}")
    print(
        f"│  Base     : {base[:12]} · Written: {len(written)} · "
        f"Declined: {len(declined)} · Skipped: {len(skipped)}"
    )
    print(f"├─ Units ({len(units)}) {rule[:56]}")
    for idx, u in enumerate(units):
        fid = u["id"]
        st = u["status"]
        att = u.get("attempts", 0)
        chk_str = u.get("apply_check", "-")
        title = u.get("title", "")
        badge = (
            "[READY]"
            if st == "patch_written"
            else ("[DECLINED]" if st == "declined" else "[SKIPPED]")
        )
        print(f"│  {badge:<10} {fid} · {title}")
        if st == "patch_written":
            print(
                f"│             Gate  : TARGETED ✓ │ NO_NEW_VULN ✓ │ "
                f"BEHAVIOUR_UNCHANGED ✓ (attempts={att})"
            )
            print(f"│             Check : git apply --check ({chk_str})")
            print(f"│             Apply : git apply {patches_display}/{fid}.patch")
        else:
            print(f"│             Tries : {att} · Reason: {u.get('decline_reason', '-')}")
        if idx + 1 < len(units):
            print("│")
    print(f"╰{rule}")
    print(f"wrote patches for {written}")
    return 0


if __name__ == "__main__":
    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__.strip().splitlines()[0])
        print("usage:")
        print("  kuron_patch.py --prepare <report dir> <all|high|F1,F2> --repo-root <dir> --base <sha>")
        print("  kuron_patch.py <patch dir> <patches dir> <repo root> --base <sha>")
        sys.exit(0)
    if len(sys.argv) < 5:
        print("usage: kuron_patch.py --prepare ... | kuron_patch.py <patch dir> <patches dir> <repo root> --base <sha>")
        sys.exit(2)
    if sys.argv[1:2] == ["--prepare"]:
        _, _, report_dir, selection = sys.argv[:4]
        sys.exit(
            cmd_prepare(
                report_dir,
                selection,
                sys.argv[sys.argv.index("--repo-root") + 1],
                sys.argv[sys.argv.index("--base") + 1],
            )
        )
    else:
        _, patch_dir, patches_dir, repo_root = sys.argv[:4]
        sys.exit(
            cmd_render(
                patch_dir,
                patches_dir,
                repo_root,
                sys.argv[sys.argv.index("--base") + 1],
            )
        )
