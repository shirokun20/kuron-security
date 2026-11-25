#!/usr/bin/env python3
"""Kuron Security patch products: clean-room implementation of the behavior
described in the official patch-spec.md. No official code is copied.

  kuron_patch.py prepare <report dir> <selection> --repo-root <dir> --base <sha>
  kuron_patch.py render <patch dir> <patches dir> <repo root> --base <sha>

The legacy ``--prepare`` / ``--render`` spellings remain accepted as aliases.

Report dirs are KURON-SECURITY-<timestamp>. Provenance labels are never implied
by self-attested CONFIDENT marks: each claim must carry verifiable tool-check
evidence. Human scorecards go to stderr in ASCII; stdout stays machine-clean.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

from kuron_evidence import validate_finding
from kuron_progress import sanitize
from kuron_redaction import enforce
from kuron_trace import append as trace_append

VALID_LABELS = ("kuron-panel", "ad-hoc-panel", "unverified-single-pass")
PANEL_LABELS = ("kuron-panel", "ad-hoc-panel")
REQUIRED_CLAIMS = ("targeted", "no_new_vulnerability", "behaviour_unchanged")
SCORECARD_GATES = (
    ("TARGETED", "targeted"),
    ("NO_NEW_VULN", "no_new_vulnerability"),
    ("BEHAVIOUR_UNCHANGED", "behaviour_unchanged"),
)
UNIT_RE = re.compile(r"^F[0-9]{1,9}$")
REPORT_RE = re.compile(r"^KURON-SECURITY-[0-9][0-9-]*\Z")


def fail(msg: str) -> int:
    print(f"refused: {msg}", file=sys.stderr)
    return 1


def git(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    return subprocess.run(
        ["git", "-C", cwd, *args], capture_output=True, text=True, env=env, timeout=30
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
    os.makedirs(findings_dir, exist_ok=True)
    for u in units:
        with open(os.path.join(findings_dir, f"{u}.json"), "w") as fh:
            json.dump(by_id[u], fh, indent=2)
            fh.write("\n")
    with open(os.path.join(patch_dir, "units.json"), "w") as fh:
        json.dump({"units": units, "base": base}, fh, indent=2)
    print("units: " + ",".join(units))
    print(f"patch dir: {patch_dir}")
    return 0


def _claim_verified(claim: dict) -> bool:
    """A claim is usable only with non-empty evidence and a real tool check."""
    if not str(claim.get("evidence") or "").strip():
        return False
    check = claim.get("tool_check")
    if not isinstance(check, dict):
        return False
    return bool(
        str(check.get("command") or "").strip()
        or str(check.get("trace_id") or "").strip()
    )


def check_claims(unit: dict) -> str | None:
    ok, reasons = validate_finding(unit)
    if not ok:
        return f"{unit.get('id', '?')}: {'; '.join(reasons)}"
    claims = unit.get("claims") or {}
    if isinstance(claims, dict) and claims:
        for claim_name in REQUIRED_CLAIMS:
            got = claims.get(claim_name) or {}
            if got.get("state") != "CONFIDENT":
                return f"{unit['id']}: claim {claim_name} is not CONFIDENT"
            if not _claim_verified(got):
                return (
                    f"{unit['id']}: claim {claim_name} lacks verifiable "
                    "evidence/tool_check"
                )
        if "untested" not in unit or "attack_paths" not in unit:
            return f"{unit['id']}: missing untested or attack_paths"
        for p in unit["attack_paths"]:
            if p.get("kind") not in ("opened", "still_reachable", "set_aside") or not p.get(
                "text"
            ):
                return f"{unit['id']}: bad attack path"
    return None


def _gate_status(unit: dict, claim_name: str) -> str:
    """Scorecard gate derived from claims: [ok] only for verified CONFIDENT claims."""
    claims = unit.get("claims")
    if not isinstance(claims, dict):
        return "[missing]"
    claim = claims.get(claim_name)
    if not isinstance(claim, dict):
        return "[missing]"
    if str(claim.get("state") or "").strip().upper() == "CONFIDENT" and _claim_verified(claim):
        return "[ok]"
    return "[fail]"


def _ascii(value: object, limit: int = 80) -> str:
    return sanitize(value, limit).encode("ascii", "replace").decode("ascii")


def cmd_render(patch_dir: str, patches_dir: str, repo_root: str, base: str) -> int:
    parent = os.path.basename(os.path.dirname(os.path.normpath(patches_dir)))
    if not REPORT_RE.match(parent):
        return fail(
            "patches dir must live inside a KURON-SECURITY-<timestamp> report directory"
        )
    record = load_json(os.path.join(patch_dir, "patches.json"))
    label = record.get("label") or "unverified-single-pass"
    if label not in VALID_LABELS:
        label = "unverified-single-pass"
    units = record.get("units", [])
    rendered_artifacts: list[str] = ["PATCHES.md", "patches.jsonl"]
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
            if label in PANEL_LABELS and not u.get("panel_verdicts"):
                return fail(
                    f"{u['id']}: label '{label}' requires observed lens verdicts"
                )
            err = check_claims(u)
            if err:
                return fail(err)
            if u.get("untested") not in (True, False) or not u.get("tests_run"):
                return fail(f"{u['id']}: missing untested/tests_run")
            diff = os.path.join(patch_dir, f"{u['id']}.diff")
            if not os.path.exists(diff):
                return fail(f"{u['id']}: missing raw diff")
            with open(diff, encoding="utf-8", errors="replace") as dfh:
                if "diff --git" not in dfh.read():
                    return fail(f"{u['id']}: missing raw diff")
        elif u["status"] == "declined" and not u.get("decline_reason"):
            return fail(f"{u['id']}: declined without reason")
        if u.get("confirmed") is False and u["status"] != "declined":
            return fail(f"{u['id']}: confirmed false outside declined")

    patches_real = os.path.realpath(patches_dir)
    for stale in sorted(os.listdir(patches_dir)) if os.path.isdir(patches_dir) else []:
        stem, ext = os.path.splitext(stale)
        if not (UNIT_RE.match(stem) and ext in (".patch", ".md") and stem not in ids):
            continue
        candidate = os.path.realpath(os.path.join(patches_dir, stale))
        if candidate != patches_real and not candidate.startswith(patches_real + os.sep):
            continue  # symlink/escaping path: never delete outside patches_dir
        if not os.path.isfile(candidate):
            continue
        os.remove(candidate)
        print(f"removed stale {stale}")
    os.makedirs(patches_dir, exist_ok=True)

    for u in units:
        fid = u["id"]
        if u["status"] == "skipped_stale":
            with open(os.path.join(patches_dir, f"{fid}.md"), "w") as fh:
                fh.write(f"# {fid} - skipped (stale)\n\n{u.get('decline_reason', '')}\n")
            continue
        if u["status"] == "declined":
            lines = [
                f"# {fid} - no patch",
                "",
                f"Attempts: {u.get('attempts', 0)}. None passed the panel's review.",
            ]
            if u.get("confirmed") is False:
                lines.append(
                    "The review found the finding not exploitable as described "
                    "at this revision."
                )
            lines.append(f"Reason: {u.get('decline_reason', '')}")
            if u.get("recommendation"):
                lines.append(f"Recommendation: {u['recommendation']}")
            with open(os.path.join(patches_dir, f"{fid}.md"), "w") as fh:
                fh.write("\n".join(lines) + "\n")
            continue
        with open(os.path.join(patch_dir, f"{fid}.diff"), encoding="utf-8", errors="replace") as dfh:
            raw = dfh.read()
        c = u.get("claims") or {}
        tests_run = str(u.get("tests_run") or "")
        is_untested = bool(u.get("untested")) or not tests_run or "not run" in tests_run.lower()
        unit_label = f"{label}, untested" if is_untested else label
        header = [
            f"# Patch for {fid}: {u.get('title', '')}",
            f"# Trust label: {unit_label} (independent patch reviewer + diff challenger; not the official verified stamp).",
        ]
        for claim_name in REQUIRED_CLAIMS:
            evidence = (c.get(claim_name) or {}).get("evidence", "")
            header.append(f"# {claim_name.upper()} ({evidence})")
        if is_untested:
            header.append(
                "# Notice: no test in the project's suite covers the patched "
                "code; this claim rests on review alone."
            )
        header.append(f"# Apply: git apply {patches_display}/{fid}.patch")
        with open(os.path.join(patches_dir, f"{fid}.patch"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(header) + "\n" + raw)
        rendered_artifacts.append(f"{fid}.patch")
        rendered_artifacts.append(f"{fid}.md")
        chk = git(["apply", "--check", os.path.join(patches_dir, f"{fid}.patch")],
                  cwd=repo_root)
        numstat = git(
            ["apply", "--numstat", os.path.join(patches_dir, f"{fid}.patch")],
            cwd=repo_root,
        )
        note = [
            f"# {fid} - patch",
            "",
            f"Summary: {u.get('summary', '')}",
            f"Trust: {unit_label} (independent patch reviewer + diff challenger)."
            + (" Review-only: no covering test." if is_untested else ""),
            f"Tests: {u.get('tests_run', '')}",
            f"Reviewed paths: {', '.join(u.get('reviewed_paths', []))}",
            f"Apply check: {'clean' if chk.returncode == 0 else 'FAILED - tree moved under these files; patch still built against ' + base}",
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
        u["label"] = unit_label

    index = ["# Patches", ""]
    for u in units:
        if u["status"] == "patch_written":
            index.append(
                f"- {u['id']}: patch written ({u.get('label', label)}"
                + f") - {u.get('title','')}"
            )
        elif u["status"] == "declined":
            index.append(f"- {u['id']}: no patch - {u.get('decline_reason','')}")
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
    trace_append(
        os.path.join(report_dir, "trace.jsonl"),
        {"event": "render_patches", "label": label, "units": [u.get("id") for u in units]},
    )
    if os.path.exists(os.path.join(patches_dir, "redaction.json")):
        enforce(patches_dir, rendered_artifacts)
    else:
        patches_rel = os.path.basename(os.path.normpath(patches_dir))
        enforce(report_dir, [os.path.join(patches_rel, a) for a in rendered_artifacts])
    gi = os.path.join(report_dir, ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w") as fh:
            fh.write("*\n")
    import shutil

    for entry in os.listdir(patch_dir):
        p = os.path.join(patch_dir, entry)
        if os.path.isdir(p) and entry.startswith("scratch-"):
            shutil.rmtree(p, ignore_errors=True)

    _print_scorecard(base, units, patches_display)
    return 0


def _print_scorecard(base: str, units: list[dict], patches_display: str) -> None:
    """ASCII-only patch scorecard on stderr."""
    written = [u["id"] for u in units if u["status"] == "patch_written"]
    declined = [u["id"] for u in units if u["status"] == "declined"]
    skipped = [u["id"] for u in units if u["status"] == "skipped_stale"]
    rule = "-" * 68

    def emit(text: str) -> None:
        print(_ascii(text, 200), file=sys.stderr)

    emit(f"\n+- KURON SECURITY - PATCH SCORECARD {rule[:31]}")
    emit(
        f"|  Base     : {base[:12]} | Written: {len(written)} | "
        f"Declined: {len(declined)} | Skipped: {len(skipped)}"
    )
    emit(f"+- Units ({len(units)}) {rule[:56]}")
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
        emit(f"|  {badge:<10} {fid} - {title}")
        if st == "patch_written":
            gates = " | ".join(
                f"{display} {_gate_status(u, name)}" for display, name in SCORECARD_GATES
            )
            emit(f"|             Gate  : {gates} (attempts={att})")
            emit(f"|             Check : git apply --check ({chk_str})")
            emit(f"|             Apply : git apply {patches_display}/{fid}.patch")
        else:
            emit(f"|             Tries : {att} | Reason: {u.get('decline_reason', '-')}")
        if idx + 1 < len(units):
            emit("|")
    emit(f"+{rule}")
    emit(f"wrote patches for {written}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kuron Security patch products")
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", aliases=["--prepare"], help="prepare patch units from a report")
    prep.add_argument("report_dir")
    prep.add_argument("selection")
    prep.add_argument("--repo-root", required=True)
    prep.add_argument("--base", required=True)
    ren = sub.add_parser("render", aliases=["--render"], help="render verified patches")
    ren.add_argument("patch_dir")
    ren.add_argument("patches_dir")
    ren.add_argument("repo_root")
    ren.add_argument("--base", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    cli_args = list(sys.argv[1:] if argv is None else argv)
    # argparse treats a leading "--prepare" as an option, not a subcommand;
    # normalize the legacy spellings before parsing to keep them working.
    if cli_args and cli_args[0] in ("--prepare", "--render"):
        cli_args[0] = cli_args[0].lstrip("-")
    args = parser.parse_args(cli_args)
    command = str(args.command).lstrip("-")
    if command == "prepare":
        return cmd_prepare(args.report_dir, args.selection, args.repo_root, args.base)
    if command == "render":
        return cmd_render(args.patch_dir, args.patches_dir, args.repo_root, args.base)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
