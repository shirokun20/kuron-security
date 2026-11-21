#!/usr/bin/env bash
# Install, verify, or remove kuron-security for AI-agent harnesses.
# Usage: ./install.sh [--harness NAME] [--local] [--check] [--list] [--uninstall]
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
HARNESS=""; LOCAL=0; CHECK=0; LIST=0; UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --harness) HARNESS="${2:?--harness needs a name}"; shift 2 ;;
    --harness=*) HARNESS="${1#--harness=}"; shift ;;
    --local) LOCAL=1; shift ;;
    --check) CHECK=1; shift ;;
    --list) LIST=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)
      sed -n '2,3p' "$0"
      echo "Usage: ./install.sh [--harness NAME] [--local] [--check] [--list] [--uninstall]"
      exit 0 ;;
    *) echo "unknown flag: $1 (try --help)" >&2; exit 2 ;;
  esac
done

skills_dir_for() {
  case "$1" in
    omp|generic) echo "$HOME/.agents/skills" ;;
    claude-code|claude) echo "$HOME/.claude/skills" ;;
    codex) echo "$HOME/.codex/skills" ;;
    opencode) echo "$HOME/.config/opencode/skills" ;;
    antigravity) echo "$HOME/.agents/skills" ;;
    *) echo "unknown harness: $1 (omp|claude-code|codex|opencode|antigravity)" >&2; exit 2 ;;
  esac
}

harness_present() {
  case "$1" in
    omp|generic) [ -d "$HOME/.agents" ] ;;
    claude-code|claude) [ -d "$HOME/.claude" ] ;;
    codex) [ -d "$HOME/.codex" ] ;;
    opencode) [ -d "$HOME/.config/opencode" ] ;;
    antigravity) [ -d "$HOME/.agents" ] ;;
  esac
}

link_into() {
  mkdir -p "$1"
  ln -sfn "$SRC" "$1/kuron-security"
  echo "linked -> $1/kuron-security"
}

unlink_from() {
  if [ -L "$1/kuron-security" ]; then
    rm "$1/kuron-security"; echo "removed $1/kuron-security"
  elif [ -e "$1/kuron-security" ]; then
    echo "kept $1/kuron-security (not a symlink, not touching)"
  else
    echo "absent: $1/kuron-security"
  fi
}

if [ "$LIST" -eq 1 ]; then
  for h in omp claude-code codex opencode antigravity; do
    d="$(skills_dir_for "$h")"
    if [ -e "$d/kuron-security" ]; then echo "installed:      $d ($h)"; else echo "not installed:  $d ($h)"; fi
  done
  echo "project-local: <repo>/.agents/skills or .opencode/skills (run ./install.sh --local inside the repo)"
  exit 0
fi

if [ "$CHECK" -eq 1 ]; then
  ok=1
  [ -f "$SRC/SKILL.md" ] && echo "ok: SKILL.md" || { echo "MISSING: SKILL.md"; ok=0; }
  command -v python3 >/dev/null && echo "ok: $(python3 --version 2>&1)" || { echo "MISSING: python3"; ok=0; }
  command -v git >/dev/null && echo "ok: $(git --version)" || { echo "MISSING: git (patch job needs it)"; ok=0; }
  python3 -m py_compile "$SRC/scripts/kuron_products.py" "$SRC/scripts/kuron_patch.py" \
    && echo "ok: scripts compile" || ok=0
  if [ "$ok" -eq 1 ]; then echo "all checks passed"; else exit 1; fi
  exit 0
fi

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -n "$HARNESS" ]; then
    unlink_from "$(skills_dir_for "$HARNESS")"
  else
    for h in omp claude-code codex opencode; do unlink_from "$(skills_dir_for "$h")"; done
  fi
  echo "done."
  exit 0
fi

if [ -n "$HARNESS" ]; then
  link_into "$(skills_dir_for "$HARNESS")"
  echo "done."
  exit 0
fi

if [ "$LOCAL" -eq 1 ]; then
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  if [ -d "$root/.opencode" ]; then link_into "$root/.opencode/skills";
  else link_into "$root/.agents/skills"; fi
  echo "done."
  exit 0
fi

n=0
for h in omp claude-code codex opencode; do
  if harness_present "$h"; then link_into "$(skills_dir_for "$h")"; n=$((n+1)); fi
done
[ "$n" -eq 0 ] && link_into "$HOME/.agents/skills"
echo "done."
