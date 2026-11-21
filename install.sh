#!/usr/bin/env bash
# Install kuron-security into every detected AI-agent harness.
# Usage: ./install.sh [--global|--local] [--list]
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
MODE="global"
for a in "$@"; do case "$a" in --global) MODE=global;; --local) MODE=local;; --list) MODE=list;; *) echo "unknown flag: $a" >&2; exit 2;; esac; done

link_into() { # $1 = skills dir
  mkdir -p "$1"
  ln -sfn "$SRC" "$1/kuron-security"
  echo "linked -> $1/kuron-security"
}

if [ "$MODE" = list ]; then
  for d in "$HOME/.agents/skills" "$HOME/.claude/skills" "$HOME/.codex/skills" "$HOME/.config/opencode/skills"; do
    if [ -e "$d/kuron-security" ]; then echo "installed: $d"; else echo "absent:    $d"; fi
  done
  echo "opencode/antigravity: also honours project-local <repo>/.opencode/skills or .agents/skills (symlink this repo there)"
  exit 0
fi

n=0
[ -d "$HOME/.agents" ] && { link_into "$HOME/.agents/skills"; n=$((n+1)); }
[ -d "$HOME/.claude" ] && { link_into "$HOME/.claude/skills"; n=$((n+1)); }
[ -d "$HOME/.codex" ] && { link_into "$HOME/.codex/skills"; n=$((n+1)); }
[ -d "$HOME/.config/opencode" ] && { link_into "$HOME/.config/opencode/skills"; n=$((n+1)); }
if [ "$MODE" = local ]; then
  git rev-parse --show-toplevel >/dev/null 2>&1 && root=$(git rev-parse --show-toplevel) || root="$PWD"
  { [ -d "$root/.opencode" ] && link_into "$root/.opencode/skills"; } || link_into "$root/.agents/skills"
  n=$((n+1))
fi
[ "$n" -eq 0 ] && { link_into "$HOME/.agents/skills"; }
echo "done."
