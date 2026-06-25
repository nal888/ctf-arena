#!/usr/bin/env bash
# arena teammate setup — installs the bundled CTF skills into Claude Code.
# Hooks auto-wire at runtime (no action needed). Run this once per machine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.claude/skills"
mkdir -p "$DEST"

echo "Installing bundled CTF skills -> $DEST"
for d in "$HERE"/skills/*/; do
  [ -d "$d" ] || continue
  cp -r "$d" "$DEST/"
  echo "  + $(basename "$d")"
done

echo
echo "Skills installed. Guard hooks auto-wire when arena runs (ARENA_HOOKS=0 to disable)."
echo
echo "Next:"
echo "  1) install + log in to Claude Code:   claude   (then /login)   — uses your plan, no API key"
echo "  2) cp .env.example .env  and set CTFD_URL, CTFD_TOKEN, PREFIX (e.g. MPTC)"
echo "       or:  python3 -m arena setup <ctf-url> <YOUR_TOKEN> --prefix MPTC"
echo "  3) python3 -m arena loop      # autonomous   |   python3 -m arena dash   # dashboard"
