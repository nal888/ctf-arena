#!/usr/bin/env python3
"""vault_nudge.py — SessionStart nudge to consult the vault first (CTF/HTB cwd only).

Documented blind spot: the solver never greps the vault (proven across runs, incl. Opus
on the CNCC web challenge). A SessionStart hook's additionalContext is delivered straight
into the model's context — not suggestible like a skill it can skip. Fires only when the
working dir looks like CTF/HTB work, so it doesn't nag unrelated sessions. Fail-open.
"""
import sys, json, os, re
from pathlib import Path

# Portable: the bundled vault (arena/vault), overridable via ARENA_VAULT. Fail-open if absent.
VAULT = os.environ.get("ARENA_VAULT") or str(Path(__file__).resolve().parents[2] / "vault")


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    cwd = (data.get("cwd") or os.getcwd() or "").lower()
    if not re.search(r"ctf|htb", cwd):
        sys.exit(0)
    if not os.path.isdir(VAULT):
        sys.exit(0)
    msg = ("CTF session — before improvising on a challenge: "
           "(1) name the category; "
           f"(2) GREP THE VAULT for the signal: `grep -i '<signal>' {VAULT}/INDEX.md` then read the "
           f"matching {VAULT}/<category>.md section (you historically skip this); "
           "(3) WEB: any value that comes back reflected in a response = test injection "
           "({{}}/${}/<%= %>, then ', then <x>) in the first 5 min BEFORE grinding traversal/LFI/static; "
           "(4) after ~2 failed attempts on one vector, switch bug class or escalate — don't grind.")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": msg}}))
    sys.exit(0)


if __name__ == "__main__":
    main()
