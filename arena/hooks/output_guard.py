#!/usr/bin/env python3
"""output_guard.py — PreToolUse(Bash) big-output guard.

The silent #1 session-killer (notes: rev/forensics): dumping a huge file/binary into context
(`cat`/`strings`/`xxd`/`hexdump`/`od`/`base64` on a big file) floods the window and kills the run.

This BLOCKS only the genuinely dangerous case — a content-dumper aimed at a real file that is large
AND has no limiter on the line. Everything else passes. Uses the ACTUAL file size (precise, low
false-positive). Fail-open on any error.

  cat flag.txt              -> allow (tiny)
  strings ./bin | head      -> allow (limiter present)
  strings ./bin             -> BLOCK if ./bin is big, tell it to pipe through head/grep
"""
import sys, json, os, re, shlex

# dumper -> output-expansion factor vs file size (xxd/od/hexdump ~3-4x; cat/strings ~1x)
DUMPERS = {"cat": 1, "strings": 1, "base64": 2, "tac": 1, "nl": 1,
           "xxd": 4, "hexdump": 4, "od": 4}
# if any of these appear on the line, the model already bounded the output -> allow
LIMITERS = ("| head", "| tail", "| grep", "| less", "| more", "| wc", "| awk", "| sed -n",
            " head -", " -c ", "| cut", "> ", ">>")
MAX_OUT = 120_000          # ~120 KB of dumped output is the ceiling before it hurts context

# high-volume COMMANDS whose output size isn't knowable from a file -> WARN (not block) when unbounded.
# These are the classic context-killers in rev/forensics CTF work.
HIGH_VOL = (
    r"\bobjdump\s+-[a-zA-Z]*[dD]", r"\breadelf\s+(-a\b|--all|-x\b|--hex-dump)",
    r"\bfind\s+/(?!.*-maxdepth)", r"\bjournalctl\b(?![^|]*-n\b)", r"\bdmesg\b",
    r"\bps\s+(aux|-ef)\b", r"\bgdb\b[^|]*\bdisassemble\b",
)

def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.exit(0)
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd.strip():
        sys.exit(0)
    low = cmd.lower()
    if any(lim in low for lim in LIMITERS):           # already bounded -> allow
        sys.exit(0)
    # heuristic: high-volume command with no limiter -> WARN (allow), nudge to bound it
    for pat in HIGH_VOL:
        if re.search(pat, cmd):
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": (
                    "output-guard: this can produce huge output and flood context — pipe it through "
                    "`head`/`grep`/`wc` or redirect to a file, then read the part you need.")}}))
            sys.exit(0)
    try:
        toks = shlex.split(cmd)
    except Exception:
        sys.exit(0)
    base = os.path.basename(toks[0]) if toks else ""
    if base not in DUMPERS:
        sys.exit(0)
    factor = DUMPERS[base]
    # find the first argument that is an existing regular file
    for t in toks[1:]:
        if t.startswith("-"):
            continue
        p = os.path.expanduser(t)
        try:
            if os.path.isfile(p):
                size = os.path.getsize(p)
                if size * factor > MAX_OUT:
                    kb = size // 1024
                    sys.stderr.write(
                        f"OUTPUT GUARD: `{base} {t}` would dump ~{size*factor//1024} KB into context "
                        f"({t} is {kb} KB) and can kill the session. Bound it: `{base} {t} | head`, "
                        f"`grep -a PATTERN {t}`, `{base} {t} | head -c 50000`, or read a range. "
                        f"Don't dump the whole file.\n")
                    sys.exit(2)
                break                                  # found the target file, it's small enough
        except Exception:
            sys.exit(0)
    sys.exit(0)

if __name__ == "__main__":
    main()
