#!/usr/bin/env python3
"""loop_guard.py — PreToolUse(Bash) anti-stuck / anti-tarpit guard.

Stops the token-burning failure modes documented for AI CTF/pentest agents:
  - grinding the SAME command over and over (stuck / tarpitted)
  - anchoring on ONE vector/bug-class with DIFFERENT payloads (the CNCC SSTI loss:
    ~30 traversal encodings + a static-file probe, every command different, so the
    old exact-match never tripped — this is the gap this version closes)

Per-session memory of recent Bash command signatures in /tmp/claude-loopguard-<sid>.log.

EXACT repeats (precise, low false-positive):
  - 3rd–4th identical recent run -> ALLOW + warning (re-think / escalate)
  - 5th+ identical recent run     -> BLOCK (exit 2): force a different approach
VECTOR-FAMILY (same host + first path segment, differing payloads):
  - 6th+ request in one family    -> ALLOW + warning to switch bug class / read the
    response signal / grep the vault. WARN only (never BLOCK — looser sig, higher FP).

Window = last 20 commands. Fail-open on any error (never break the session).
"""
import sys, json, os, re

WINDOW = 20          # how many recent commands to remember
WARN_AT = 3          # warn once the current EXACT cmd has appeared this many times
BLOCK_AT = 5         # hard-block exact repeats at this many
FAMILY_WARN = 6      # warn once this many requests hit the same host+path-segment family


def family(sig):
    """Same target/vector family = host + first path segment of the first http(s) URL.
    Returns 'host|seg' or None for non-network commands. Tool-agnostic (curl/wget/python/httpie)."""
    u = re.search(r'https?://([^/\s\'"]+)([^\s\'"?]*)', sig)
    if not u:
        return None
    host = u.group(1)
    parts = [p for p in (u.group(2) or "/").split("/") if p]
    return host + "|" + (parts[0] if parts else "")


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.exit(0)                                  # not our shape -> allow
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = (data.get("tool_input") or {}).get("command", "")
    sig = re.sub(r"\s+", " ", cmd).strip()
    if not sig:
        sys.exit(0)
    sid = data.get("session_id") or "default"
    sid = re.sub(r"[^A-Za-z0-9_-]", "", sid)[:64] or "default"
    path = f"/tmp/claude-loopguard-{sid}.log"

    try:
        prior = []
        if os.path.exists(path):
            with open(path) as f:
                prior = [l.rstrip("\n") for l in f][-WINDOW:]
        count = prior.count(sig) + 1                 # exact repeats, including this attempt
        with open(path, "w") as f:
            f.write("\n".join((prior + [sig])[-WINDOW:]) + "\n")
    except Exception:
        sys.exit(0)                                  # fail-open

    # --- exact-repeat: block / warn (unchanged behavior) ---
    if count >= BLOCK_AT:
        sys.stderr.write(
            f"LOOP GUARD: this exact command has run {count}× recently — you are stuck or being "
            f"tarpitted. STOP repeating it. Change approach: try a different vector, re-read the "
            f"target's actual response, or escalate (Opus / critic / human). Do NOT re-run as-is.\n")
        sys.exit(2)                                  # block + stderr shown to the model
    if count >= WARN_AT:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": (
                f"loop-guard: ran this {count}× already — if it keeps failing, change approach or "
                f"escalate instead of repeating (block at {BLOCK_AT}×).")}}))
        sys.exit(0)

    # --- vector-family: warn on anchoring (differing payloads, same endpoint) ---
    fam = family(sig)
    if fam:
        fam_count = sum(1 for h in prior if family(h) == fam) + 1
        if fam_count >= FAMILY_WARN:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": (
                    f"loop-guard: {fam_count} requests to the same target/vector family ({fam}) with "
                    f"differing payloads — you may be anchoring on ONE bug class (e.g. traversal/LFI). "
                    f"Switch bug class (SSTI/SQLi/SSRF/upload/auth), re-read the response for a "
                    f"reflected-input or error signal, or grep the vault. Don't keep fuzzing one vector.")}}))
            sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
