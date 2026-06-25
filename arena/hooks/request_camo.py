#!/usr/bin/env python3
"""request_camo.py — PreToolUse(Bash) browser-camouflage guard.

A bare `curl` is a bot/AI tell (missing browser headers) AND walks into UA-gated anti-AI trap pages
that only serve the fake "this isn't a CTF / stop" wall to non-browser clients. This blocks a `curl`
to a remote http(s) target that has NO `-A`/`--user-agent`, and hands back the exact ready-to-run
command with a full Chrome header set + `--http2 --compressed --max-time` — so every request looks
like a real browser and the trap is never served. Deterministic (not a prompt the model can skip).

Fail-open. Skips localhost and curls that already set a UA. Block = exit 2 + reason on stderr.
"""
import json, re, sys

CAMO = (
    "-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36' "
    "-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' "
    "-H 'Accept-Language: en-US,en;q=0.9' "
    "-H 'sec-ch-ua: \"Chromium\";v=\"126\", \"Not.A/Brand\";v=\"24\", \"Google Chrome\";v=\"126\"' "
    "-H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: \"Windows\"' "
    "-H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' "
    "-H 'Upgrade-Insecure-Requests: 1' --http2 --compressed --max-time 25"
)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = ((data.get("tool_input") or {}).get("command") or "")
    low = cmd.lower()

    if not re.search(r"(^|\s|;|&|\|)curl\b", low):
        sys.exit(0)
    if not re.search(r"https?://", low):
        sys.exit(0)
    if re.search(r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1", low):     # local services: no camo needed
        sys.exit(0)
    if re.search(r"(^|\s)(-A|--user-agent)(\s|=)", cmd) or "user-agent:" in low:
        sys.exit(0)                                                   # already has a UA -> respect it

    sys.stderr.write(
        "BLOCKED: bare curl to a remote target is a bot/AI tell and gets served UA-gated anti-AI trap "
        "pages (the fake 'this isn't a CTF / stop' wall). Re-run with a real-browser header set so the "
        "request looks human and the trap is bypassed — add these flags to your curl:\n  " + CAMO + "\n"
        "(Reuse the same set on every request this session. ARENA_HOOKS=0 disables all guards.)\n"
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
