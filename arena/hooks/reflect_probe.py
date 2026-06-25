#!/usr/bin/env python3
"""reflect_probe.py — PostToolUse(Bash) reflected-input detector.

The #1 injection tell is a value you SENT in an HTTP request coming back VERBATIM in
the response (query param, body field, header). The CNCC "Can see, can't have" web
challenge had exactly this in the FIRST response and it was ignored for ~90% of the
session while grinding path-traversal + a static file server; the bug was Go
text/template SSTI on that reflected param.

When a sent value (>=4 chars) is reflected in the command's output, inject a reminder
to run the injection probe set BEFORE grinding traversal/LFI/static. Nudges ONCE per
session (dedupe flag) to avoid noise. Fail-open; never blocks (PostToolUse — the tool
already ran, this only adds context).
"""
import sys, json, os, re


def sent_values(cmd):
    vals = set()
    # query params ?k=v / &k=v
    for m in re.finditer(r'[?&]([A-Za-z0-9_]+)=([^&\s\'"]+)', cmd):
        vals.add(m.group(2))
    # -d / --data / --data-urlencode  k=v
    for m in re.finditer(r'(?:--data-urlencode|--data-raw|--data|-d)\s+["\']?[^=\s"\']*=([^&"\'\s]+)', cmd):
        vals.add(m.group(1))
    # -H 'Header: value'
    for m in re.finditer(r'-H\s+["\']([^:"\']+):\s*([^"\']+)["\']', cmd):
        vals.add(m.group(2).strip())
    # strip url-encoding noise, keep distinctive values
    out = set()
    for v in vals:
        v = v.strip()
        if len(v) >= 4 and not v.isdigit():          # skip short + pure-numeric (cache busters etc.)
            out.add(v)
    return out


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.exit(0)
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not re.search(r'\b(curl|wget|https?://|requests\.)', cmd):
        sys.exit(0)

    resp = data.get("tool_response")
    if isinstance(resp, dict):
        out = (resp.get("stdout") or "") + "\n" + (resp.get("stderr") or "")
    else:
        out = str(resp or "")
    if not out.strip():
        sys.exit(0)

    hit = next((v for v in sent_values(cmd) if v in out), None)
    if not hit:
        sys.exit(0)

    # dedupe: nudge once per session
    sid = re.sub(r"[^A-Za-z0-9_-]", "", data.get("session_id") or "default")[:64] or "default"
    flag = f"/tmp/claude-reflect-{sid}.flag"
    if os.path.exists(flag):
        sys.exit(0)
    try:
        open(flag, "w").close()
    except Exception:
        pass

    msg = ("reflect-probe: a value you sent (\"" + hit[:48] + "\") is REFLECTED verbatim in the "
           "response — the #1 injection tell. BEFORE grinding traversal/LFI/static, probe THIS param: "
           "SSTI {{7*7}} / ${7*7} / <%=7*7%>  (Go/Echo: {{.}} renders but {{7*7}} does NOT -> "
           "{{.File \"/flag.txt\"}}), then XSS <x>, then SQLi '. See vault/web.md SSTI. Recognition "
           "beats grinding.")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": msg}}))
    sys.exit(0)


if __name__ == "__main__":
    main()
