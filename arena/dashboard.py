"""Live dashboard — serves the same Command Center UI as the original (viz/live.html).

It parses each solver's transcript (.logs/<label>.log) into the rich per-racer detail the UI wants
(tokens, cost, tool counts, shell verbs, activity series, tool log) and emits the same /api/states
shape, so viz/live.html renders identically. /cards is a lean grid fallback.

  arena dash   ->   http://127.0.0.1:<DASH_PORT>
"""
from __future__ import annotations

import collections
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config

# (input, output, cache_read, cache_write) $/Mtok — calibrated like the original tracker
PRICE = {"sonnet": (3.0, 15.0, 0.30, 3.75), "opus": (15.0, 75.0, 1.50, 18.75)}

_cache: dict = {}


def _price_for(model: str):
    return PRICE["opus"] if "opus" in (model or "") else PRICE["sonnet"]


def runlog_stats(logpath: str, model: str = "sonnet") -> dict | None:
    """Parse a solver's stream-json transcript → tokens, cost, tools, verbs, activity series, tool log."""
    try:
        mt = os.path.getmtime(logpath)
    except OSError:
        return None
    key = (logpath, mt)
    if key in _cache:
        return _cache[key]
    out = inp = cr = cw = 0
    tools, verbs, series, calls, errs = collections.Counter(), collections.Counter(), [], [], {}
    try:
        with open(logpath) as f:
            for line in f:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                t = o.get("type")
                if t == "assistant":
                    m = o.get("message", {})
                    u = m.get("usage", {}) or {}
                    out += u.get("output_tokens", 0); inp += u.get("input_tokens", 0)
                    cr += u.get("cache_read_input_tokens", 0); cw += u.get("cache_creation_input_tokens", 0)
                    turn = 0
                    for b in m.get("content", []):
                        if isinstance(b, dict) and b.get("type") == "tool_use":
                            turn += 1
                            nm = b["name"]
                            short = nm.split("__")[1] if nm.startswith("mcp__") and "__" in nm[5:] else nm
                            tools[short] += 1
                            ip = b.get("input", {}) or {}
                            if nm == "Bash":
                                c = (ip.get("command", "") or "").strip().split()
                                if c and c[0] != "#":
                                    verbs[c[0].split("/")[-1]] += 1
                            arg = ip.get("command") or ip.get("file_path") or ip.get("pattern") or ip.get("url") or ip.get("description") or ""
                            calls.append({"id": b.get("id"), "tool": short, "arg": " ".join(str(arg).split())[:160], "err": False})
                    series.append(turn)
                elif t == "user":
                    for b in o.get("message", {}).get("content", []):
                        if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error"):
                            errs[b.get("tool_use_id")] = True
    except OSError:
        return None
    for c in calls:
        if errs.get(c["id"]):
            c["err"] = True
        c.pop("id", None)
    p = _price_for(model)
    cost = (inp * p[0] + out * p[1] + cr * p[2] + cw * p[3]) / 1e6
    res = {"out": out, "inp": inp, "cr": cr, "cost": round(cost, 4),
           "tools": dict(tools.most_common()), "verbs": dict(verbs.most_common()),
           "series": series[-120:], "calls": calls[-80:]}
    _cache[key] = res
    return res


def gather(cfg: Config) -> list[dict]:
    """Emit the original /api/states shape from arena's .state.json + .logs/<label>.log."""
    out = []
    for sf in cfg.workdir.glob("*/*/.state.json"):
        try:
            s = json.loads(sf.read_text())
        except Exception:
            continue
        cdir = sf.parent
        racers = {}
        for label, r in (s.get("racers") or {}).items():
            model = r.get("provider", "claude")
            detail = runlog_stats(str(cdir / ".logs" / f"{label}.log"), model)
            tools = sum(detail["tools"].values()) if detail else 0
            racers[label] = {
                "model": model, "status": r.get("status"), "flag": r.get("flag"),
                "start": r.get("start", 0), "elapsed": r.get("elapsed", 0),
                "tools": tools, "out_tok": (detail or {}).get("out"),
                "cost_usd": (detail or {}).get("cost"), "detail": detail,
            }
        bus = cdir / "FINDINGS.md"
        # Liveness must track the solver, not the once-written .state.json. Use the freshest
        # log mtime (updates every few seconds while a solver streams) so the UI's freshness
        # gate (Date.now - _mtime < 8s) stays "live" for the whole run instead of going dead 8s in.
        logdir = cdir / ".logs"
        mtimes = [sf.stat().st_mtime]
        if logdir.exists():
            mtimes += [p.stat().st_mtime for p in logdir.glob("*.log")]
        out.append({
            "header": f"{cdir.parent.name}/{cdir.name}",
            "_path": str(sf.relative_to(cfg.root)) if str(sf).startswith(str(cfg.root)) else str(sf),
            "_mtime": max(mtimes),
            "mode": s.get("mode", "normal"),
            "racers": racers,
            "findings": bus.read_text()[-2000:] if bus.exists() else "",
        })
    out.sort(key=lambda d: d["_mtime"], reverse=True)
    return out


# lean fallback grid (served at /cards)
CARDS = """<!doctype html><meta charset=utf-8><title>arena · cards</title>
<style>body{margin:0;background:#0d1117;color:#e6edf3;font-family:-apple-system,Segoe UI,Roboto,sans-serif}
main{padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.c{background:#1c2230;border:1px solid #2b3242;border-left:3px solid #2dd4bf;border-radius:12px;padding:12px 14px}
.c.won{border-left-color:#3fb950}.name{font-weight:700}.mode{font-size:10px;color:#8b949e;text-transform:uppercase}
.r{font-size:12.5px;margin-top:5px}.flag{margin-top:8px;color:#bbf7d0;background:#0f2e22;border:1px solid #3fb950;border-radius:8px;padding:6px 9px}</style>
<main id=m></main><script>
async function t(){let d=[];try{d=await(await fetch('/api/states',{cache:'no-store'})).json()}catch(e){}
document.getElementById('m').innerHTML=d.map(s=>{const rs=Object.entries(s.racers||{});const won=rs.some(([k,r])=>r.status==='WON');
const rows=rs.map(([k,r])=>`<div class=r>${k} · ${r.status}${r.flag?' · ⚑ '+r.flag:''}</div>`).join('');
return `<div class="c ${won?'won':''}"><div class=name>${s.header}</div><div class=mode>${s.mode}</div>${rows}</div>`}).join('')||'no runs yet'}
t();setInterval(t,1500)</script>"""


def serve(cfg: Config) -> None:
    viz = cfg.root / "viz"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, name: str, fallback: bytes) -> bytes:
            try:
                return (viz / name).read_bytes()
            except OSError:
                return fallback

        def do_GET(self):
            if self.path.startswith("/api/states"):
                self._send(json.dumps(gather(cfg)).encode(), "application/json")
            elif self.path.startswith("/cards"):
                self._send(CARDS.encode(), "text/html; charset=utf-8")
            elif self.path.startswith("/system"):
                self._send(self._file("system.html", b"<h1>viz/system.html missing</h1>"), "text/html; charset=utf-8")
            else:
                self._send(self._file("live.html", CARDS.encode()), "text/html; charset=utf-8")

    print(f"arena dashboard → http://127.0.0.1:{cfg.dash_port}  (Command Center)")
    ThreadingHTTPServer(("127.0.0.1", cfg.dash_port), H).serve_forever()
