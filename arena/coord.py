"""Coordinator — Opus oversees the whole board and steers stuck solvers via the bus.

One pass: read each unsolved challenge's description + latest racer transcript + FINDINGS, ask Opus for
a priority order + a targeted steer per challenge + any unsubmitted flag candidates, then write the
steers into each challenge's FINDINGS.md (the same bus the racers read). PULL-based, like comp/coord.py.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .config import Config
from .critic import _final_text, summarize
from .solvers import available, get_solver

NEVER = r"\Z\A"

PROMPT = (
    "You are the COORDINATOR of a live CTF. For each UNSOLVED challenge below you get its category/name, "
    "description, the latest solver TRACE (what it tried, with tool outputs), and shared FINDINGS.\n"
    "1) PRIORITY: order them to focus on next (closest-to-solved / high-value / easy first).\n"
    "2) STEER: for each stuck one, a SHORT specific technical steer for the next attempt (name the exact "
    "technique/tool/endpoint/assumption to try or drop), grounded in its trace. Not generic.\n"
    "3) FLAG_CANDIDATES: any correct-looking flag in a trace that was never submitted.\n"
    "Return ONLY JSON: {\"priority\":[\"cat/name\",...],\"steers\":{\"cat/name\":\"...\"},"
    "\"flag_candidates\":{\"cat/name\":\"...\"}}\n\nCHALLENGES:\n"
)


def _latest_trace(chal_dir: Path) -> str:
    logs = sorted((chal_dir / ".logs").glob("*.log"), key=lambda p: p.stat().st_mtime) if (chal_dir / ".logs").exists() else []
    return summarize(logs[-1].read_text()) if logs else ""


def survey(cfg: Config) -> list[dict]:
    solved = {p.name for p in (cfg.workdir / ".solved").glob("*")} if (cfg.workdir / ".solved").exists() else set()
    out = []
    for cidf in sorted(cfg.workdir.glob("*/*/.cid")):
        if cidf.read_text().strip() in solved:
            continue
        d = cidf.parent
        out.append({
            "dir": d,
            "slug": f"{d.parent.name}/{d.name}",
            "desc": (d / "desc.md").read_text()[:400] if (d / "desc.md").exists() else "",
            "findings": (d / "FINDINGS.md").read_text()[-1500:] if (d / "FINDINGS.md").exists() else "",
            "trace": _latest_trace(d),
        })
    return out


def _build(chals: list[dict]) -> str:
    blocks = [f"\n### {c['slug']}\nDESC: {c['desc'] or '(none)'}\nFINDINGS:\n{c['findings'] or '(none)'}\n"
              f"TRACE:\n{c['trace'] or '(no run yet)'}\n" for c in chals]
    return PROMPT + "\n".join(blocks)


def one_pass(cfg: Config, dry: bool = False) -> None:
    chals = survey(cfg)
    if not chals:
        print("[coord] no unsolved challenges — nothing to do")
        return
    prompt = _build(chals)
    print(f"[coord] surveyed {len(chals)}: {', '.join(c['slug'] for c in chals)}")
    if dry:
        print("\n=== WOULD SEND (--dry) ===\n" + prompt[:6000])
        return
    provider = "claude" if "claude" in available() else cfg.provider
    res = get_solver(provider).solve(prompt, str(cfg.root), NEVER, timeout=420,
                                     model="opus" if provider == "claude" else None)
    m = re.search(r"\{.*\}", _final_text(res.raw), re.S)
    if not m:
        print("[coord] no JSON back")
        return
    try:
        data = json.loads(m.group(0))
    except Exception:
        print("[coord] bad JSON")
        return
    if data.get("priority"):
        print("[coord] PRIORITY:", " > ".join(data["priority"]))
    by_slug = {c["slug"]: c for c in chals}
    for slug, steer in (data.get("steers") or {}).items():
        c = by_slug.get(slug)
        if c and steer:
            with open(c["dir"] / "FINDINGS.md", "a") as f:
                f.write(f"\n### COORDINATOR STEER ({time.strftime('%H:%M:%S')})\n{steer.strip()}\n")
            print(f"[coord] steered {slug}: {steer[:100]}")
    for slug, flag in (data.get("flag_candidates") or {}).items():
        print(f"[coord] ⚑ candidate {slug}: {flag}  (verify + submit manually)")


def run_coord(cfg: Config, dry: bool = False, loop: int = 0) -> int:
    if loop:
        while True:
            one_pass(cfg, dry)
            print(f"[coord] sleeping {loop}s\n")
            time.sleep(loop)
    one_pass(cfg, dry)
    return 0
