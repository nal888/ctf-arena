"""Adversarial critic — reads a FAILED attempt's transcript (+ greps the vault) and writes a sharp
steer for the next attempt. Ported from comp/race.py. Uses Opus (Claude) to reason about the failure;
the steer is then fed into the escalated retry to break wrong-vector anchoring.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import Config
from .solvers import available, get_solver

NEVER = r"\Z\A"  # a regex that never matches → solve() reads the full output instead of stopping at a flag

PROMPT = (
    "You are an ADVERSARIAL CTF reviewer. The previous agent FAILED to capture the flag. Below is a "
    "condensed transcript of what it did:\n\n{summary}\n\n"
    "Figure out why it's stuck and redirect it:\n"
    "1. Name the vector it ANCHORED on. Before calling anything a RED HERRING, rule out that it was just "
    "TESTED WRONG or SHALLOWLY — wrong target/object, wrong payload, or only one variation tried. A capability "
    "that is clearly PRESENT (an input is accepted, an endpoint responds, a field is writable) but produced no "
    "result is often the REAL bug exercised the wrong way, not a dead end. Only tell it to ABANDON a vector "
    "you're confident was tested correctly AND exhaustively.\n"
    "2. Name the WRONG assumption it made.\n"
    "3. Name concrete things it NEVER TRIED.\n"
    "4. If a vault is available, grep it (vault/INDEX.md + the matching vault/<category>.md) for a pattern "
    "matching this challenge's signal — it likely skipped a known technique.\n"
    "5. Prefer the SIMPLEST exploit; if it's overcomplicating, name the direct path.\n"
    "6. LIVE CTF — no writeups exist. If it hinges on a specific format/algorithm/CVE/protocol you're unsure "
    "of, WebSearch THAT SPECIFIC TECHNIQUE (not the challenge name) and fold it in.\n\n"
    "Output ONLY a SHORT, BLUNT steer (max ~150 words): exactly what to try, what to ABANDON, which "
    "payload/endpoint/technique."
)


def summarize(raw: str, max_reason: int = 8, max_cmds: int = 20) -> str:
    """Condense a stream-json transcript into reasoning + tool calls + tool results."""
    reasons, cmds = [], []
    for line in raw.splitlines():
        try:
            o = json.loads(line)
        except Exception:
            continue
        if not isinstance(o, dict):
            continue
        t = o.get("type")
        if t == "assistant":
            for b in o.get("message", {}).get("content", []):
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text" and b.get("text", "").strip():
                    reasons.append(" ".join(b["text"].split()))
                elif b.get("type") == "tool_use":
                    a = b.get("input", {}) or {}
                    v = a.get("command") or a.get("url") or a.get("pattern") or a.get("description") or ""
                    cmds.append(f"{b.get('name')}: {' '.join(str(v).split())[:120]}")
        elif t == "user":
            for b in o.get("message", {}).get("content", []):
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    if isinstance(c, list):
                        c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                    cmds.append(f"RESULT: {' '.join(str(c).split())[:160]}")
    if not reasons and not cmds:
        return raw[-3000:]                                   # non-stream-json (codex/gemini) → raw tail
    out = "REASONING (last):\n" + "\n".join(f"- {r[:200]}" for r in reasons[-max_reason:])
    out += "\n\nTOOL CALLS / RESULTS (last):\n" + "\n".join(f"- {c}" for c in cmds[-max_cmds:])
    return out[:6000]


def _final_text(raw: str) -> str:
    """Pull the model's final text out of a stream-json transcript (or return the raw)."""
    texts = []
    for line in raw.splitlines():
        try:
            o = json.loads(line)
        except Exception:
            continue
        if not isinstance(o, dict):
            continue
        if o.get("type") == "result" and o.get("result"):
            texts.append(str(o["result"]))
        elif o.get("type") == "assistant":
            for b in o.get("message", {}).get("content", []):
                if isinstance(b, dict) and b.get("type") == "text":
                    texts.append(b["text"])
    return ("\n".join(texts).strip() or raw.strip())[:4000]


def critique(cfg: Config, chal_dir: Path, failed_raw: str, desc: str, conn: str) -> str:
    """Return a steer for the next attempt, or '' if nothing useful."""
    summary = summarize(failed_raw)
    if not summary.strip():
        return ""
    prompt = PROMPT.format(summary=summary)
    if desc:
        prompt += f"\n\nChallenge: {desc}"
    if conn:
        prompt += f"\nRemote: {conn}"
    # Use Opus (Claude) to steer when available — best reasoner; else fall back to the run's provider.
    provider = "claude" if "claude" in available() else cfg.provider
    model = "opus" if provider == "claude" else None
    res = get_solver(provider).solve(prompt, str(chal_dir), NEVER, timeout=300, model=model)
    return _final_text(res.raw)
