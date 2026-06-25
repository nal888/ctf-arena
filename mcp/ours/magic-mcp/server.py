#!/usr/bin/env python3
"""
magic MCP — CyberChef-"Magic"-style auto-decoder for CTF blobs.

Saves the agent from manually running decode → look → decode again across many
turns. One `magic(blob)` call best-first-searches encoding cascades (base64/32/16/
85/58, hex, url, rot13/N/47, atbash, morse, binary, decimal, gzip/zlib/bz2/lzma,
single-byte XOR…), scores branches (entropy, chi²-vs-English, magic bytes, flag
crib) and returns the winning operation chain + decoded output.

Tools:
  magic(data, depth=8)      -> auto-detect + recursively decode; returns best chain + candidates
  decode(data, ops)         -> apply a specific op chain, e.g. ["base64","rot13","hex"]
  detect(data)              -> which single-step decodes look applicable (no recursion)
  entropy(data)             -> Shannon entropy + printable ratio (is it encoded/encrypted?)

Install:  uses stdlib only (+ `pip install mcp` for the server).
Run:      python3 server.py     (register via mcpServers in settings.json)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import magic_engine as E
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("magic")

@mcp.tool()
def magic(data: str, depth: int = 8) -> str:
    """Auto-detect and recursively decode an encoded blob (CyberChef Magic style).
    Returns the best decode chain + output, plus ranked alternative candidates.
    Feed it the raw blob; ≥32 bytes detects most reliably."""
    res = E.magic(data, depth=depth)
    lines = [f"input: {res['input_preview']}", f"(searched {res['nodes']} branches)", ""]
    if res["best"]:
        b = res["best"]
        tag = "FLAG" if b["flag"] else "best"
        lines.append(f"[{tag}] {' -> '.join(b['chain'])}")
        lines.append(f"       {b['output']}")
    else:
        lines.append("no decode improved on the input — may be plaintext, encrypted, or an unsupported scheme")
    others = [c for c in res["candidates"][1:] if c]
    if others:
        lines.append("\nother candidates:")
        for c in others[:5]:
            lines.append(f"  {' -> '.join(c['chain'])}  ({c['note']})\n     {c['output'][:120]}")
    return "\n".join(lines)

@mcp.tool()
def decode(data: str, ops: list) -> str:
    """Apply a specific decode chain in order, e.g. ops=["base64","rot13","hex"].
    Op names match those magic() returns (base64, base64url, base32, hex, base85,
    ascii85, base58, url, html-entity, rot13, rotN (e.g. 'rot5'), rot47, atbash,
    reverse, binary, decimal, morse, gzip, zlib, bzip2, lzma)."""
    cur = data.encode("latin1", "replace")
    trace = []
    name_map = {fn.__name__.replace("op_", ""): fn for fn in E.OPS}
    for step in ops:
        s = str(step).lower()
        applied = False
        # exact op or a brute variant like rot5 / xor0x41
        for fn in E.OPS:
            for label, out in fn(cur):
                if label.lower() == s:
                    cur = out; trace.append(f"{label} -> {E._preview(cur, 80)}"); applied = True; break
            if applied: break
        if not applied:
            trace.append(f"{s}: (no match / not applicable here)")
    return "\n".join(trace) + f"\n\nRESULT: {E._preview(cur, 400)}"

@mcp.tool()
def detect(data: str) -> str:
    """Show which single-step decodes look applicable right now (no recursion).
    Useful to see your options before committing to a chain."""
    cur = data.encode("latin1", "replace").strip()
    hits = []
    for fn in E.OPS:
        for label, out in fn(cur)[:1]:
            if out:
                hits.append(f"  {label:12} -> {E._preview(out, 70)}")
    return ("applicable decodes:\n" + "\n".join(hits)) if hits else "no single-step decode looks applicable"

@mcp.tool()
def entropy(data: str) -> str:
    """Shannon entropy + printable ratio of the data — high entropy (>7.5) suggests
    encrypted/compressed; ~6 suggests base64; low + printable suggests text/encoding."""
    b = data.encode("latin1", "replace")
    ent = E.shannon(b); pr = E.printable_ratio(b)
    hint = ("looks encrypted/compressed" if ent > 7.5 else
            "looks base64-ish" if 5.5 < ent <= 7.5 else
            "looks like text/simple-encoding")
    mb = E.magic_hit(b)
    return f"entropy: {ent:.2f}/8   printable: {pr:.0%}   -> {hint}" + (f"\nmagic bytes: {mb} file!" if mb else "")

if __name__ == "__main__":
    mcp.run()
