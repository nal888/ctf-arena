# netsession MCP

Persistent TCP sessions for CTF — the gap Bash/pwndbg/ghidra don't cover.

Bash is one-shot (can't hold a live connection across calls). `pwndbg` debugs a *local* binary, not a *remote* service. This MCP holds live TCP sessions in a long-running process so the agent can interact across multiple tool calls.

## Use it for
- **Interactive pwn**: `connect(host,port)` to a `nc`-style service, then `send`/`recv`/`hexsend` to probe and iterate without re-running a script each time.
- **Reverse shells**: `listen(port)` → trigger payload → `sessions()` shows the caught shell → `shell(sid, "id; cat /root/root.txt")`. (This is the exact loop that cost hours on Connected — agent couldn't see the human's `nc`.)

## Tools
| tool | does |
|---|---|
| `connect(host, port)` | open a persistent TCP session (returns `sid`) |
| `listen(port)` | start a listener to catch a reverse shell |
| `sessions()` | list active sessions/listeners |
| `send(sid, data, newline=True)` | send text |
| `hexsend(sid, hexbytes)` | send raw bytes (binary pwn payloads) |
| `recv(sid, timeout=2.0, until="")` | drain output (optionally until a marker) |
| `shell(sid, cmd, timeout=8.0)` | run a command on a shell session, framed output |
| `close(sid)` | close it |

## Honest scope
- Great for **interactive probing + revshell handling**.
- For **precise binary pwn** (cyclic patterns, struct packing, ROP chains, GDB sync) a **pwntools script is still better** — use this for the interactive/triage part, drop to a pwntools script for the exploit.

## Install / run
```bash
pip install mcp        # once
```
Registered in `~/.claude/settings.json` under `mcpServers.netsession` (command: `python3 .../server.py`) and allowlisted as `mcp__netsession__*`. Restart Claude Code (or reload) to load it.

## Note
Listeners bind 0.0.0.0 — fine on a CTF VPN; don't run untrusted exposure. Local state only; sessions die when the MCP process restarts.
