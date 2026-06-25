# CTF MCP servers (optional)

arena's solver works with plain `bash`/`curl` — **MCPs are a bonus**, not required. These are the
CTF-relevant ones. Bug-bounty/intel servers (hackerone, cve) are deliberately excluded.

MCP config lives in **`~/.claude.json`** under `mcpServers` (Claude Code ignores `mcpServers` in
`settings.json`). Edit it, then **restart Claude Code**. Template: `mcp.example.json`.

## Ours (bundled in `mcp/ours/` — just wire them up)
| server | what | run |
|---|---|---|
| **magic** | CyberChef-"Magic" auto-decoder (base64/32/16/85/58, hex, rot, xor, gzip…). One call decodes nested blobs. | `python3 mcp/ours/magic-mcp/server.py` |
| **netsession** | live TCP sessions / reverse-shell catcher — catch + drive a shell from inside Claude | `python3 mcp/ours/netsession/server.py` |

Both need the `mcp` Python package: `pip install mcp`. Run `./setup-mcp.sh` to install that and print
the ready-to-paste config (with the correct absolute paths filled in).

## Downloaded (get these yourself, then point the config at them)
| server | what | where to get it |
|---|---|---|
| **kali_mcp** (CTF-Solver) | 55+ Kali tools, all CTF categories, real exec | the CTF-Solver project — runs a Flask backend on `localhost:5000`; **start it first** (`CTF-Solver/start.sh &`) |
| **radare2** (`r2mcp`) | ~40 r2 ops — reverse/pwn | ships with radare2 (`r2pm -i r2mcp`) |
| **pwndbg** (`pwndbg-mcp`) | gdb/pwndbg — pwn debugging | pwndbg-mcp package |
| **ghidra** | decompile/disassemble — reverse | ghidramcp bridge + a Ghidra server on `:8090` |
| **pcap-analysis** | PCAP/network forensics | Pcap-Analysis-MCP project |
| **mem-forensics** | Windows memory forensics (Volatility) | Windows-Memory-Forensics-MCP project |
| **frida-hacking** | Frida instrumentation — reverse/mobile | frida-game-hacking-mcp project |
| **hexstrike** | 150+ recon/web tools | hexstrike server on `:8888` |
| **jshook** | JS hooking — web/reverse | `npx -y @jshookmcp/jshook` |
| **burp** | Burp proxy/repeater/scanner | Burp Suite + the AI-agent extension (SSE on `:9876`) |

## Setup
1. `./setup-mcp.sh` — installs `mcp`, prints the **ours** entries with real paths.
2. Install any downloaded servers you want (table above), note their install path.
3. Edit `~/.claude.json` → `mcpServers`: paste the ours entries; for downloaded ones copy from
   `mcp.example.json`, replacing `__TOOLS__` with your install path.
4. Restart Claude Code. `/mcp` shows what loaded.

## Start order for a comp
1. `CTF-Solver/start.sh &` (kali_mcp backend on `:5000`)
2. optional: hexstrike `:8888`, Burp for the burp MCP, Ghidra server `:8090`
3. restart Claude Code so it connects.

## Security
All servers are localhost-only. kali_mcp/CTF-Solver executes tools as you — fine on a CTF Kali box,
**don't expose it**. No API keys are stored in this folder.
