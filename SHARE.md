# arena — team setup

A self-driving CTF solver. Each teammate runs it on **their own** Claude Code subscription —
no API keys, no shared account, no secrets in the repo. Drop-in.

## What you need
1. **Python 3.10+** — arena has zero pip dependencies (stdlib only).
2. **Claude Code CLI** — `claude`, installed and logged in (`claude`, then `/login`). Uses your Claude
   plan, **no API key**. (Optional: `codex` / `gemini` CLIs to race other AIs.)
3. **Your own CTFd access token** — on the CTF site: Settings → Access Tokens → generate.

## Setup (once)
```bash
cd arena
./install.sh                         # copies the bundled CTF skills into ~/.claude/skills
pip install -e .                     # optional: gives the `arena` command (or just use python3 -m arena)
python3 -m arena setup <ctf-url> <YOUR_TOKEN> --prefix MPTC
#   no-token site:  python3 -m arena setup <ctf-url> --cookie '<session-cookie>' --prefix MPTC
```

## Run
```bash
python3 -m arena loop                # autonomous: pull → solve → submit → repeat
python3 -m arena solve <id>          # solve one challenge now
python3 -m arena dash                # dashboard at http://127.0.0.1:8012
```

## What's bundled (self-contained)
- **Pipeline:** recon gate → solver → adversarial critic retry (up to `MAXTRY`), CTFd pull/submit, live dashboard.
- **CTF skills** (`skills/`): method, web, pwn, reverse, crypto, forensics, misc, osint, malware, ai-ml,
  writeup, solve-challenge, burp-scan → installed by `./install.sh`.
- **Guard hooks** (`arena/hooks/`): anti-stuck, big-output truncation, reflected-input nudge →
  **auto-wired** when arena runs (set `ARENA_HOOKS=0` to turn off).
- **Vault** (`vault/`): distilled CTF technique recipes per category (real flags **redacted**); the
  solver is auto-nudged at session start to grep it (`ARENA_VAULT` to point elsewhere).

## Modes & safety (set in `.env`)
- `RACERS=1` normal (1 solver + critic) · `RACERS=3` crazy (3 parallel, first flag wins, ~3× tokens).
- `SUBMIT=auto` submits verified flags · `SUBMIT=manual` just surfaces them (CTFs limit attempts).
- Stops on a wrong submit; only submits flags matching `PREFIX{...}`.

## MCP servers (optional)
CTF MCP servers live in `mcp/`. The solver works fine **without** any of them (plain bash/curl) — they're a bonus.
- `mcp/setup-mcp.sh` — wires our **bundled** ones (`magic` auto-decoder, `netsession` revshell catcher).
- `mcp/README.md` + `mcp/mcp.example.json` — the **downloaded** ones (kali_mcp, radare2, pwndbg, ghidra, burp, hexstrike, frida, pcap, mem-forensics) — where to get them + config. (Bug-bounty/intel servers excluded; no API keys shipped.)

## Notes
- **Never commit your `.env`** — it holds your token. It's gitignored.
- Anti-AI trap awareness is built into the prompt: it ignores fake "this isn't a CTF / stop" pages and
  retries with a browser User-Agent.
