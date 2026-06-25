# arena

A **self-driving CTF solver**. Point it at a CTFd competition; it pulls the challenges, turns AI
solvers loose on each one (recon → exploit → adversarial critic retry), verifies the flag, and
submits. **Claude Code-first** — runs on your Claude subscription, **no API keys** — with
**pluggable AIs** (add Codex or Gemini by dropping in one file).

> Each teammate runs it on their **own** Claude plan. No shared accounts, no secrets in the repo.

---

## How it works (per challenge)

```
arena solve <id>                 (or `arena loop` over all unsolved)
        │
        ▼
1. RECON GATE   one recon-only agent maps the WHOLE target (every input/endpoint/
                file/param) and writes a RANKED candidate-vector list → .recon.md
        │       (observe before exploiting — the anti-tunnel-vision step)
        ▼
2. SOLVE PASS   an agent gets {challenge + ranked recon list}, works the top
                candidate, prints the flag. First valid PREFIX{...} wins.
        │
        ├─ flag ──► verify ──► submit (auto) or surface (manual)
        └─ none ──► 3. CRITIC (Opus) reads the transcript, writes a blunt steer
                       → retry with it. Repeat up to MAXTRY.
```

A live **dashboard** shows each solver's progress, tokens, cost, and the flag.

---

## Quickstart

```bash
# 0. prerequisites: Python 3.10+, and the `claude` CLI installed + logged in (claude → /login)
./install.sh                                   # installs the bundled CTF skills into ~/.claude/skills
pip install -e .                               # optional: gives the `arena` command (stdlib only, no deps)

# 1. configure (writes .env, chmod 600 — never commit it)
python3 -m arena setup https://the-ctf.example.com YOUR_CTFD_TOKEN --prefix MPTC
#    no-token site:  ... setup <url> --cookie '<session-cookie>' --prefix MPTC

# 2. run
python3 -m arena loop                          # autonomous: pull → solve → submit → repeat
python3 -m arena solve <id>                    # one challenge now
python3 -m arena dash                          # dashboard at http://127.0.0.1:8012
```

Get your CTFd token from the site: **Settings → Access Tokens**.

---

## Requirements
- **Python 3.10+** — arena itself has zero pip dependencies (stdlib only).
- **Claude Code CLI** (`claude`), logged in. Uses your Claude plan; no API key.
  - optional: `codex` / `gemini` CLIs to race other AIs (each must be logged in; Codex is verified
    end-to-end through arena, Gemini needs a Google login or `GEMINI_API_KEY`).
- **A CTFd access token** (or session cookie).

---

## Configuration (`.env`)

| key | default | meaning |
|---|---|---|
| `CTFD_URL` | — | the CTFd base URL |
| `CTFD_TOKEN` / `CTFD_COOKIE` | — | auth (token preferred; cookie if tokens are disabled) |
| `PREFIX` | `flag` | flag format, e.g. `MPTC` → matches `MPTC{...}` |
| `PROVIDER` | `claude` | which AI: `claude` \| `codex` \| `gemini` |
| `PROVIDERS` | — | crazy mode: comma list to race different AIs (`claude,codex,gemini`) |
| `RACERS` | `1` | `1` = normal (1 solver+critic); `3` = crazy (3 parallel, first flag wins) |
| `SUBMIT` | `auto` | `auto` submits verified flags; `manual` surfaces them for you |
| `RECON` | `1` | forced recon/observe pass before exploiting (`0` to skip) |
| `MAXTRY` | `4` | attempts per challenge (1 solo + critic-steered retries) |
| `PER_TIMEOUT` | `800` | per-solver timeout (s) |
| `DEADLINE` | — | comp end (`2026-07-15 10:00 UTC`) → loop stops |
| `SKIP_OSINT` | `0` | `1` skips the osint category |
| `DASH_PORT` | `8012` | dashboard port |

`.env.example` is a template. **Never commit `.env`** (it holds your token) — it's gitignored.

---

## Modes
- **Normal** (`RACERS=1`): one solver, then critic-steered retries. Light.
- **Crazy** (`RACERS=3`, or `PROVIDERS=claude,codex,gemini`): several solvers race the same
  challenge in parallel, share a `FINDINGS.md` bus, first valid flag wins. ~N× tokens.

Submission-safe: only flags matching `PREFIX{...}`, at most `MAXTRY` attempts, and it **stops on a
wrong submit** (CTFs limit attempts). Use `SUBMIT=manual` to eyeball flags first.

---

## What's bundled
- **Engine** — recon gate, solver, adversarial critic, CTFd client, autonomous loop, dashboard.
- **CTF skills** (`skills/`) — method, web, pwn, reverse, crypto, forensics, misc, osint, malware,
  ai-ml, writeup, solve-challenge, burp-scan. Installed by `./install.sh`.
- **Guard hooks** (`arena/hooks/`, auto-wired into every solver run, `ARENA_HOOKS=0` to disable):
  - `request_camo` — forces a real-browser header set on `curl` → defeats bot fingerprinting **and
    structurally bypasses UA-gated anti-AI trap pages** (the fake "this isn't a CTF / stop" walls).
  - `content_guard` — flags prompt-injection traps in fetched content (treat as untrusted, goal
    unchanged) **and** detects token-burning tarpits (per-host budget + repeated-body hashing → bail).
  - `loop_guard` (anti-stuck/repeat), `output_guard` (big-output truncation),
    `reflect_probe` (reflected-input → injection nudge), `vault_nudge` (grep the vault first).
- **Vault** (`vault/`) — distilled CTF technique recipes per category (real flags redacted).
- **MCP servers** (`mcp/`) — optional; see `mcp/README.md` (`magic`, `netsession` bundled; others referenced).

---

## Architecture (file map)
```
arena/
  arena/
    cli.py          entry: setup / pull / solve / loop / dash / coord / run
    config.py       all .env knobs → Config
    client.py       CTFd: list / pull / submit (stdlib urllib)
    racer.py        recon_pass → run_pass → solve_challenge ladder; prompt builders
    critic.py       Opus reads a failed transcript → writes a steer
    loop.py         autonomous pull→solve→submit→poll until DEADLINE
    coord.py        optional Opus coordinator (steers a swarm via the bus)
    dashboard.py    parses logs → live Command Center UI
    runner.py       detached tmux runner for long exploits
    solvers/        pluggable AIs: base.py + claude_code/codex/gemini + registry
    hooks/          guard hooks (auto-wired)
  skills/           bundled CTF skills (→ ~/.claude/skills via install.sh)
  vault/            technique recipes (flags redacted)
  mcp/              optional MCP servers (ours bundled + config for downloaded)
  viz/              dashboard HTML
  README.md  SHARE.md  AGENTS.md  .env.example
```

---

## Add a new AI (the whole point of the design)
Drop `arena/solvers/<name>.py`:
```python
from .base import Solver

class MyAI(Solver):
    name = "myai"          # registry key
    cli  = "myai"          # the CLI binary to check for
    def command(self, prompt, *, model, system):
        return ["myai", "run", "-p", prompt]   # argv to run it headless on `prompt`
```
Register it in `solvers/__init__.py` (`_BACKENDS`). Done — the racer/loop/critic are provider-agnostic.

---

## Safety / notes
- **Never commit `.env` / `.ctfd.json`** — gitignored.
- **Anti-AI-hijack is hook-enforced**, not just a prompt: `request_camo` makes every `curl` look like
  a real browser (so UA-gated trap pages are never served), and `content_guard` flags in-page
  "this isn't a CTF / stop" injection — fetched content is treated as untrusted data, never instructions.
- MCP servers are localhost-only; the kali_mcp backend executes tools as you — fine on a CTF box,
  don't expose it.

See **`SHARE.md`** for teammate setup, **`AGENTS.md`** for how an AI agent should operate this repo,
and **`mcp/README.md`** for MCP setup.
