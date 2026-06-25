# arena

**A self-driving CTF solver.** Point it at a CTFd competition — it pulls the challenges, turns AI
solvers loose on each one, verifies the flag, and submits.

**Claude Code-first** (runs on your Claude subscription, **no API keys**) · **pluggable AIs** (Codex,
Gemini — one file each) · **anti-detection & anti-trap built in**.

> Each teammate runs it on their **own** Claude plan. No shared accounts, no secrets in the repo.

---

## Quickstart

```bash
# prerequisites: Python 3.10+  and  the `claude` CLI installed + logged in (claude → /login)
git clone https://github.com/nal888/ctf-arena && cd ctf-arena
./install.sh                                              # installs the CTF skills into ~/.claude/skills
python3 -m arena setup https://the-ctf.example.com  YOUR_CTFD_TOKEN  --prefix MPTC
python3 -m arena loop                                    # go: pull → solve → submit → repeat
```
Token = CTFd site → **Settings → Access Tokens**. Watch it live: `python3 -m arena dash` → http://127.0.0.1:8012

---

## How it works

arena is a **harness** — the AI does the hacking; arena runs the loop, races solvers, critiques
failures, and submits. Two layers:

### The autonomous loop — `arena loop`
```
pull unsolved challenges ─► for each one: solve ─► submit verified flag ─► sleep ─► repeat
      (CTFd API)                  │              (stops on a wrong submit;       (until DEADLINE)
                                  │               only PREFIX{...} flags)
                                  ▼
                          solve_challenge  (below)
```

### Solving one challenge — `solve_challenge` (also `arena solve <id>`)
```
1. RECON GATE  ── one recon-only agent maps the WHOLE target (every input, param,
   │              header, endpoint, file, reflected value) and writes a RANKED list
   │              of candidate vulns → .recon.md.   ← observe before exploiting
   ▼              (this is the anti-tunnel-vision step)

2. SOLVE PASS  ── an AI solver gets: challenge + the ranked recon list (+ any critic
   │              steer). It works the highest-confidence candidate first and prints
   │              the flag. Guard hooks fire on every command (browser-camo, anti-stuck,
   │              injection/tarpit — see below).
   │
   ├─ flag?  ── yes ─►  verify it matches PREFIX{...}  ─►  done
   │   │ no
   │   ▼
   3. CRITIC  ── Opus reads the failed transcript + greps the vault, writes a short
   │            blunt steer ("you tested X wrong, try Y") ─┐
   │                                                       │
   └───────────── retry the SOLVE PASS with that steer ◄──┘   (loop up to MAXTRY)

▼
submit (auto)  or  surface for you (manual)        ── live dashboard the whole time
```

**In words:** recon **prevents** fixation (rank vectors before committing) · the solver **exploits**
best-first · the critic **corrects** on failure · the loop **repeats** until solved or `MAXTRY`. In
**crazy mode** several solvers race the same challenge in parallel and the first valid flag wins.

### Example (the "Angry Employee" web challenge)
1. **Recon** maps the API, flags a suspicious `vault_filter` field + an IDOR on `/users/<id>`.
2. **Solve pass** registers, walks the IDOR, reads the target user's hidden credential → `MPTC{...}`.
3. Flag matches `MPTC{...}` → submitted (or surfaced). Critic never needed. ~30s.

---

## Configuration (`.env`)

| key | default | meaning |
|---|---|---|
| `CTFD_URL` | — | CTFd base URL |
| `CTFD_TOKEN` / `CTFD_COOKIE` | — | auth (token preferred; cookie if tokens are off) |
| `PREFIX` | `flag` | flag format, e.g. `MPTC` → matches `MPTC{...}` |
| `PROVIDER` | `claude` | which AI: `claude` \| `codex` \| `gemini` |
| `PROVIDERS` | — | crazy mode: race different AIs, e.g. `claude,codex,gemini` |
| `RACERS` | `1` | `1` = normal (1 solver + critic) · `3` = crazy (3 parallel) |
| `SUBMIT` | `auto` | `auto` submits verified flags · `manual` just surfaces them |
| `RECON` | `1` | forced recon pass before exploiting (`0` to skip) |
| `MAXTRY` | `4` | attempts/challenge (1 solo + critic-steered retries) |
| `PER_TIMEOUT` | `800` | per-solver timeout (s) |
| `DEADLINE` | — | comp end (`2026-07-15 10:00 UTC`) → loop stops |
| `DASH_PORT` | `8012` | dashboard port |

Run `python3 -m arena setup ...` to write `.env`, or copy `.env.example`. **Never commit `.env`** — gitignored.

---

## Commands
```bash
python3 -m arena setup <url> <token> --prefix MPTC   # configure (writes .env)
python3 -m arena pull                                # download unsolved challenges
python3 -m arena solve <id>                          # solve one now
python3 -m arena loop                                # autonomous loop
python3 -m arena dash                                # live dashboard
python3 -m arena coord                               # optional: Opus steers the whole board
```
`pip install -e .` gives you the shorter `arena ...` form (optional; stdlib only, no deps).

---

## What's bundled
- **Engine** — recon gate · solver · adversarial critic · CTFd client · autonomous loop · dashboard · coordinator.
- **Pluggable AIs** (`solvers/`) — `claude` (default), `codex`, `gemini`; add one in ~6 lines.
- **CTF skills** (`skills/`) — method, web, pwn, reverse, crypto, forensics, misc, osint, malware, ai-ml,
  writeup, solve-challenge, burp-scan → installed by `./install.sh`.
- **Vault** (`vault/`) — distilled "signal → technique → command" recipes per category (flags redacted).
- **Guard hooks** (`arena/hooks/`, auto-wired, `ARENA_HOOKS=0` to disable):
  | hook | when | what it does |
  |---|---|---|
  | `request_camo` | before curl | forces a real-browser header set → beats bot fingerprinting **and** bypasses UA-gated anti-AI trap pages |
  | `content_guard` | after fetch | flags "this isn't a CTF / stop" injection (treat as untrusted) + detects token-burning tarpits → bail |
  | `loop_guard` | before cmd | blocks grinding the same command / warns on fuzzing one vector |
  | `output_guard` | before cmd | caps huge output so it can't blow the context |
  | `reflect_probe` | after fetch | reflected input → nudge to test injection |
  | `vault_nudge` | session start | grep the vault for the challenge's signal first |
- **MCP servers** (`mcp/`) — optional; `magic` + `netsession` bundled, others referenced (`mcp/README.md`).

---

## Architecture
```
arena/
  arena/
    cli.py        entry: setup / pull / solve / loop / dash / coord
    config.py     all .env knobs → Config
    client.py     CTFd: list / pull / submit  (stdlib urllib, no deps)
    racer.py      recon_pass → run_pass → solve_challenge ladder + prompt builders
    critic.py     Opus reads a failed transcript → writes a steer
    loop.py       autonomous pull → solve → submit → poll
    coord.py      optional Opus coordinator (steers a swarm via the bus)
    dashboard.py  parses logs → live Command Center UI
    solvers/      pluggable AIs: base + claude_code/codex/gemini + registry
    hooks/        the 6 guard hooks above
  skills/  vault/  mcp/  viz/        README.md  AGENTS.md  CLAUDE.md  SHARE.md  LICENSE
```

---

## Add a new AI
Drop `arena/solvers/<name>.py`:
```python
from .base import Solver

class MyAI(Solver):
    name = "myai"          # registry key (use as PROVIDER)
    cli  = "myai"          # CLI binary to check for
    def command(self, prompt, *, model, system):
        return ["myai", "run", "-p", prompt]   # argv to run it headless on `prompt`
```
Register it in `solvers/__init__.py` → `_BACKENDS`. Nothing else changes — racer/loop/critic are provider-agnostic.

---

## Safety
- **Secrets never enter git** — `.env`, `.ctfd.json`, `run/` are gitignored.
- **Anti-AI-hijack is hook-enforced**, not a prompt: every `curl` looks like a real browser (UA-gated
  trap pages never served) and injected "stop / not a CTF" text is flagged as untrusted data.
- **Submission-safe** — only `PREFIX{...}` flags, capped attempts, stops on a wrong submit.
- MCP servers are localhost-only; the kali_mcp backend runs tools as you — fine on a CTF box, don't expose it.

---

For teammates: **`SHARE.md`**. For an AI agent operating this repo: **`AGENTS.md`**. MCP setup: **`mcp/README.md`**.
