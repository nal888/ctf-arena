# CLAUDE.md

This repo is **arena**, a self-driving CTF solver (a harness that drives AI solvers against a CTFd
competition).

- **How to operate it / how the code works / guardrails →** see **AGENTS.md** (read it first).
- **Overview & setup →** see **README.md**.

Critical rules:
- **Never commit `.env`, `.ctfd.json`, or `run/`** — they hold tokens/cookies/flags and are gitignored.
  This repo is public.
- Keep the core **stdlib-only**; keep the system prompt **lean** (structural fixes beat prompt prose).
- Redact real `PREFIX{...}` flags from anything you add to `vault/`.

Verify after changes:
```bash
python3 -c "from arena import cli,racer,critic,loop,coord,dashboard,client,config; print('ok')"
```
