"""Configuration — one source of truth, loaded from a .env file + environment.

Everything the system needs is here. A teammate edits ONE file (.env) and runs `arena loop`.
No secrets in code; the CTFd token lives only in .env (gitignored).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# Defaults live here so the .env can stay tiny — most users only set url + token.
DEFAULTS = {
    "CTFD_URL": "",
    "CTFD_TOKEN": "",
    "CTFD_COOKIE": "",            # browser 'session' cookie, used when API tokens are disabled
    "PREFIX": "flag",             # flag prefix; this comp = MPTC
    "PROVIDER": "claude",        # which AI: claude | codex | gemini  (default claude)
    "PROVIDERS": "",             # crazy mode: comma list to RACE different AIs (e.g. claude,codex,gemini); empty = angles of PROVIDER
    "RACERS": "1",               # 1 = normal (single solver + critic); 3 = crazy (parallel race)
    "SUBMIT": "auto",            # auto = submit verified flags; manual = surface only, you submit
    "SKIP_OSINT": "0",           # 1 = skip the osint category
    "DEADLINE": "",              # comp end, e.g. '2026-07-15 10:00 UTC'; empty = no deadline
    "PER_TIMEOUT": "800",        # per-solver timeout (seconds)
    "MAXTRY": "4",               # attempts per challenge before giving up (1 solo + critic-steered retries)
    "RECON": "1",                # 1 = forced recon/observe pass (enumerate + rank candidate vectors) before exploiting
    "RETRIES": "3",              # CTFd network retries on 429/5xx/timeout, backoff+jitter (0 = off)
    "HTTP_TIMEOUT": "25",        # per-request timeout (seconds)
    "SKIP_STUCK": "1",           # 1 = after MAXTRY fails, mark challenge 'needs human' + stop re-grinding it (0 = keep retrying every loop)
    "POLL": "240",               # seconds between re-polling for new challenges
    "GAP": "20",                 # politeness gap between challenges
    "WORKDIR": "run",            # where challenges are pulled to
    "DASH_PORT": "8012",
}


def _load_env(env_path: Path) -> None:
    """Load KEY=VALUE lines from .env into os.environ (without overriding real env vars)."""
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


@dataclass
class Config:
    root: Path                   # the arena project root (where .env + run/ live)
    url: str
    token: str
    cookie: str
    prefix: str
    provider: str
    providers: list[str]
    racers: int
    submit: str
    skip_osint: bool
    deadline: str
    per_timeout: int
    maxtry: int
    recon: bool
    retries: int
    http_timeout: int
    skip_stuck: bool
    poll: int
    gap: int
    workdir: Path
    dash_port: int

    @property
    def flag_re(self) -> str:
        """Strict flag regex derived from the prefix, e.g. MPTC{...}. Override with FLAG_RE in env."""
        custom = os.environ.get("FLAG_RE")
        if custom:
            return custom
        return rf"(?i){re.escape(self.prefix)}\{{[A-Za-z0-9_!?@.\-]{{2,}}\}}"

    @classmethod
    def load(cls, root: Path | None = None) -> "Config":
        root = root or Path.cwd()
        _load_env(root / ".env")

        def g(key: str) -> str:
            return os.environ.get(key, DEFAULTS[key])

        return cls(
            root=root,
            url=g("CTFD_URL").rstrip("/"),
            token=g("CTFD_TOKEN"),
            cookie=g("CTFD_COOKIE"),
            prefix=g("PREFIX"),
            provider=g("PROVIDER"),
            providers=[p.strip() for p in g("PROVIDERS").split(",") if p.strip()],
            racers=int(g("RACERS")),
            submit=g("SUBMIT"),
            skip_osint=g("SKIP_OSINT") == "1",
            deadline=g("DEADLINE"),
            per_timeout=int(g("PER_TIMEOUT")),
            maxtry=int(g("MAXTRY")),
            recon=g("RECON") == "1",
            retries=int(g("RETRIES")),
            http_timeout=int(g("HTTP_TIMEOUT")),
            skip_stuck=g("SKIP_STUCK") == "1",
            poll=int(g("POLL")),
            gap=int(g("GAP")),
            workdir=root / g("WORKDIR"),
            dash_port=int(g("DASH_PORT")),
        )
