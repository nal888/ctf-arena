"""Autonomous loop: pull → solve each unsolved challenge → submit → poll → repeat until deadline.

Submission-safe: at most `maxtry` attempts/challenge, only verified flags, and it STOPS on a wrong
submit instead of burning more attempts (CTFs limit submissions).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from .client import Client
from .config import Config
from .racer import solve_challenge


def _deadline_passed(cfg: Config) -> bool:
    if not cfg.deadline:
        return False
    try:
        s = cfg.deadline.replace("UTC", "").strip()
        dl = datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return datetime.now(timezone.utc) >= dl


def run_loop(cfg: Config) -> int:
    client = Client(cfg)
    solved = cfg.workdir / ".solved"
    solved.mkdir(parents=True, exist_ok=True)
    print(f"arena loop — provider={cfg.provider} racers={cfg.racers} submit={cfg.submit}")

    while True:
        if _deadline_passed(cfg):
            print("deadline reached — stopping.")
            return 0
        try:
            client.pull_all()
        except Exception as e:
            print(f"pull failed: {e}")

        for cidf in sorted(cfg.workdir.glob("*/*/.cid")):
            chal = cidf.parent
            cid = cidf.read_text().strip()
            if (solved / cid).exists():
                continue
            if cfg.skip_osint and "osint" in str(chal).lower():
                continue

            flag = solve_challenge(cfg, chal)            # runs the escalation ladder (attempt → critic → retry)
            if not flag:
                print(f"[{cid}] {chal.name}: no flag")
            elif cfg.submit == "manual":
                print(f"[{cid}] {chal.name} FLAG (manual, submit yourself): {flag}")
            else:
                status, msg = client.submit(cid, flag)
                print(f"[{cid}] {chal.name} {status}: {flag}  ({msg})")
                if status in ("correct", "already_solved"):
                    (solved / cid).write_text(flag)
            time.sleep(cfg.gap)

        time.sleep(cfg.poll)
