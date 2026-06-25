"""Detached tmux runner for long / flaky / one-shot exploits.

Survives the harness reaping a backgrounded process, keeps the network, and tees to a logfile the
agent reads. Use instead of nohup/&/setsid for any long remote exploit.
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from shutil import which


def _log(name: str) -> str:
    return f"/tmp/arena_{name}.log"


def start(name: str, cmd: list[str], cwd: str) -> int:
    if not which("tmux"):
        print("tmux not installed (sudo apt install tmux)")
        return 1
    log = _log(name)
    Path(log).write_text("")
    runner = f"/tmp/arena_{name}.cmd"
    Path(runner).write_text("#!/bin/bash\ncd " + shlex.quote(cwd) + "\n" + " ".join(shlex.quote(c) for c in cmd) + "\n")
    inner = f"bash {shlex.quote(runner)} 2>&1 | tee -a {shlex.quote(log)}; echo '[arena run: exited]' >> {shlex.quote(log)}"
    subprocess.run(["tmux", "new-session", "-d", "-s", f"arena_{name}", inner])
    print(f"started arena_{name}  → log: {log}")
    print(f"  read: arena run --tail {name}   stop: arena run --stop {name}")
    return 0


def tail(name: str) -> int:
    return subprocess.run(["tail", "-n", "60", _log(name)]).returncode


def stop(name: str) -> int:
    subprocess.run(["tmux", "kill-session", "-t", f"arena_{name}"], stderr=subprocess.DEVNULL)
    print(f"stopped arena_{name}")
    return 0


def ls() -> int:
    subprocess.run("tmux ls 2>/dev/null | grep '^arena_' || echo '(no runs)'", shell=True)
    return 0
