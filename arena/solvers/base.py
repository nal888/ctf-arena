"""Solver interface — the contract every AI backend implements.

Provider Strategy pattern: each AI (Claude Code, Codex, Gemini, ...) is a thin Adapter that only
says HOW to invoke its CLI; this base class owns the shared work (run it headless in the challenge
dir, stream output, pull out the flag, support first-flag-wins kill). Adding an AI = one small file.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from shutil import which


@dataclass
class SolveResult:
    provider: str
    flag: str | None
    raw: str
    returncode: int | None

    @property
    def ok(self) -> bool:
        return self.flag is not None


class Solver(ABC):
    """A pluggable AI backend. Subclasses set `name`/`cli` and implement `command()`."""

    name: str = "base"          # registry key, e.g. "claude"
    cli: str = ""               # executable to check for availability, e.g. "claude"

    @abstractmethod
    def command(self, prompt: str, *, model: str | None, system: str | None) -> list[str]:
        """Return the argv that runs this AI HEADLESS on `prompt`, with cwd = the challenge dir.

        Escape hatch: a backend may fold `system` into the prompt if its CLI has no system flag.
        """

    def available(self) -> bool:
        """True if this AI's CLI is installed."""
        return bool(self.cli) and which(self.cli) is not None

    def solve(
        self,
        prompt: str,
        cwd: str,
        flag_re: str,
        *,
        timeout: int = 800,
        model: str | None = None,
        system: str | None = None,
        stop: threading.Event | None = None,
        log_path: str | None = None,
    ) -> SolveResult:
        """Run the AI, stream its output (live to log_path if given), return on first flag / stop / timeout / exit."""
        cmd = self.command(prompt, model=model, system=system)
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, preexec_fn=os.setsid,
        )
        logf = open(log_path, "w") if log_path else None
        buf: list[str] = []
        flag: str | None = None
        start = time.time()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                buf.append(line)
                if logf:                                  # stream live so the dashboard sees progress
                    logf.write(line)
                    logf.flush()
                m = re.search(flag_re, line)
                if m:
                    flag = m.group(0)
                    break
                if (stop and stop.is_set()) or (time.time() - start > timeout):
                    break
        finally:
            if logf:
                logf.close()
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
        return SolveResult(self.name, flag, "".join(buf), proc.poll())
