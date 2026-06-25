"""Google Gemini CLI backend. Headless via `gemini -y -p <prompt>` (verified against gemini-cli).

Requires the `gemini` CLI to be authenticated first (Google login, or set GEMINI_API_KEY / a
project id) — otherwise it exits with a setup/project error before doing any work.
"""
from __future__ import annotations

from .base import Solver


class Gemini(Solver):
    name = "gemini"
    cli = "gemini"

    def command(self, prompt: str, *, model: str | None, system: str | None) -> list[str]:
        full = f"{system}\n\n{prompt}" if system else prompt
        cmd = ["gemini", "-y", "-p", full]           # -y = auto-approve tools, -p = prompt (headless)
        if model:
            cmd[1:1] = ["-m", model]
        return cmd
