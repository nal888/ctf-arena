"""OpenAI Codex CLI backend. Headless via `codex exec` (verified against the codex CLI; -m sets the model).

Requires the `codex` CLI to be logged in. End-to-end tested through arena's solver path.
"""
from __future__ import annotations

from .base import Solver


class Codex(Solver):
    name = "codex"
    cli = "codex"

    def command(self, prompt: str, *, model: str | None, system: str | None) -> list[str]:
        # codex has no separate system flag → fold the angle into the prompt (escape hatch).
        full = f"{system}\n\n{prompt}" if system else prompt
        cmd = ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", full]
        if model:
            cmd[2:2] = ["-m", model]
        return cmd
