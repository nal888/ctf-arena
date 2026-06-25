"""Claude Code backend — the default. Runs `claude -p` headless on a Claude subscription (no API key)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .base import Solver

_HOOKS = Path(__file__).resolve().parents[1] / "hooks"   # arena/arena/hooks (bundled with the package)


def _hook_settings() -> str | None:
    """Wire the bundled guard hooks portably via a --settings JSON string (abs paths, any machine).

    loop_guard (anti-stuck), output_guard (big-output truncation), reflect_probe (reflected-input
    nudge). Set ARENA_HOOKS=0 to disable. `claude --settings` MERGES this with the user's own settings.
    """
    if os.environ.get("ARENA_HOOKS", "1") == "0" or not _HOOKS.is_dir():
        return None

    def c(name: str) -> dict:
        return {"type": "command", "command": f"python3 {_HOOKS / name}"}

    return json.dumps({"hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [
            c("request_camo.py"), c("loop_guard.py"), c("output_guard.py")]}],
        "PostToolUse": [{"matcher": "Bash", "hooks": [
            c("reflect_probe.py"), c("content_guard.py")]}],
        "SessionStart": [{"hooks": [c("vault_nudge.py")]}],   # nudge the solver to grep the bundled vault
    }})


class ClaudeCode(Solver):
    name = "claude"
    cli = "claude"

    def command(self, prompt: str, *, model: str | None, system: str | None) -> list[str]:
        cmd = [
            "claude", "-p", prompt,
            "--model", model or "sonnet",
            "--dangerously-skip-permissions",
            "--output-format", "stream-json", "--verbose",
        ]
        hooks = _hook_settings()
        if hooks:
            cmd += ["--settings", hooks]
        if system:                                   # per-racer "angle" goes in the system prompt
            cmd[5:5] = ["--append-system-prompt", system]
        return cmd
