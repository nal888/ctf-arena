"""Solver registry — resolve an AI backend by name.

To add a new AI: write `solvers/<name>.py` with a `Solver` subclass, then add it to `_BACKENDS`.
That's the only change needed anywhere — the racer/loop are provider-agnostic.
"""
from __future__ import annotations

from .base import SolveResult, Solver
from .claude_code import ClaudeCode
from .codex import Codex
from .gemini import Gemini

_BACKENDS: dict[str, type[Solver]] = {b.name: b for b in (ClaudeCode, Codex, Gemini)}


def get_solver(name: str) -> Solver:
    try:
        return _BACKENDS[name]()
    except KeyError:
        raise ValueError(f"unknown AI '{name}'. available: {', '.join(_BACKENDS)}") from None


def registered() -> list[str]:
    """All AI names the system knows about."""
    return list(_BACKENDS)


def available() -> list[str]:
    """AI names whose CLI is actually installed on this machine."""
    return [name for name, cls in _BACKENDS.items() if cls().available()]


__all__ = ["Solver", "SolveResult", "get_solver", "registered", "available"]
