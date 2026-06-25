"""arena CLI — one entry point for the whole system.

  arena setup <url> [token]   configure the CTFd connection (writes .env)
  arena pull                  download all unsolved challenges
  arena solve <id>            solve one challenge now
  arena loop                  autonomous loop: pull -> solve -> submit -> repeat
  arena dash                  start the web dashboard
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config


def cmd_setup(args: argparse.Namespace) -> int:
    """Write a .env with the CTFd connection. Token (or --cookie) keeps the system out of the code."""
    root = Path.cwd()
    lines = [f"CTFD_URL={args.url.rstrip('/')}"]
    if args.token:
        lines.append(f"CTFD_TOKEN={args.token}")
    if args.cookie:
        lines.append(f"CTFD_COOKIE={args.cookie}")
    if args.prefix:
        lines.append(f"PREFIX={args.prefix}")
    (root / ".env").write_text("\n".join(lines) + "\n")
    (root / ".env").chmod(0o600)
    print(f"wrote {root/'.env'} (chmod 600). Edit it to tune RACERS/SUBMIT/DEADLINE/etc.")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    from .client import Client
    cfg = Config.load()
    n = Client(cfg).pull_all()
    print(f"pulled {n} unsolved challenge(s) into {cfg.workdir}")
    return 0


def cmd_solve(args: argparse.Namespace) -> int:
    from .racer import solve_one
    cfg = Config.load()
    return solve_one(cfg, args.id)


def cmd_loop(args: argparse.Namespace) -> int:
    from .loop import run_loop
    return run_loop(Config.load())


def cmd_dash(args: argparse.Namespace) -> int:
    from .dashboard import serve
    serve(Config.load())
    return 0


def cmd_coord(args: argparse.Namespace) -> int:
    from .coord import run_coord
    return run_coord(Config.load(), dry=args.dry, loop=args.loop)


def cmd_run(args: argparse.Namespace) -> int:
    from . import runner
    if args.tail:
        return runner.tail(args.tail)
    if args.stop:
        return runner.stop(args.stop)
    if args.list:
        return runner.ls()
    if not args.name or not args.rest:
        print("usage: arena run <name> <cmd...>  |  arena run --tail/--stop <name>  |  arena run --list")
        return 1
    return runner.start(args.name, args.rest, str(Path.cwd()))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="arena", description="self-driving CTF solver")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="configure the CTFd connection")
    s.add_argument("url")
    s.add_argument("token", nargs="?", default="")
    s.add_argument("--cookie", default="", help="browser session cookie (if API tokens are off)")
    s.add_argument("--prefix", default="", help="flag prefix, e.g. MPTC")
    s.set_defaults(fn=cmd_setup)

    sub.add_parser("pull", help="download all unsolved challenges").set_defaults(fn=cmd_pull)

    sv = sub.add_parser("solve", help="solve one challenge")
    sv.add_argument("id")
    sv.set_defaults(fn=cmd_solve)

    sub.add_parser("loop", help="autonomous solve loop").set_defaults(fn=cmd_loop)
    sub.add_parser("dash", help="start the web dashboard").set_defaults(fn=cmd_dash)

    co = sub.add_parser("coord", help="Opus coordinator: steer the swarm via the bus")
    co.add_argument("--dry", action="store_true", help="survey + show the prompt, no Opus call")
    co.add_argument("--loop", type=int, default=0, help="repeat every N seconds")
    co.set_defaults(fn=cmd_coord)

    rn = sub.add_parser("run", help="detached tmux runner for long exploits")
    rn.add_argument("name", nargs="?")
    rn.add_argument("rest", nargs=argparse.REMAINDER)
    rn.add_argument("--tail", help="tail a run's log")
    rn.add_argument("--stop", help="stop a run")
    rn.add_argument("--list", action="store_true", help="list runs")
    rn.set_defaults(fn=cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
