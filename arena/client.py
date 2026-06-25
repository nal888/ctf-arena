"""CTFd client — list, pull, submit. Stdlib only (urllib), no `requests` dependency.

Note: CTFd 3.8 token auth needs Content-Type: application/json on EVERY request or it silently 302s.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from .config import Config


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "challenge"


class Client:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.cfg.token:
            h["Authorization"] = f"Token {self.cfg.token}"
        elif self.cfg.cookie:
            h["Cookie"] = f"session={self.cfg.cookie}"
        return h

    def _req(self, path: str, data: dict | None = None, raw: bool = False):
        url = path if path.startswith("http") else self.cfg.url + path
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
            url, data=body, method="POST" if data is not None else "GET", headers=self._headers()
        )
        with urllib.request.urlopen(req, timeout=25) as r:
            content = r.read()
        return content if raw else json.loads(content)

    # --- reads ---
    def challenges(self) -> list[dict]:
        return self._req("/api/v1/challenges").get("data", [])

    def detail(self, cid) -> dict:
        return self._req(f"/api/v1/challenges/{cid}").get("data", {})

    def solved_ids(self) -> set[int]:
        for ep in ("/api/v1/teams/me/solves", "/api/v1/users/me/solves"):
            try:
                return {s["challenge_id"] for s in self._req(ep).get("data", [])}
            except Exception:
                continue
        return set()

    # --- pull ---
    def pull_all(self) -> int:
        solved = self.solved_ids()
        n = 0
        for ch in self.challenges():
            if ch["id"] in solved:
                continue
            self._pull_one(ch["id"], ch.get("category", "misc"), ch.get("name", str(ch["id"])))
            n += 1
        return n

    def _pull_one(self, cid, category: str, name: str) -> Path:
        d = self.detail(cid)
        folder = self.cfg.workdir / slug(category) / slug(name)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / ".cid").write_text(str(cid))
        desc = f"# {name}\n\ncategory: {category}\npoints: {d.get('value','?')}\n\n{d.get('description','')}"
        (folder / "desc.md").write_text(desc)
        if d.get("connection_info"):
            (folder / ".conn").write_text(d["connection_info"])
        for fpath in d.get("files", []):
            self._download(fpath, folder)
        return folder

    def _download(self, fpath: str, folder: Path) -> None:
        url = self.cfg.url + fpath
        if self.cfg.token and "token=" not in url:
            url += ("&" if "?" in url else "?") + f"token={self.cfg.token}"
        try:
            data = self._req(url, raw=True)
        except Exception:
            return
        fname = slug(fpath.split("/")[-1].split("?")[0]) or "file"
        # keep a sensible extension
        ext = fpath.split("/")[-1].split("?")[0]
        if "." in ext:
            fname = fname.rsplit("_", 1)[0] + "." + ext.rsplit(".", 1)[-1]
        (folder / fname).write_bytes(data)

    # --- submit ---
    def submit(self, cid, flag: str) -> tuple[str, str]:
        r = self._req("/api/v1/challenges/attempt", data={"challenge_id": int(cid), "submission": flag})
        d = r.get("data", {})
        return d.get("status", "?"), d.get("message", "")
