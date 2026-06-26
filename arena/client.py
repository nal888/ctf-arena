"""CTFd client — list, pull, submit. Stdlib only (urllib), no `requests` dependency.

Note: CTFd 3.8 token auth needs Content-Type: application/json on EVERY request or it silently 302s.
"""
from __future__ import annotations

import json
import random
import re
import time
import urllib.error
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

    RETRY_CODES = {408, 429, 500, 502, 503, 504}

    def _req(self, path: str, data: dict | None = None, raw: bool = False):
        url = path if path.startswith("http") else self.cfg.url + path
        body = json.dumps(data).encode() if data is not None else None
        timeout = getattr(self.cfg, "http_timeout", 25)
        retries = getattr(self.cfg, "retries", 0)
        last: Exception | None = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(
                url, data=body, method="POST" if data is not None else "GET", headers=self._headers()
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    content = r.read()
                return content if raw else json.loads(content)
            except urllib.error.HTTPError as e:
                last = e
                if e.code not in self.RETRY_CODES or attempt >= retries:
                    raise
                ra = e.headers.get("Retry-After") if e.headers else None       # honor 429 Retry-After
                wait = float(ra) if (ra and ra.isdigit()) else 0.0
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
                if attempt >= retries:
                    raise
                wait = 0.0
            time.sleep(min(wait or (0.5 * (2 ** attempt) + random.uniform(0, 0.5)), 30))   # backoff + jitter
        raise last                                                              # exhausted

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
        conn = d.get("connection_info") or self._resolve_instance(cid, d.get("description") or "")
        if conn:
            (folder / ".conn").write_text(conn)
        for fpath in d.get("files", []):
            self._download(fpath, folder)
        return folder

    def _resolve_instance(self, cid, description: str) -> str:
        """Some CTFs hand the live target via `curl https://HOST/<id> -H 'Authorization: TOKEN'` in the
        description (no connection_info; the id/token are filled in by the browser). Resolve it here with
        the real challenge id + token so `.conn` holds a ready target the solver can hit directly."""
        m = re.search(r"""curl\s+https?://([^/\s"'<]+)/""", description)
        if not m or not self.cfg.token:
            return ""
        host = m.group(1)
        req = urllib.request.Request(
            f"https://{host}/{cid}",
            headers={"Authorization": self.cfg.token, "User-Agent": "Mozilla/5.0"},   # instance endpoint wants the raw token
        )
        try:
            with urllib.request.urlopen(req, timeout=getattr(self.cfg, "http_timeout", 25)) as r:
                body = r.read().decode("utf-8", "ignore")
        except Exception:
            return ""
        u = re.search(r"""https?://[^\s"'<)]+""", body)         # the live challenge URL in the response
        return u.group(0) if u else ""

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
