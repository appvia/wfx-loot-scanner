"""Minimal GitHub REST client (standard library only)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, path: str = ""):
        super().__init__(f"HTTP {status} {path}: {message}")
        self.status = status
        self.path = path


def find_token(gh_user: str | None = None) -> str | None:
    """GH_TOKEN, then GITHUB_TOKEN, then the gh CLI (optionally a specific account)."""
    if not gh_user:
        for var in ("GH_TOKEN", "GITHUB_TOKEN"):
            if os.environ.get(var):
                return os.environ[var].strip()
    if shutil.which("gh"):
        cmd = ["gh", "auth", "token"] + (["-u", gh_user] if gh_user else [])
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    return None


def api_url_for(github_url: str) -> str:
    host = urllib.parse.urlparse(github_url).netloc
    return "https://api.github.com" if host in ("github.com", "www.github.com") else f"{github_url.rstrip('/')}/api/v3"


class GitHub:
    def __init__(self, token: str, api_url: str = "https://api.github.com", log=None):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.calls = 0
        self._lock = threading.Lock()
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))

    # ------------------------------------------------------------------ core
    def _request(self, url: str, accept: str = "application/vnd.github+json"):
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"wfx-loot-scanner/{__version__}",
        })
        for attempt in range(6):
            with self._lock:
                self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, dict(r.headers), r.read()
            except urllib.error.HTTPError as e:
                body = e.read()
                headers = dict(e.headers or {})
                wait = self._rate_limit_wait(e.code, headers, body)
                if wait is not None and attempt < 5:
                    self.log(f"  rate limited, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if e.code >= 500 and attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                return e.code, headers, body
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError(0, str(e), url) from e
        raise GitHubError(0, "retries exhausted", url)

    @staticmethod
    def _rate_limit_wait(status, headers, body):
        if status not in (403, 429):
            return None
        h = {k.lower(): v for k, v in headers.items()}
        if "retry-after" in h:
            return min(int(h["retry-after"]) + 1, 900)
        if h.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in h:
            return max(1, min(int(h["x-ratelimit-reset"]) - int(time.time()) + 2, 3600))
        if b"secondary rate limit" in body.lower():
            return 60
        return None

    def _url(self, path: str, params: dict | None = None) -> str:
        url = path if path.startswith("http") else f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def get(self, path: str, params: dict | None = None, allow: tuple[int, ...] = ()):
        """GET returning parsed JSON. Statuses in `allow` return None instead of raising."""
        status, _, body = self._request(self._url(path, params))
        if status in allow:
            return None
        if status >= 400:
            raise GitHubError(status, _message(body), path)
        return json.loads(body) if body else None

    def get_raw(self, path: str) -> bytes:
        status, _, body = self._request(self._url(path), accept="application/vnd.github.raw+json")
        if status >= 400:
            raise GitHubError(status, _message(body), path)
        return body

    def paginate(self, path: str, params: dict | None = None, key: str | None = None,
                 stop=None, max_pages: int | None = None, allow: tuple[int, ...] = ()):
        """Yield items across pages. `stop(item)` returning True ends iteration."""
        params = {"per_page": 100, **(params or {})}
        url = self._url(path, params)
        pages = 0
        while url:
            status, headers, body = self._request(url)
            if status in allow:
                return
            if status >= 400:
                raise GitHubError(status, _message(body), path)
            data = json.loads(body) if body else []
            items = data.get(key, []) if key else data
            for it in items:
                if stop and stop(it):
                    return
                yield it
            pages += 1
            if max_pages and pages >= max_pages:
                return
            url = _next_link({k.lower(): v for k, v in headers.items()}.get("link", ""))

    # ------------------------------------------------------------------ helpers
    def owner_repos(self, owner: str) -> list[dict]:
        try:
            return list(self.paginate(f"orgs/{owner}/repos", {"type": "all"}))
        except GitHubError as e:
            if e.status != 404:
                raise
        return list(self.paginate(f"users/{owner}/repos", {"type": "owner"}))


def _next_link(link: str) -> str | None:
    m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
    return m.group(1) if m else None


def _message(body: bytes) -> str:
    try:
        return json.loads(body).get("message", "")[:300]
    except ValueError:
        return body[:300].decode("utf-8", "replace")
