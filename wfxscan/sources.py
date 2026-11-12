"""Where repository data comes from: a local git repository or the GitHub API.

Both sources expose the same interface so every check runs the same way in either mode.
Neither source executes repository content.
"""
from __future__ import annotations

import datetime as dt
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .github import GitHub, GitHubError
from .iocs import IOCs, ContentIOC

# Isolate git from user/system config (URL rewrites, fsmonitor, textconv etc.).
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "safe.directory=*"]


def git(repo, *args, timeout=3600, binary=False, env_extra=None):
    p = subprocess.run(["git", *GIT_SAFE, "-C", str(repo), *args],
                       env={**GIT_ENV, **(env_extra or {})}, capture_output=True, timeout=timeout)
    out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
    return p.returncode, out, p.stderr.decode("utf-8", "replace")


@dataclass
class FileChange:
    path: str
    additions: int
    status: str = "modified"
    blob_sha: str | None = None
    patch: str | None = None  # API mode only


@dataclass
class Commit:
    sha: str
    author: str
    date: dt.datetime
    subject: str
    login: str | None = None
    files: list[FileChange] = field(default_factory=list)

    def ctx(self) -> str:
        who = f"@{self.login}" if self.login else self.author
        return f"{self.sha[:12]} {self.date.strftime('%Y-%m-%d %H:%M')}Z {who} \"{self.subject}\""


@dataclass
class ContentHit:
    ioc: ContentIOC
    commit: Commit | None
    sha: str
    paths: list[str]


def _parse_date(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


# ============================================================================ git
class GitSource:
    mode = "git"

    def __init__(self, path: Path, since: str, iocs: IOCs, max_tips: int = 50):
        self.path = Path(path)
        self.since = since
        self.iocs = iocs
        self.max_tips = max_tips
        self.notes: list[str] = []
        self._commits: list[Commit] | None = None
        rc, _, err = git(self.path, "rev-parse", "--git-dir")
        if rc != 0:
            raise RuntimeError(f"not a git repository: {err.strip()}")

    def _refs(self, *prefixes):
        _, out, _ = git(self.path, "for-each-ref", "--format=%(refname)", *prefixes)
        return [r for r in out.splitlines() if r and not r.endswith("/HEAD")]

    def _log_base(self):
        return ["log", "--exclude=refs/pull/*/merge", "--all", f"--since={self.since}"]

    def branches(self) -> list[str]:
        names = []
        for ref in self._refs("refs/heads", "refs/remotes"):
            parts = ref.split("/")
            names.append("/".join(parts[2:]) if parts[1] == "heads" else "/".join(parts[3:]))
        return sorted(set(names))

    def commits(self) -> list[Commit]:
        if self._commits is not None:
            return self._commits
        rc, out, err = git(self.path, *self._log_base(), "--no-renames", "--numstat",
                           "--format=%x1e%H%x1f%an <%ae>%x1f%cI%x1f%s")
        if rc != 0 and "does not have any commits" not in err and out == "":
            if self._refs("refs/heads", "refs/remotes", "refs/pull"):
                raise RuntimeError(f"git log failed: {err.strip()[-200:]}")
        commits = []
        for chunk in out.split("\x1e")[1:]:
            lines = chunk.strip("\n").split("\n")
            try:
                sha, author, cdate, subject = lines[0].split("\x1f", 3)
            except ValueError:
                continue
            c = Commit(sha, author, _parse_date(cdate), subject)
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) == 3:
                    c.files.append(FileChange(parts[2], int(parts[0]) if parts[0].isdigit() else 0))
            commits.append(c)
        self._commits = commits
        return commits

    def content_hits(self) -> list[ContentHit]:
        by_sha = {c.sha: c for c in self.commits()}
        hits = []
        for ioc in self.iocs.content:
            args = [*self._log_base(), "--no-renames", f"-G{ioc.regex}", "--name-only", "--format=%x1e%H"]
            if ioc.paths:
                args += ["--", *[f":(glob){p}**" if p.endswith("/") else f":(glob)**/*{p}" for p in ioc.paths]]
            rc, out, err = git(self.path, *args)
            if rc != 0 and out == "" and err.strip():
                raise RuntimeError(f"git log -G failed for {ioc.id}: {err.strip()[-200:]}")
            for chunk in out.split("\x1e")[1:]:
                lines = [ln for ln in chunk.strip("\n").split("\n") if ln]
                if not lines:
                    continue
                sha = lines[0].strip()
                paths = [p for p in lines[1:] if ioc.applies_to(p)] or lines[1:]
                hits.append(ContentHit(ioc, by_sha.get(sha), sha, paths))
        return hits

    def blob(self, commit_sha: str, path: str) -> bytes | None:
        rc, out, _ = git(self.path, "cat-file", "blob", f"{commit_sha}:{path}", binary=True)
        return out if rc == 0 else None

    def tips(self) -> list[str]:
        refs = self._refs("refs/heads", "refs/remotes")
        _, head, _ = git(self.path, "symbolic-ref", "-q", "HEAD")
        head = head.strip()
        refs.sort(key=lambda r: (r != head, r))
        if len(refs) > self.max_tips:
            self.notes.append(f"branch tip checks limited to {self.max_tips} of {len(refs)} branches")
        return refs[: self.max_tips]

    def tip_files(self, ref: str) -> list[str]:
        _, out, _ = git(self.path, "ls-tree", "-r", "--name-only", ref)
        return out.splitlines()

    def read_tip(self, ref: str, path: str) -> bytes | None:
        return self.blob(ref, path)

    def commit_exists(self, sha: str) -> bool:
        return git(self.path, "cat-file", "-e", f"{sha}^{{commit}}")[0] == 0


# ============================================================================ API
class ApiSource:
    mode = "api"

    def __init__(self, gh: GitHub, slug: str, meta: dict, since: str, iocs: IOCs,
                 max_branches: int = 100, max_commits: int = 3000, pulls: list[dict] | None = None):
        self.gh = gh
        self.slug = slug
        self.meta = meta
        self.default = meta.get("default_branch") or "main"
        self.since = since
        self.since_dt = _parse_date(since if "T" in since else f"{since}T00:00:00Z")
        self.iocs = iocs
        self.max_branches = max_branches
        self.max_commits = max_commits
        self.pulls = pulls or []
        self.notes: list[str] = []
        self._branches: list[dict] | None = None
        self._commits: list[Commit] | None = None
        self._tree: dict[str, str] | None = None

    def _branch_objs(self):
        if self._branches is None:
            self._branches = list(self.gh.paginate(f"repos/{self.slug}/branches", allow=(404, 409)))
        return self._branches

    def branches(self) -> list[str]:
        return sorted(b["name"] for b in self._branch_objs())

    def _list_shas(self) -> list[str]:
        names = [b["name"] for b in self._branch_objs()]
        suspicious = [n for n in names if self.iocs.branch_match(n)]
        order = [self.default] + suspicious + [n for n in names if n != self.default and n not in suspicious]
        order = list(dict.fromkeys(order))
        if len(order) > self.max_branches:
            self.notes.append(f"commit history read from {self.max_branches} of {len(order)} branches")
            order = order[: self.max_branches]
        shas: dict[str, None] = {}
        for name in order:
            for c in self.gh.paginate(f"repos/{self.slug}/commits", {"sha": name, "since": self.since_dt.isoformat()},
                                      allow=(404, 409)):
                shas.setdefault(c["sha"])
            if len(shas) >= self.max_commits:
                break
        # Commits on pull requests survive deletion of the head branch.
        for pr in self.pulls:
            for c in self.gh.paginate(f"repos/{self.slug}/pulls/{pr['number']}/commits", allow=(404,), max_pages=3):
                d = (c.get("commit") or {}).get("committer", {}).get("date")
                if d and _parse_date(d) >= self.since_dt:
                    shas.setdefault(c["sha"])
        out = list(shas)
        if len(out) > self.max_commits:
            self.notes.append(f"commit details limited to {self.max_commits} of {len(out)} commits")
            out = out[: self.max_commits]
        return out

    def commits(self) -> list[Commit]:
        if self._commits is not None:
            return self._commits
        commits = []
        for sha in self._list_shas():
            d = self.gh.get(f"repos/{self.slug}/commits/{sha}", allow=(404, 422))
            if not d:
                continue
            cm = d.get("commit", {})
            a = cm.get("author") or {}
            c = Commit(sha, f"{a.get('name', '')} <{a.get('email', '')}>",
                       _parse_date(cm.get("committer", {}).get("date") or a.get("date")),
                       (cm.get("message") or "").split("\n", 1)[0],
                       login=(d.get("author") or {}).get("login"))
            for f in d.get("files") or []:
                c.files.append(FileChange(f["filename"], int(f.get("additions") or 0), f.get("status", ""),
                                          f.get("sha"), f.get("patch")))
            if len(d.get("files") or []) >= 300:
                self.notes.append(f"{sha[:12]} changes 300+ files; only the first 300 were inspected")
            commits.append(c)
        self._commits = commits
        return commits

    def content_hits(self) -> list[ContentHit]:
        hits = []
        for c in self.commits():
            for f in c.files:
                if f.patch is not None:
                    text = "\n".join(ln[1:] for ln in f.patch.split("\n")
                                     if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
                elif self._worth_fetching(f.path):
                    raw = self.blob(c.sha, f.path) if f.status != "removed" else None
                    text = raw.decode("utf-8", "replace") if raw else ""
                else:
                    continue
                for ioc in self.iocs.content:
                    if ioc.applies_to(f.path) and ioc.rx.search(text):
                        hits.append(ContentHit(ioc, c, c.sha, [f.path]))
        return hits

    def _worth_fetching(self, path: str) -> bool:
        return (path.startswith(".github/") or path.endswith(("package.json", ".sh", "tasks.json"))
                or self.iocs.payload_path_match(path) is not None)

    def _blob_by_sha(self, blob_sha: str) -> bytes | None:
        try:
            return self.gh.get_raw(f"repos/{self.slug}/git/blobs/{blob_sha}")
        except GitHubError:
            return None

    def blob(self, commit_sha: str, path: str) -> bytes | None:
        for c in self.commits():
            if c.sha == commit_sha:
                for f in c.files:
                    if f.path == path and f.blob_sha:
                        return self._blob_by_sha(f.blob_sha)
        return None

    def tips(self) -> list[str]:
        if len(self._branch_objs()) > 1:
            self.notes.append("branch tip checks cover the default branch only in API mode")
        return [self.default] if self._branch_objs() else []

    def _tree_map(self) -> dict[str, str]:
        if self._tree is None:
            t = self.gh.get(f"repos/{self.slug}/git/trees/{self.default}", {"recursive": "1"}, allow=(404, 409, 422)) or {}
            if t.get("truncated"):
                self.notes.append("repository tree is too large for one API call; tip checks are partial")
            self._tree = {e["path"]: e["sha"] for e in t.get("tree", []) if e.get("type") == "blob"}
        return self._tree

    def tip_files(self, ref: str) -> list[str]:
        return list(self._tree_map())

    def read_tip(self, ref: str, path: str) -> bytes | None:
        sha = self._tree_map().get(path)
        return self._blob_by_sha(sha) if sha else None

    def commit_exists(self, sha: str) -> bool:
        return self.gh.get(f"repos/{self.slug}/commits/{sha}", allow=(404, 409, 422)) is not None
