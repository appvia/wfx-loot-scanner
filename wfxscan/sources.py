"""Where repository data comes from: a local git repository or the GitHub API.

Both sources expose the same interface so every check runs the same way in either mode.
Repository data is untrusted: git is run so that repository config and attributes cannot
start programs (no textconv, external diff, signature verification, hooks or fsmonitor),
and output is parsed NUL-separated so names and messages cannot break parsing.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import urllib.parse
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .github import GitHub, GitHubError
from .iocs import IOCs, ContentIOC

TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")

# Command-line config overrides any repository config that could start a program or change output.
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "core.quotePath=false",
            "-c", "log.showSignature=false", "-c", "core.pager=cat"]
NO_DIFF_PROGRAMS = ["--no-textconv", "--no-ext-diff"]
MAX_BLOB = 20 * 1024 * 1024
NUMSTAT_RE = re.compile(r"^\n?(\d+|-)\t(\d+|-)\t(.*)$", re.S)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def child_env(extra=None) -> dict:
    """Environment for git: no GitHub tokens, no user or system git config, never prompt."""
    env = {k: v for k, v in os.environ.items() if k not in TOKEN_VARS and not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
    env.update(extra or {})
    return env


def git(repo, *args, timeout=3600, binary=False, env_extra=None, git_dir=None):
    loc = [f"--git-dir={git_dir}"] if git_dir else ["-C", str(repo)]
    p = subprocess.run(["git", *GIT_SAFE, *loc, *args], env=child_env(env_extra), capture_output=True, timeout=timeout,
                       cwd=str(git_dir) if git_dir else None)  # keep the caller's directory out of attribute lookup
    out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
    return p.returncode, out, p.stderr.decode("utf-8", "replace")


def resolve_git_dir(path: Path) -> Path:
    """The repository's own git directory. Refuses to search parent directories."""
    path = Path(path).resolve()
    dot = path / ".git"
    if dot.is_dir():
        return dot
    if dot.is_file():
        m = re.match(r"gitdir: (.+)", dot.read_text().strip())
        if m:
            return (path / m.group(1)).resolve()
    if (path / "HEAD").is_file() and (path / "objects").is_dir():
        return path  # bare repository or mirror
    raise RuntimeError(f"not a git repository (or not its top level): {path}")


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
        self.git_dir = resolve_git_dir(self.path)
        self.since = since
        self.iocs = iocs
        self.max_tips = max_tips
        self.notes: list[str] = []
        self.truncated = False
        self._commits: list[Commit] | None = None
        rc, _, err = self._git("rev-parse", "--git-dir")
        if rc != 0:
            raise RuntimeError(f"not a git repository: {err.strip()}")

    def _git(self, *args, binary=False):
        return git(self.path, *args, binary=binary, git_dir=self.git_dir)

    def _refs(self, *prefixes):
        _, out, _ = self._git("for-each-ref", "--format=%(refname)", *prefixes)
        return [r for r in out.split("\n") if r and not r.endswith("/HEAD")]

    def _log_base(self):
        return ["log", *NO_DIFF_PROGRAMS, "--no-renames", "-z", "--exclude=refs/pull/*/merge", "--all",
                f"--since={self.since}"]

    def branches(self) -> list[str]:
        names = []
        for ref in self._refs("refs/heads", "refs/remotes"):
            parts = ref.split("/")
            names.append("/".join(parts[2:]) if parts[1] == "heads" else "/".join(parts[3:]))
        return sorted(set(names))

    def commits(self) -> list[Commit]:
        if self._commits is not None:
            return self._commits
        rc, out, err = self._git(*self._log_base(), "--numstat", "--format=%H%x00%an <%ae>%x00%cI%x00%s")
        if rc != 0 and out == "" and self._refs("refs/heads", "refs/remotes", "refs/pull"):
            raise RuntimeError(f"git log failed: {err.strip()[-200:]}")
        commits, tokens, i = [], out.split("\0"), 0
        while i + 3 < len(tokens):
            sha = tokens[i].lstrip("\n")
            if not SHA_RE.match(sha):
                i += 1
                continue
            try:
                c = Commit(sha, tokens[i + 1], _parse_date(tokens[i + 2]), tokens[i + 3])
            except ValueError:
                self.notes.append(f"could not parse commit {sha[:12]}")
                self.truncated = True
                i += 4
                continue
            i += 4
            while i < len(tokens):
                m = NUMSTAT_RE.match(tokens[i])
                if not m:
                    break
                c.files.append(FileChange(m.group(3), int(m.group(1)) if m.group(1).isdigit() else 0))
                i += 1
            commits.append(c)
        self._commits = commits
        return commits

    def content_hits(self) -> list[ContentHit]:
        by_sha = {c.sha: c for c in self.commits()}
        hits = []
        for ioc in self.iocs.content:
            args = [*self._log_base(), f"-G{ioc.regex}", "--name-only", "--format=%H"]
            if ioc.paths:
                args += ["--", *[f":(glob){p}**" if p.endswith("/") else f":(glob)**/*{p}" for p in ioc.paths]]
            rc, out, err = self._git(*args)
            if rc != 0 and out == "" and err.strip():
                raise RuntimeError(f"git log -G failed for {ioc.id}: {err.strip()[-200:]}")
            sha, paths = None, []
            for tok in out.split("\0") + [None]:
                t = tok.lstrip("\n") if tok is not None else None
                if t is None or (t in by_sha and SHA_RE.match(t)):
                    if sha:
                        hits.append(ContentHit(ioc, by_sha.get(sha), sha, [p for p in paths if ioc.applies_to(p)] or paths))
                    sha, paths = t, []
                elif t:
                    paths.append(t)
        return hits

    def blob(self, commit_sha: str, path: str) -> bytes | None:
        spec = f"{commit_sha}:{path}"
        rc, size, _ = self._git("cat-file", "-s", spec)
        if rc != 0:
            return None
        if int(size.strip() or 0) > MAX_BLOB:
            self.notes.append(f"skipped {path} at {commit_sha[:12]}: larger than {MAX_BLOB // 1048576} MB")
            self.truncated = True
            return None
        rc, out, _ = self._git("cat-file", "blob", spec, binary=True)
        return out if rc == 0 else None

    def tips(self) -> list[str]:
        refs = self._refs("refs/heads", "refs/remotes")
        _, head, _ = self._git("symbolic-ref", "-q", "HEAD")
        head = head.strip()
        refs.sort(key=lambda r: (r != head, r))
        if len(refs) > self.max_tips:
            self.notes.append(f"branch tip checks limited to {self.max_tips} of {len(refs)} branches")
            self.truncated = True
        return refs[: self.max_tips]

    def tip_files(self, ref: str) -> list[str]:
        _, out, _ = self._git("ls-tree", "-r", "-z", "--name-only", ref)
        return [p for p in out.split("\0") if p]

    def read_tip(self, ref: str, path: str) -> bytes | None:
        return self.blob(ref, path)

    def commit_exists(self, sha: str) -> bool:
        return self._git("cat-file", "-e", f"{sha}^{{commit}}")[0] == 0


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
        self.truncated = False
        self._branches: list[dict] | None = None
        self._commits: list[Commit] | None = None
        self._tree: dict[str, str] | None = None

    def _branch_objs(self):
        if self._branches is None:
            self._branches = list(self.gh.paginate(f"repos/{self.slug}/branches", allow=(404, 409), max_pages=50))
            if len(self._branches) >= 5000:
                self.notes.append("branch listing stopped at 5,000 branches")
                self.truncated = True
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
            self.truncated = True
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
            self.truncated = True
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
                self.truncated = True
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
            data = self.gh.get_raw(f"repos/{self.slug}/git/blobs/{blob_sha}", max_bytes=MAX_BLOB)
        except GitHubError as e:
            if e.status == 404:
                return None
            raise  # permission and rate-limit failures must surface as ERROR, not a pass
        if data is None:
            self.notes.append(f"skipped blob {blob_sha[:12]}: larger than {MAX_BLOB // 1048576} MB")
            self.truncated = True
        return data

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
            ref = urllib.parse.quote(self.default, safe="")
            t = self.gh.get(f"repos/{self.slug}/git/trees/{ref}", {"recursive": "1"}, allow=(404, 409, 422)) or {}
            if t.get("truncated"):
                self.notes.append("repository tree is too large for one API call; tip checks are partial")
                self.truncated = True
            self._tree = {e["path"]: e["sha"] for e in t.get("tree", []) if e.get("type") == "blob"}
        return self._tree

    def tip_files(self, ref: str) -> list[str]:
        return list(self._tree_map())

    def read_tip(self, ref: str, path: str) -> bytes | None:
        sha = self._tree_map().get(path)
        return self._blob_by_sha(sha) if sha else None

    def commit_exists(self, sha: str) -> bool:
        return self.gh.get(f"repos/{self.slug}/commits/{sha}", allow=(404, 409, 422)) is not None
