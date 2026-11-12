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


def git_stream(git_dir, *args):
    """Run git and yield stdout lines as bytes, without holding the whole output in memory."""
    p = subprocess.Popen(["git", *GIT_SAFE, f"--git-dir={git_dir}", *args], env=child_env(), cwd=str(git_dir),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        yield from p.stdout
    finally:
        p.stdout.close()
        err = p.stderr.read().decode("utf-8", "replace")
        if p.wait() != 0 and err.strip():
            raise RuntimeError(f"git {args[0]} failed: {err.strip()[-200:]}")


_ESC = {b"n": b"\n", b"t": b"\t", b'"': b'"', b"\\": b"\\", b"a": b"\a", b"b": b"\b",
        b"f": b"\f", b"r": b"\r", b"v": b"\v"}


def unquote_path(raw: bytes) -> str:
    """Undo git's C-style quoting of a path in diff headers ("a/we\\"ird" -> a/we"ird)."""
    if not raw.startswith(b'"'):
        return raw.decode("utf-8", "replace")
    body, out, i = raw[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i:i + 1]
        if ch == b"\\" and i + 1 < len(body):
            nxt = body[i + 1:i + 2]
            if re.fullmatch(rb"[0-7]{3}", body[i + 1:i + 4]):
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
                continue
            out += _ESC.get(nxt, nxt)
            i += 2
            continue
        out += ch
        i += 1
    return out.decode("utf-8", "replace")


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
    read_cap = None  # local reads are cheap: read every unique file on branch tips

    def __init__(self, path: Path, since: str, iocs: IOCs, max_tips: int = 50):
        self.path = Path(path)
        self.git_dir = resolve_git_dir(self.path)
        self.since = since
        self.iocs = iocs
        self.max_tips = max_tips
        self.notes: list[str] = []
        self.truncated = False
        self._commits: list[Commit] | None = None
        self._tip_cache: dict[str, list[tuple[str, str]]] = {}
        self._tips: list[str] | None = None
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
        """Stream every diff in the window once and match changed lines in Python.

        git's own regex engine (-G) is several times slower on large histories. Added and removed
        lines both count, so reverted payloads are still found.
        """
        by_sha = {c.sha: c for c in self.commits()}
        found: dict[tuple[str, str], list[str]] = {}
        any_rx = self.iocs.content_any_b
        sha, path, in_header = None, "", False
        args = [*self._log_base(), "-p", "--format=%x00C%H"]
        args.remove("-z")
        for line in git_stream(self.git_dir, *args):
            if line.startswith(b"\x00C"):
                sha, path, in_header = line[2:].strip().decode(), "", False
            elif line.startswith(b"diff --git "):
                path, in_header = "", True
            elif in_header:
                if line.startswith(b"@@"):
                    in_header = False
                elif line.startswith((b"--- ", b"+++ ")):
                    name = line[4:].rstrip(b"\n")
                    if name.endswith(b"\t"):  # git appends a tab when the name contains a space
                        name = name[:-1]
                    if name != b"/dev/null":
                        p = unquote_path(name)
                        path = p[2:] if p[:2] in ("a/", "b/") else p
            elif sha and line[:1] in (b"+", b"-") and any_rx.search(line, 1):
                for ioc in self.iocs.content:
                    if ioc.rxb.search(line, 1) and ioc.applies_to(path):
                        paths = found.setdefault((ioc.id, sha), [])
                        if path not in paths:
                            paths.append(path)
        by_id = {i.id: i for i in self.iocs.content}
        return [ContentHit(by_id[i], by_sha.get(s), s, paths) for (i, s), paths in found.items()]

    def blob(self, commit_sha: str, path: str | None) -> bytes | None:
        spec = f"{commit_sha}:{path}" if path is not None else commit_sha
        rc, size, _ = self._git("cat-file", "-s", spec)
        if rc != 0:
            return None
        if int(size.strip() or 0) > MAX_BLOB:
            self.notes.append(f"skipped {path or 'blob'} at {commit_sha[:12]}: larger than {MAX_BLOB // 1048576} MB")
            self.truncated = True
            return None
        rc, out, _ = self._git("cat-file", "blob", spec, binary=True)
        return out if rc == 0 else None

    def tips(self) -> list[str]:
        if self._tips is None:
            self._tips = self._compute_tips()
        return self._tips

    def _compute_tips(self) -> list[str]:
        refs = self._refs("refs/heads", "refs/remotes")
        _, head, _ = self._git("symbolic-ref", "-q", "HEAD")
        head = head.strip()
        refs.sort(key=lambda r: (r != head, r))
        if len(refs) > self.max_tips:
            self.notes.append(f"branch tip checks limited to {self.max_tips} of {len(refs)} branches")
            self.truncated = True
        return refs[: self.max_tips]

    def tip_entries(self, ref: str) -> list[tuple[str, str]]:
        """(path, blob sha) for every file on a branch tip. Cached: several checks walk the same tips."""
        if ref not in self._tip_cache:
            _, out, _ = self._git("ls-tree", "-r", "-z", "--full-tree", ref)
            entries = []
            for rec in out.split("\0"):
                meta, _, path = rec.partition("\t")
                parts = meta.split(" ")
                if path and len(parts) == 3 and parts[1] == "blob":
                    entries.append((path, parts[2]))
            self._tip_cache[ref] = entries
        return self._tip_cache[ref]

    def tip_files(self, ref: str) -> list[str]:
        return [p for p, _ in self.tip_entries(ref)]

    def read_blob(self, blob_sha: str) -> bytes | None:
        return self.blob(blob_sha, None)

    def read_blobs(self, shas: list[str]) -> dict[str, bytes]:
        """Read many blobs in one `git cat-file --batch` process. Oversized blobs are skipped."""
        shas = [x for x in dict.fromkeys(shas) if SHA_RE.match(x)]
        if not shas:
            return {}
        p = subprocess.run(["git", *GIT_SAFE, f"--git-dir={self.git_dir}", "cat-file", "--batch"],
                           input=("\n".join(shas) + "\n").encode(), env=child_env(), cwd=str(self.git_dir),
                           capture_output=True, timeout=3600)
        out, data, i = {}, p.stdout, 0
        while i < len(data):
            nl = data.index(b"\n", i)
            head = data[i:nl].split(b" ")
            i = nl + 1
            if len(head) != 3:  # "<sha> missing"
                continue
            sha, size = head[0].decode(), int(head[2])
            if size <= MAX_BLOB:
                out[sha] = data[i:i + size]
            else:
                self.notes.append(f"skipped blob {sha[:12]}: larger than {MAX_BLOB // 1048576} MB")
                self.truncated = True
            i += size + 1
        return out

    def existed_before(self, commit: Commit, f: FileChange) -> bool:
        """Did this path exist in the commit's first parent (i.e. was an existing file changed)?"""
        return self._git("cat-file", "-e", f"{commit.sha}^:{f.path}")[0] == 0

    def read_tip(self, ref: str, path: str) -> bytes | None:
        return self.blob(ref, path)

    def commit_exists(self, sha: str) -> bool:
        return self._git("cat-file", "-e", f"{sha}^{{commit}}")[0] == 0


# ============================================================================ API
class ApiSource:
    mode = "api"
    read_cap = 200  # every read is an API call

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
        if len(self._branch_objs()) > 1 and "branch tip checks cover the default branch only in API mode" not in self.notes:
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

    def tip_entries(self, ref: str) -> list[tuple[str, str]]:
        return list(self._tree_map().items())

    def tip_files(self, ref: str) -> list[str]:
        return list(self._tree_map())

    def read_blob(self, blob_sha: str) -> bytes | None:
        return self._blob_by_sha(blob_sha)

    def read_blobs(self, shas: list[str]) -> dict[str, bytes]:
        return {sha: data for sha in dict.fromkeys(shas) if (data := self._blob_by_sha(sha)) is not None}

    @staticmethod
    def existed_before(commit: Commit, f: FileChange) -> bool:
        return f.status in ("modified", "changed")

    def read_tip(self, ref: str, path: str) -> bytes | None:
        sha = self._tree_map().get(path)
        return self._blob_by_sha(sha) if sha else None

    def commit_exists(self, sha: str) -> bool:
        return self.gh.get(f"repos/{self.slug}/commits/{sha}", allow=(404, 409, 422)) is not None
