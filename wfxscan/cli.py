"""Command-line entry point."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import csv
import datetime as dt
import io
import re
import sys
import urllib.request
from pathlib import Path

from . import __version__
from .checks import RepoScan, recent_pulls
from .github import GitHub, GitHubError, api_url_for, find_token
from .iocs import IOCs
from .report import STATUS_ORDER, write_reports
from .sources import ApiSource, GitSource, git

EXIT_CLEAN, EXIT_REVIEW, EXIT_FLAGGED, EXIT_USAGE = 0, 1, 2, 64


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        log(f"error: {message}")
        sys.exit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    ap = Parser(prog="wfx-scan", description="Scan GitHub organisations or repositories for indicators of the "
                "wfx-loot CI secret-stealer campaign (November 2026).")
    t = ap.add_argument_group("targets (at least one)")
    t.add_argument("--org", action="append", default=[], metavar="OWNER",
                   help="organisation or user whose repositories to scan (repeatable)")
    t.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME", help="single repository (repeatable)")
    t.add_argument("--path", action="append", default=[], metavar="DIR",
                   help="existing local clone to scan as-is (repeatable); fetch it yourself first")
    ap.add_argument("--mode", choices=["api", "clone"], default="api",
                    help="api: read everything through the GitHub API, nothing stored locally (default). "
                         "clone: mirror-clone each repository into --workdir and read history with git")
    ap.add_argument("--since", help="start of the history window, YYYY-MM-DD (default: from the IOC set, 2026-10-01)")
    ap.add_argument("--include-archived", action="store_true", help="also scan archived repositories")
    ap.add_argument("--jobs", type=int, default=4, help="repositories scanned in parallel (default 4)")
    ap.add_argument("--out", default="reports", help="report directory (default ./reports)")
    ap.add_argument("--workdir", default="work", help="mirror clone directory for --mode clone (default ./work)")
    ap.add_argument("--github-url", default="https://github.com", help="GitHub or GitHub Enterprise Server URL")
    ap.add_argument("--gh-user", help="use the token of this gh CLI account instead of the active one")
    ap.add_argument("--max-branches", type=int, default=100, help="API mode: branches whose history is read (default 100)")
    ap.add_argument("--max-commits", type=int, default=3000, help="API mode: commits inspected per repository (default 3000)")
    ap.add_argument("--no-dataset", action="store_true", help="do not download SafeDep's affected-repositories list")
    ap.add_argument("--offline", action="store_true", help="no network access at all (only valid with --path)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def load_affected(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"wfx-loot-scanner/{__version__}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8", "replace")
        rows = csv.DictReader(io.StringIO(text))
        return {row["repository"].strip().lower(): row for row in rows if row.get("repository")}
    except Exception as e:  # noqa: BLE001
        log(f"warning: could not load SafeDep dataset ({e}); WFX-17 will be skipped")
        return None


def origin_slug(path: Path, github_url: str) -> str | None:
    rc, out, _ = git(path, "remote", "get-url", "origin")
    if rc != 0:
        return None
    host = re.sub(r"^https?://", "", github_url).rstrip("/")
    m = re.search(rf"(?:{re.escape(host)}|github\.com)[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$", out.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def mirror_sync(workdir: Path, slug: str, token: str, github_url: str) -> Path:
    """Create or update a bare mirror (all branches, tags and refs/pull/*) using the token over HTTPS."""
    dest = workdir / f"{slug}.git"
    auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{github_url.rstrip('/')}/.extraheader",
           "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}"}  # env, so the token is not on the command line
    if (dest / "HEAD").exists():
        rc, _, err = git(dest, "remote", "update", "--prune", env_extra=env)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, _, err = git(dest.parent, "clone", "--mirror", "--quiet", f"{github_url.rstrip('/')}/{slug}.git",
                         str(dest), env_extra=env)
    if rc != 0:
        raise RuntimeError(f"git {'fetch' if (dest / 'HEAD').exists() else 'clone'} failed: {err.strip()[-300:]}")
    return dest


def main(argv=None):
    a = build_parser().parse_args(argv)
    if not (a.org or a.repo or a.path):
        build_parser().error("give at least one --org, --repo or --path")
    if a.offline and (a.org or a.repo):
        build_parser().error("--offline only works with --path")

    iocs = IOCs()
    since = a.since or iocs.default_since
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
        build_parser().error("--since must be YYYY-MM-DD")
    since_iso = f"{since}T00:00:00Z"

    gh = None
    if not a.offline:
        token = find_token(a.gh_user)
        if token:
            gh = GitHub(token, api_url_for(a.github_url), log=log)
        elif a.org or a.repo:
            build_parser().error("no GitHub token: set GH_TOKEN, or log in with `gh auth login`")
        else:
            log("warning: no GitHub token found; API checks will be skipped")
    affected = None if (a.offline or a.no_dataset) else load_affected(iocs.sources["safedep_affected_csv"])

    # ------------------------------------------------------------ targets
    targets: list[tuple[str, dict | None, Path | None]] = []  # (name, repo metadata, local path)
    skipped = 0
    for owner in a.org:
        try:
            repos = gh.owner_repos(owner)
        except GitHubError as e:
            log(f"error: cannot list repositories for {owner}: {e}")
            continue
        kept = [r for r in repos if a.include_archived or not r.get("archived")]
        skipped += len(repos) - len(kept)
        log(f"{owner}: {len(repos)} repositories, {len(kept)} to scan")
        targets += [(r["full_name"], r, None) for r in kept]
    for slug in a.repo:
        try:
            targets.append((slug, gh.get(f"repos/{slug}"), None))
        except GitHubError as e:
            log(f"error: {slug}: {e}")
    for p in a.path:
        p = Path(p).expanduser().resolve()
        targets.append((origin_slug(p, a.github_url) or p.name, None, p))

    seen, uniq = set(), []
    for t in targets:
        if t[0].lower() not in seen:
            seen.add(t[0].lower())
            uniq.append(t)
    targets = uniq
    workdir = Path(a.workdir).expanduser().resolve()

    def work(t):
        name, meta, path = t
        slug = name if "/" in name else None
        src, error, pulls, pulls_error = None, "", None, ""
        api_ok = gh is not None and slug is not None
        if api_ok:
            try:
                pulls = recent_pulls(gh, slug, since_iso)
            except GitHubError as e:
                pulls_error = str(e)
        try:
            if path is not None:
                src = GitSource(path, since, iocs)
            elif a.mode == "clone":
                src = GitSource(mirror_sync(workdir, slug, gh.token, a.github_url), since, iocs)
            else:
                src = ApiSource(gh, slug, meta or {}, since, iocs, a.max_branches, a.max_commits, pulls=pulls)
        except Exception as e:  # noqa: BLE001
            error = str(e)
        scan = RepoScan(name, src, iocs, gh if api_ok else None, slug, since_iso, pulls, affected)
        scan.pulls_error = pulls_error
        res = scan.run()
        res.error = error
        res.mode = a.mode if path is None else "path"
        res.finish()
        return res

    mode_label = a.mode if (a.org or a.repo) else "path"
    log(f"Scanning {len(targets)} repositories ({mode_label} mode, window from {since}, {a.jobs} in parallel)")
    results = []
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for i, res in enumerate(ex.map(work, targets), 1):
            c = res.counts()
            log(f"[{i}/{len(targets)}] {res.name}: {res.status} "
                f"(pass {c['PASS']}, warn {c['WARN']}, fail {c['FAIL']}, skip {c['SKIP']}, error {c['ERROR']})"
                + (f" {res.error[:100]}" if res.error else ""))
            results.append(res)

    meta = {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "version": __version__, "ioc_set_version": iocs.version, "mode": a.mode,
        "targets": [f"org:{o}" for o in a.org] + [f"repo:{r}" for r in a.repo] + [f"path:{p}" for p in a.path],
        "since": since, "attack_start": iocs.attack_start.strftime("%Y-%m-%d %H:%M UTC"),
        "skipped": skipped, "skipped_reason": "archived" if skipped else "",
        "api_calls": gh.calls if gh else 0, "sources": iocs.sources,
    }
    paths = write_reports(results, Path(a.out).expanduser(), meta)

    counts = {s: sum(r.status == s for r in results) for s in STATUS_ORDER}
    print("\nwfx-loot scan summary")
    for s in STATUS_ORDER:
        print(f"  {s:<20} {counts[s]}")
    for r in results:
        if r.status not in ("CLEAN",):
            print(f"  -> {r.status:<19} {r.name}")
    print(f"\nReport: {paths['md']}\nJSON:   {paths['json']}\nCSV:    {paths['csv']}")
    if counts["LIKELY COMPROMISED"] or counts["SUSPICIOUS"]:
        sys.exit(EXIT_FLAGGED)
    sys.exit(EXIT_REVIEW if counts["REVIEW"] or counts["INCOMPLETE"] else EXIT_CLEAN)
