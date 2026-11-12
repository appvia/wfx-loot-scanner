"""Regression tests for the security audit findings. Repositories under scan are untrusted input."""
import contextlib
import csv
import io
import os
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from tests.fixtures import sh, write, commit
from wfxscan import cli, github, report, sources
from wfxscan.checks import CheckResult, Hit, RepoResult, RepoScan
from wfxscan.github import GitHubError
from wfxscan.iocs import IOCs
from wfxscan.sources import ApiSource, GitSource

SINCE, SINCE_ISO = "2026-10-01", "2026-10-01T00:00:00Z"


def statuses(result):
    return {c.id: c.status for c in result.checks}


def git_scan(path):
    iocs = IOCs()
    return RepoScan(Path(path).name, GitSource(path, SINCE, iocs), iocs, None, None, SINCE_ISO, None, None).run()


class TestRepositoryCannotRunCode(unittest.TestCase):
    def _hostile_repo(self, root: Path, marker: Path, bare: bool) -> Path:
        repo = root / "r"
        repo.mkdir()
        sh(repo, "init", "-q", "-b", "main")
        write(repo, "a.txt", "one\n")
        commit(repo, "init", "2026-11-11T10:00:00Z")
        write(repo, "a.txt", "two\n")
        commit(repo, "change", "2026-11-11T11:00:00Z")
        if bare:
            subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(root / "b.git")], check=True)
            repo = root / "b.git"
            gd = repo
        else:
            gd = repo / ".git"
        # info/attributes is always honoured, whatever the work tree.
        (gd / "info").mkdir(exist_ok=True)
        (gd / "info" / "attributes").write_text("* diff=evil\n")
        for k, v in (("diff.evil.textconv", f"sh -c 'touch {marker}; cat \"$0\"'"),
                     ("diff.evil.command", f"sh -c 'touch {marker}'"),
                     ("diff.external", f"sh -c 'touch {marker}'"),
                     ("log.showSignature", "true"),
                     ("gpg.program", f"sh -c 'touch {marker}'")):
            subprocess.run(["git", f"--git-dir={gd}", "config", k, v], check=True)
        return repo

    def test_repository_config_cannot_run_programs(self):
        for bare in (False, True):
            with self.subTest(bare=bare), tempfile.TemporaryDirectory() as d:
                marker = Path(d) / "PWNED"
                repo = self._hostile_repo(Path(d), marker, bare)
                # sanity: plain git would run the textconv driver
                subprocess.run(["git", "-C", str(repo), "log", "-p", "-Gtwo", "--all"], capture_output=True)
                self.assertTrue(marker.exists(), "fixture does not trigger textconv")
                marker.unlink()
                git_scan(repo)
                self.assertFalse(marker.exists(), "repository config caused a command to run")

    def test_path_inside_another_repo_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            outer = Path(d) / "outer"
            (outer / "sub").mkdir(parents=True)
            sh(outer, "init", "-q")
            with self.assertRaises(RuntimeError):
                GitSource(outer / "sub", SINCE, IOCs())

    def test_token_not_passed_to_git(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret", "GITHUB_TOKEN": "secret"}):
            env = sources.child_env()
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)


class TestHostileGitData(unittest.TestCase):
    def test_quoted_and_non_ascii_paths_are_detected(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "r"
            repo.mkdir()
            sh(repo, "init", "-q", "-b", "main")
            write(repo, "é/.ci-abc123.sh", "x\n")
            write(repo, 'q"t/.ci-def456.sh', "x\n")
            commit(repo, "add", "2026-11-11T10:00:00Z")
            r = git_scan(repo)
            wfx04 = next(c for c in r.checks if c.id == "WFX-04")
            self.assertEqual(wfx04.status, "FAIL")
            self.assertEqual(len(wfx04.hits), 2, wfx04.hits)

    def test_separator_bytes_in_subject_do_not_break_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "r"
            repo.mkdir()
            sh(repo, "init", "-q", "-b", "main")
            write(repo, ".ci-abc123.sh", "x\n")
            commit(repo, "a\x1eb\x1fc\x01d", "2026-11-11T10:00:00Z")
            write(repo, ".github/workflows/x.yml", "WF_CALLBACK: 1\n")
            commit(repo, "ci: refresh build cache", "2026-11-11T11:00:00Z")
            s = statuses(git_scan(repo))
            for cid in ("WFX-03", "WFX-04", "WFX-07"):
                self.assertEqual(s[cid], "FAIL", cid)
            self.assertNotIn("ERROR", s.values())


class TestReportEscaping(unittest.TestCase):
    def hostile_result(self):
        r = RepoResult("acme/<img src=x onerror=alert(1)>")
        c = CheckResult("WFX-04", "Payload files in history", summary="x | y")
        c.hits.append(Hit("CRITICAL", "'<script>alert(1)</script>/.ci-abc123.sh'",
                          "abc `x` [Rotate tokens here](https://evil.example/login)\n## Fake heading"))
        c.status = "FAIL"
        r.checks.append(c)
        r.notes.append("<b>note</b>")
        r.finish()
        return r

    def test_markdown_is_escaped(self):
        md = report._markdown([self.hostile_result()], {
            "generated": "now", "version": "t", "ioc_set_version": "t", "mode": "api", "targets": ["org:x"],
            "since": SINCE, "attack_start": "x", "skipped": 0, "skipped_reason": "", "api_calls": 0, "sources": {}})
        for bad in ("<img", "<script", "<b>", "](https://evil", "\n## Fake heading"):
            self.assertNotIn(bad, md)

    def test_csv_formula_cells_are_neutralised(self):
        self.assertEqual(report._csv_cell("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        self.assertEqual(report._csv_cell("+1"), "'+1")
        self.assertEqual(report._csv_cell("ok"), "ok")
        with tempfile.TemporaryDirectory() as d:
            r = RepoResult("=cmd|' /C calc'!A0")
            r.checks.append(CheckResult("WFX-01", "t", status="PASS"))
            paths = report.write_reports([r], Path(d), {
                "generated": "now", "version": "t", "ioc_set_version": "t", "mode": "api", "targets": [],
                "since": SINCE, "attack_start": "x", "api_calls": 0, "sources": {}})
            rows = list(csv.reader(io.StringIO(paths["csv"].read_text())))
            self.assertTrue(rows[1][0].startswith("'="))


class TestTokenStaysOnGitHub(unittest.TestCase):
    def test_authorization_dropped_on_cross_host_redirect(self):
        h = github.SameHostRedirectHandler()
        req = urllib.request.Request("https://api.github.com/x", headers={"Authorization": "Bearer t"})
        new = h.redirect_request(req, None, 302, "Found", {}, "https://evil.example/y")
        self.assertIsNone(new.get_header("Authorization"))
        same = h.redirect_request(req, None, 302, "Found", {}, "https://api.github.com/z")
        self.assertEqual(same.get_header("Authorization"), "Bearer t")

    def test_pagination_link_to_other_host_is_ignored(self):
        gh = github.GitHub("t", "https://api.github.com")
        self.assertIsNone(gh._safe_next('<https://evil.example/p?page=2>; rel="next"'))
        self.assertEqual(gh._safe_next('<https://api.github.com/p?page=2>; rel="next"'), "https://api.github.com/p?page=2")

    def test_plain_http_github_url_refused(self):
        with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()) as err:
            cli.main(["--org", "x", "--github-url", "http://ghes.example"])
        self.assertIn("must be an https:// URL", err.getvalue())
        self.assertEqual(e.exception.code, cli.EXIT_USAGE)


class FailingGitHub:
    token, calls = "t", 0

    def __init__(self, status):
        self.status = status
        self.requested = []

    def paginate(self, path, params=None, key=None, stop=None, max_pages=None, allow=()):
        self.requested.append(path)
        if path.endswith("/branches"):
            return iter([{"name": "a#b"}])
        if "/actions/" in path:
            raise GitHubError(self.status, "Resource not accessible", path)
        return iter([])

    def get(self, path, params=None, allow=()):
        self.requested.append(path)
        if "/actions/" in path:
            raise GitHubError(self.status, "Resource not accessible", path)
        return None

    def get_raw(self, path):
        raise GitHubError(self.status, "denied", path)


class TestFailuresAreNotClean(unittest.TestCase):
    def scan(self, status):
        iocs, gh = IOCs(), FailingGitHub(status)
        src = ApiSource(gh, "acme/w", {"default_branch": "a#b"}, SINCE, iocs, pulls=[])
        return RepoScan("acme/w", src, iocs, gh, "acme/w", SINCE_ISO, [], {}).run(), gh

    def test_permission_denied_is_incomplete(self):
        r, _ = self.scan(403)
        self.assertEqual(statuses(r)["WFX-13"], "ERROR")
        self.assertEqual(r.status, "INCOMPLETE")

    def test_branch_names_are_url_encoded(self):
        _, gh = self.scan(404)
        self.assertIn("repos/acme/w/git/trees/a%23b", gh.requested)

    def test_unlistable_org_is_incomplete_and_non_zero(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(cli, "find_token", return_value="t"), \
                mock.patch.object(cli.GitHub, "owner_repos", side_effect=GitHubError(403, "SAML", "orgs/x/repos")):
            with self.assertRaises(SystemExit) as e, contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                cli.main(["--org", "x", "--no-dataset", "--out", d])
            self.assertEqual(e.exception.code, cli.EXIT_REVIEW)
            self.assertIn("INCOMPLETE", next(Path(d).glob("*.md")).read_text())

    def test_truncated_coverage_is_incomplete(self):
        r = RepoResult("x")
        r.checks.append(CheckResult("WFX-01", "t", status="PASS"))
        r.truncated = True
        r.finish()
        self.assertEqual(r.status, "INCOMPLETE")


class TestOriginParsing(unittest.TestCase):
    def test_origin_must_be_the_github_host(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "remote", "add", "origin", "https://evil.example/github.com/acme/w.git"], check=True)
            self.assertIsNone(cli.origin_slug(Path(d), "https://github.com"))
            subprocess.run(["git", "-C", d, "remote", "set-url", "origin", "git@github.com:acme/w.git"], check=True)
            self.assertEqual(cli.origin_slug(Path(d), "https://github.com"), "acme/w")


if __name__ == "__main__":
    unittest.main()
