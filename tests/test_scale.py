"""Regression tests for large-organisation runs: transient network errors, per-repository failures, limits and speed."""
import contextlib
import http.client
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.fixtures import commit, sh, write
from wfxscan import cli, github, sources
from wfxscan.checks import RepoScan
from wfxscan.iocs import IOCs
from wfxscan.sources import GitSource

SINCE, SINCE_ISO = "2026-10-01", "2026-10-01T00:00:00Z"


class FlakyResponse:
    status, headers = 200, {}

    def __init__(self, fail):
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        if self.fail:
            raise http.client.IncompleteRead(b"x" * 10, 5)
        return b'{"ok": true}'


class TestNetwork(unittest.TestCase):
    def test_incomplete_read_is_retried(self):
        gh = github.GitHub("t")
        responses = iter([FlakyResponse(True), FlakyResponse(True), FlakyResponse(False)])
        with mock.patch.object(gh._opener, "open", side_effect=lambda *a, **k: next(responses)), \
                mock.patch.object(github.time, "sleep"):
            self.assertEqual(gh.get("x"), {"ok": True})

    def test_persistent_network_failure_becomes_github_error(self):
        gh = github.GitHub("t")
        with mock.patch.object(gh._opener, "open", side_effect=ConnectionResetError("reset")), \
                mock.patch.object(github.time, "sleep"):
            with self.assertRaises(github.GitHubError):
                gh.get("x")


class TestOneRepositoryCannotStopTheRun(unittest.TestCase):
    def test_unexpected_exception_is_contained(self):
        repos = [{"full_name": "acme/a", "archived": False}, {"full_name": "acme/b", "archived": False}]
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(cli, "find_token", return_value="t"), \
                mock.patch.object(cli.GitHub, "owner_repos", return_value=repos), \
                mock.patch.object(cli, "recent_pulls", side_effect=http.client.IncompleteRead(b"", 1)), \
                mock.patch.object(cli, "ApiSource", side_effect=RuntimeError("boom")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as e:
                cli.main(["--org", "acme", "--no-dataset", "--out", d])
            self.assertEqual(e.exception.code, cli.EXIT_REVIEW)
            text = next(Path(d).glob("*.md")).read_text()
            self.assertIn("acme/a: INCOMPLETE", text)
            self.assertIn("acme/b: INCOMPLETE", text)


def many_branch_repo(root: Path, branches: int) -> Path:
    repo = root / "r"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    write(repo, "go.mod", "module x\n")
    write(repo, "web/package.json", '{"name": "x"}')
    write(repo, "api/package.json", '{"name": "y"}')
    write(repo, "api/go.sum", 'example.com/y v1.0.0 h1:x=\n')
    commit(repo, "init", "2026-11-11T10:00:00Z")
    for i in range(branches):
        sh(repo, "branch", f"feature/{i}")
    return repo


def spy_stream(seen):
    orig = sources.git_stream

    def spy(*a, **k):
        seen.append("log -p")
        return orig(*a, **k)
    return spy


class TestContentParsing(unittest.TestCase):
    def test_quoted_paths_and_dash_lines_in_diffs(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "r"
            repo.mkdir()
            sh(repo, "init", "-q", "-b", "main")
            write(repo, 'notes.txt', "-- keep\n")
            write(repo, '.github/workflows/we"ird é.yml', "on: push\n")
            commit(repo, "init", "2026-11-11T09:00:00Z")
            write(repo, 'notes.txt', "")  # removed line shows as '--- keep'
            write(repo, '.github/workflows/we"ird é.yml', "on: push\n  - run: curl https://api.telegram.org/bot1/x\n")
            commit(repo, "change", "2026-11-11T10:00:00Z")
            iocs = IOCs()
            hits = GitSource(repo, SINCE, iocs).content_hits()
            got = {(h.ioc.id, tuple(h.paths)) for h in hits}
            self.assertIn(("telegram-generic", ('.github/workflows/we"ird é.yml',)), got)


class TestLimitsAndSpeed(unittest.TestCase):
    def test_same_file_on_many_branches_is_not_a_limit(self):
        with tempfile.TemporaryDirectory() as d:
            iocs = IOCs()
            repo = many_branch_repo(Path(d), 40)
            r = RepoScan("r", GitSource(repo, SINCE, iocs), iocs, None, None, SINCE_ISO, None, None).run()
            self.assertEqual(r.status, "CLEAN", r.notes)
            self.assertFalse(r.truncated, r.notes)

    def test_tip_listing_is_cached_and_content_is_one_pass_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            iocs = IOCs()
            repo = many_branch_repo(Path(d), 5)
            seen = []
            orig = sources.git

            def spy(r, *a, **k):
                seen.append(a[0] if a[0] != "log" else "log -G" if any(x.startswith("-G") for x in a)
                            else "log -p" if "-p" in a else "log")
                return orig(r, *a, **k)

            with mock.patch.object(sources, "git", spy), mock.patch.object(sources, "git_stream", spy_stream(seen)):
                RepoScan("r", GitSource(repo, SINCE, iocs), iocs, None, None, SINCE_ISO, None, None).run()
            self.assertEqual(seen.count("log -G"), 0, seen)
            self.assertEqual(seen.count("log -p"), 1, seen)
            self.assertLessEqual(seen.count("ls-tree"), 6, seen)  # one per tip


if __name__ == "__main__":
    unittest.main()
