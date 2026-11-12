"""Tests for false-positive tuning: exclusions, WFX-05 severity, clone-mode file limits and tip defaults."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.fixtures import commit, sh, write
from wfxscan import cli
from wfxscan.checks import RepoScan
from wfxscan.iocs import IOCs
from wfxscan.sources import GitSource

SINCE, SINCE_ISO = "2026-10-01", "2026-10-01T00:00:00Z"
BIG = "\n".join(f"      - run: echo step{i}" for i in range(1500)) + "\n"
WF = "name: CI\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"


def scan(repo):
    iocs = IOCs()
    return RepoScan("r", GitSource(repo, SINCE, iocs), iocs, None, None, SINCE_ISO, None, None).run()


def wfx05(result):
    return next(c for c in result.checks if c.id == "WFX-05")


class TestLargeWorkflowSeverity(unittest.TestCase):
    def repo(self, d):
        r = Path(d) / "r"
        r.mkdir()
        sh(r, "init", "-q", "-b", "main")
        write(r, ".github/workflows/ci.yml", WF)
        commit(r, "init", "2026-10-02T10:00:00Z")
        return r

    def test_new_generated_workflow_is_low(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            write(r, ".github/workflows/agent.lock.yml", WF + BIG)
            commit(r, "feat: add agentic workflow", "2026-11-11T10:00:00Z")
            res = scan(r)
            self.assertEqual({h.severity for h in wfx05(res).hits}, {"LOW"})
            self.assertEqual(res.status, "CLEAN")

    def test_injection_into_existing_workflow_in_window_is_medium(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            write(r, ".github/workflows/ci.yml", WF + BIG)
            commit(r, "build: expand pipeline", "2026-11-11T10:00:00Z")
            res = scan(r)
            self.assertEqual({h.severity for h in wfx05(res).hits}, {"MEDIUM"})
            self.assertEqual(res.status, "REVIEW")

    def test_existing_workflow_before_window_is_low(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            write(r, ".github/workflows/ci.yml", WF + BIG)
            commit(r, "build: expand pipeline", "2026-10-20T10:00:00Z")
            self.assertEqual({h.severity for h in wfx05(scan(r)).hits}, {"LOW"})

    def test_corroborated_by_subject_or_content_is_high(self):
        for subject, extra in (("ci: refresh build cache", ""), ("build: tweak", "          WF_CALLBACK: x\n")):
            with self.subTest(subject=subject), tempfile.TemporaryDirectory() as d:
                r = self.repo(d)
                write(r, ".github/workflows/ci.yml", WF + BIG + extra)
                commit(r, subject, "2026-11-11T10:00:00Z")
                self.assertEqual({h.severity for h in wfx05(scan(r)).hits}, {"HIGH"})


class TestCloneModeReadsEveryFile(unittest.TestCase):
    def test_many_unique_manifests_are_all_read(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / "r"
            r.mkdir()
            sh(r, "init", "-q", "-b", "main")
            for i in range(320):
                write(r, f"svc{i}/go.mod", f"module example.com/svc{i}\n")
            write(r, "svc7/go.sum", "github.com/onuragtas/redock v1.0.282 h1:x=\n")
            commit(r, "init", "2026-11-11T10:00:00Z")
            res = scan(r)
            self.assertFalse(res.truncated, res.notes)
            self.assertEqual(next(c for c in res.checks if c.id == "WFX-11").status, "FAIL")


class TestOptions(unittest.TestCase):
    def test_default_max_tips_is_200(self):
        self.assertEqual(cli.build_parser().parse_args(["--org", "x"]).max_tips, 200)

    def test_exclude_skips_named_repositories(self):
        repos = [{"full_name": f"acme/{n}", "archived": False} for n in ("scanner", "app", "tools-ioc")]
        scanned = []

        def fake_scan(*a, **k):
            raise RuntimeError("stop")

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(cli, "find_token", return_value="t"), \
                mock.patch.object(cli.GitHub, "owner_repos", return_value=repos), \
                mock.patch.object(cli, "recent_pulls", side_effect=lambda gh, slug, s: scanned.append(slug) or []), \
                mock.patch.object(cli, "ApiSource", side_effect=fake_scan), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["--org", "acme", "--exclude", "ACME/Scanner", "--exclude", "acme/*-ioc",
                          "--no-dataset", "--out", d])
            self.assertEqual(scanned, ["acme/app"])
            self.assertIn("acme/scanner", next(Path(d).glob("*.md")).read_text().lower())


if __name__ == "__main__":
    unittest.main()
