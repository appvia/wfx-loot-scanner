import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import PAYLOAD_SCRIPT, build_clean, build_infected
from wfxscan.checks import CHECKS, RepoScan
from wfxscan.github import GitHubError
from wfxscan.iocs import IOCs
from wfxscan.sources import ApiSource, GitSource

SINCE = "2026-10-01"
SINCE_ISO = "2026-10-01T00:00:00Z"


def statuses(result):
    return {c.id: c.status for c in result.checks}


class TestIOCs(unittest.TestCase):
    def test_regexes_are_valid_for_git(self):
        """Every content regex must also compile as POSIX ERE for `git log -G`."""
        iocs = IOCs()
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                            "--allow-empty", "-m", "x"], check=True)
            for ioc in iocs.content:
                p = subprocess.run(["git", "-C", d, "log", f"-G{ioc.regex}", "--format=%H"], capture_output=True)
                self.assertEqual(p.returncode, 0, f"{ioc.id}: {p.stderr.decode()}")

    def test_package_parsing(self):
        iocs = IOCs()
        lock = '{"packages": [{"name": "digitalelvis/neuronai-studio", "version": "v3.14.3"}]}'
        self.assertEqual(iocs.package_hits("composer.lock", lock), ["digitalelvis/neuronai-studio v3.14.3"])
        ok = '{"packages": [{"name": "digitalelvis/neuronai-studio", "version": "v3.14.2"}]}'
        self.assertEqual(iocs.package_hits("composer.lock", ok), [])
        gosum = "github.com/onuragtas/redock v1.0.282 h1:abc=\ngithub.com/onuragtas/redock v1.0.282/go.mod h1:def=\n"
        self.assertEqual(iocs.package_hits("go.sum", gosum), ["github.com/onuragtas/redock v1.0.282"])
        self.assertEqual(iocs.package_hits("go.sum", "github.com/onuragtas/redock v1.0.2820 h1:x\n"), [])

    def test_branch_confidence(self):
        iocs = IOCs()
        self.assertEqual(iocs.branch_match("chore/k3j9x2ab")[0], "MEDIUM")
        self.assertEqual(iocs.branch_match("chore/annoying")[0], "LOW")
        self.assertEqual(iocs.branch_match("wfx-docs")[0], "CRITICAL")
        self.assertIsNone(iocs.branch_match("chore/too-long-name"))

    def test_every_check_has_a_method(self):
        for cid, *_ in CHECKS:
            self.assertTrue(hasattr(RepoScan, "c_" + cid.replace("-", "_").lower()), cid)


class TestGitMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.infected, cls.clean = build_infected(root), build_clean(root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scan(self, path, iocs=None):
        iocs = iocs or IOCs()
        return RepoScan(path.name, GitSource(path, SINCE, iocs), iocs, None, None, SINCE_ISO, None, None).run()

    def test_infected_repo(self):
        iocs = IOCs()
        iocs.sha256[hashlib.sha256(PAYLOAD_SCRIPT.encode()).hexdigest()] = "test payload"
        r = self.scan(self.infected, iocs)
        s = statuses(r)
        for cid in ("WFX-02", "WFX-03", "WFX-04", "WFX-05", "WFX-06", "WFX-07", "WFX-08",
                    "WFX-09", "WFX-11", "WFX-12", "WFX-18"):
            self.assertEqual(s[cid], "FAIL", f"{cid}: {r.checks}")
        self.assertEqual(s["WFX-10"], "PASS")
        for cid in ("WFX-01", "WFX-13", "WFX-14", "WFX-15", "WFX-16", "WFX-17"):
            self.assertEqual(s[cid], "SKIP", cid)
        self.assertEqual(r.status, "LIKELY COMPROMISED")

    def test_reverted_payload_is_still_found(self):
        r = self.scan(self.infected)
        wfx06 = next(c for c in r.checks if c.id == "WFX-06")
        subjects = " ".join(h.ref for h in wfx06.hits)
        self.assertIn("ci: refresh build cache", subjects)
        self.assertIn("ci: restore", subjects)

    def test_branch_patterns(self):
        r = self.scan(self.infected)
        details = " ".join(h.detail for c in r.checks if c.id == "WFX-02" for h in c.hits)
        self.assertIn("wfx-docs", details)
        self.assertIn("chore/k3j9x2ab", details)

    def test_clean_repo(self):
        r = self.scan(self.clean)
        self.assertEqual(r.status, "CLEAN", [(c.id, c.hits) for c in r.checks if c.hits])
        self.assertTrue(all(c.status in ("PASS", "SKIP") for c in r.checks))


class FakeGitHub:
    """Serves canned REST responses for one repository."""
    token = "test"
    calls = 0

    def __init__(self, slug):
        p = f"repos/{slug}"
        self.lists = {
            f"{p}/branches": [{"name": "main"}],
            f"{p}/pulls": [{"number": 7, "title": "docs: dependency audit notes", "state": "open",
                            "head": {"ref": "wfx-docs"}, "user": {"login": "victim"}, "body": "Routine dependency audit notes.",
                            "html_url": "https://github.com/x/y/pull/7", "created_at": "2026-11-10T12:50:00Z",
                            "updated_at": "2026-11-10T12:50:00Z"}],
            f"{p}/pulls/7/commits": [{"sha": "p" * 40, "commit": {"committer": {"date": "2026-11-10T12:50:00Z"}}}],
            f"{p}/commits": [{"sha": "a" * 40}],
            f"{p}/actions/artifacts": [{"name": "wfx-loot-123", "created_at": "2026-11-10T14:02:00Z"}],
            f"{p}/actions/runs": [{"workflow_id": 1, "run_number": n, "head_sha": "z" * 40, "path": ".github/workflows/ci.yml"}
                                  for n in (10, 11, 13)],
        }
        self.objects = {
            f"{p}/commits/{'a' * 40}": {"commit": {"author": {"name": "victim", "email": "v@users.noreply.github.com"},
                                                   "committer": {"date": "2026-11-10T14:01:00Z"},
                                                   "message": "ci: refresh build cache\n"},
                                        "author": {"login": "victim"},
                                        "files": [{"filename": ".github/workflows/ci.yml", "status": "modified",
                                                   "additions": 1508, "sha": "b" * 40,
                                                   "patch": "@@ -1 +1 @@\n+  WF_CALLBACK: \"http://194.150.166.244:8080/exfil\"\n"}]},
            f"{p}/commits/{'p' * 40}": {"commit": {"author": {"name": "victim", "email": "v@x"},
                                                   "committer": {"date": "2026-11-10T12:50:00Z"},
                                                   "message": "docs: dependency audit notes"},
                                        "files": [{"filename": "docs/wfx-audit.md", "status": "added", "additions": 1, "sha": "c" * 40,
                                                   "patch": "+Routine supply-chain review notes."}]},
            f"{p}/git/trees/main": {"tree": [{"path": "README.md", "type": "blob", "sha": "d" * 40}]},
            f"{p}/actions/caches": {"total_count": 1, "actions_caches": [{"key": "wfx-12345", "created_at": "x", "ref": "refs/heads/main"}]},
        }

    def paginate(self, path, params=None, key=None, stop=None, max_pages=None, allow=()):
        for it in self.lists.get(path, []):
            if stop and stop(it):
                return
            yield it

    def get(self, path, params=None, allow=()):
        if path.endswith("/actions/runs"):
            return {"total_count": 0}
        if path in self.objects:
            return self.objects[path]
        if any(s in allow for s in (404, 422)):
            return None
        raise GitHubError(404, "Not Found", path)

    def get_raw(self, path, max_bytes=None):
        return b"name: CI\n"


class TestApiMode(unittest.TestCase):
    def test_api_repo(self):
        iocs, slug = IOCs(), "acme/widgets"
        gh = FakeGitHub(slug)
        pulls = list(gh.paginate(f"repos/{slug}/pulls"))
        src = ApiSource(gh, slug, {"default_branch": "main"}, SINCE, iocs, pulls=pulls)
        r = RepoScan(slug, src, iocs, gh, slug, SINCE_ISO, pulls, {"acme/widgets": {"indicators": "workflow_injection"}}).run()
        s = statuses(r)
        for cid in ("WFX-01", "WFX-02", "WFX-03", "WFX-04", "WFX-05", "WFX-06", "WFX-07",
                    "WFX-13", "WFX-14", "WFX-16", "WFX-17"):
            self.assertEqual(s[cid], "FAIL", f"{cid}: {[c for c in r.checks if c.id == cid]}")
        self.assertEqual(s["WFX-15"], "WARN")
        self.assertEqual(r.status, "LIKELY COMPROMISED")
        pr = next(c for c in r.checks if c.id == "WFX-01")
        self.assertIn("@victim", pr.hits[0].detail)


if __name__ == "__main__":
    unittest.main()
