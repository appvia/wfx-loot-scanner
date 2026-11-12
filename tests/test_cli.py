"""End-to-end tests of the wfx-scan command and validation of the IOC data file."""
import csv
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import build_clean, build_infected
from wfxscan.checks import CHECKS, SEV_ORDER
from wfxscan.iocs import DATA_FILE

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "wfx-scan"


def run(*args, cwd):
    return subprocess.run([sys.executable, "-I", str(LAUNCHER), *args], cwd=cwd, capture_output=True, text=True)


class TestCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.infected, cls.clean = build_infected(cls.root), build_clean(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_exit_code_flagged(self):
        out = self.root / "r1"
        p = run("--offline", "--path", str(self.infected), "--out", str(out), cwd=self.root)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("LIKELY COMPROMISED", p.stdout)

    def test_exit_code_clean_and_reports(self):
        out = self.root / "r2"
        p = run("--offline", "--path", str(self.clean), "--out", str(out), cwd=self.root)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        md, js, cs = (next(out.glob(f"*.{ext}")) for ext in ("md", "json", "csv"))
        text = md.read_text()
        for cid, *_ in CHECKS:
            self.assertIn(cid, text)
        self.assertIn("## Checks performed", text)
        data = json.loads(js.read_text())
        self.assertEqual(len(data["repositories"][0]["checks"]), len(CHECKS))
        rows = list(csv.DictReader(cs.open()))
        self.assertEqual({r["check_id"] for r in rows}, {c[0] for c in CHECKS})

    def test_usage_errors(self):
        self.assertEqual(run(cwd=self.root).returncode, 64)
        self.assertEqual(run("--offline", "--org", "x", cwd=self.root).returncode, 64)
        self.assertEqual(run("--path", ".", "--since", "Nov 1", "--offline", cwd=self.root).returncode, 64)


class TestIOCData(unittest.TestCase):
    def setUp(self):
        self.d = json.loads(DATA_FILE.read_text())

    def test_shapes(self):
        sevs = set(SEV_ORDER)
        check_ids = {c[0] for c in CHECKS}
        for h in self.d["sha256"]:
            self.assertRegex(h["hash"], r"^[0-9a-f]{64}$")
        for c in self.d["commits"]:
            self.assertRegex(c["sha"], r"^[0-9a-f]{40}$")
        for c in self.d["content"]:
            self.assertIn(c["severity"], sevs, c["id"])
            self.assertIn(c["check"], check_ids, c["id"])
            re.compile(c["regex"])
        for b in self.d["branch_patterns"] + self.d["payload_paths"]:
            self.assertIn(b["severity"], sevs)
            re.compile(b["regex"])
        for s in self.d["commit_subjects"]:
            self.assertIn(s["severity_ci"], sevs)
            self.assertIn(s["severity_other"], sevs | {None})

    def test_every_entry_has_a_source(self):
        for key in ("branch_patterns", "commit_subjects", "payload_paths", "content", "sha256", "commits", "packages"):
            for e in self.d[key]:
                self.assertTrue(e.get("source"), f"{key}: {e}")

    def test_no_live_telegram_tokens(self):
        self.assertIsNone(re.search(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}", DATA_FILE.read_text()))


if __name__ == "__main__":
    unittest.main()
