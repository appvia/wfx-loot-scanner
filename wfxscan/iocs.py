"""Indicator set for the wfx-loot campaign, loaded from data/iocs.json.

Regular expressions in iocs.json are written in the subset shared by Python `re`
and POSIX ERE (used by `git log -G`): no \\s, \\d, \\b or look-arounds.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "iocs.json"


@dataclass
class ContentIOC:
    id: str
    check: str
    severity: str
    regex: str
    rx: re.Pattern
    rxb: re.Pattern  # same pattern for raw bytes (git diff output)
    description: str
    paths: list[str] | None

    def applies_to(self, path: str) -> bool:
        if not self.paths:
            return True
        return any(path.startswith(p) or path.endswith(p) for p in self.paths)


class IOCs:
    def __init__(self, path: Path = DATA_FILE):
        d = json.loads(Path(path).read_text())
        self.raw = d
        self.version = d["ioc_set_version"]
        self.sources = d["sources"]
        self.attack_start = dt.datetime.fromisoformat(d["attack_start"].replace("Z", "+00:00"))
        self.default_since = d["default_since"]

        p = d["probe"]
        self.pr_titles = {t.lower() for t in p["pr_titles"]}
        self.pr_bodies = [b.lower() for b in p["pr_bodies"]]
        self.probe_branches = set(p["head_branches"])

        self.branch_patterns = [(re.compile(b["regex"]), b["severity"], b["description"])
                                for b in d["branch_patterns"]]
        self._low_if_letters = {b["regex"] for b in d["branch_patterns"] if b.get("low_if_all_letters")}
        self.subjects = {s["subject"].lower(): s for s in d["commit_subjects"]}
        self.authors = {a["login"].lower(): a for a in d["compromised_authors"]}
        self.payload_paths = [(re.compile(x["regex"]), x["severity"], x["description"])
                              for x in d["payload_paths"]]
        self.big_workflow_lines = int(d["large_workflow_insertion_lines"])
        self.content = [ContentIOC(c["id"], c["check"], c["severity"], c["regex"], re.compile(c["regex"]),
                                   re.compile(c["regex"].encode()), c["description"], c.get("paths")) for c in d["content"]]
        self.content_any_b = re.compile(b"|".join(b"(?:" + c.rxb.pattern + b")" for c in self.content))
        self.sha256 = {h["hash"].lower(): h["description"] for h in d["sha256"]}
        self.commits = {c["sha"].lower(): c["description"] for c in d["commits"]}
        self.packages = d["packages"]
        self.cache_prefix = d["actions"]["cache_key_prefix"]
        self.artifact_prefix = d["actions"]["artifact_name_prefix"]
        self.font_path = d["ghostaction_font_path"]

    # ------------------------------------------------------------------ helpers
    def branch_match(self, name: str):
        """(severity, description) for a campaign-like branch name, or None.

        Random 8-character names almost always contain a digit; all-letter names such as
        chore/upgrades are usually real branches, so they are reported as LOW.
        """
        for rx, sev, desc in self.branch_patterns:
            if rx.match(name):
                if rx.pattern in self._low_if_letters and name.split("/", 1)[-1].isalpha():
                    return "LOW", desc + "; all letters, probably a real branch name"
                return sev, desc
        return None

    def payload_path_match(self, path: str):
        for rx, sev, desc in self.payload_paths:
            if rx.search(path):
                return sev, desc
        return None

    def package_hits(self, path: str, text: str) -> list[str]:
        """Return descriptions of affected package versions referenced in a manifest."""
        name = path.rsplit("/", 1)[-1]
        hits = []
        if name == "composer.lock":
            try:
                lock = json.loads(text)
            except ValueError:
                lock = {}
            pkgs = (lock.get("packages") or []) + (lock.get("packages-dev") or [])
            for want in self.packages:
                if want["ecosystem"] != "packagist":
                    continue
                for p in pkgs:
                    if p.get("name") == want["name"] and p.get("version") in want["versions"]:
                        hits.append(f"{want['name']} {p.get('version')}")
        elif name in ("go.mod", "go.sum"):
            for want in self.packages:
                if want["ecosystem"] != "go":
                    continue
                for v in want["versions"]:
                    if re.search(rf"(^|[ \t]){re.escape(want['name'])}[ \t]+{re.escape(v)}([ \t/]|$)", text, re.M):
                        hits.append(f"{want['name']} {v}")
        return sorted(set(hits))


MANIFEST_NAMES = {"composer.lock", "go.mod", "go.sum"}
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
