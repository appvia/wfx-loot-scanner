"""Check definitions and the per-repository runner."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .github import GitHub, GitHubError
from .iocs import IOCs, MANIFEST_NAMES, WORKFLOW_RE
from .sources import Commit

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# id, title, what it looks for, data needed
CHECKS = [
    ("WFX-01", "Probe pull requests", "Pull requests titled 'docs: dependency audit notes', from a 'wfx-docs' branch or with the probe body text. The PR author account is compromised.", "API"),
    ("WFX-02", "Campaign branch names", "Branches named wfx-docs, ci-check-NNNN or chore/xxxxxxxx (8 lower-case alphanumerics).", "history"),
    ("WFX-03", "Campaign commit messages", "Commit subjects used by the attacker (ci: refresh build cache, chore: add ci helper, chore: add dependency audit workflow, docs: dependency audit notes) and, within the attack window, the clean-up subjects (ci: restore, ci: cleanup, chore: initial commit) when they touch CI files. Also commits by known compromised bot accounts.", "history"),
    ("WFX-04", "Payload files in history", "Files added at any point in the window: .ci-xxxxxx.sh, .github/workflows/build-audit-xxxxxx.yml, docs/wfx-audit.md.", "history"),
    ("WFX-05", "Large workflow insertion", "A single commit adding 1,000 or more lines to a workflow file (the payload is about 1,500 lines). HIGH with campaign indicators in the same commit, MEDIUM for an existing workflow in the attack window, LOW otherwise (new or generated files).", "history"),
    ("WFX-06", "Exfiltration endpoints and tokens", "Exfiltration IP addresses, WF_CTOKEN campaign tokens, attacker Telegram chat and bot IDs, and Telegram API calls in CI files. Added or removed lines both count, so reverted payloads are still found.", "history"),
    ("WFX-07", "Payload markers", "Payload configuration variables (WF_CALLBACK, WF_TG_BOTS, WF_EXFIL_* etc.), marker strings (wfx-loot, WFX-BEGIN, wfx-ci-, .wfx-) and payload workflow or step names.", "history"),
    ("WFX-08", "npm postinstall hook", "References to the .ci-xxxxxx.sh payload script, as used by the postinstall hook in package.json.", "history"),
    ("WFX-09", "Known payload hashes", "SHA-256 of candidate files (payload paths, large workflow insertions, CI files in flagged commits) compared with published payload hashes.", "history"),
    ("WFX-10", "Known attacker commits", "Presence of published attacker commit SHAs.", "history"),
    ("WFX-11", "Affected package versions", "composer.lock, go.mod and go.sum on branch tips referencing a published malicious package version.", "tree"),
    ("WFX-12", "Payload files on branch tips", "Payload files, or a package.json postinstall hook calling .ci-xxxxxx.sh, still present on branch tips.", "tree"),
    ("WFX-13", "Actions cache entries", "GitHub Actions cache entries with a 'wfx-' key prefix (cache exfiltration channel).", "API"),
    ("WFX-14", "Workflow artefacts", "Workflow artefacts named 'wfx-loot-*' (artefact exfiltration channel).", "API"),
    ("WFX-15", "Deleted workflow runs", "Gaps in workflow run numbers since the attack began. The attacker deletes the run and its logs; a missing run number is often the only trace.", "API"),
    ("WFX-16", "Flagged commits with no run", "Flagged commits that have no surviving workflow run, consistent with the run having been deleted.", "API"),
    ("WFX-17", "SafeDep affected list", "Repository appears in SafeDep's published list of repositories that received malicious commits.", "dataset"),
    ("WFX-18", "GhostAction (October) indicators", "Indicators from the earlier GhostAction wave that overlaps with this campaign: 193.32.204.199, the #ghc2 cron tag, a fake public/fonts/fa-solid-400.woff2 that is not a WOFF2 font, VS Code tasks that run on folder open.", "history"),
]
CHECK_TITLES = {c[0]: c[1] for c in CHECKS}


@dataclass
class Hit:
    severity: str
    detail: str
    ref: str = ""
    commit: str | None = None


@dataclass
class CheckResult:
    id: str
    title: str
    status: str = "PASS"  # PASS, WARN, FAIL, SKIP, ERROR
    summary: str = ""
    hits: list[Hit] = field(default_factory=list)

    def add(self, severity, detail, ref="", commit=None):
        if not any(h.detail == detail and h.ref == ref for h in self.hits):
            self.hits.append(Hit(severity, detail, ref, commit))

    def finish(self):
        if self.status in ("SKIP", "ERROR"):
            return
        top = max((SEV_ORDER[h.severity] for h in self.hits), default=0)
        # LOW findings are listed for context but do not change the result.
        self.status = "FAIL" if top >= 3 else "WARN" if top == 2 else "PASS"
        self.hits.sort(key=lambda h: -SEV_ORDER[h.severity])


@dataclass
class RepoResult:
    name: str
    mode: str = ""
    status: str = "CLEAN"
    error: str = ""
    truncated: bool = False  # a coverage limit was reached somewhere
    notes: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def max_sev(self) -> int:
        return max((SEV_ORDER[h.severity] for c in self.checks for h in c.hits), default=0)

    def finish(self):
        m = self.max_sev
        incomplete = self.error or self.truncated or any(c.status == "ERROR" for c in self.checks)
        self.status = ("LIKELY COMPROMISED" if m >= 4 else "SUSPICIOUS" if m == 3 else
                       "REVIEW" if m == 2 else "INCOMPLETE" if incomplete else "CLEAN")

    def counts(self):
        out = {s: 0 for s in ("PASS", "WARN", "FAIL", "SKIP", "ERROR")}
        for c in self.checks:
            out[c.status] += 1
        return out


# ============================================================================ helpers
def touches_ci(c: Commit, iocs: IOCs) -> bool:
    return any(WORKFLOW_RE.match(f.path) or f.path.endswith("package.json") or iocs.payload_path_match(f.path)
               for f in c.files)


PULLS_CAP = 2000


def recent_pulls(gh: GitHub, slug: str, since_iso: str) -> list[dict]:
    """Pull requests (any state) updated since the window start, newest first, up to PULLS_CAP."""
    return list(gh.paginate(f"repos/{slug}/pulls", {"state": "all", "sort": "updated", "direction": "desc"},
                            stop=lambda p: p["updated_at"] < since_iso, allow=(404,), max_pages=PULLS_CAP // 100))


# ============================================================================ runner
class RepoScan:
    def __init__(self, name, source, iocs: IOCs, gh: GitHub | None, slug: str | None,
                 since_iso: str, pulls: list[dict] | None, affected: dict | None):
        self.name, self.src, self.iocs, self.gh, self.slug = name, source, iocs, gh, slug
        self.since_iso = since_iso
        self.pulls = pulls
        self.pulls_error = ""
        self.affected = affected
        self.flagged: dict[str, Commit | None] = {}
        self.run_shas: set[str] | None = None
        self.truncated = False
        self.result = RepoResult(name, mode=source.mode if source else "api")

    def run(self) -> RepoResult:
        for cid, title, _, needs in CHECKS:
            cr = CheckResult(cid, title)
            try:
                if needs == "API" and not (self.gh and self.slug):
                    cr.status, cr.summary = "SKIP", "needs GitHub API access (no token or not a GitHub repository)"
                elif needs in ("history", "tree") and self.src is None:
                    cr.status, cr.summary = "SKIP", "no repository data available"
                else:
                    getattr(self, "c_" + cid.replace("-", "_").lower())(cr)
            except GitHubError as e:
                # 404 on an Actions endpoint means Actions is not enabled. Anything else (403 permission,
                # SSO, exhausted rate limit) means we could not look, which must not read as a pass.
                if e.status == 404 and needs == "API":
                    cr.status, cr.summary = "SKIP", f"not available for this repository (GitHub API: {e})"
                else:
                    cr.status, cr.summary = "ERROR", f"GitHub API: {e}"
            except Exception as e:  # noqa: BLE001 - report and carry on
                cr.status, cr.summary = "ERROR", f"{type(e).__name__}: {e}"
            cr.finish()
            for h in cr.hits:
                if h.commit and SEV_ORDER[h.severity] >= 3:
                    self.flagged.setdefault(h.commit, None)
            self.result.checks.append(cr)
        if self.src is not None:
            self.result.notes.extend(dict.fromkeys(self.src.notes))
            self.truncated = self.truncated or self.src.truncated
        self.result.notes = list(dict.fromkeys(self.result.notes))
        self.result.truncated = self.truncated
        self.result.finish()
        return self.result

    def _limit(self, cr, what: str):
        cr.summary += f" (limit reached: {what})"
        self.result.notes.append(f"{cr.id}: limit reached, {what}")
        self.truncated = True

    def _flag(self, cr, sev, detail, c: Commit, ref_extra=""):
        cr.add(sev, detail, c.ctx() + ref_extra, commit=c.sha)
        if SEV_ORDER[sev] >= 3:
            self.flagged[c.sha] = c

    # ------------------------------------------------------------------ checks
    def c_wfx_01(self, cr):
        if self.pulls is None:
            raise RuntimeError(self.pulls_error or "pull requests could not be listed")
        pulls = self.pulls
        for p in pulls:
            reasons = []
            if (p.get("title") or "").strip().lower() in self.iocs.pr_titles:
                reasons.append("probe title")
            if (p.get("head") or {}).get("ref") in self.iocs.probe_branches:
                reasons.append(f"head branch '{p['head']['ref']}'")
            body = (p.get("body") or "").lower()
            if any(b in body for b in self.iocs.pr_bodies):
                reasons.append("probe body text")
            if reasons:
                user = (p.get("user") or {}).get("login", "?")
                sev = "HIGH" if reasons == ["probe body text"] else "CRITICAL"
                cr.add(sev, f"PR #{p['number']} ({p.get('state')}) by @{user}: {', '.join(reasons)}. Treat @{user} as compromised.",
                       f"{p.get('html_url')} opened {p.get('created_at')}")
        cr.summary = f"{len(pulls)} pull requests updated since {self.since_iso[:10]} inspected"
        if len(pulls) >= PULLS_CAP:
            self._limit(cr, f"first {PULLS_CAP} pull requests only")

    def c_wfx_02(self, cr):
        names = self.src.branches()
        for n in names:
            m = self.iocs.branch_match(n)
            if m:
                cr.add(m[0], f"branch '{n}': {m[1]}")
        for p in self.pulls or []:
            ref = (p.get("head") or {}).get("ref", "")
            m = self.iocs.branch_match(ref)
            if m and ref not in names:
                cr.add(m[0], f"PR #{p['number']} head branch '{ref}' (since deleted): {m[1]}", p.get("html_url", ""))
        cr.summary = f"{len(names)} branches inspected"

    def c_wfx_03(self, cr):
        commits = self.src.commits()
        for c in commits:
            s = self.iocs.subjects.get(c.subject.strip().lower())
            if s:
                ci = touches_ci(c, self.iocs)
                sev = s["severity_ci"] if ci else s["severity_other"]
                in_window = c.date >= self.iocs.attack_start
                if sev and (in_window or not s["window_only"]):
                    self._flag(cr, sev, f"attacker commit message ({s['description']})" + (", touches CI files" if ci else ""), c)
            who = (c.login or c.author).lower()
            for login, a in self.iocs.authors.items():
                if who.startswith(login):
                    self._flag(cr, a["severity"], f"commit by {login}: {a['description']}", c)
        cr.summary = f"{len(commits)} commits since {self.since_iso[:10]} inspected"

    def c_wfx_04(self, cr):
        n = 0
        for c in self.src.commits():
            for f in c.files:
                n += 1
                m = self.iocs.payload_path_match(f.path)
                if m:
                    self._flag(cr, m[0], f"'{f.path}': {m[1]}", c)
        cr.summary = f"{n} file changes inspected"

    def c_wfx_05(self, cr):
        """The payload adds ~1,500 lines to an existing workflow. Size alone is weak evidence (generated
        workflows such as gh-aw lock files are often larger), so severity depends on corroboration."""
        lim, n = self.iocs.big_workflow_lines, 0
        corroborated = {h.sha for h in self._content() if SEV_ORDER[h.ioc.severity] >= 3}
        for c in self.src.commits():
            for f in c.files:
                if not WORKFLOW_RE.match(f.path):
                    continue
                n += 1
                if f.additions < lim:
                    continue
                detail = f"+{f.additions} lines to '{f.path}' in one commit"
                if c.subject.strip().lower() in self.iocs.subjects or c.sha in corroborated:
                    self._flag(cr, "HIGH", detail + " with campaign indicators", c)
                elif c.date >= self.iocs.attack_start and self.src.existed_before(c, f):
                    self._flag(cr, "MEDIUM", detail + " (existing workflow, attack window)", c)
                else:
                    self._flag(cr, "LOW", detail + " (new file or before the attack window)", c)
        cr.summary = f"{n} workflow file changes inspected (threshold {lim} lines)"

    def _content(self):
        if not hasattr(self, "_content_hits"):
            self._content_hits = self.src.content_hits()
        return self._content_hits

    def _content_check(self, cr, check_id):
        iocs = [i for i in self.iocs.content if i.check == check_id]
        for h in self._content():
            if h.ioc.check != check_id:
                continue
            detail = f"{h.ioc.description} in {', '.join(h.paths[:3]) or 'diff'} (pattern {h.ioc.id})"
            if h.commit:
                self._flag(cr, h.ioc.severity, detail, h.commit)
            else:
                cr.add(h.ioc.severity, detail, h.sha[:12], commit=h.sha)
        cr.summary = f"{len(iocs)} pattern group(s) searched across added and removed lines since {self.since_iso[:10]}"

    def c_wfx_06(self, cr):
        self._content_check(cr, "WFX-06")

    def c_wfx_07(self, cr):
        self._content_check(cr, "WFX-07")

    def c_wfx_08(self, cr):
        self._content_check(cr, "WFX-08")

    def c_wfx_09(self, cr):
        cands: dict[tuple[str, str], Commit] = {}
        for c in self.src.commits():
            flagged = c.sha in self.flagged
            for f in c.files:
                if f.status == "removed":
                    continue
                if (self.iocs.payload_path_match(f.path)
                        or (WORKFLOW_RE.match(f.path) and f.additions >= self.iocs.big_workflow_lines)
                        or (flagged and (WORKFLOW_RE.match(f.path) or f.path.endswith((".sh", "package.json"))))):
                    cands[(c.sha, f.path)] = c
        hashed = 0
        if len(cands) > 200:
            self._limit(cr, f"200 of {len(cands)} candidate files hashed")
        for (sha, path), c in list(cands.items())[:200]:
            data = self.src.blob(sha, path)
            if data is None:
                continue
            hashed += 1
            h = hashlib.sha256(data).hexdigest()
            if h in self.iocs.sha256:
                self._flag(cr, "CRITICAL", f"'{path}' matches published hash ({self.iocs.sha256[h]})", c)
        cr.summary = f"{hashed} candidate file(s) hashed against {len(self.iocs.sha256)} published hashes"

    def c_wfx_10(self, cr):
        for sha, desc in self.iocs.commits.items():
            if self.src.commit_exists(sha):
                cr.add("CRITICAL", f"commit {sha[:12]} present: {desc}", sha, commit=sha)
        cr.summary = f"{len(self.iocs.commits)} published commit SHAs looked up"

    def _tip_blobs(self, want) -> dict[str, tuple[str, list[str]]]:
        """Unique files on branch tips matching want(path): blob sha -> (path, refs it appears on)."""
        out: dict[str, tuple[str, list[str]]] = {}
        for ref in self.src.tips():
            for path, sha in self.src.tip_entries(ref):
                if want(path):
                    out.setdefault(sha, (path, []))[1].append(ref)
        return out

    @staticmethod
    def _where(refs: list[str]) -> str:
        short = [r.split("/", 2)[-1] if r.startswith("refs/heads/") else r for r in refs]
        return short[0] + (f" and {len(short) - 1} other branch(es)" if len(short) > 1 else "")

    def c_wfx_11(self, cr):
        cap = self.src.read_cap  # None: no limit (local reads are cheap)
        blobs = self._tip_blobs(lambda p: p.rsplit("/", 1)[-1] in MANIFEST_NAMES)
        if cap and len(blobs) > cap:
            self._limit(cr, f"{cap} of {len(blobs)} unique manifest files read")
        chosen = list(blobs.items())[:cap]
        contents = self.src.read_blobs([sha for sha, _ in chosen])
        for sha, (path, refs) in chosen:
            data = contents.get(sha)
            for hit in self.iocs.package_hits(path, (data or b"").decode("utf-8", "replace")):
                cr.add("HIGH", f"{path} pins affected version {hit}", self._where(refs))
        cr.summary = f"{len(chosen)} unique manifest file(s) read across {len(self.src.tips())} branch tip(s)"

    def c_wfx_12(self, cr):
        tips = self.src.tips()
        hook = next(i for i in self.iocs.content if i.id == "postinstall-hook")
        present: dict[str, list[str]] = {}
        for ref in tips:
            for path, _ in self.src.tip_entries(ref):
                if self.iocs.payload_path_match(path):
                    present.setdefault(path, []).append(ref)
        for path, refs in present.items():
            sev, desc = self.iocs.payload_path_match(path)
            cr.add(sev, f"'{path}' present: {desc}", self._where(refs))
        cap = self.src.read_cap
        blobs = self._tip_blobs(lambda p: p.rsplit("/", 1)[-1] == "package.json" and "node_modules/" not in p)
        if cap and len(blobs) > cap:
            self._limit(cr, f"{cap} of {len(blobs)} unique package.json files parsed")
        chosen = list(blobs.items())[:cap]
        contents = self.src.read_blobs([sha for sha, _ in chosen])
        for sha, (path, refs) in chosen:
            try:
                scripts = json.loads(contents.get(sha) or b"{}").get("scripts") or {}
            except (ValueError, AttributeError):
                continue
            for k in ("preinstall", "install", "postinstall", "prepare"):
                if hook.rx.search(str(scripts.get(k, ""))):
                    cr.add("CRITICAL", f"{path} '{k}' script runs the payload script", self._where(refs))
        cr.summary = f"{len(tips)} branch tip(s) inspected, {len(chosen)} unique package.json file(s) parsed"

    def c_wfx_13(self, cr):
        r = self.gh.get(f"repos/{self.slug}/actions/caches", {"key": self.iocs.cache_prefix, "per_page": 100})
        for c in (r or {}).get("actions_caches", []):
            cr.add("CRITICAL", f"cache entry '{c.get('key')}'", f"created {c.get('created_at')} ref {c.get('ref')}")
        cr.summary = f"cache entries with key prefix '{self.iocs.cache_prefix}': {(r or {}).get('total_count', 0)}"

    def c_wfx_14(self, cr):
        n = 0
        for a in self.gh.paginate(f"repos/{self.slug}/actions/artifacts", key="artifacts",
                                  stop=lambda a: (a.get("created_at") or "") < self.since_iso, max_pages=20):
            n += 1
            if (a.get("name") or "").startswith(self.iocs.artifact_prefix):
                cr.add("CRITICAL", f"artefact '{a['name']}'",
                       f"created {a.get('created_at')} commit {((a.get('workflow_run') or {}).get('head_sha') or '')[:12]}")
        cr.summary = f"{n} artefact(s) created since {self.since_iso[:10]} inspected"

    def _runs(self):
        start = self.iocs.attack_start.date().isoformat()
        runs = list(self.gh.paginate(f"repos/{self.slug}/actions/runs", {"created": f">={start}"},
                                     key="workflow_runs", max_pages=10))
        self.run_shas = {r.get("head_sha") for r in runs}
        return runs, start

    def c_wfx_15(self, cr):
        runs, start = self._runs()
        by_wf: dict[str, list[int]] = {}
        for r in runs:
            by_wf.setdefault(r.get("path") or str(r.get("workflow_id")), []).append(int(r["run_number"]))
        gaps = 0
        for wf, nums in sorted(by_wf.items()):
            nums = sorted(set(nums))
            missing = sorted(set(range(nums[0], nums[-1] + 1)) - set(nums))
            if missing:
                gaps += len(missing)
                shown = ", ".join(f"#{m}" for m in missing[:12]) + (" ..." if len(missing) > 12 else "")
                cr.add("MEDIUM", f"{len(missing)} missing run number(s) in {wf}: {shown}")
        cr.summary = f"{len(runs)} run(s) across {len(by_wf)} workflow(s) since {start}, {gaps} missing run number(s)"
        if len(runs) >= 1000:
            self._limit(cr, "first 1,000 runs only")

    def c_wfx_16(self, cr):
        window = [s for s, c in self.flagged.items() if c is None or c.date >= self.iocs.attack_start]
        if self.run_shas is None:
            self._runs()
        for sha in window:
            if sha in self.run_shas:
                continue
            r = self.gh.get(f"repos/{self.slug}/actions/runs", {"head_sha": sha, "per_page": 1}) or {}
            if r.get("total_count", 0) == 0:
                c = self.flagged.get(sha)
                cr.add("HIGH", "flagged commit has no surviving workflow run (deleted, or the workflow never triggered)",
                       c.ctx() if c else sha[:12], commit=sha)
        cr.summary = f"{len(window)} flagged commit(s) in the attack window checked for runs"

    def c_wfx_17(self, cr):
        if self.affected is None:
            cr.status, cr.summary = "SKIP", "SafeDep dataset not loaded (offline or download failed)"
            return
        row = self.affected.get((self.slug or self.name).lower())
        if row:
            cr.add("CRITICAL", f"listed by SafeDep: {row.get('indicators')} ({row.get('malicious_commits')} malicious commit(s), "
                               f"authors {row.get('commit_authors')})", row.get("evidence_url", ""))
        cr.summary = f"checked against {len(self.affected)} listed repositories"

    def c_wfx_18(self, cr):
        self._content_check(cr, "WFX-18")
        fp = self.iocs.font_path
        seen = 0
        for c in self.src.commits():
            for f in c.files:
                if f.path.endswith(fp) and f.status != "removed":
                    seen += 1
                    data = self.src.blob(c.sha, f.path) or b""
                    if data and not data.startswith(b"wOF2"):
                        self._flag(cr, "CRITICAL", f"'{f.path}' is not a WOFF2 font (GhostAction stealer)", c)
        for sha, (path, refs) in self._tip_blobs(lambda p: p.endswith(fp)).items():
            seen += 1
            data = self.src.read_blob(sha) or b""
            if data and not data.startswith(b"wOF2"):
                cr.add("CRITICAL", f"'{path}' on branch tip is not a WOFF2 font (GhostAction stealer)", self._where(refs))
        cr.summary += f"; {seen} file(s) at {fp} inspected"
