"""Markdown, JSON and CSV report writers."""
from __future__ import annotations

import csv
import datetime as dt
import json
import re
from dataclasses import asdict
from pathlib import Path

from .checks import CHECKS, RepoResult

STATUS_ORDER = ["LIKELY COMPROMISED", "SUSPICIOUS", "REVIEW", "INCOMPLETE", "CLEAN"]
STATUS_MEANING = {
    "LIKELY COMPROMISED": "At least one critical indicator. Treat the repository's secrets and the accounts involved as compromised.",
    "SUSPICIOUS": "At least one high-severity indicator. Investigate before ruling out compromise.",
    "REVIEW": "Medium-severity indicators only. These are often benign; confirm by hand.",
    "INCOMPLETE": "No indicators found, but coverage was partial (a check could not run, a limit was reached, or the target could not be read).",
    "CLEAN": "Every check that could run found nothing.",
}
RESULT_MEANING = "PASS: nothing found. WARN: medium-severity hits. FAIL: high or critical hits. SKIP: not applicable or no access. ERROR: the check failed to run."


_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_MD_SPECIAL = re.compile(r"[\\`*_{}\[\]()#+!|<>&~]")


def _md_escape(s) -> str:
    """Make untrusted text inert in Markdown and HTML: no tags, links, emphasis, headings or table breaks."""
    s = _CONTROL.sub(" ", str(s))
    return _MD_SPECIAL.sub(lambda m: f"&#{ord(m.group())};", s)


def _code(s) -> str:
    return f"<code>{_md_escape(s)}</code>"


_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(v) -> str:
    """Stop spreadsheets treating untrusted text as a formula."""
    v = "" if v is None else str(v)
    return "'" + v if v.startswith(_CSV_FORMULA) else v


def write_reports(results: list[RepoResult], out_dir: Path, meta: dict) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    paths = {ext: out_dir / f"wfx-scan-{stamp}.{ext}" for ext in ("md", "json", "csv")}
    results = sorted(results, key=lambda r: (STATUS_ORDER.index(r.status), r.name.lower()))

    paths["json"].write_text(json.dumps({"meta": meta, "repositories": [asdict(r) for r in results]}, indent=2))

    with paths["csv"].open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["repository", "repository_status", "check_id", "check", "result", "check_summary",
                    "severity", "finding", "reference"])
        for r in results:
            for c in r.checks or [None]:
                rows = (c.hits if c else None) or [None]
                for h in rows:
                    w.writerow([_csv_cell(x) for x in (
                        r.name, r.status, c.id if c else "", c.title if c else "", c.status if c else "",
                        (c.summary if c else r.error), h.severity if h else "", h.detail if h else "", h.ref if h else "")])

    paths["md"].write_text(_markdown(results, meta))
    return paths


def _markdown(results: list[RepoResult], meta: dict) -> str:
    counts = {s: 0 for s in STATUS_ORDER}
    for r in results:
        counts[r.status] += 1
    L = []
    L += ["# wfx-loot exposure report", "",
          "| | |", "|---|---|",
          f"| Generated | {meta['generated']} |",
          f"| Scanner | wfx-loot-scanner {meta['version']}, IOC set {meta['ioc_set_version']} |",
          f"| Mode | {meta['mode']} |",
          f"| Targets | {_md_escape(', '.join(meta['targets']))} |",
          f"| History window | commits since {meta['since']} (attack began {meta['attack_start']}) |",
          f"| Repositories scanned | {len(results)}" + (f" ({meta['skipped']} skipped: {meta['skipped_reason']})" if meta.get("skipped") else "") + " |",
          f"| Excluded by --exclude | {_md_escape(', '.join(meta.get('excluded') or [])) or 'none'} |",
          f"| GitHub API calls | {meta.get('api_calls', 0)} |", ""]

    L += ["## Summary", "", "| Status | Repositories | Meaning |", "|---|---|---|"]
    L += [f"| {s} | {counts[s]} | {STATUS_MEANING[s]} |" for s in STATUS_ORDER]
    L += [""]

    L += ["## Repositories", "", "| Repository | Status | Pass | Warn | Fail | Skip | Error |", "|---|---|---|---|---|---|---|"]
    for r in results:
        c = r.counts()
        L.append(f"| {_md_escape(r.name)} | {r.status} | {c['PASS']} | {c['WARN']} | {c['FAIL']} | {c['SKIP']} | {c['ERROR']} |")
    L += ["", RESULT_MEANING, ""]

    L += ["## Results by repository", ""]
    for r in results:
        body = _repo_section(r)
        if r.status == "CLEAN":
            c = r.counts()
            L += [f"<details><summary>{_md_escape(r.name)}: CLEAN ({c['PASS']} passed, {c['SKIP']} skipped)</summary>", "",
                  *body, "</details>", ""]
        else:
            L += [f"### {_md_escape(r.name)}: {r.status}", "", *body]

    L += ["## Checks performed", "", "| ID | Check | What it looks for | Data used |", "|---|---|---|---|"]
    for cid, title, what, needs in CHECKS:
        L.append(f"| {cid} | {title} | {_md_escape(what)} | {needs} |")
    L += ["", "Data used: *history* is commit history in the window (local git or API), *tree* is files on branch tips, "
          "*API* is GitHub REST data, *dataset* is SafeDep's published list.", ""]

    L += ["## If a repository is flagged", "",
          "1. Rotate every secret and variable the repository can read, including environment and organisation secrets, "
          "and any cloud role its workflows can assume through OIDC.",
          "2. Revoke the commit or pull request author's personal access tokens, OAuth app grants, SSH keys and sessions, and enforce 2FA. "
          "Any account that opened a probe pull request is compromised even if no payload followed.",
          "3. Delete the `wfx-docs` branch, close the probe pull request and remove any payload still present.",
          "4. Check cloud accounts for persistence: Entra ID federated credentials named `wfx-ci-*`; CloudTrail `AssumeRole` or "
          "`AssumeRoleWithWebIdentity` sessions named `wfx-*` followed by `CreateAccessKey` or `UpdateAssumeRolePolicy`; role trust "
          "policies containing `\"Principal\": {\"AWS\": \"*\"}`; GCP `GenerateAccessToken` and `SignJwt` calls from the GitHub "
          "workload identity pool; Vault JWT logins from the GitHub OIDC issuer.",
          "5. Treat any machine that ran `npm install` on an affected commit as compromised.",
          "6. Withdraw any package version built between the malicious commit and the clean-up commit and publish again from a clean commit.",
          ""]
    L += ["## References", ""]
    L += [f"- {_md_escape(k)}: {_md_escape(v)}" for k, v in meta["sources"].items()]
    return "\n".join(L) + "\n"


def _repo_section(r: RepoResult) -> list[str]:
    L = []
    if r.error:
        L += [f"Error: {_md_escape(r.error)}", ""]
    L += ["| ID | Check | Result | Detail |", "|---|---|---|---|"]
    for c in r.checks:
        n = f" ({len(c.hits)} finding{'s' if len(c.hits) != 1 else ''})" if c.hits else ""
        L.append(f"| {c.id} | {c.title} | {c.status}{n} | {_md_escape(c.summary)} |")
    L.append("")
    findings = [(c, h) for c in r.checks for h in c.hits]
    if findings:
        L += ["Findings:", ""]
        for c, h in findings:
            L.append(f"- **{h.severity}** {c.id}: {_md_escape(h.detail)}" + (f"<br>{_code(h.ref)}" if h.ref else ""))
        L.append("")
    if r.notes:
        L += ["Coverage notes:", ""] + [f"- {_md_escape(n)}" for n in r.notes] + [""]
    return L
