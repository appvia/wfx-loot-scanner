# Check reference

Every check reports one of PASS, WARN, FAIL, SKIP or ERROR, with a one-line summary of what it covered (for example "412 commits since 2026-10-01 inspected"). Findings carry a severity:

| Severity | Effect |
|---|---|
| CRITICAL | check FAILs; repository is LIKELY COMPROMISED |
| HIGH | check FAILs; repository is at least SUSPICIOUS |
| MEDIUM | check WARNs; repository is at least REVIEW |
| LOW | listed for context only; no effect on results |

"Window" means commits whose committer date is on or after `--since` (default 2026-10-01). "Attack window" means on or after 10 November 2026 12:45 UTC, when the campaign began.

Sources: **A** is Aikido, **S** is SafeDep. Full links are in the [README](../README.md#the-incident).

---

## WFX-01 Probe pull requests

**Looks for:** pull requests (open, closed or merged) updated within the window that:

- are titled `docs: dependency audit notes`, or
- come from a branch named `wfx-docs`, or
- contain the probe body text `Routine dependency audit notes.`

**Severity:** CRITICAL for the title or branch, HIGH for the body text alone.

**Why:** the probe confirms the stolen token can write. Both sources say the PR author's account is compromised even if no payload followed, so the finding names the account. (A, S)

**Needs:** API (Pull requests: read).

## WFX-02 Campaign branch names

**Looks for:** branches, and head branches of pull requests whose branch has since been deleted, matching:

| Pattern | Severity |
|---|---|
| `wfx-docs` | CRITICAL |
| `ci-check-NNNN` (4 digits) | HIGH |
| `chore/xxxxxxxx` (8 lower-case letters or digits) | MEDIUM, or LOW if all letters |

**False positives:** `chore/` plus 8 characters can be a real name such as `chore/upgrades`. Random names almost always contain a digit, so all-letter names are LOW. (A)

## WFX-03 Campaign commit messages

**Looks for:** commit subjects used by the attacker, on every branch read.

| Subject | Severity if it touches CI files | Otherwise |
|---|---|---|
| `chore: add ci helper` | CRITICAL | MEDIUM |
| `chore: add dependency audit workflow` | CRITICAL | HIGH |
| `ci: refresh build cache` | HIGH | MEDIUM |
| `docs: dependency audit notes` | HIGH | HIGH |
| `ci: restore`, `ci: cleanup`, `chore: initial commit` | MEDIUM, attack window only | not reported |

"CI files" means `.github/workflows/*`, any `package.json`, or a payload path. The clean-up subjects are common, so they only count when they are in the attack window and touch CI files.

Also reports commits by accounts whose tokens are known to have been used (`wdio-bot`, MEDIUM). (A, S)

## WFX-04 Payload files in history

**Looks for:** files changed in the window at these paths:

| Path | Severity |
|---|---|
| `.ci-xxxxxx.sh` (any directory) | CRITICAL |
| `.github/workflows/build-audit-xxxxxx.yml` | CRITICAL |
| `docs/wfx-audit.md` (probe file) | HIGH |

(A, S)

## WFX-05 Large workflow insertion

**Looks for:** one commit adding 1,000 or more lines to a workflow file. The injected payload is about 1,500 lines.

**Severity:** HIGH in the attack window or with a campaign subject, MEDIUM otherwise. (A, S)

## WFX-06 Exfiltration endpoints and tokens

**Looks for**, in added and removed diff lines, so reverted payloads are still caught:

| Indicator | Severity |
|---|---|
| exfiltration servers `194.150.166.244`, `18.143.168.96`, `153.75.82.159` | CRITICAL |
| `WF_CTOKEN` campaign tokens (3) | CRITICAL |
| attacker Telegram chat ID and bot IDs (5) | CRITICAL |
| `api.telegram.org` in workflows, `package.json` or shell scripts | MEDIUM (often a legitimate notification) |

Only the numeric bot ID part of each Telegram bot token is stored, so the repository does not contain the attacker's credentials. (A, S)

## WFX-07 Payload markers

**Looks for**, in added and removed lines:

| Indicator | Severity |
|---|---|
| `wfx-loot`, `WFX-BEGIN`, `wfx-ci-`, `.wfx-`, `/tmp/wfx-scan-`, `RUNNER_TEMP/wfx-` | CRITICAL |
| payload configuration variables: `WF_CALLBACK`, `WF_CTOKEN`, `WF_TG_BOTS`, `WF_TG_CHAT`, `WF_MEMSCAN`, `WF_EXFIL_*`, `WF_PRIVATE`, `WF_FALLBACK`, `WF_MAXFILES`, `WF_TARBALL` | HIGH |
| workflow name `Dependency Audit xxxx` or step `Pass runtime` in a workflow | HIGH |

(A, S)

## WFX-08 npm postinstall hook

**Looks for:** any added or removed line referencing `.ci-xxxxxx.sh`, which is how the `postinstall` hook calls the payload. CRITICAL.

The hook also runs on developer machines during `npm install`. (A, S)

## WFX-09 Known payload hashes

**Looks for:** SHA-256 of candidate files compared with the published hashes. Candidate files are:

- payload paths
- workflow files with large insertions
- workflow files, shell scripts and `package.json` in commits already flagged at HIGH or above

Up to 200 files per repository are hashed. A match is CRITICAL. A non-match proves nothing, because the payload varies between repositories. (A, S)

## WFX-10 Known attacker commits

**Looks for:** published attacker commit SHAs. In API mode GitHub resolves commits across a fork network, so this also catches forks of affected repositories. CRITICAL. (S)

## WFX-11 Affected package versions

**Looks for:** `composer.lock`, `go.mod` and `go.sum` on branch tips pinning a published malicious version. HIGH.

| Package | Versions |
|---|---|
| `digitalelvis/neuronai-studio` (Packagist) | 3.14.3 |
| `github.com/vkuznet/gocurl` | v0.0.0-20261111095532-8d5aad0cb0da |
| `github.com/onuragtas/redock`, `github.com/onuragtas/docker-env` | v1.0.278, v1.0.280, v1.0.282 |

Branch tips are the default branch in API mode and up to 50 branches in clone mode. Up to 100 manifest files per repository are read. (A, S)

## WFX-12 Payload files on branch tips

**Looks for**, on branch tips:

- payload files (as in WFX-04) still present
- a `package.json` whose `preinstall`, `install`, `postinstall` or `prepare` script runs `.ci-xxxxxx.sh` (CRITICAL)

Up to 50 `package.json` files per repository are parsed, ignoring `node_modules/`. Both sources found repositories where the attacker never reverted.

## WFX-13 Actions cache entries

**Looks for:** GitHub Actions cache keys starting `wfx-`, one of the payload's exfiltration channels. CRITICAL.

**Needs:** Actions: read. SKIP if Actions is disabled or the token lacks access.

The deployed configuration had this channel switched off, so finding nothing here does not rule out theft. (A)

## WFX-14 Workflow artefacts

**Looks for:** artefacts created in the window named `wfx-loot-*`. CRITICAL. The same caveat as WFX-13 applies. (A)

## WFX-15 Deleted workflow runs

**Looks for:** gaps in each workflow's run numbers among runs created since the attack began. A gap means runs were deleted. MEDIUM.

Aikido calls this the most reliable sign that the payload ran, because the attacker deletes the run and its logs. People also delete runs, so treat it as supporting evidence. Only the first 1,000 runs are read. (A)

## WFX-16 Flagged commits with no run

**Looks for:** commits flagged at HIGH or above, in the attack window, that have no workflow run. HIGH.

This is consistent with the run having been deleted. It also happens when no workflow was triggered, for example a push to a branch with no matching workflow. (A)

## WFX-17 SafeDep affected list

**Looks for:** the repository in SafeDep's list of repositories that received malicious commits. The list is downloaded at run time. CRITICAL.

The list covers the default branches of public repositories only. SKIP if the download fails or `--no-dataset` is set. (S)

## WFX-18 GhostAction (October) indicators

Accounts hit by the October GhostAction wave were far more likely to be used in this one, and in more than 100 repositories the new payload was added to GhostAction's workflow files. This check looks for:

| Indicator | Severity |
|---|---|
| `193.32.204.199` or the `#ghc2` cron tag in any diff | CRITICAL |
| `public/fonts/fa-solid-400.woff2` that does not start with the WOFF2 signature (the real Font Awesome file does) | CRITICAL |
| a VS Code task with `"runOn": "folderOpen"` in `.vscode/tasks.json` | MEDIUM |

(A)
