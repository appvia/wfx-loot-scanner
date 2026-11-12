<a href="https://www.appvia.io/"><img src="docs/assets/appvia-banner.png" alt="Appvia" width="100%"></a>

<p align="center">
  <a href="https://www.appvia.io/"><img src="https://img.shields.io/static/v1?label=APPVIA&message=Security%20Tooling&labelColor=022859&color=1578E4&style=for-the-badge" alt="Appvia Security Tooling"></a>
  <a href="https://github.com/appvia/wfx-loot-scanner/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/appvia/wfx-loot-scanner/ci.yml?branch=main&label=CI&labelColor=022859&style=for-the-badge" alt="CI"></a>
  <a href="https://github.com/appvia/wfx-loot-scanner/blob/main/LICENSE"><img src="https://img.shields.io/github/license/appvia/wfx-loot-scanner?label=licence&labelColor=022859&color=1578E4&style=for-the-badge" alt="Licence"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1578E4?labelColor=022859&logo=python&logoColor=white&style=for-the-badge" alt="Python 3.10+">
  <a href="https://appvia-community.slack.com/join/shared_invite/zt-1s7i7xy85-T155drryqU56emm09ojMVA#/shared-invite/email"><img src="https://img.shields.io/badge/Slack-Join%20Community-1578E4?labelColor=022859&logo=slack&style=for-the-badge" alt="Slack Community"></a>
</p>

# wfx-loot-scanner

Checks GitHub organisations and repositories for signs of the **wfx-loot** campaign: a CI secret stealer pushed into tens of thousands of repositories using stolen GitHub credentials, starting 10 November 2026 at 12:45 UTC.

It runs 18 checks per repository and writes a Markdown, JSON and CSV report showing the result of every check, not just the hits.

- No third-party dependencies: Python 3.10+ and git.
- Read-only. It never writes to GitHub and never executes repository content.
- Works through the GitHub API alone, or from mirror clones for larger estates.

## The incident

For each repository a stolen token can write to, the attacker:

1. **Probes** with a pull request titled `docs: dependency audit notes` from a `wfx-docs` branch. Any account that opened one is compromised, even if nothing followed.
2. **Pushes the payload** in one of three ways:
   - `ci: refresh build cache` adds about 1,500 lines to an existing workflow.
   - `chore: add ci helper` adds `.ci-xxxxxx.sh` and an npm `postinstall` hook that runs it, including on developer machines.
   - `chore: add dependency audit workflow` adds `.github/workflows/build-audit-xxxxxx.yml` on a `chore/xxxxxxxx` branch.
3. **Cleans up**: reverts within minutes (`ci: restore`, `ci: cleanup`) and deletes the workflow run and its logs. A missing run number is often the only trace.

The payload takes every secret, variable and token the workflow can reach, exchanges GitHub OIDC tokens for AWS, GCP and Azure sessions, and tries to leave persistence that survives rotation: AWS role trust policies opened to `*`, new IAM access keys, and Entra ID federated credentials named `wfx-ci-*`.

Primary sources:

- Aikido Security (first report): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories
- SafeDep (independent analysis and IOC data): https://safedep.io/blog/github-actions-wfx-credential-stealer
  - IOC list: https://safedep.io/data/blogs/wfx-github-actions-iocs.csv
  - Affected repositories: https://safedep.io/data/blogs/wfx-github-actions-affected-repositories.csv

The indicators this tool uses are in [`wfxscan/data/iocs.json`](wfxscan/data/iocs.json), with the source of each. See [docs/checks.md](docs/checks.md) for what each check does and [docs/iocs.md](docs/iocs.md) for how to update the indicators.

## Requirements

| Requirement | Version | Needed for |
|---|---|---|
| Python | 3.10 or later | everything |
| git | 2.30 or later | `--mode clone` and `--path` |
| GitHub token | see below | `--org`, `--repo`, and the API checks for `--path` |
| `gh` CLI | any recent | optional, as a token source |

There is nothing to install. Run `./wfx-scan` from a checkout, or install it as a command:

```sh
pipx install .        # or: pip install .
wfx-scan --help
```

## Authentication

The token is taken from, in order:

1. `GH_TOKEN`
2. `GITHUB_TOKEN`
3. `gh auth token` (the active `gh` account, or the one named with `--gh-user`)

If you have several GitHub identities in `gh`, for example a personal account and an Enterprise Managed User, pick one without switching:

```sh
gh auth login -h github.com          # add an account
gh auth status                       # list accounts
./wfx-scan --gh-user my-emu-account --org my-org
```

### Permissions

The scanner only reads. Give it the least access that covers the repositories you want to scan.

**Fine-grained personal access token** (recommended). One token per organisation.

| Setting | Value |
|---|---|
| Resource owner | the organisation |
| Repository access | All repositories |
| Repository permissions | Metadata: read, Contents: read, Pull requests: read, Actions: read |
| Organisation permissions | none |

Some organisations must approve fine-grained tokens before they work.

**Classic personal access token or `gh` login**: the `repo` scope. Public repositories only need a token with no scopes.

**GitHub App**: an installation token with the same repository permissions as the fine-grained token, passed as `GH_TOKEN`.

**SAML single sign-on**: classic tokens must be authorised for the organisation (Settings, Developer settings, Personal access tokens, Configure SSO). Tokens created by `gh auth login` in a browser are normally authorised as part of the login.

What each permission is used for:

| Permission | Used by |
|---|---|
| Metadata | listing repositories and branches |
| Contents | commits, diffs, trees and file contents (WFX-02 to WFX-12, WFX-18); mirror clones |
| Pull requests | probe pull requests and their commits (WFX-01, WFX-02) |
| Actions | caches, artefacts and workflow runs (WFX-13 to WFX-16) |

If a permission is missing, the affected checks are marked SKIP or ERROR in the report rather than silently passing.

## Usage

```sh
# Every repository in one or more organisations, through the API only
./wfx-scan --org my-org --org my-other-org

# Mirror-clone first, then scan with git (faster for large organisations)
./wfx-scan --mode clone --org my-org

# Specific repositories
./wfx-scan --repo my-org/service-a --repo my-org/service-b

# Existing local clones (fetch them first; API checks run if origin is on GitHub and a token is available)
./wfx-scan --path ~/src/service-a

# Fully offline, local clones only
./wfx-scan --offline --path ~/src/service-a
```

Options:

| Option | Default | Description |
|---|---|---|
| `--org OWNER` | | Organisation or user; repeatable |
| `--repo OWNER/NAME` | | Single repository; repeatable |
| `--path DIR` | | Existing local clone, scanned as-is; repeatable |
| `--mode api\|clone` | `api` | Where history is read from (see below) |
| `--since YYYY-MM-DD` | `2026-10-01` | Start of the history window. The default also covers the October GhostAction wave |
| `--include-archived` | off | Archived repositories are read-only, so they are skipped by default |
| `--jobs N` | 4 | Repositories scanned in parallel |
| `--out DIR` | `./reports` | Report directory |
| `--workdir DIR` | `./work` | Mirror clones for `--mode clone` |
| `--github-url URL` | `https://github.com` | GitHub Enterprise Server base URL |
| `--gh-user LOGIN` | | Use this `gh` account's token |
| `--max-branches N` | 100 | API mode: branches whose history is read |
| `--max-commits N` | 3000 | API mode: commits inspected per repository |
| `--no-dataset` | off | Do not download SafeDep's affected-repositories list (WFX-17 is skipped) |
| `--offline` | off | No network access; only valid with `--path` |

### API mode or clone mode?

Cloning is not required. Both modes run the same checks and should agree.

| | `--mode api` (default) | `--mode clone` |
|---|---|---|
| Local storage | none | a bare mirror of every repository in `--workdir` |
| Speed | slower: about two API calls per commit in the window | fast after the first clone |
| API usage | high. Roughly 10 calls per repository plus 2 per commit | about 5 calls per repository |
| History | commits since `--since` on up to 100 branches, plus commits on pull requests | every ref, including `refs/pull/*` |
| Branch tip checks (WFX-11, WFX-12) | default branch only | up to 50 branches |
| Very large commits | first 300 files per commit | complete |

Use API mode for a quick look or a small estate. Use clone mode for hundreds of repositories, a long `--since` window, or when you need every branch checked. As a guide, 40 repositories with about 780 commits in the window took 3 minutes and 1,574 API calls in API mode, and 27 seconds and 163 API calls in clone mode.

The REST API allows 5,000 requests an hour for a user token. The scanner waits and retries when it hits a rate limit.

## Output

Each run writes three files to `--out`, named `wfx-scan-YYYYMMDD-HHMMSS.*`:

- **`.md`**: run details, a status summary, a table of every repository with pass, warn, fail, skip and error counts, the result of every check for every repository with findings and coverage notes, a description of each check, and what to do if a repository is flagged. Clean repositories are collapsed.
- **`.json`**: the same data, for tooling.
- **`.csv`**: one row per check per repository, plus one row per finding, for spreadsheets.

Repository status:

| Status | Meaning |
|---|---|
| LIKELY COMPROMISED | at least one critical indicator |
| SUSPICIOUS | at least one high-severity indicator |
| REVIEW | medium-severity indicators only; often benign |
| INCOMPLETE | nothing found, but at least one check could not run |
| CLEAN | every check that could run found nothing |

Check result: PASS (nothing found), WARN (medium findings), FAIL (high or critical findings), SKIP (not applicable or no access), ERROR (the check failed to run). Low-confidence findings are listed but do not change a result.

Reports contain repository names, commit details and account names. Treat them as sensitive. `reports/` is git-ignored.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | all repositories CLEAN |
| 1 | at least one REVIEW or INCOMPLETE, none worse |
| 2 | at least one SUSPICIOUS or LIKELY COMPROMISED |
| 64 | usage error |

## If something is flagged

1. Rotate every secret and variable the repository can read, including environment and organisation secrets, and anything its workflows can reach through OIDC.
2. Revoke the author's tokens, OAuth app grants, SSH keys and sessions, and enforce 2FA.
3. Delete the `wfx-docs` branch, close the probe pull request and remove any payload still present.
4. Check cloud accounts for persistence:
   - Entra ID: federated credentials named `wfx-ci-*` that you did not create.
   - AWS CloudTrail: `AssumeRole` or `AssumeRoleWithWebIdentity` with session name `wfx-*`, followed by `CreateAccessKey` or `UpdateAssumeRolePolicy`. Role trust policies containing `"Principal": {"AWS": "*"}`.
   - GCP: `GenerateAccessToken` and `SignJwt` calls from the GitHub workload identity pool.
   - Vault: JWT logins from the GitHub OIDC issuer.
5. Treat any machine that ran `npm install` on an affected commit as compromised.
6. Withdraw package versions built between the malicious commit and the clean-up commit.

## Limitations

- Indicators are a snapshot (see `ioc_set_version` in `iocs.json`). The campaign was still active when the sources were published.
- A branch deleted without a pull request leaves nothing to find in either mode, apart from commits that are still reachable elsewhere. Force-pushed history is gone.
- Run-number gaps (WFX-15) also appear when people delete runs. Use them to support other findings, not on their own.
- The scanner looks at repositories only. It does not read the organisation audit log or cloud logs; do that separately (see above).
- SafeDep's list covers default branches of public repositories only.

## How the scanner protects itself

- Repository content is only read and pattern-matched, never run.
- git runs with global and system config ignored (so `insteadOf` rewrites, credential helpers and diff drivers do not apply), hooks and fsmonitor disabled.
- Clone mode uses bare mirrors, so nothing is checked out.
- The token is passed to git through the environment, not the command line.

## Development

```sh
python3 -m unittest -v
```

The tests build throwaway repositories containing inert copies of the indicators and run every check against them, along with a clean control repository and a fake GitHub API for API mode. CI runs them on Python 3.10 and 3.13.

Layout:

```
wfx-scan                 launcher (no install needed)
wfxscan/
  cli.py                 arguments, target discovery, mirror cloning, parallel runner
  checks.py              the 18 checks and result model
  sources.py             git and GitHub API data sources (same interface)
  github.py              minimal REST client with pagination and rate-limit handling
  iocs.py                loads and compiles the indicator set
  report.py              Markdown, JSON and CSV output
  data/iocs.json         indicators, with sources
tests/                   unittest suite and fixtures
docs/                    check reference, IOC format and brand assets
```

## Licence

Copyright 2026 [Appvia Ltd](https://www.appvia.io/). Licensed under the [Apache License, Version 2.0](LICENSE).

Indicators of compromise are taken from the public research by Aikido Security and SafeDep linked above, with credit to them. The Appvia logo is a trademark of Appvia Ltd and is not covered by the licence.

---

<p align="center">Built by <a href="https://www.appvia.io/">Appvia</a>. Get there faster.</p>

