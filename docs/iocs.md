# Updating the indicators

All indicators live in [`wfxscan/data/iocs.json`](../wfxscan/data/iocs.json). Code changes are only needed for a new kind of check.

When you change it:

1. Add the source to the entry's `source` field.
2. Bump `ioc_set_version` to the date of the newest source used.
3. Run `python3 -m unittest`. One test checks that every content regex works in both Python and `git log -G`.

## Regular expressions

Content patterns are used by Python (API mode) and by `git log -G` (clone and path modes), which uses POSIX extended regular expressions. Stick to the common subset:

- Allowed: literals, `.`, `\.`, `[a-z0-9]`, `{n}`, `*`, `+`, `?`, `|`, `( )`, `^`, `$`.
- Not allowed: `\s`, `\d`, `\w`, `\b`, look-arounds, non-greedy quantifiers, `(?i)`.

## Fields

| Key | Used by | Notes |
|---|---|---|
| `attack_start` | WFX-03, WFX-05, WFX-15, WFX-16 | start of the attack window |
| `default_since` | all history checks | default for `--since` |
| `probe` | WFX-01 | PR titles, body text and head branches |
| `branch_patterns` | WFX-02 | `regex`, `severity`; `low_if_all_letters` downgrades all-letter matches to LOW |
| `commit_subjects` | WFX-03 | `severity_ci` when the commit touches CI files, `severity_other` otherwise (null means not reported); `window_only` limits it to the attack window |
| `compromised_authors` | WFX-03 | login prefixes |
| `payload_paths` | WFX-04, WFX-09, WFX-12 | path regex |
| `large_workflow_insertion_lines` | WFX-05, WFX-09 | threshold |
| `content` | WFX-06, WFX-07, WFX-08, WFX-18 | `check` assigns the pattern to a check; optional `paths` limits it to paths starting or ending with one of the values |
| `sha256` | WFX-09 | lower-case hex |
| `commits` | WFX-10 | full SHAs |
| `packages` | WFX-11 | `ecosystem` is `packagist` (composer.lock) or `go` (go.mod, go.sum) |
| `actions` | WFX-13, WFX-14 | cache key and artefact name prefixes |
| `ghostaction_font_path` | WFX-18 | file checked for the WOFF2 signature |
| `sources` | report | listed under References |

## Things deliberately left out

- **Attacker Telegram bot tokens.** Only the numeric bot ID is stored, so the repository does not hold live credentials and GitHub secret scanning does not block pushes.
- **Go module zip hashes** from SafeDep's list. `go.sum` records `h1:` hashes, not SHA-256 of the zip, so these cannot be matched. WFX-11 checks the versions instead.
- **The `Restore cache xxxx` step name.** It matches too many real workflows.
