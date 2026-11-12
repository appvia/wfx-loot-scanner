"""Builds throwaway git repositories that contain (inert) campaign indicators."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
       "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com"}

PAYLOAD_SCRIPT = "#!/bin/sh\n# inert test fixture\nexport WF_CALLBACK='http://194.150.166.244:8080/exfil'\n"
INJECTED_STEPS = "\n".join(f"      - run: echo step{i}" for i in range(1500)) + (
    "\n      - name: Restore cache j632\n        env:\n          WF_CALLBACK: \"http://18.143.168.96:8080/exfil\"\n"
    "          WF_CTOKEN: \"b42d70a7aab9140ca19e8249\"\n        run: echo '<!--WFX-BEGIN-->'\n")


def sh(repo: Path, *args, date: str | None = None):
    env = dict(ENV)
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), *args], env=env, check=True, capture_output=True)


def write(repo: Path, path: str, text: str | bytes):
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text if isinstance(text, bytes) else text.encode())


def commit(repo: Path, msg: str, date: str):
    sh(repo, "add", "-A")
    sh(repo, "commit", "-q", "--allow-empty", "-m", msg, date=date)


def build_infected(root: Path) -> Path:
    repo = root / "infected"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    write(repo, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n")
    write(repo, "package.json", json.dumps({"name": "x", "scripts": {"test": "vitest"}}, indent=2))
    write(repo, "go.mod", "module example.com/x\n\nrequire github.com/onuragtas/docker-env v1.0.280\n")
    commit(repo, "initial", "2026-10-05T10:00:00Z")

    # Variant 1: workflow injection, reverted shortly after
    original = (repo / ".github/workflows/ci.yml").read_text()
    write(repo, ".github/workflows/ci.yml", original + INJECTED_STEPS)
    commit(repo, "ci: refresh build cache", "2026-11-10T14:01:00Z")
    write(repo, ".github/workflows/ci.yml", original)
    commit(repo, "ci: restore", "2026-11-10T14:05:00Z")

    # Variant 2: npm postinstall hook, left in place
    write(repo, ".ci-dwgd2n.sh", PAYLOAD_SCRIPT)
    write(repo, "package.json", json.dumps({"name": "x", "scripts": {
        "test": "vitest", "postinstall": "sh ./.ci-dwgd2n.sh >/dev/null 2>&1; _r=$?; if [ \"$_r\" -eq 42 ]; then exit 42; fi"}}, indent=2))
    commit(repo, "chore: add ci helper", "2026-11-10T15:00:00Z")

    # GhostAction: JavaScript pretending to be a font
    write(repo, "public/fonts/fa-solid-400.woff2", "fetch('http://193.32.204.199:8080')")
    commit(repo, "assets", "2026-10-20T09:00:00Z")

    # Variant 3: throwaway branch with a new workflow
    sh(repo, "checkout", "-q", "-b", "chore/k3j9x2ab")
    write(repo, ".github/workflows/build-audit-m8bnpk.yml",
          "name: Dependency Audit y82c\non: push\njobs:\n  audit_base:\n    steps:\n      - name: Pass runtime\n")
    commit(repo, "chore: add dependency audit workflow", "2026-11-10T16:00:00Z")

    # Probe branch
    sh(repo, "checkout", "-q", "main")
    sh(repo, "checkout", "-q", "-b", "wfx-docs")
    write(repo, "docs/wfx-audit.md", "Routine supply-chain review notes.\n")
    commit(repo, "docs: dependency audit notes", "2026-11-10T12:50:00Z")
    sh(repo, "checkout", "-q", "main")
    return repo


def build_clean(root: Path) -> Path:
    repo = root / "clean"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    write(repo, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n")
    write(repo, "public/fonts/fa-solid-400.woff2", b"wOF2\x00\x01real font")
    commit(repo, "feat: add ci", "2026-11-01T10:00:00Z")
    write(repo, "README.md", "hello\n")
    commit(repo, "chore: initial commit", "2026-11-11T10:00:00Z")  # benign: does not touch CI
    sh(repo, "checkout", "-q", "-b", "feature/login")
    commit(repo, "ci: cleanup", "2026-11-11T11:00:00Z")  # benign: touches nothing
    sh(repo, "checkout", "-q", "main")
    return repo
