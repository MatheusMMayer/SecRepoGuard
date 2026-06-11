"""Analise de potenciais segredos adicionados ao historico Git."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .github import RepositoryError
from .secrets import scan_text_for_secrets

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
MAX_DIFF_SIZE = 5 * 1024 * 1024


def _run_git(repository: Path, arguments: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepositoryError(
            f"A leitura do historico excedeu o limite de {timeout} segundos."
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or "falha desconhecida").strip().splitlines()[-1]
        raise RepositoryError(f"Falha ao ler o historico Git: {detail}")
    return result.stdout


def _added_lines(diff: str) -> list[tuple[str, int, str]]:
    additions: list[tuple[str, int, str]] = []
    current_file = ""
    new_line = 0

    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            current_file = path[2:] if path.startswith("b/") else path
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if not current_file or not new_line:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            additions.append((current_file, new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            continue
        elif not line.startswith("\\"):
            new_line += 1
    return additions


def scan_git_history(repository: Path, limit: int = 100) -> dict:
    if not (repository / ".git").exists():
        raise RepositoryError(
            "--scan-history exige um repositorio Git local ou clonado."
        )

    revision_args = ["rev-list", "--all"]
    if limit > 0:
        revision_args.append(f"--max-count={limit}")
    commits = [
        line.strip()
        for line in _run_git(repository, revision_args).splitlines()
        if line.strip()
    ]

    findings: list[dict] = []
    skipped_commits = 0
    seen = set()
    for commit in commits:
        diff = _run_git(
            repository,
            [
                "show",
                "--format=",
                "--no-ext-diff",
                "--no-renames",
                "--unified=0",
                commit,
                "--",
            ],
        )
        if len(diff.encode("utf-8", errors="replace")) > MAX_DIFF_SIZE:
            skipped_commits += 1
            continue

        for file_name, line_number, content in _added_lines(diff):
            for finding in scan_text_for_secrets(content, file_name):
                key = (commit, file_name, line_number, finding["type"])
                if key in seen:
                    continue
                seen.add(key)
                finding["line"] = line_number
                finding["commit"] = commit[:12]
                finding["origin"] = "git_history"
                findings.append(finding)

    return {
        "commits_scanned": len(commits),
        "commits_skipped": skipped_commits,
        "findings": findings,
    }
