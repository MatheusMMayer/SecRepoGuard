"""Orquestracao dos scanners sem executar codigo do alvo."""

from __future__ import annotations

from pathlib import Path

from .dependencies import scan_dependency_file
from .secrets import scan_file_for_secrets
from .utils import iter_project_files


def scan_project(
    root: Path, scan_secrets: bool = True, scan_dependencies: bool = True
) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Caminho inexistente ou invalido: {root}")

    result = {
        "files_scanned": 0,
        "files_ignored": 0,
        "ignored_reasons": {},
        "secrets": [],
        "dependencies": [],
        "history": {
            "commits_scanned": 0,
            "commits_skipped": 0,
            "findings": [],
        },
    }
    for path, ignored_reason in iter_project_files(root):
        if ignored_reason:
            result["files_ignored"] += 1
            reasons = result["ignored_reasons"]
            reasons[ignored_reason] = reasons.get(ignored_reason, 0) + 1
            continue

        result["files_scanned"] += 1
        if scan_secrets:
            result["secrets"].extend(scan_file_for_secrets(path, root))
        if scan_dependencies:
            result["dependencies"].extend(scan_dependency_file(path, root))
    return result
