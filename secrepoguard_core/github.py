"""Validacao e clonagem segura de repositorios publicos do GitHub."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$"
)


class RepositoryError(RuntimeError):
    """Erro compreensivel de validacao ou clonagem."""


def validate_github_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if not GITHUB_URL_RE.fullmatch(normalized):
        raise RepositoryError(
            "URL invalida. Use https://github.com/usuario/repositorio"
        )
    return normalized


def clone_repository(url: str, full_history: bool = False) -> tuple[Path, Path]:
    """Clona o repositorio e retorna (projeto, diretorio temporario)."""
    normalized = validate_github_url(url)
    if shutil.which("git") is None:
        raise RepositoryError(
            "Git nao foi encontrado. Instale o Git ou use --path."
        )

    temporary_root = Path(tempfile.mkdtemp(prefix="secrepoguard_"))
    destination = temporary_root / "repository"
    command = ["git", "clone", "--no-tags"]
    if not full_history:
        command.extend(["--depth", "1"])
    command.extend(["--", normalized, str(destination)])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise RepositoryError("A clonagem excedeu o limite de 120 segundos.") from exc

    if result.returncode != 0:
        shutil.rmtree(temporary_root, ignore_errors=True)
        detail = (result.stderr or "falha desconhecida").strip().splitlines()[-1]
        raise RepositoryError(f"Nao foi possivel clonar o repositorio: {detail}")
    return destination, temporary_root
