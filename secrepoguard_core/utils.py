"""Utilitarios compartilhados e regras de leitura segura."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

MAX_FILE_SIZE = 1024 * 1024

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    "coverage",
}

TEXT_EXTENSIONS = {
    "",
    ".conf",
    ".cfg",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".properties",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

SPECIAL_TEXT_FILES = {
    ".env",
    ".env.example",
    "dockerfile",
    "package.json",
    "requirements.txt",
}


def is_probably_text(path: Path, sample_size: int = 4096) -> bool:
    """Rejeita arquivos com bytes NUL sem depender de bibliotecas externas."""
    try:
        with path.open("rb") as stream:
            sample = stream.read(sample_size)
    except OSError:
        return False
    return b"\x00" not in sample


def is_supported_text_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in SPECIAL_TEXT_FILES
        or name.startswith(".env.")
        or path.suffix.lower() in TEXT_EXTENSIONS
    )


def iter_project_files(
    root: Path, max_file_size: int = MAX_FILE_SIZE
) -> Iterator[tuple[Path, str | None]]:
    """Produz arquivos e o motivo de descarte, sem seguir links simbolicos."""
    for path in root.rglob("*"):
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            yield path, "fora da raiz analisada"
            continue

        if any(part in IGNORED_DIRECTORIES for part in relative_parts):
            if path.is_file():
                yield path, "diretorio ignorado"
            continue
        if path.is_symlink():
            yield path, "link simbolico"
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_file_size:
                yield path, "arquivo maior que 1 MB"
                continue
        except OSError:
            yield path, "erro ao consultar arquivo"
            continue
        if not is_supported_text_file(path):
            yield path, "extensao nao suportada"
            continue
        if not is_probably_text(path):
            yield path, "possivel arquivo binario"
            continue
        yield path, None


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")
