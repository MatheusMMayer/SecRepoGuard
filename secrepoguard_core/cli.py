"""Interface argparse do SecRepoGuard."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .github import RepositoryError, clone_repository
from .history import scan_git_history
from .report import build_report, format_text, write_json_report, write_text_report
from .scanner import scan_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrepoguard",
        description=(
            "Auditoria basica de segredos e dependencias em repositorios publicos."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--repo", help="URL publica de um repositorio GitHub.")
    source.add_argument("--path", help="Caminho de um projeto local.")
    parser.add_argument("--output", help="Caminho para o relatorio TXT.")
    parser.add_argument("--json", dest="json_output", help="Caminho para JSON.")
    parser.add_argument(
        "--scan-history",
        action="store_true",
        help="Procura segredos nas linhas adicionadas ao historico Git.",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        default=100,
        metavar="N",
        help="Numero maximo de commits analisados; use 0 para todos (padrao: 100).",
    )

    scans = parser.add_mutually_exclusive_group()
    scans.add_argument(
        "--scan-secrets", action="store_true", help="Analisa apenas segredos."
    )
    scans.add_argument(
        "--scan-dependencies",
        action="store_true",
        help="Analisa apenas dependencias.",
    )
    scans.add_argument("--all", action="store_true", help="Executa todas as analises.")
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Mantem o repositorio clonado na pasta temporaria.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.history_limit < 0:
        parser.error("--history-limit deve ser zero ou um numero positivo.")
    temporary_root: Path | None = None

    scan_secrets = args.scan_secrets or args.all
    scan_dependencies = args.scan_dependencies or args.all
    if not (scan_secrets or scan_dependencies or args.scan_history):
        scan_secrets = scan_dependencies = True

    try:
        if args.repo:
            project_root, temporary_root = clone_repository(
                args.repo, full_history=args.scan_history
            )
            source = args.repo
        else:
            project_root = Path(args.path).expanduser().resolve()
            source = args.path

        scan_result = scan_project(
            project_root,
            scan_secrets=scan_secrets,
            scan_dependencies=scan_dependencies,
        )
        if args.scan_history:
            scan_result["history"] = scan_git_history(
                project_root, limit=args.history_limit
            )
        report = build_report(scan_result, source)
        print(format_text(report), end="")

        if args.output:
            write_text_report(report, Path(args.output))
        if args.json_output:
            write_json_report(report, Path(args.json_output))
        if temporary_root and args.keep:
            print(f"\nRepositorio mantido em: {project_root}")
        return 0
    except (RepositoryError, OSError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    finally:
        if temporary_root and not args.keep:
            shutil.rmtree(temporary_root, ignore_errors=True)
