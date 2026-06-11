"""Criacao dos relatorios de terminal, TXT e JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def build_report(scan_result: dict, source: str) -> dict:
    history = scan_result.get(
        "history",
        {"commits_scanned": 0, "commits_skipped": 0, "findings": []},
    )
    vulnerabilities = scan_result.get(
        "vulnerabilities",
        {
            "dependencies_queried": 0,
            "dependencies_skipped": 0,
            "findings": [],
        },
    )
    risky_dependencies = [
        item
        for item in scan_result["dependencies"]
        if item["severity"] in SEVERITIES
    ]
    all_findings = (
        scan_result["secrets"]
        + history["findings"]
        + risky_dependencies
        + vulnerabilities["findings"]
    )
    severity_counts = {
        severity: sum(
            1 for finding in all_findings if finding["severity"] == severity
        )
        for severity in SEVERITIES
    }
    return {
        "tool": "SecRepoGuard",
        "version": __version__,
        "source": source,
        "scanned_at": datetime.now(timezone.utc).astimezone().isoformat(
            timespec="seconds"
        ),
        "notice": (
            "Os achados sao potenciais e precisam de validacao humana. "
            "A base de dependencias e local e nao substitui uma ferramenta SCA."
        ),
        "summary": {
            "files_scanned": scan_result["files_scanned"],
            "files_ignored": scan_result["files_ignored"],
            "potential_secrets": len(scan_result["secrets"]),
            "history_secrets": len(history["findings"]),
            "commits_scanned": history["commits_scanned"],
            "commits_skipped": history["commits_skipped"],
            "dependencies_analyzed": len(scan_result["dependencies"]),
            "dependency_risks": len(risky_dependencies),
            "osv_dependencies_queried": vulnerabilities["dependencies_queried"],
            "osv_dependencies_skipped": vulnerabilities["dependencies_skipped"],
            "known_vulnerabilities": len(vulnerabilities["findings"]),
            "unknown_severity": sum(
                1
                for finding in vulnerabilities["findings"]
                if finding["severity"] == "UNKNOWN"
            ),
            "severity": severity_counts,
            "ignored_reasons": scan_result["ignored_reasons"],
        },
        "secrets": scan_result["secrets"],
        "history_findings": history["findings"],
        "dependencies": scan_result["dependencies"],
        "vulnerabilities": vulnerabilities["findings"],
        "recommendations": [
            "Valide cada achado antes de tomar medidas.",
            "Rotacione credenciais reais expostas e remova-as tambem do historico Git.",
            "Use variaveis de ambiente ou um cofre de segredos.",
            "Atualize dependencias com testes e consulte avisos oficiais de seguranca.",
            "Execute ferramentas especializadas em pipelines CI/CD para maior cobertura.",
        ],
    }


def format_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "SecRepoGuard - Relatorio de Auditoria",
        "=" * 38,
        "",
        f"Origem analisada: {report['source']}",
        f"Data/hora: {report['scanned_at']}",
        f"Arquivos analisados: {summary['files_scanned']}",
        f"Arquivos ignorados: {summary['files_ignored']}",
        f"Segredos potenciais: {summary['potential_secrets']}",
        f"Commits analisados: {summary['commits_scanned']}",
        f"Commits ignorados por tamanho: {summary['commits_skipped']}",
        f"Segredos potenciais no historico: {summary['history_secrets']}",
        f"Dependencias analisadas: {summary['dependencies_analyzed']}",
        f"Dependencias de risco: {summary['dependency_risks']}",
        f"Dependencias consultadas no OSV: {summary['osv_dependencies_queried']}",
        f"Dependencias sem versao exata: {summary['osv_dependencies_skipped']}",
        f"Vulnerabilidades conhecidas: {summary['known_vulnerabilities']}",
        "",
        "Resumo por severidade:",
        f"CRITICAL: {summary['severity']['CRITICAL']}",
        f"HIGH: {summary['severity']['HIGH']}",
        f"MEDIUM: {summary['severity']['MEDIUM']}",
        f"LOW: {summary['severity']['LOW']}",
        f"UNKNOWN: {summary['unknown_severity']}",
        "",
        f"AVISO: {report['notice']}",
        "",
        "Segredos potenciais:",
    ]
    if not report["secrets"]:
        lines.append("Nenhum potencial segredo encontrado.")
    for finding in report["secrets"]:
        lines.extend(
            [
                f"[{finding['severity']}] {finding['type']}",
                f"Arquivo: {finding['file']}",
                f"Linha: {finding['line']}",
                f"Trecho: {finding['snippet']}",
                f"Recomendacao: {finding['recommendation']}",
                "",
            ]
        )

    lines.append("Segredos potenciais no historico Git:")
    if not report["history_findings"]:
        lines.append("Nenhum potencial segredo encontrado no historico analisado.")
    for finding in report["history_findings"]:
        lines.extend(
            [
                f"[{finding['severity']}] {finding['type']}",
                f"Commit: {finding['commit']}",
                f"Arquivo: {finding['file']}",
                f"Linha adicionada: {finding['line']}",
                f"Trecho: {finding['snippet']}",
                f"Recomendacao: {finding['recommendation']}",
                "",
            ]
        )

    lines.append("Dependencias de risco:")
    risks = [
        item
        for item in report["dependencies"]
        if item["severity"] in SEVERITIES
    ]
    if not risks:
        lines.append("Nenhuma dependencia de risco identificada pela base local.")
    for finding in risks:
        lines.extend(
            [
                f"[{finding['severity']}] {finding['name']} {finding['version']}",
                f"Arquivo: {finding['file']}",
                f"Motivo: {finding['reason']}",
                f"Recomendacao: {finding['recommendation']}",
                "",
            ]
        )

    lines.append("Vulnerabilidades atuais consultadas no OSV.dev:")
    if not report["vulnerabilities"]:
        lines.append("Nenhuma vulnerabilidade conhecida retornada pelo OSV.")
    for finding in report["vulnerabilities"]:
        aliases = ", ".join(finding["aliases"]) or "nenhum"
        fixed = ", ".join(finding["fixed_versions"]) or "nao informado"
        lines.extend(
            [
                (
                    f"[{finding['severity']}] {finding['id']} - "
                    f"{finding['name']} {finding['version']}"
                ),
                f"Ecossistema: {finding['ecosystem']}",
                f"Arquivo: {finding['file']}",
                f"Aliases: {aliases}",
                f"Resumo: {finding['summary']}",
                f"Versoes corrigidas: {fixed}",
                f"Recomendacao: {finding['recommendation']}",
            ]
        )
        if finding["references"]:
            lines.append(f"Referencia: {finding['references'][0]}")
        lines.append("")

    lines.extend(["Recomendacoes gerais:"])
    lines.extend(f"- {item}" for item in report["recommendations"])
    return "\n".join(lines).rstrip() + "\n"


def write_text_report(report: dict, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(format_text(report), encoding="utf-8")


def write_json_report(report: dict, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
