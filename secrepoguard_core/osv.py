"""Consulta opcional de vulnerabilidades atuais na API publica OSV.dev."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from . import __version__

OSV_API = "https://api.osv.dev/v1"
USER_AGENT = f"SecRepoGuard/{__version__}"
TIMEOUT_SECONDS = 20


class OsvError(RuntimeError):
    """Falha compreensivel de comunicacao ou resposta do OSV."""


def _request_json(
    url: str,
    payload: dict | None = None,
    opener=None,
) -> dict:
    open_url = opener or urlopen
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST" if data is not None else "GET",
    )
    try:
        with open_url(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise OsvError(f"OSV respondeu com HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise OsvError(f"Nao foi possivel acessar o OSV.dev: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OsvError("O OSV.dev retornou uma resposta JSON invalida.") from exc


def _severity(vulnerability: dict) -> tuple[str, str | None]:
    candidates = [vulnerability.get("database_specific", {}).get("severity")]
    candidates.extend(
        affected.get("database_specific", {}).get("severity")
        for affected in vulnerability.get("affected", [])
    )
    candidates.extend(
        affected.get("ecosystem_specific", {}).get("severity")
        for affected in vulnerability.get("affected", [])
    )
    for candidate in candidates:
        normalized = str(candidate or "").upper()
        if normalized in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}:
            return ("MEDIUM" if normalized == "MODERATE" else normalized), None

    for item in vulnerability.get("severity", []):
        score = str(item.get("score", ""))
        numeric = re.search(r"(?:^|/)(10(?:\.0)?|[0-9](?:\.\d+)?)$", score)
        if numeric:
            value = float(numeric.group(1))
            if value >= 9:
                return "CRITICAL", score
            if value >= 7:
                return "HIGH", score
            if value >= 4:
                return "MEDIUM", score
            if value > 0:
                return "LOW", score
        if score:
            return "UNKNOWN", score
    return "UNKNOWN", None


def _fixed_versions(vulnerability: dict, dependency: dict) -> list[str]:
    fixed = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        if (
            package.get("name", "").lower() != dependency["name"].lower()
            or package.get("ecosystem") != dependency["ecosystem"]
        ):
            continue
        for version_range in affected.get("ranges", []):
            if version_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in version_range.get("events", []):
                if event.get("fixed"):
                    fixed.add(str(event["fixed"]))
    return sorted(fixed)


def _format_finding(vulnerability: dict, dependency: dict) -> dict:
    severity, severity_score = _severity(vulnerability)
    fixed_versions = _fixed_versions(vulnerability, dependency)
    aliases = [str(item) for item in vulnerability.get("aliases", [])]
    references = [
        str(item["url"])
        for item in vulnerability.get("references", [])
        if item.get("url")
    ][:5]
    recommendation = (
        f"Atualize para uma versao corrigida: {', '.join(fixed_versions)}."
        if fixed_versions
        else "Consulte o advisory e atualize para uma versao corrigida."
    )
    return {
        "category": "vulnerability",
        "id": str(vulnerability.get("id", "OSV desconhecido")),
        "aliases": aliases,
        "name": dependency["name"],
        "version": dependency["resolved_version"],
        "ecosystem": dependency["ecosystem"],
        "file": dependency["file"],
        "severity": severity,
        "severity_score": severity_score,
        "summary": str(
            vulnerability.get("summary")
            or vulnerability.get("details")
            or "Vulnerabilidade conhecida sem resumo."
        ).splitlines()[0][:500],
        "fixed_versions": fixed_versions,
        "references": references,
        "published": vulnerability.get("published"),
        "modified": vulnerability.get("modified"),
        "recommendation": recommendation,
    }


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Agrupa registros OSV equivalentes que compartilham IDs ou aliases."""
    groups: list[dict] = []
    severity_rank = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    for finding in findings:
        identifiers = {finding["id"], *finding["aliases"]}
        matching = [
            group
            for group in groups
            if group["dependency_key"]
            == (
                finding["ecosystem"],
                finding["name"].lower(),
                finding["version"],
                finding["file"],
            )
            and group["identifiers"] & identifiers
        ]
        if not matching:
            groups.append(
                {
                    "dependency_key": (
                        finding["ecosystem"],
                        finding["name"].lower(),
                        finding["version"],
                        finding["file"],
                    ),
                    "identifiers": identifiers,
                    "findings": [finding],
                }
            )
            continue

        primary = matching[0]
        primary["identifiers"].update(identifiers)
        primary["findings"].append(finding)
        for extra in matching[1:]:
            primary["identifiers"].update(extra["identifiers"])
            primary["findings"].extend(extra["findings"])
            groups.remove(extra)

    deduplicated = []
    for group in groups:
        candidates = group["findings"]
        preferred = sorted(
            candidates,
            key=lambda item: (
                item["id"].startswith("GHSA-"),
                severity_rank.get(item["severity"], 0),
            ),
            reverse=True,
        )[0].copy()
        preferred["severity"] = max(
            (item["severity"] for item in candidates),
            key=lambda severity: severity_rank.get(severity, 0),
        )
        preferred["aliases"] = sorted(
            group["identifiers"] - {preferred["id"]}
        )
        preferred["fixed_versions"] = sorted(
            {
                version
                for item in candidates
                for version in item["fixed_versions"]
            }
        )
        preferred["references"] = list(
            dict.fromkeys(
                reference
                for item in candidates
                for reference in item["references"]
            )
        )[:5]
        preferred["recommendation"] = (
            "Atualize para uma versao corrigida: "
            + ", ".join(preferred["fixed_versions"])
            + "."
            if preferred["fixed_versions"]
            else "Consulte o advisory e atualize para uma versao corrigida."
        )
        deduplicated.append(preferred)
    return deduplicated


def query_osv(dependencies: list[dict], opener=None) -> dict:
    """Consulta dependencias com versao exata e retorna achados normalizados."""
    queryable = []
    seen_dependencies = set()
    for dependency in dependencies:
        version = dependency.get("resolved_version")
        ecosystem = dependency.get("ecosystem")
        if not version or ecosystem not in {"PyPI", "npm"}:
            continue
        key = (ecosystem, dependency["name"].lower(), version, dependency["file"])
        if key in seen_dependencies:
            continue
        seen_dependencies.add(key)
        queryable.append(dependency)

    if not queryable:
        return {
            "dependencies_queried": 0,
            "dependencies_skipped": len(dependencies),
            "findings": [],
        }

    base_queries = [
        {
            "package": {
                "name": dependency["name"],
                "ecosystem": dependency["ecosystem"],
            },
            "version": dependency["resolved_version"],
        }
        for dependency in queryable
    ]
    payload = {"queries": base_queries}
    batch = _request_json(f"{OSV_API}/querybatch", payload, opener)
    results = batch.get("results")
    if not isinstance(results, list) or len(results) != len(queryable):
        raise OsvError("O OSV.dev retornou um lote com formato inesperado.")

    combined_vulns = [list(result.get("vulns", [])) for result in results]
    pending = [
        (index, result["next_page_token"])
        for index, result in enumerate(results)
        if result.get("next_page_token")
    ]
    page_count = 0
    while pending:
        page_count += 1
        if page_count > 100:
            raise OsvError("O OSV.dev excedeu o limite seguro de paginacao.")
        page_payload = {
            "queries": [
                {**base_queries[index], "page_token": token}
                for index, token in pending
            ]
        }
        page = _request_json(f"{OSV_API}/querybatch", page_payload, opener)
        page_results = page.get("results")
        if not isinstance(page_results, list) or len(page_results) != len(pending):
            raise OsvError("O OSV.dev retornou uma pagina com formato inesperado.")
        next_pending = []
        for (original_index, _token), page_result in zip(pending, page_results):
            combined_vulns[original_index].extend(page_result.get("vulns", []))
            if page_result.get("next_page_token"):
                next_pending.append(
                    (original_index, page_result["next_page_token"])
                )
        pending = next_pending

    vulnerability_ids = {
        str(item["id"])
        for vulnerabilities in combined_vulns
        for item in vulnerabilities
        if item.get("id")
    }

    def fetch_detail(vulnerability_id: str) -> tuple[str, dict]:
        return (
            vulnerability_id,
            _request_json(
                f"{OSV_API}/vulns/{quote(vulnerability_id, safe='')}",
                opener=opener,
            ),
        )

    details = {}
    if vulnerability_ids:
        with ThreadPoolExecutor(
            max_workers=min(12, len(vulnerability_ids))
        ) as executor:
            details = dict(executor.map(fetch_detail, vulnerability_ids))

    findings = []
    seen_findings = set()
    for dependency, vulnerabilities in zip(queryable, combined_vulns):
        for item in vulnerabilities:
            vulnerability_id = str(item.get("id", ""))
            key = (
                vulnerability_id,
                dependency["ecosystem"],
                dependency["name"].lower(),
                dependency["resolved_version"],
                dependency["file"],
            )
            if not vulnerability_id or key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(_format_finding(details[vulnerability_id], dependency))

    return {
        "dependencies_queried": len(queryable),
        "dependencies_skipped": len(dependencies) - len(queryable),
        "findings": _deduplicate_findings(findings),
    }
