"""Analise local e deterministica de dependencias."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .utils import read_text

RISK_DATABASE = {
    "python": {
        "django": ("3.2", "HIGH"),
        "flask": ("1.0", "MEDIUM"),
        "requests": ("2.20", "MEDIUM"),
        "pyyaml": ("5.4", "MEDIUM"),
        "cryptography": ("3.4", "MEDIUM"),
    },
    "javascript": {
        "lodash": ("4.17.21", "HIGH"),
        "express": ("4.17.0", "MEDIUM"),
        "axios": ("0.21.1", "MEDIUM"),
        "minimist": ("1.2.6", "HIGH"),
        "jquery": ("3.5.0", "MEDIUM"),
    },
}

REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|>=|~=)\s*"
    r"([0-9]+(?:\.[0-9]+)*(?:[A-Za-z0-9_.-]*)?)"
)
VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")
EXACT_VERSION_RE = re.compile(
    r"^[vV]?(\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?)$"
)


def version_tuple(version: str) -> tuple[int, ...] | None:
    match = VERSION_RE.search(version)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_version_below(found: str, minimum: str) -> bool:
    current = version_tuple(found)
    required = version_tuple(minimum)
    if current is None or required is None:
        return False
    width = max(len(current), len(required))
    return current + (0,) * (width - len(current)) < required + (0,) * (
        width - len(required)
    )


def _evaluate(
    name: str,
    version: str,
    ecosystem: str,
    source: Path,
    root: Path | None,
    exact_version: str | None = None,
) -> dict:
    normalized_name = name.lower().replace("_", "-")
    rule = RISK_DATABASE[ecosystem].get(normalized_name)
    relative = str(source.relative_to(root)) if root else str(source)
    result = {
        "category": "dependency",
        "name": name,
        "version": version,
        "resolved_version": exact_version,
        "ecosystem": "PyPI" if ecosystem == "python" else "npm",
        "file": relative,
        "severity": "NONE",
        "status": "not_evaluated",
        "reason": "Dependencia sem regra na base local.",
        "recommendation": "Consulte fontes oficiais e mantenha a dependencia atualizada.",
    }
    if not rule:
        return result

    minimum, severity = rule
    if version_tuple(version) is None:
        result.update(
            {
                "severity": "LOW",
                "status": "unresolved",
                "reason": "Nao foi possivel determinar uma versao numerica fixa.",
                "recommendation": (
                    f"Revise a restricao e use ao menos a versao {minimum}."
                ),
            }
        )
    elif is_version_below(version, minimum):
        result.update(
            {
                "severity": severity,
                "status": "risk",
                "reason": f"Versao inferior a {minimum}, conforme a base local.",
                "recommendation": (
                    f"Atualize para {minimum} ou uma versao estavel mais recente."
                ),
            }
        )
    else:
        result.update(
            {
                "status": "ok",
                "reason": f"Versao atende ao minimo local {minimum}.",
                "recommendation": "Continue acompanhando avisos oficiais de seguranca.",
            }
        )
    return result


def parse_requirements(path: Path, root: Path | None = None) -> list[dict]:
    dependencies = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "git+")):
            continue
        match = REQUIREMENT_RE.match(stripped)
        if not match:
            continue
        name, _operator, version = match.groups()
        dependencies.append(
            _evaluate(
                name,
                version,
                "python",
                path,
                root,
                exact_version=version if _operator == "==" else None,
            )
        )
    return dependencies


def parse_package_json(path: Path, root: Path | None = None) -> list[dict]:
    try:
        data = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return []
    dependencies = []
    for section in ("dependencies", "devDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, version in values.items():
            version_text = str(version)
            exact_match = EXACT_VERSION_RE.fullmatch(version_text.strip())
            dependencies.append(
                _evaluate(
                    str(name),
                    version_text,
                    "javascript",
                    path,
                    root,
                    exact_version=exact_match.group(1) if exact_match else None,
                )
            )
    return dependencies


def scan_dependency_file(path: Path, root: Path | None = None) -> list[dict]:
    if path.name.lower() == "requirements.txt":
        return parse_requirements(path, root)
    if path.name.lower() == "package.json":
        return parse_package_json(path, root)
    return []
