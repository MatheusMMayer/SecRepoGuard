"""Deteccao heuristica de potenciais segredos em texto."""

from __future__ import annotations

import re
from pathlib import Path

from .utils import read_text

ASSIGNMENT_PATTERNS = [
    (
        "Token de servico privilegiado",
        "HIGH",
        re.compile(
            r"(?i)\b(SUPABASE_SERVICE_ROLE_KEY)\b\s*[:=]\s*([\"']?)([^\s\"'#;,]+)\2"
        ),
        "Remova o token do repositorio, rotacione-o e use um cofre de segredos.",
    ),
    (
        "Token de acesso",
        "HIGH",
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:ACCESS_TOKEN|AUTH_TOKEN|GITHUB_TOKEN|TOKEN))"
            r"\b\s*[:=]\s*"
            r"([\"']?)([^\s\"'#;,]+)\2"
        ),
        "Revogue e rotacione o token; carregue-o por variavel de ambiente.",
    ),
    (
        "Chave secreta",
        "HIGH",
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:SECRET_KEY|JWT_SECRET|CLIENT_SECRET|SECRET))"
            r"\b\s*[:=]\s*"
            r"([\"']?)([^\s\"'#;,]+)\2"
        ),
        "Remova e rotacione o segredo; use variavel de ambiente ou cofre.",
    ),
    (
        "Senha hardcoded",
        "HIGH",
        re.compile(
            r"(?i)\b(DB_PASSWORD|PASSWORD|PASSWD|PWD)\b\s*[:=]\s*"
            r"([\"']?)([^\s\"'#;,]+)\2"
        ),
        "Mova a senha para uma variavel de ambiente e rotacione a credencial.",
    ),
    (
        "Chave de API",
        "MEDIUM",
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:API_KEY|APIKEY|API_TOKEN))\b\s*[:=]\s*"
            r"([\"']?)([^\s\"'#;,]+)\2"
        ),
        "Mova a chave para uma variavel de ambiente e rotacione-a se for real.",
    ),
    (
        "URL de banco de dados",
        "HIGH",
        re.compile(
            r"(?i)\b(DATABASE_URL|DB_URL)\b\s*[:=]\s*([\"']?)([^\s\"'#;]+)\2"
        ),
        "Remova credenciais da URL, rotacione-as e use configuracao externa.",
    ),
]

DATABASE_URL_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s\"']+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
)

PROVIDER_PATTERNS = [
    (
        "Possivel token GitHub",
        "HIGH",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
        ),
        "Revogue o token no GitHub e substitua-o por um segredo externo.",
    ),
    (
        "Possivel chave de API Google",
        "HIGH",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,50}\b"),
        "Restrinja e rotacione a chave no Google Cloud; remova-a do historico.",
    ),
    (
        "Possivel chave de acesso AWS",
        "HIGH",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "Desative a chave no IAM, investigue o uso e gere outra credencial.",
    ),
    (
        "Possivel chave secreta Stripe",
        "HIGH",
        re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,255}\b"),
        "Revogue e rotacione a chave no Stripe; use armazenamento seguro.",
    ),
    (
        "Possivel token Slack",
        "HIGH",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,255}\b"),
        "Revogue o token no Slack e remova-o do repositorio.",
    ),
    (
        "Possivel chave OpenAI",
        "HIGH",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b"),
        "Revogue a chave, gere uma nova e carregue-a por variavel de ambiente.",
    ),
]

PLACEHOLDER_MARKERS = {
    "changeme",
    "example",
    "placeholder",
    "your_",
    "<",
    "${",
}


def _looks_relevant(value: str) -> bool:
    normalized = value.strip()
    if len(normalized) < 8:
        return False
    lower = normalized.lower()
    return not any(marker in lower for marker in PLACEHOLDER_MARKERS)


def mask_value(value: str, visible: int = 4) -> str:
    """Mascara o valor integralmente, preservando apenas um pequeno prefixo."""
    value = value.strip()
    if not value:
        return "********"
    prefix_length = min(visible, max(1, len(value) // 3))
    return f"{value[:prefix_length]}********"


def _masked_assignment(line: str, match: re.Match[str]) -> str:
    value = match.group(3)
    start, end = match.span(3)
    return f"{line[:start]}{mask_value(value)}{line[end:]}".strip()[:200]


def scan_text_for_secrets(text: str, display_path: str) -> list[dict]:
    findings: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line_fingerprints = set()
        database_assignment_found = False
        for finding_type, severity, pattern, recommendation in ASSIGNMENT_PATTERNS:
            match = pattern.search(line)
            if not match or not _looks_relevant(match.group(3)):
                continue
            if finding_type == "URL de banco de dados":
                database_assignment_found = True
            findings.append(
                {
                    "category": "secret",
                    "type": finding_type,
                    "severity": severity,
                    "file": display_path,
                    "line": line_number,
                    "snippet": _masked_assignment(line, match),
                    "recommendation": recommendation,
                }
            )
            line_fingerprints.add((match.start(3), match.end(3)))

        private_match = PRIVATE_KEY_RE.search(line)
        if private_match:
            findings.append(
                {
                    "category": "secret",
                    "type": "Possivel chave privada",
                    "severity": "HIGH",
                    "file": display_path,
                    "line": line_number,
                    "snippet": private_match.group(0),
                    "recommendation": (
                        "Remova a chave do repositorio, rotacione-a e revise o historico."
                    ),
                }
            )

        if not database_assignment_found:
            for match in DATABASE_URL_RE.finditer(line):
                url = match.group(0)
                findings.append(
                    {
                        "category": "secret",
                        "type": "Possivel URL de banco de dados",
                        "severity": "HIGH",
                        "file": display_path,
                        "line": line_number,
                        "snippet": line.replace(url, mask_value(url, 8)).strip()[:200],
                        "recommendation": (
                            "Remova credenciais da URL, rotacione-as e use configuracao "
                            "externa."
                        ),
                    }
                )

        for match in JWT_RE.finditer(line):
            token = match.group(0)
            findings.append(
                {
                    "category": "secret",
                    "type": "Possivel token JWT",
                    "severity": "MEDIUM",
                    "file": display_path,
                    "line": line_number,
                    "snippet": line.replace(token, mask_value(token)).strip()[:200],
                    "recommendation": (
                        "Valide o token, revogue-o se estiver ativo e use armazenamento seguro."
                    ),
                }
            )

        for finding_type, severity, pattern, recommendation in PROVIDER_PATTERNS:
            for match in pattern.finditer(line):
                if any(
                    start <= match.start() and match.end() <= end
                    for start, end in line_fingerprints
                ):
                    continue
                value = match.group(0)
                findings.append(
                    {
                        "category": "secret",
                        "type": finding_type,
                        "severity": severity,
                        "file": display_path,
                        "line": line_number,
                        "snippet": line.replace(value, mask_value(value)).strip()[:200],
                        "recommendation": recommendation,
                    }
                )
    return findings


def scan_file_for_secrets(path: Path, root: Path | None = None) -> list[dict]:
    relative = str(path.relative_to(root)) if root else str(path)
    return scan_text_for_secrets(read_text(path), relative)
