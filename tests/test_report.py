import json

from secrepoguard_core.report import (
    build_report,
    format_text,
    write_json_report,
    write_text_report,
)
from secrepoguard_core.scanner import scan_project


def test_report_is_generated_in_text_and_json(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.py").write_text(
        'API_KEY = "fake_1234567890abcdef"\n', encoding="utf-8"
    )
    report = build_report(scan_project(source), str(source))
    text_path = tmp_path / "report.txt"
    json_path = tmp_path / "report.json"

    write_text_report(report, text_path)
    write_json_report(report, json_path)

    assert "SecRepoGuard - Relatorio de Auditoria" in text_path.read_text(
        encoding="utf-8"
    )
    assert json.loads(json_path.read_text(encoding="utf-8"))["tool"] == "SecRepoGuard"
    assert "validacao humana" in format_text(report)


def test_ignored_directories_are_not_scanned(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bad.js").write_text(
        'API_KEY = "should_not_be_detected_123"\n', encoding="utf-8"
    )
    (tmp_path / "safe.py").write_text("print('texto')\n", encoding="utf-8")

    result = scan_project(tmp_path)

    assert result["files_scanned"] == 1
    assert result["files_ignored"] == 1
    assert result["secrets"] == []


def test_report_includes_osv_vulnerability(tmp_path):
    scan_result = scan_project(tmp_path)
    scan_result["vulnerabilities"] = {
        "dependencies_queried": 1,
        "dependencies_skipped": 0,
        "findings": [
            {
                "category": "vulnerability",
                "id": "GHSA-test-1234",
                "aliases": ["CVE-2026-0001"],
                "name": "demo",
                "version": "1.0.0",
                "ecosystem": "PyPI",
                "file": "requirements.txt",
                "severity": "CRITICAL",
                "severity_score": None,
                "summary": "Advisory ficticio.",
                "fixed_versions": ["1.0.1"],
                "references": ["https://osv.dev/GHSA-test-1234"],
                "published": None,
                "modified": None,
                "recommendation": "Atualize para 1.0.1.",
            }
        ],
    }

    text = format_text(build_report(scan_result, str(tmp_path)))

    assert "Vulnerabilidades conhecidas: 1" in text
    assert "[CRITICAL] GHSA-test-1234 - demo 1.0.0" in text
    assert "CVE-2026-0001" in text
