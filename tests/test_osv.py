import json

from secrepoguard_core.osv import query_osv


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def _dependency(name="django", version="2.2.0", resolved_version="2.2.0"):
    return {
        "name": name,
        "version": version,
        "resolved_version": resolved_version,
        "ecosystem": "PyPI",
        "file": "requirements.txt",
    }


def test_queries_osv_and_normalizes_vulnerability():
    def opener(request, timeout):
        if request.full_url.endswith("/querybatch"):
            payload = json.loads(request.data.decode("utf-8"))
            assert payload["queries"][0]["package"]["ecosystem"] == "PyPI"
            assert payload["queries"][0]["version"] == "2.2.0"
            return FakeResponse({"results": [{"vulns": [{"id": "GHSA-test-1234"}]}]})
        return FakeResponse(
            {
                "id": "GHSA-test-1234",
                "aliases": ["CVE-2026-0001"],
                "summary": "Vulnerabilidade ficticia para teste.",
                "affected": [
                    {
                        "package": {"name": "django", "ecosystem": "PyPI"},
                        "ecosystem_specific": {"severity": "HIGH"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "4.2.20"},
                                ],
                            }
                        ],
                    }
                ],
                "references": [{"url": "https://osv.dev/GHSA-test-1234"}],
            }
        )

    result = query_osv([_dependency()], opener=opener)

    assert result["dependencies_queried"] == 1
    assert result["dependencies_skipped"] == 0
    assert result["findings"][0]["id"] == "GHSA-test-1234"
    assert result["findings"][0]["severity"] == "HIGH"
    assert result["findings"][0]["fixed_versions"] == ["4.2.20"]


def test_skips_dependency_without_exact_version_without_network():
    called = False

    def opener(request, timeout):
        nonlocal called
        called = True
        raise AssertionError("A rede nao deveria ser usada.")

    result = query_osv(
        [_dependency(version=">=2.0", resolved_version=None)],
        opener=opener,
    )

    assert called is False
    assert result["dependencies_queried"] == 0
    assert result["dependencies_skipped"] == 1
    assert result["findings"] == []


def test_deduplicates_osv_records_that_share_cve():
    def opener(request, timeout):
        if request.full_url.endswith("/querybatch"):
            return FakeResponse(
                {
                    "results": [
                        {
                            "vulns": [
                                {"id": "GHSA-test-1234"},
                                {"id": "PYSEC-2026-1"},
                            ]
                        }
                    ]
                }
            )
        vulnerability_id = request.full_url.rsplit("/", 1)[-1]
        return FakeResponse(
            {
                "id": vulnerability_id,
                "aliases": ["CVE-2026-0001"],
                "summary": "Mesmo advisory em duas bases.",
                "database_specific": {
                    "severity": (
                        "HIGH"
                        if vulnerability_id.startswith("GHSA-")
                        else "UNKNOWN"
                    )
                },
                "affected": [],
                "references": [],
            }
        )

    result = query_osv([_dependency()], opener=opener)

    assert len(result["findings"]) == 1
    assert result["findings"][0]["id"] == "GHSA-test-1234"
    assert "PYSEC-2026-1" in result["findings"][0]["aliases"]


def test_follows_querybatch_pagination():
    batch_calls = 0

    def opener(request, timeout):
        nonlocal batch_calls
        if request.full_url.endswith("/querybatch"):
            batch_calls += 1
            payload = json.loads(request.data.decode("utf-8"))
            if payload["queries"][0].get("page_token"):
                return FakeResponse(
                    {"results": [{"vulns": [{"id": "GHSA-page-2"}]}]}
                )
            return FakeResponse(
                {
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-page-1"}],
                            "next_page_token": "next-page",
                        }
                    ]
                }
            )
        vulnerability_id = request.full_url.rsplit("/", 1)[-1]
        return FakeResponse(
            {
                "id": vulnerability_id,
                "aliases": [],
                "summary": "Advisory paginado.",
                "affected": [],
                "references": [],
            }
        )

    result = query_osv([_dependency()], opener=opener)

    assert batch_calls == 2
    assert {item["id"] for item in result["findings"]} == {
        "GHSA-page-1",
        "GHSA-page-2",
    }
