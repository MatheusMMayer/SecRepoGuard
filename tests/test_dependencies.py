import json

from secrepoguard_core.dependencies import (
    is_version_below,
    parse_package_json,
    parse_requirements,
)


def test_reads_requirements_and_classifies_old_version(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("django==2.2\nrequests>=2.18.4\nflask~=2.0\n", encoding="utf-8")

    dependencies = parse_requirements(path, tmp_path)
    by_name = {item["name"].lower(): item for item in dependencies}

    assert len(dependencies) == 3
    assert by_name["django"]["severity"] == "HIGH"
    assert by_name["django"]["resolved_version"] == "2.2"
    assert by_name["requests"]["severity"] == "MEDIUM"
    assert by_name["requests"]["resolved_version"] is None
    assert by_name["flask"]["status"] == "ok"


def test_reads_package_json_and_classifies_lodash(tmp_path):
    path = tmp_path / "package.json"
    path.write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "4.17.15"},
                "devDependencies": {"minimist": "^1.2.0"},
            }
        ),
        encoding="utf-8",
    )

    dependencies = parse_package_json(path, tmp_path)
    by_name = {item["name"]: item for item in dependencies}

    assert by_name["lodash"]["severity"] == "HIGH"
    assert by_name["lodash"]["resolved_version"] == "4.17.15"
    assert by_name["minimist"]["severity"] == "HIGH"
    assert by_name["minimist"]["resolved_version"] is None


def test_version_comparison_handles_different_lengths():
    assert is_version_below("2.9", "2.20")
    assert not is_version_below("4.17.21", "4.17.21")
