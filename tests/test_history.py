import subprocess

from secrepoguard_core.history import scan_git_history
from secrepoguard_core.report import build_report, format_text
from secrepoguard_core.scanner import scan_project


def _git(repository, *arguments):
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def test_finds_removed_secret_in_git_history_and_masks_it(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "SecRepoGuard Test")
    _git(repository, "config", "user.email", "test@example.invalid")

    config = repository / "config.py"
    secret = "fake_historical_key_123456"
    config.write_text(f'API_KEY = "{secret}"\n', encoding="utf-8")
    _git(repository, "add", "config.py")
    _git(repository, "commit", "-m", "add fictitious key")

    config.write_text("# Credential removed from source code.\n", encoding="utf-8")
    _git(repository, "add", "config.py")
    _git(repository, "commit", "-m", "remove fictitious key")

    history = scan_git_history(repository, limit=10)
    report_data = scan_project(
        repository, scan_secrets=False, scan_dependencies=False
    )
    report_data["history"] = history
    report = build_report(report_data, str(repository))
    text = format_text(report)

    assert history["commits_scanned"] == 2
    assert len(history["findings"]) == 1
    assert history["findings"][0]["commit"]
    assert secret not in text
    assert "fake********" in text


def test_finds_provider_key_without_assignment_in_history(tmp_path):
    repository = tmp_path / "provider-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "SecRepoGuard Test")
    _git(repository, "config", "user.email", "test@example.invalid")

    key = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    source = repository / "client.js"
    source.write_text(f'connect("{key}");\n', encoding="utf-8")
    _git(repository, "add", "client.js")
    _git(repository, "commit", "-m", "add fictitious provider token")

    source.write_text("connect(process.env.GITHUB_TOKEN);\n", encoding="utf-8")
    _git(repository, "add", "client.js")
    _git(repository, "commit", "-m", "remove fictitious provider token")

    history = scan_git_history(repository, limit=10)

    assert any(
        item["type"] == "Possivel token GitHub" for item in history["findings"]
    )
    assert all(key not in item["snippet"] for item in history["findings"])
