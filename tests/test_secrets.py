from pathlib import Path

from secrepoguard_core.secrets import mask_value, scan_file_for_secrets


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "config.py"
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_fake_api_key_and_masks_value(tmp_path):
    path = _write(tmp_path, 'API_KEY = "fake_1234567890abcdef"\n')
    findings = scan_file_for_secrets(path, tmp_path)

    assert any(item["type"] == "Chave de API" for item in findings)
    assert "fake_1234567890abcdef" not in findings[0]["snippet"]
    assert "********" in findings[0]["snippet"]


def test_mask_value_never_returns_complete_secret():
    secret = "supersecretvalue"
    masked = mask_value(secret)
    assert secret not in masked
    assert masked.endswith("********")


def test_detects_hardcoded_password(tmp_path):
    path = _write(tmp_path, 'DB_PASSWORD = "fake_password_123"\n')
    findings = scan_file_for_secrets(path, tmp_path)
    assert any(item["type"] == "Senha hardcoded" for item in findings)


def test_detects_private_key(tmp_path):
    path = _write(tmp_path, "-----BEGIN PRIVATE KEY-----\nFAKE\n")
    findings = scan_file_for_secrets(path, tmp_path)
    assert any(item["type"] == "Possivel chave privada" for item in findings)


def test_database_assignment_is_not_duplicated(tmp_path):
    path = _write(
        tmp_path,
        'DATABASE_URL = "postgres://fake:fake_password@localhost/fake_db"\n',
    )
    findings = scan_file_for_secrets(path, tmp_path)
    database_findings = [
        item for item in findings if "banco de dados" in item["type"].lower()
    ]
    assert len(database_findings) == 1


def test_detects_prefixed_api_key_variable(tmp_path):
    secret = "sk-proj-1234567890abcdefghijklmnop"
    path = _write(tmp_path, f'OPENAI_API_KEY = "{secret}"\n')
    findings = scan_file_for_secrets(path, tmp_path)

    assert any(item["type"] == "Chave de API" for item in findings)
    assert secret not in findings[0]["snippet"]


def test_detects_provider_key_without_variable_name(tmp_path):
    key = "AIzaSyA1234567890abcdefghijklmnopqrst"
    path = _write(tmp_path, f'client.configure("{key}")\n')
    findings = scan_file_for_secrets(path, tmp_path)

    assert any(item["type"] == "Possivel chave de API Google" for item in findings)
    assert all(key not in item["snippet"] for item in findings)
