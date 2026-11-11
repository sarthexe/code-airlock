"""test_mcp.py - End-to-end harness workflow verification for the MCP server."""
import json
from pathlib import Path
import pytest
from code_airlock import mcp_server as airlock

OPENAI = "sk-abcdefghijklmnopqrstuvwxyz123456"
AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "ops@northwind.example"


@pytest.fixture(autouse=True)
def fresh_vault(monkeypatch):
    monkeypatch.delenv("AIRLOCK_WORKSPACE", raising=False)
    airlock.VAULT = airlock.VaultSession()
    yield


def test_dehydrate_rehydrate_roundtrip():
    text = f"Alice Smith (alice@acme.io) uses {OPENAI}."
    first = airlock.airlock_dehydrate(text)
    for token in ("<PERSON_1>", "<EMAIL_1>", "<API_KEY_1>"):
        assert token in first["sanitized_text"]
    assert "alice@acme.io" not in first["sanitized_text"]
    assert first["redacted_count"] >= 3
    repeat = airlock.airlock_dehydrate("Alice Smith pinged again")
    assert "<PERSON_1>" in repeat["sanitized_text"]
    restored = airlock.airlock_rehydrate(first["sanitized_text"])
    assert restored["rehydrated_text"] == text
    assert restored["restored_count"] == 3


def test_env_to_config_zero_leak(tmp_path):
    secrets = [OPENAI, AWS, EMAIL]
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={OPENAI}\nAWS_ACCESS_KEY_ID={AWS}\nCONTACT_EMAIL={EMAIL}\n",
                   encoding="utf-8")
    read = airlock.airlock_read_file(str(env))
    sanitized = read["sanitized_text"]
    for token in ("<API_KEY_1>", "<API_KEY_2>", "<EMAIL_1>"):
        assert token in sanitized
    for secret in secrets:
        assert secret not in sanitized
        assert secret not in json.dumps(read)

    config = tmp_path / "config.json"
    llm_output = json.dumps({"openai": "<API_KEY_1>", "aws": "<API_KEY_2>", "contact": "<EMAIL_1>"})
    written = airlock.airlock_write_file(str(config), llm_output)
    assert written["status"] == "written"
    assert written["restored_tokens"] == ["<API_KEY_1>", "<API_KEY_2>", "<EMAIL_1>"]
    for secret in secrets:
        assert secret not in json.dumps(written)

    on_disk = config.read_text(encoding="utf-8")
    for secret in secrets:
        assert secret in on_disk
    assert "<API_KEY_1>" not in on_disk


def test_vault_status_safety():
    airlock.airlock_dehydrate(f"Bob Jones emailed bob@acme.io with {OPENAI}")
    status = airlock.airlock_vault_status()
    blob = json.dumps(status)
    assert "<PERSON_1>" in status["tokens"]
    assert "<EMAIL_1>" in status["tokens"]
    assert status["counts"]["API_KEY"] == 1
    for secret in ("Bob Jones", "bob@acme.io", OPENAI):
        assert secret not in blob


def test_inline_and_key_value_secrets_roundtrip():
    text = "postgres://user:pass12345@192.168.1.1:5432/db WEBHOOK_SECRET=whsec_abc12345"
    first = airlock.airlock_dehydrate(text)
    sanitized = first["sanitized_text"]
    assert "pass12345" not in sanitized
    assert "whsec_abc12345" not in sanitized
    assert airlock.airlock_rehydrate(sanitized)["rehydrated_text"] == text


def test_write_blocks_unresolved_tokens(tmp_path):
    target = tmp_path / "output.txt"
    result = airlock.airlock_write_file(str(target), "key=<API_KEY_999>")
    assert result["status"] == "error"
    assert result["unresolved_tokens"] == ["<API_KEY_999>"]
    assert not target.exists()


def test_path_traversal_blocked():
    with pytest.raises(ValueError, match="sensitive"):
        airlock.airlock_read_file(str(Path.home() / ".ssh" / "id_rsa"))


def test_repr_never_exposes_secrets():
    airlock.airlock_dehydrate(f"key {OPENAI}")
    rendered = repr(airlock.VAULT)
    assert "active_tokens=1" in rendered
    assert OPENAI not in rendered
    assert str(airlock.VAULT) == rendered


def test_case_insensitive_rehydration():
    text = f"key {OPENAI}"
    first = airlock.airlock_dehydrate(text)
    for variant in ("<api_key_1>", "< API_KEY_1 >"):
        result = airlock.airlock_rehydrate(first["sanitized_text"].replace("<API_KEY_1>", variant))
        assert result["rehydrated_text"] == text
        assert result["restored_count"] == 1
