"""test_mcp.py - End-to-end harness workflow verification for the MCP server."""
import json
import pytest
import mcp_server as airlock

OPENAI = "sk-abcdefghijklmnopqrstuvwxyz123456"
AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "ops@northwind.example"


@pytest.fixture(autouse=True)
def fresh_vault():
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
