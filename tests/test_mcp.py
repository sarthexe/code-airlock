"""test_mcp.py - End-to-end harness workflow verification for the MCP server."""
import json
import sys
from pathlib import Path
import pytest
from code_airlock import __main__ as cli
from code_airlock import mcp_server as airlock
from code_airlock.engine import CascadeEngine, stage2_ok

OPENAI = "sk-abcdefghijklmnopqrstuvwxyz123456"
AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "ops@northwind.example"


@pytest.fixture(autouse=True)
def fresh_vault(monkeypatch):
    monkeypatch.delenv("AIRLOCK_WORKSPACE", raising=False)
    monkeypatch.delenv("AIRLOCK_CONFIG", raising=False)
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


def test_scrub_text_tracks_tokens():
    result = airlock.airlock_scrub_text(f"secret {OPENAI}", use_ner=False)
    assert OPENAI not in result["sanitized_text"]
    assert result["tokens"] == ["<API_KEY_1>"]
    assert airlock.VAULT.vault["<API_KEY_1>"] == OPENAI


def test_scan_command_detects_secret(tmp_path, monkeypatch, capsys):
    target = tmp_path / "leak.txt"
    target.write_text(f"key={OPENAI}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["code-airlock", "scan", str(target)])
    assert cli.main() == 1
    output = capsys.readouterr().out
    assert "[API_KEY]" in output
    assert OPENAI not in output


def test_scan_command_clean(tmp_path, monkeypatch, capsys):
    target = tmp_path / "clean.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["code-airlock", "scan", str(target)])
    assert cli.main() == 0
    assert "0 secrets detected across 1 files" in capsys.readouterr().out


def test_init_installs_pre_commit_hook(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sys, "argv", ["code-airlock", "init", "--pre-commit", "--config"])
    assert cli.main() == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert "python -m code_airlock scan --staged" in hook.read_text(encoding="utf-8")
    assert (repo / ".airlock.toml").exists()


def test_airlock_exec_injects_and_scrubs(tmp_path):
    stripe = "sk_live_" + "testexecsecret1234567890abcd"
    env = tmp_path / ".env"
    env.write_text(f"STRIPE_SECRET_KEY={stripe}\n", encoding="utf-8")
    command = [sys.executable, "-c", "import os; print(os.environ['STRIPE_SECRET_KEY'])"]
    result = airlock.airlock_exec(command, str(env))
    assert result["exit_code"] == 0
    assert stripe not in result["stdout"]
    assert "<API_KEY_1>" in result["stdout"]
    assert airlock.VAULT.vault["<API_KEY_1>"] == stripe


def test_airlock_exec_blocks_shell():
    with pytest.raises(ValueError, match="disallowed"):
        airlock.airlock_exec(["bash", "-c", "echo hi"])


def test_airlock_toml_custom_patterns_and_allowlist(tmp_path, monkeypatch):
    (tmp_path / ".airlock.toml").write_text(
        "[allowlist]\nterms = [\"MyInternalApp\"]\n"
        "[custom_patterns]\nEMPLOYEE_ID = 'EMP-[0-9]{6}'\n"
        "INTERNAL_TICKET = 'JIRA-[0-9]{4,6}'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    engine = CascadeEngine()
    spans = engine.detect("MyInternalApp EMP-123456 and JIRA-4567", use_ner=False)
    labels = {s.label for s in spans}
    assert {"EMPLOYEE_ID", "INTERNAL_TICKET"} <= labels
    assert stage2_ok("MyInternalApp", "ORGANIZATION", engine.allowlist) is False
    vault = airlock.VaultSession()
    sanitized, _ = vault.dehydrate("MyInternalApp EMP-123456 and JIRA-4567", spans)
    assert "<EMPLOYEE_ID_1>" in sanitized


def _isolated_harness(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(work)
    monkeypatch.setattr(cli, "doctor", lambda *a, **k: 0)
    return home, work


def test_install_configures_all_harnesses_globally(tmp_path, monkeypatch):
    home, work = _isolated_harness(tmp_path, monkeypatch)
    opencode = home / ".config" / "opencode" / "opencode.json"
    opencode.parent.mkdir(parents=True)
    opencode.write_text(json.dumps({
        "theme": "dark",
        "mcp": {
            "servers": {"rea": {"type": "local", "command": ["rea"]}},
            "timeout": {"startup": 45000},
        },
    }), encoding="utf-8")
    claude = home / ".claude.json"
    claude.write_text(json.dumps({
        "keep": True,
        "mcpServers": {"rea": {"command": ["rea"]}},
    }), encoding="utf-8")
    cursor = home / ".cursor" / "mcp.json"
    cursor.parent.mkdir(parents=True)
    cursor.write_text(json.dumps({
        "mcpServers": {"rea": {"command": ["rea"]}},
    }), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["code-airlock", "install"])
    assert cli.main() == 0

    data = json.loads(opencode.read_text(encoding="utf-8"))
    assert data["theme"] == "dark"
    assert data["mcp"]["timeout"] == {"startup": 45000}
    assert data["mcp"]["servers"]["rea"] == {"type": "local", "command": ["rea"]}
    assert data["mcp"]["servers"]["code-airlock"]["command"][1:] == ["-m", "code_airlock.mcp_server"]
    assert "code-airlock" not in data["mcp"]
    data = json.loads(claude.read_text(encoding="utf-8"))
    assert data["keep"] is True
    assert data["mcpServers"]["rea"] == {"command": ["rea"]}
    assert data["mcpServers"]["code-airlock"]["args"] == ["-m", "code_airlock.mcp_server"]
    data = json.loads(cursor.read_text(encoding="utf-8"))
    assert data["mcpServers"]["rea"] == {"command": ["rea"]}
    assert data["mcpServers"]["code-airlock"]["command"] == sys.executable
    for rule in (home / ".config" / "opencode" / "AGENTS.md", home / ".claude" / "CLAUDE.md"):
        assert rule.exists()
        assert cli.MARKER in rule.read_text(encoding="utf-8")
    for absent in ("AGENTS.md", "CLAUDE.md", ".cursorrules", ".mcp.json", ".cursor", ".airlock.toml"):
        assert not (work / absent).exists()


def test_install_target_limits_global_configuration(tmp_path, monkeypatch):
    home, work = _isolated_harness(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["code-airlock", "install", "--target", "claude"])
    assert cli.main() == 0

    assert (home / ".claude.json").exists()
    assert (home / ".claude" / "CLAUDE.md").exists()
    assert not (home / ".config" / "opencode" / "opencode.json").exists()
    assert not (home / ".cursor" / "mcp.json").exists()
    assert not (work / "CLAUDE.md").exists()


def test_init_writes_only_detected_rule_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENCODE", "1")
    monkeypatch.setattr(sys, "argv", ["code-airlock", "init"])
    assert cli.main() == 0

    assert (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / ".cursorrules").exists()


def test_mcp_handshake_includes_airlock_instructions():
    instructions = airlock.mcp.instructions
    for tool in ("airlock_read_file", "airlock_write_file", "airlock_exec", "airlock_scrub_text"):
        assert tool in instructions
