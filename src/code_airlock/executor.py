"""Guarded subprocess execution with vault environment injection and output scrubbing."""
from __future__ import annotations
import os, re, subprocess
from pathlib import Path
from .engine import Span

BLOCKED_EXEC = frozenset({
    "rm", "del", "format", "mkfs", "dd", "shutdown", "reboot",
    "powershell", "cmd", "bash", "sh", "zsh",
})
SECRET_KEY_RE = re.compile(r"(?i)(KEY|SECRET|TOKEN|PASSWORD|PASS)$")


def _check(command: list[str]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x.strip() for x in command):
        raise ValueError("command must be a non-empty list of strings")
    exe = Path(command[0]).name.lower().split(".")[0]
    if exe in BLOCKED_EXEC:
        raise ValueError(f"disallowed executable: {command[0]}")


def _read_env(path: str, validate) -> dict[str, str]:
    target = validate(path)
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"could not read env file: {target}") from exc
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        pairs[key] = value
    return pairs


def _register(pairs: dict[str, str], engine, vault) -> None:
    for key, value in pairs.items():
        if not value:
            continue
        spans = engine.detect(value, use_ner=False)
        if not spans and len(value) >= 8 and SECRET_KEY_RE.search(key):
            spans = [Span(0, len(value), "API_KEY", value, 1.0, "stage1")]
        if spans:
            vault.dehydrate(value, spans)


def _scrub(text: str, engine, vault) -> str:
    if not text:
        return text
    spans = engine.detect(text, use_ner=False)
    cleaned, _ = vault.dehydrate(text, spans)
    for raw, token in sorted(vault.reverse_map.items(), key=lambda kv: len(kv[0]), reverse=True):
        cleaned = cleaned.replace(raw, token)
    return cleaned


def run_command(command: list[str], env_file: str, engine, vault, validate_path) -> dict:
    _check(command)
    cwd = validate_path(os.getenv("AIRLOCK_WORKSPACE") or os.getcwd())
    pairs = _read_env(env_file, validate_path) if env_file else {}
    _register(pairs, engine, vault)
    hydrated = [vault.rehydrate(arg) for arg in command]
    _check(hydrated)
    child_env = os.environ.copy()
    child_env.update(pairs)
    try:
        proc = subprocess.run(hydrated, cwd=str(cwd), env=child_env, capture_output=True,
                              text=True, timeout=30, shell=False)
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": "command timed out"}
    except OSError as exc:
        return {"exit_code": -1, "stdout": "", "stderr": _scrub(str(exc), engine, vault)}
    return {"exit_code": proc.returncode, "stdout": _scrub(proc.stdout or "", engine, vault),
            "stderr": _scrub(proc.stderr or "", engine, vault)}
