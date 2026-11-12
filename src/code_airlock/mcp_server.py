"""mcp_server.py - FastMCP stdio server exposing code-airlock to coding harnesses."""
from __future__ import annotations
import os, re, time
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from .engine import CascadeEngine
from .executor import run_command
from .sanitizer import VaultSession, TOKEN_VARIANT_RE as TOKEN_RE

mcp = FastMCP("code-airlock")
ENGINE = CascadeEngine()
VAULT = VaultSession()
BLOCKED_DIRS = frozenset({".ssh", ".aws", ".gnupg", ".kube"})
MAX_FILE_BYTES = 1_048_576


def _canonical(token: str) -> str:
    inner = re.sub(r"\s+", "", token[1:-1]).upper()
    return f"<{inner}>"


def _validate_path(file_path: str) -> Path:
    """Resolve a path and enforce sensitive-directory and workspace jailing."""
    path = Path(file_path).expanduser().resolve()
    parts = {p.lower() for p in path.parts}
    if parts & BLOCKED_DIRS or "system32" in parts:
        raise ValueError(f"access denied: sensitive directory: {path}")
    if os.name != "nt" and (path == Path("/etc") or Path("/etc") in path.parents):
        raise ValueError(f"access denied: system directory: {path}")
    workspace = os.getenv("AIRLOCK_WORKSPACE")
    if workspace:
        root = Path(workspace).expanduser().resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"access denied: outside AIRLOCK_WORKSPACE: {path}") from exc
    return path


def _dehydrate(text: str, use_ner: bool = True) -> dict:
    started = time.perf_counter()
    spans = ENGINE.detect(text, use_ner=use_ner)
    sanitized, _ = VAULT.dehydrate(text, spans)
    tokens = list(dict.fromkeys(TOKEN_RE.findall(sanitized)))
    return {"sanitized_text": sanitized, "redacted_count": len(spans),
            "latency_ms": round((time.perf_counter() - started) * 1000, 2), "tokens": tokens}


@mcp.tool()
def airlock_dehydrate(text: str) -> dict:
    """Redact PII from text and return session-stable tokens."""
    return _dehydrate(text)


@mcp.tool()
def airlock_scrub_text(text: str, use_ner: bool = True) -> dict:
    """Scrub arbitrary in-memory text, optionally with Stage-1-only speed."""
    return _dehydrate(text, use_ner=use_ner)


@mcp.tool()
def airlock_exec(command: list[str], env_file: str = "") -> dict:
    """Run a guarded subprocess with vault-injected env and scrubbed output."""
    return run_command(command, env_file, ENGINE, VAULT, _validate_path)


@mcp.tool()
def airlock_rehydrate(text: str) -> dict:
    """Restore <ENTITY_n> tokens from the active session vault."""
    restored = VAULT.rehydrate(text)
    restored_count = sum(1 for t in TOKEN_RE.findall(text) if _canonical(t) in VAULT.vault)
    return {"rehydrated_text": restored, "restored_count": restored_count}


@mcp.tool()
def airlock_read_file(path: str) -> dict:
    """Read a bounded UTF-8 text file and return sanitized contents plus telemetry."""
    target = _validate_path(path)
    if not target.is_file():
        raise ValueError(f"not a regular file: {target}")
    if target.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file too large (max {MAX_FILE_BYTES} bytes): {target}")
    data = target.read_bytes()
    if b"\x00" in data:
        raise ValueError(f"binary file not supported: {target}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"file is not valid UTF-8 text: {target}") from exc
    return {"path": str(target), **_dehydrate(text)}


@mcp.tool()
def airlock_write_file(path: str, content: str) -> dict:
    """Rehydrate tokens locally and write plaintext, blocking unresolved tokens."""
    target = _validate_path(path)
    restored_tokens = list(dict.fromkeys(
        _canonical(t) for t in TOKEN_RE.findall(content) if _canonical(t) in VAULT.vault
    ))
    restored = VAULT.rehydrate(content)
    unresolved = VAULT.find_unresolved_tokens(restored)
    if unresolved:
        return {"status": "error", "error": "unresolved_tokens",
                "unresolved_tokens": unresolved, "path": str(target)}
    target.write_text(restored, encoding="utf-8")
    return {"status": "written", "path": str(target), "restored_tokens": restored_tokens}


@mcp.tool()
def airlock_vault_status() -> dict:
    """Return token metadata only; raw secret values are never exposed."""
    counts: dict[str, int] = {}
    for token in VAULT.vault:
        label = token.strip("<>").rsplit("_", 1)[0]
        counts[label] = counts.get(label, 0) + 1
    return {"tokens": sorted(VAULT.vault), "counts": counts, "total": len(VAULT.vault)}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
