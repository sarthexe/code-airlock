"""mcp_server.py - FastMCP stdio server exposing pii-airlock to coding harnesses."""
from __future__ import annotations
import re, time
from mcp.server.fastmcp import FastMCP
from engine import CascadeEngine
from sanitizer import StreamRehydrator, VaultSession

mcp = FastMCP("pii-airlock")
ENGINE = CascadeEngine()
VAULT = VaultSession()
TOKEN_RE = re.compile(r"<[A-Z_]+_\d+>")


def _dehydrate(text: str) -> dict:
    started = time.perf_counter()
    spans = ENGINE.detect(text)
    sanitized, _ = VAULT.dehydrate(text, spans)
    tokens = list(dict.fromkeys(TOKEN_RE.findall(sanitized)))
    return {"sanitized_text": sanitized, "redacted_count": len(spans),
            "latency_ms": round((time.perf_counter() - started) * 1000, 2), "tokens": tokens}


@mcp.tool()
def airlock_dehydrate(text: str) -> dict:
    """Redact PII from text and return session-stable tokens."""
    return _dehydrate(text)


@mcp.tool()
def airlock_rehydrate(text: str) -> dict:
    """Restore <ENTITY_n> tokens from the active session vault."""
    rehydrator = StreamRehydrator(VAULT.vault)
    restored = rehydrator.process_chunk(text) + rehydrator.flush()
    restored_count = sum(1 for t in TOKEN_RE.findall(text) if t in VAULT.vault)
    return {"rehydrated_text": restored, "restored_count": restored_count}


@mcp.tool()
def airlock_read_file(path: str) -> dict:
    """Read a local file and return its sanitized contents plus telemetry."""
    with open(path, encoding="utf-8") as handle:
        return {"path": path, **_dehydrate(handle.read())}


@mcp.tool()
def airlock_write_file(path: str, content: str) -> dict:
    """Rehydrate tokens locally and write plaintext straight to disk."""
    restored_tokens = [t for t in dict.fromkeys(TOKEN_RE.findall(content)) if t in VAULT.vault]
    rehydrator = StreamRehydrator(VAULT.vault)
    restored = rehydrator.process_chunk(content) + rehydrator.flush()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(restored)
    return {"status": "written", "path": path, "restored_tokens": restored_tokens}


@mcp.tool()
def airlock_vault_status() -> dict:
    """Return token metadata only; raw secret values are never exposed."""
    counts: dict[str, int] = {}
    for token in VAULT.vault:
        label = token.strip("<>").rsplit("_", 1)[0]
        counts[label] = counts.get(label, 0) + 1
    return {"tokens": sorted(VAULT.vault), "counts": counts, "total": len(VAULT.vault)}


if __name__ == "__main__":
    mcp.run()
