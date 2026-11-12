"""config.py - Optional .airlock.toml allowlist, custom Stage-1 patterns, and MCP config merging."""
from __future__ import annotations
import json, os, re
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10 fallback; config is optional
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def load_config(path: str | Path | None = None):
    """Return (allowlist terms, compiled custom patterns) from .airlock.toml."""
    if tomllib is None:
        return frozenset(), {}
    target = Path(path or os.getenv("AIRLOCK_CONFIG") or ".airlock.toml")
    if not target.is_file():
        return frozenset(), {}
    try:
        with target.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return frozenset(), {}
    terms = data.get("allowlist", {})
    terms = terms.get("terms", []) if isinstance(terms, dict) else []
    allowlist = frozenset(str(term).lower() for term in terms) if isinstance(terms, list) else frozenset()
    patterns = {}
    patterns_data = data.get("custom_patterns", {})
    for label, raw in (patterns_data.items() if isinstance(patterns_data, dict) else []):
        if not re.fullmatch(r"[A-Z_]+", label) or not isinstance(raw, str):
            continue
        try:
            patterns[label] = re.compile(raw)
        except re.error:
            continue
    return allowlist, patterns


def merge_mcp_config(path: str | Path, top_key: str, name: str, server: dict) -> tuple[Path, bool]:
    """Merge one MCP server into a JSON file, preserving every other key and server."""
    target = Path(path).expanduser()
    existed = target.is_file()
    data: dict = {}
    if existed:
        try:
            data = json.loads(target.read_text(encoding="utf-8") or "{}")
        except (OSError, ValueError) as exc:
            raise ValueError(f"invalid JSON, left unchanged: {target}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"top-level JSON is not an object, left unchanged: {target}")
    servers = data.setdefault(top_key, {})
    if not isinstance(servers, dict):
        raise ValueError(f"'{top_key}' is not an object, left unchanged: {target}")
    entry = servers.get(name)
    entry = dict(entry) if isinstance(entry, dict) else {}
    entry.update(server)
    servers[name] = entry
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target, existed
