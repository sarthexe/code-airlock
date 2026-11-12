"""config.py - Optional .airlock.toml allowlist and custom Stage-1 patterns."""
from __future__ import annotations
import os, re
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
