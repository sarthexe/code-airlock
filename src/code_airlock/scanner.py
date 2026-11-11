"""scanner.py - Fast Stage-1 Git/CI secret scanner with masked output."""
from __future__ import annotations
import subprocess
from pathlib import Path
from .engine import CascadeEngine

SECRET_LABELS = frozenset({"API_KEY", "AUTH_TOKEN", "CREDIT_CARD", "GOVT_ID", "IBAN_CRYPTO"})
SKIP_PARTS = frozenset({".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "build", "dist"})
MAX_BYTES = 1_048_576


def _mask(value: str) -> str:
    text = value.replace("\n", " ")
    if len(text) <= 8:
        return "*" * len(text)
    return text[:2] + "***" + text[-2:]


def _skip(path: Path) -> bool:
    posix = path.as_posix().lower()
    if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in posix.split("/")):
        return True
    if "gold_set" in posix or "benchmark" in posix:
        return True
    return posix.startswith("tests/") or "/tests/" in posix


def _collect(paths: list[str], staged: bool) -> list[Path] | None:
    if staged:
        proc = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"], capture_output=True)
        if proc.returncode:
            print("[error] could not read staged files; is this a git repository?")
            return None
        return [Path(p.decode("utf-8", "replace")) for p in proc.stdout.split(b"\0") if p]
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            files.append(path)
    return files


def scan(paths: list[str] | None = None, staged: bool = False, deep: bool = False) -> int:
    """Scan files and return 1 when secrets are found, 0 when clean."""
    engine = CascadeEngine()
    files = _collect(paths or ["."], staged)
    if files is None:
        return 1
    findings: set[tuple[str, int, str, str]] = set()
    scanned = 0
    for path in files:
        if _skip(path):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > MAX_BYTES or b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for span in engine.detect(text, use_ner=deep):
            if span.label in SECRET_LABELS:
                line = text.count("\n", 0, span.start) + 1
                findings.add((str(path), line, span.label, _mask(span.text)))
    for file, line, label, preview in sorted(findings):
        print(f"{file}:{line} -> [{label}] {preview}")
    if findings:
        return 1
    print(f"[ok] code-airlock scan: 0 secrets detected across {scanned} files")
    return 0
