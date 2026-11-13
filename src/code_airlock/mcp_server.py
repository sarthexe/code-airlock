"""mcp_server.py - FastMCP stdio server exposing code-airlock to coding harnesses."""
from __future__ import annotations
import os, re, time
from pathlib import Path
from typing import Annotated
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field
from .engine import CascadeEngine
from .executor import run_command
from .sanitizer import VaultSession, TOKEN_VARIANT_RE as TOKEN_RE

mcp = FastMCP(
    "code-airlock",
    instructions=(
        "ZERO-TRUST SECRET & PII AIRLOCK: Never use native file-read, file-write, or bash/cat tools "
        "on .env files, credentials, or files containing API keys/PII. Always use `airlock_read_file` to read, "
        "`airlock_write_file` to write (preserving <ENTITY_N> tokens), `airlock_exec` to run scripts/tests "
        "with .env secrets injected and stdout scrubbed, and `airlock_scrub_text` for raw snippets."
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Read & Sanitize Local File",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def airlock_read_file(
    path: Annotated[str, Field(
        description="Relative or absolute filesystem path to the UTF-8 text file to read (max 1 MB). "
                    "Sensitive system directories (.ssh, .aws, .gnupg, .kube, /etc) and binary files are blocked."
    )],
) -> dict:
    """Read a local UTF-8 text file and replace secrets and PII with reversible `<ENTITY_N>` placeholders.

    Purpose & Behavior:
    Reads up to 1 MB of text from `path`, runs two-stage secret/PII detection (deterministic regex plus
    contextual NER), stores raw values in the local in-memory session vault, and returns sanitized text
    containing session-consistent placeholders such as `<API_KEY_1>`, `<AUTH_TOKEN_1>`, or `<PERSON_1>`.
    Does not modify the file on disk.

    When to Use:
    - Use this instead of native file-read or `cat` commands for `.env`, configuration, log, or source files
      that may contain credentials or PII.
    - Pair with `airlock_write_file` to update the file on disk with real secrets automatically restored.
    - For in-memory strings rather than files, use `airlock_dehydrate` or `airlock_scrub_text`.

    Returns:
    A JSON-serializable object with `{"path": str, "sanitized_text": str, "redacted_count": int,
    "latency_ms": float, "tokens": list[str]}`. Raises a tool error if the file is missing, binary,
    exceeds 1 MB, or violates workspace or system-directory guardrails.
    """
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rehydrate Tokens & Write Local File",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def airlock_write_file(
    path: Annotated[str, Field(
        description="Destination filesystem path where the rehydrated UTF-8 file will be created or overwritten. "
                    "Parent directories are created automatically; sensitive system directories (.ssh, .aws, "
                    ".gnupg, .kube) and out-of-workspace paths are blocked."
    )],
    content: Annotated[str, Field(
        description="Full UTF-8 file content to write, containing <ENTITY_N> placeholders (e.g., <API_KEY_1>, "
                    "<AUTH_TOKEN_1>) from the active session vault that will be restored to their original secret "
                    "values before writing to disk."
    )],
) -> dict:
    """Write UTF-8 text to a local file after restoring every `<ENTITY_N>` placeholder to its original secret.

    Purpose & Behavior:
    Replaces every `<ENTITY_N>` placeholder in `content` (matching case-insensitively and tolerating inner
    whitespace) with its original raw value from the local session vault, creates parent directories if
    needed, and overwrites or creates the file at `path`. If `content` contains an unknown or hallucinated
    placeholder such as `<API_KEY_999>`, the write is aborted and the target file is left untouched.

    When to Use:
    - Use after `airlock_read_file` or `airlock_dehydrate` when saving refactored configs, `.env` files, or
      code so real credentials are restored on disk without exposing them to the model.
    - Do not invent new `<ENTITY_N>` numbers that were not returned earlier in the session. Call
      `airlock_vault_status` if unsure which tokens exist.

    Returns:
    A JSON-serializable object with `{"status": "written", "path": str, "restored_tokens": list[str]}` on
    success, or `{"status": "error", "error": "unresolved_tokens", "unresolved_tokens": list[str],
    "path": str}` when the write is blocked. Raises a tool error for path or workspace guardrail violations.
    """
    target = _validate_path(path)
    restored_tokens = list(dict.fromkeys(
        _canonical(t) for t in TOKEN_RE.findall(content) if _canonical(t) in VAULT.vault
    ))
    restored = VAULT.rehydrate(content)
    unresolved = VAULT.find_unresolved_tokens(restored)
    if unresolved:
        return {"status": "error", "error": "unresolved_tokens",
                "unresolved_tokens": unresolved, "path": str(target)}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(restored, encoding="utf-8")
    return {"status": "written", "path": str(target), "restored_tokens": restored_tokens}


@mcp.tool(
    annotations=ToolAnnotations(
        title="Execute Subprocess with Injected Secrets & Scrubbed Output",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    )
)
def airlock_exec(
    command: Annotated[list[str], Field(
        description="Argv command list to execute without a shell (e.g., ['pytest', '-v'] or "
                    "['python', 'scripts/check.py']). The first element is the executable and subsequent "
                    "elements are literal arguments."
    )],
    env_file: Annotated[str, Field(
        description="Optional path to a local .env file (KEY=VALUE lines) whose raw secrets are injected into "
                    "the child process environment at runtime and registered in the session vault so any "
                    "leaked values in stdout/stderr are scrubbed."
    )] = "",
) -> dict:
    """Run a local subprocess with `.env` credentials injected and scrub secrets/PII from its output.

    Purpose & Behavior:
    Executes `command` directly via `subprocess.run(..., shell=False)` with a 30-second timeout inside the
    allowed workspace. If `env_file` is provided, parses `KEY=VALUE` pairs, injects the real unmasked values
    into the child process environment, and registers those secrets in the session vault. Before returning,
    both `stdout` and `stderr` are scrubbed so printed secrets and stack-trace leaks become `<ENTITY_N>`
    placeholders.

    When to Use:
    - Use this instead of native bash/terminal execution whenever running tests (`pytest`), migrations, or
      scripts that need live `.env` credentials or may print sensitive values.
    - Pass commands as a tokenized list of strings (`["pytest", "tests/"]`), never as a single shell string.
    - Use `airlock_scrub_text` when you only need to sanitize already-captured output without running anything.

    Returns:
    A JSON-serializable object with `{"exit_code": int, "stdout": str, "stderr": str}` where both streams have
    secrets replaced by `<ENTITY_N>` placeholders. Timeouts and launch failures return `exit_code: -1` with a
    scrubbed explanatory `stderr`. Raises a tool error for disallowed executables or invalid commands.
    """
    return run_command(command, env_file, ENGINE, VAULT, _validate_path)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Scrub Secrets & PII from In-Memory Text (Configurable Speed)",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
def airlock_scrub_text(
    text: Annotated[str, Field(
        description="Raw in-memory text, log output, or code snippet to sanitize by replacing detected "
                    "secrets and PII with reversible <ENTITY_N> placeholders."
    )],
    use_ner: Annotated[bool, Field(
        description="When False (default), runs fast deterministic regex and key-value heuristics only "
                    "(~0.2ms) to catch API keys, tokens, passwords, emails, and IPs. Set to True to also run "
                    "the ONNX GLiNER neural model (~55ms) for contextual person, organization, and location names."
    )] = False,
) -> dict:
    """Sanitize in-memory text with reversible `<ENTITY_N>` placeholders using fast or full detection.

    Purpose & Behavior:
    Scans `text` for sensitive values, stores original values in the session vault, and replaces them with
    `<ENTITY_N>` tokens (e.g., `<API_KEY_1>`). By default (`use_ner=False`), runs deterministic regex and
    key-value rules in ~0.2ms for high-speed log/code scrubbing. With `use_ner=True`, also runs the local
    ONNX GLiNER model to redact unstructured `PERSON`, `ORGANIZATION`, and `LOCATION` entities.

    When to Use:
    - Use `airlock_scrub_text(text, use_ner=False)` for fast sub-millisecond scrubbing of terminal logs,
      stack traces, or code snippets where credential/token/email/IP redaction is enough.
    - Use `airlock_dehydrate(text)` (or `airlock_scrub_text(text, use_ner=True)`) for natural-language
      prompts or documents that also contain human names, organizations, or locations.
    - Use `airlock_read_file` instead when the text lives in a file on disk.

    Returns:
    A JSON-serializable object with `{"sanitized_text": str, "redacted_count": int, "latency_ms": float,
    "tokens": list[str]}` listing the generated `<ENTITY_N>` placeholders.
    """
    return _dehydrate(text, use_ner=use_ner)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Dehydrate Text (Full Regex + Contextual NER Redaction)",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
)
def airlock_dehydrate(
    text: Annotated[str, Field(
        description="Raw input text containing credentials, connection strings, or natural-language PII "
                    "(names, emails, phones, IPs, SSNs, credit cards) to convert into <ENTITY_N> vault placeholders."
    )],
) -> dict:
    """Convert raw text containing secrets and contextual PII into reversible `<ENTITY_N>` placeholders.

    Purpose & Behavior:
    Runs both deterministic pattern matching (API keys, JWTs, URI passwords, cards, SSNs, emails, IPs) and
    contextual ONNX GLiNER entity recognition (person names, organizations, locations) on `text`. Every
    detected span is stored in the local session vault and replaced with a deterministic placeholder such as
    `<PERSON_1>` or `<API_KEY_1>`.

    When to Use:
    - Use `airlock_dehydrate` when you need full-coverage PII plus secret redaction on raw text and plan to
      restore original values later via `airlock_rehydrate`.
    - Choose `airlock_scrub_text(text, use_ner=False)` instead for sub-millisecond credential/regex scrubbing
      of code or logs without loading the neural NER model.
    - Choose `airlock_read_file` instead when reading directly from a local file path.

    Returns:
    A JSON-serializable object with `{"sanitized_text": str, "redacted_count": int, "latency_ms": float,
    "tokens": list[str]}`.
    """
    return _dehydrate(text)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rehydrate Vault Placeholders in Text",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def airlock_rehydrate(
    text: Annotated[str, Field(
        description="Text containing <ENTITY_N> placeholders (e.g., <API_KEY_1>, <PERSON_1>) generated earlier "
                    "in the current session by airlock_dehydrate, airlock_scrub_text, or airlock_read_file."
    )],
) -> dict:
    """Restore `<ENTITY_N>` placeholders in an in-memory string to their original values from the session vault.

    Purpose & Behavior:
    Looks up each `<ENTITY_N>` token in `text` (matching case-insensitively and tolerating extra inner
    whitespace such as `< api_key_1 >`) against the current in-memory session vault and substitutes the
    original raw string. Tokens that do not exist in the vault are left unchanged. Does not modify the vault.

    When to Use:
    - Use after `airlock_dehydrate` or `airlock_scrub_text` when an in-memory payload needs its original
      values restored.
    - WARNING: The response contains raw unmasked secrets. Never call this on `.env` or credential file
      contents that should stay hidden from model context. Use `airlock_write_file` instead to restore
      secrets directly onto disk without returning them to the agent.

    Returns:
    A JSON-serializable object with `{"rehydrated_text": str, "restored_count": int}`.
    """
    restored = VAULT.rehydrate(text)
    restored_count = sum(1 for t in TOKEN_RE.findall(text) if _canonical(t) in VAULT.vault)
    return {"rehydrated_text": restored, "restored_count": restored_count}


@mcp.tool(
    annotations=ToolAnnotations(
        title="Inspect Session Vault Metadata",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def airlock_vault_status() -> dict:
    """Inspect the session vault's token inventory and entity counts without exposing raw secret values.

    Purpose & Behavior:
    Queries the current in-memory `VaultSession` and returns active placeholder token names (e.g.,
    `["<API_KEY_1>", "<AUTH_TOKEN_1>"]`), total stored token count, and a breakdown by entity category.
    Raw secret strings are never included in the response.

    When to Use:
    - Call before `airlock_write_file` or `airlock_rehydrate` to verify which `<ENTITY_N>` placeholders are
      currently registered, so you do not reference tokens that do not exist.
    - Use this instead of `airlock_rehydrate` when you only need token metadata, not raw values.

    Returns:
    A JSON-serializable object with `{"tokens": list[str], "counts": dict[str, int], "total": int}`.
    """
    counts: dict[str, int] = {}
    for token in VAULT.vault:
        label = token.strip("<>").rsplit("_", 1)[0]
        counts[label] = counts.get(label, 0) + 1
    return {"tokens": sorted(VAULT.vault), "counts": counts, "total": len(VAULT.vault)}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
