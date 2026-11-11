"""sanitizer.py - Reversible Pseudonymization & Streaming Rehydrator."""
from __future__ import annotations
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import Span

TOKEN_PATTERN = re.compile(r"^<[A-Z_]+_\d+>$")
TOKEN_VARIANT_RE = re.compile(r"<\s*[A-Za-z_]+\s*_\s*\d+\s*>")
VALID_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789")


class VaultSession:
    """In-memory dictionary managing pseudonymization for a single request lifecycle."""

    def __init__(self) -> None:
        self.vault: dict[str, str] = {}
        self.forward_map: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def __repr__(self) -> str:
        return f"<VaultSession active_tokens={len(self.forward_map)}>"

    def __str__(self) -> str:
        return self.__repr__()

    def _get_or_create_token(self, label: str, val: str) -> str:
        key = (label, val)
        if key in self.forward_map:
            return self.forward_map[key]
        self._counters[label] = self._counters.get(label, 0) + 1
        tok = f"<{label}_{self._counters[label]}>"
        self.forward_map[key] = tok
        self.vault[tok] = val
        return tok

    def dehydrate(self, text: str, spans: list[Span]) -> tuple[str, dict[str, str]]:
        """Replace spans right-to-left with deterministic tokens, preserving identical values."""
        left_to_right = sorted(spans, key=lambda s: s.start)
        span_tokens = [(s, self._get_or_create_token(s.label, s.text)) for s in left_to_right]
        right_to_left = sorted(span_tokens, key=lambda x: x[0].start, reverse=True)

        dehydrated = text
        for s, tok in right_to_left:
            dehydrated = dehydrated[:s.start] + tok + dehydrated[s.end:]
        return dehydrated, dict(self.vault)

    def rehydrate(self, text: str) -> str:
        """Rehydrate canonical and case/whitespace-mangled vault tokens."""
        def replace(match: re.Match) -> str:
            raw = match.group(0)
            inner = re.sub(r"\s+", "", raw[1:-1]).upper()
            return self.vault.get(f"<{inner}>", raw)
        return TOKEN_VARIANT_RE.sub(replace, text)

    def find_unresolved_tokens(self, text: str) -> list[str]:
        """Return unique token-shaped placeholders left after rehydration."""
        return list(dict.fromkeys(TOKEN_VARIANT_RE.findall(text)))


class StreamRehydrator:
    """Stateful sliding-window parser for LLM Server-Sent Events (SSE) token streams."""

    def __init__(self, vault: dict[str, str], max_token_len: int = 32):
        self.vault = vault
        self.max_token_len = max_token_len
        self.buffer = ""

    def process_chunk(self, chunk: str) -> str:
        """Process incoming stream chunk character-by-character with zero math/code delay."""
        out: list[str] = []
        for ch in chunk:
            if not self.buffer:
                if ch == "<":
                    self.buffer = "<"
                else:
                    out.append(ch)
            else:
                if ch == ">":
                    candidate = self.buffer + ">"
                    out.append(self.vault.get(candidate, candidate))
                    self.buffer = ""
                elif ch == "<":
                    out.append(self.buffer)
                    self.buffer = "<"
                elif ch in VALID_TOKEN_CHARS:
                    self.buffer += ch
                    if len(self.buffer) > self.max_token_len:
                        out.append(self.buffer)
                        self.buffer = ""
                else:
                    # Non-token character (space, operator, etc.) flushes buffer immediately
                    out.append(self.buffer + ch)
                    self.buffer = ""
        return "".join(out)

    def flush(self) -> str:
        """Flush any residual buffered characters at stream termination."""
        residual = self.buffer
        self.buffer = ""
        return residual


def rehydrate(text: str, vault: dict[str, str]) -> str:
    """Convenience helper to rehydrate full text through StreamRehydrator."""
    r = StreamRehydrator(vault)
    return r.process_chunk(text) + r.flush()
