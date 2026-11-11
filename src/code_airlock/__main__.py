"""Zero-friction CLI for code-airlock: MCP server, proxy, doctor, and init."""
from __future__ import annotations
import argparse, sys
from pathlib import Path

RULE = """# code-airlock security rules
Always use `airlock_read_file` and `airlock_write_file` when reading or writing `.env`, `*secret*`, credentials, or deployment configs. Never inspect secret files using raw bash (`cat`, `grep`) or native file read tools.
"""
MARKER = "code-airlock security rules"
CONFIG = """{
  "mcpServers": {
    "code-airlock": {
      "command": "python",
      "args": ["-m", "code_airlock.mcp_server"]
    }
  }
}"""


def doctor() -> int:
    from .engine import CascadeEngine
    from .sanitizer import VaultSession
    sample = ("API key sk-proj-abc123def456ghi789jkl012mno345; "
              "postgres://user:pass12345@10.0.0.5:5432/db; "
              "contact alice@acme.io and Alice Smith.")
    engine = CascadeEngine(lazy=False)
    spans = engine.detect(sample)
    labels = {s.label for s in spans}
    vault = VaultSession()
    dehydrated, _ = vault.dehydrate(sample, spans)
    restored = vault.rehydrate(dehydrated)
    expected = {"API_KEY", "AUTH_TOKEN", "EMAIL", "PERSON"}
    missing = expected - labels
    ok = restored == sample and not missing
    print(f"[{'ok' if not missing else 'fail'}] GLiNER ready on {engine.device}; labels: {', '.join(sorted(labels))}")
    print(f"[{'ok' if restored == sample else 'fail'}] round-trip rehydration ({len(spans)} spans)")
    if not ok:
        if missing: print(f"[fail] missing detectors: {', '.join(sorted(missing))}")
        return 1
    print("\nOpenCode (~/.config/opencode/opencode.json):")
    print('{"mcp": {"code-airlock": {"type": "local", "command": ["python", "-m", "code_airlock.mcp_server"]}}}')
    print("\nCursor / Claude Code / Claude Desktop:")
    print(CONFIG)
    return 0


def init() -> int:
    for name in (".cursorrules", "CLAUDE.md"):
        target = Path.cwd() / name
        existing = target.read_text(encoding="utf-8") if target.exists() else ""
        if MARKER in existing:
            print(f"[ok] {name} already contains code-airlock rules")
            continue
        separator = "\n\n" if existing.strip() else ""
        target.write_text(existing.rstrip() + separator + RULE, encoding="utf-8")
        print(f"[ok] updated {name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="code-airlock", description="Local PII/secret gate for coding agents")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("mcp", help="start the MCP stdio server (default)")
    sub.add_parser("proxy", help="start the OpenAI-compatible HTTP proxy")
    sub.add_parser("doctor", help="verify the model and print MCP configuration")
    sub.add_parser("init", help="add code-airlock rules to .cursorrules and CLAUDE.md")
    args = parser.parse_args()
    if args.command in (None, "mcp"):
        from .mcp_server import main as run
        run()
        return 0
    if args.command == "proxy":
        from .proxy import main as run
        run()
        return 0
    if args.command == "doctor":
        return doctor()
    if args.command == "init":
        return init()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
