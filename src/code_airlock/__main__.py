"""Zero-friction CLI: MCP server, proxy, doctor, init, and secret scanning."""
from __future__ import annotations
import argparse, os, sys
from pathlib import Path

RULE = """# code-airlock security rules
Always use `airlock_read_file` and `airlock_write_file` when reading or writing `.env`, `*secret*`, credentials, or deployment configs. Never inspect secret files using raw bash (`cat`, `grep`) or native file read tools.
"""
MARKER = "code-airlock security rules"
HOOK = """#!/bin/sh
# Installed by code-airlock
python -m code_airlock scan --staged
"""
CONFIG_TEMPLATE = """# code-airlock project configuration
[allowlist]
terms = ["MyInternalApp", "staging.corp.local"]

[custom_patterns]
# EMPLOYEE_ID = 'EMP-[0-9]{6}'
# INTERNAL_TICKET = 'JIRA-[0-9]{4,6}'
"""
CONFIG = """{
  "mcpServers": {
    "code-airlock": {
      "command": "python",
      "args": ["-m", "code_airlock.mcp_server"]
    }
  }
}"""
RULE_FILES = {"opencode": "AGENTS.md", "claude": "CLAUDE.md", "cursor": ".cursorrules"}
HARNESSES = tuple(RULE_FILES)


def _detect_harness(explicit_target: str | None = None) -> list[str]:
    """Resolve the active coding harness from a flag, its environment, or local footprints."""
    if explicit_target:
        return list(HARNESSES) if explicit_target == "all" else [explicit_target]
    if os.environ.get("OPENCODE") or os.environ.get("OPENCODE_VERSION") or os.environ.get("OPENCODE_CONFIG_DIR"):
        return ["opencode"]
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        return ["claude"]
    if os.environ.get("CURSOR_TRACE_ID") or (os.environ.get("VSCODE_PID") and Path(".cursor").exists()):
        return ["cursor"]
    cwd, home = Path.cwd(), Path.home()
    found = []
    if (cwd / "opencode.json").exists() or (cwd / ".opencode").exists() or (home / ".config" / "opencode").exists():
        found.append("opencode")
    if (cwd / "CLAUDE.md").exists() or (cwd / ".claude").exists() or (cwd / ".mcp.json").exists() or (home / ".claude").exists():
        found.append("claude")
    if (cwd / ".cursor").exists() or (cwd / ".cursorrules").exists() or (home / ".cursor").exists():
        found.append("cursor")
    return found or list(HARNESSES)


def doctor(show_config: bool = True) -> int:
    from .engine import CascadeEngine
    from .sanitizer import VaultSession
    sample = ("API key sk-" + "proj-abc123def456ghi789jkl012mno345; "
              "postgres://user:" + "pass12345" + "@10.0.0.5:5432/db; "
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
    print(f"[{'ok' if not missing else 'fail'}] GLiNER ONNX ready ({engine.device}); labels: {', '.join(sorted(labels))}")
    print(f"[{'ok' if restored == sample else 'fail'}] round-trip rehydration ({len(spans)} spans)")
    if not ok:
        if missing: print(f"[fail] missing detectors: {', '.join(sorted(missing))}")
        return 1
    if show_config:
        print("\nOpenCode (~/.config/opencode/opencode.json):")
        print('{"mcp": {"servers": {"code-airlock": {"type": "local", "command": ["python", "-m", "code_airlock.mcp_server"]}}}}')
        print("\nCursor / Claude Code / Claude Desktop:")
        print(CONFIG)
    return 0


def _append_rule(target: Path, label: str) -> None:
    """Append the airlock rule block once, creating parent directories as needed."""
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    if MARKER in existing:
        print(f"[ok] {label} already contains code-airlock rules")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    separator = "\n\n" if existing.strip() else ""
    target.write_text(existing.rstrip() + separator + RULE, encoding="utf-8")
    print(f"[ok] updated {label}")


def _install_hook(root: Path) -> bool:
    """Install the pre-commit hook when the directory is a Git repository."""
    hooks = root / ".git" / "hooks"
    if not hooks.is_dir():
        return False
    hook = hooks / "pre-commit"
    existing = hook.read_text(encoding="utf-8") if hook.exists() else ""
    if "code-airlock scan --staged" in existing:
        print("[ok] .git/hooks/pre-commit already installed")
    else:
        separator = "\n\n" if existing.strip() else ""
        hook.write_text(existing.rstrip() + separator + HOOK, encoding="utf-8")
        os.chmod(hook, 0o755)
        print("[ok] installed .git/hooks/pre-commit")
    return True


def init(pre_commit: bool = False, config: bool = False, targets: list[str] | None = None) -> int:
    targets = _detect_harness() if targets is None else targets
    if config:
        config_path = Path.cwd() / ".airlock.toml"
        if config_path.exists():
            print("[ok] .airlock.toml already exists")
        else:
            config_path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
            print("[ok] created .airlock.toml")
    for harness in targets:
        name = RULE_FILES[harness]
        _append_rule(Path.cwd() / name, name)
    if pre_commit and not _install_hook(Path.cwd()):
        print("[skip] no .git/hooks directory")
    return 0


def install(target: str | None = None, home: Path | None = None, workspace: Path | None = None,
            check: bool = True) -> int:
    """Register code-airlock globally for every harness, then warm up the engine."""
    from .config import merge_mcp_config
    home = home or Path.home()
    workspace = workspace or Path.cwd()
    harnesses = list(HARNESSES) if target in (None, "all") else [target]
    command = [sys.executable, "-m", "code_airlock.mcp_server"]
    spec = {"command": sys.executable, "args": ["-m", "code_airlock.mcp_server"]}
    configs, rules = [], []
    if "opencode" in harnesses:
        configs.append((home / ".config" / "opencode" / "opencode.json", "mcp.servers",
                        {"type": "local", "command": command}))
        rules.append(home / ".config" / "opencode" / "AGENTS.md")
    if "claude" in harnesses:
        configs.append((home / ".claude.json", "mcpServers", spec))
        rules.append(home / ".claude" / "CLAUDE.md")
    if "cursor" in harnesses:
        configs.append((home / ".cursor" / "mcp.json", "mcpServers", spec))
    failed = 0
    print(f"[ok] Installing globally for: {', '.join(harnesses)}")
    for path, top_key, server in configs:
        try:
            updated, existed = merge_mcp_config(path, top_key, "code-airlock", dict(server))
            print(f"[ok] {'updated' if existed else 'created'}: {updated}")
        except (OSError, ValueError) as exc:
            failed = 1
            print(f"[fail] {exc}")
    for path in rules:
        try:
            _append_rule(path, str(path))
        except OSError as exc:
            failed = 1
            print(f"[fail] {exc}")
    if check:
        if (workspace / ".git").exists():
            _install_hook(workspace)
        failed |= doctor(show_config=False)
    print("\nRestart your agents to load the code-airlock tools.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="code-airlock", description="Local PII/secret gate for coding agents")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("mcp", help="start the MCP stdio server (default)")
    sub.add_parser("proxy", help="start the OpenAI-compatible HTTP proxy")
    sub.add_parser("doctor", help="verify the model and print MCP configuration")
    init_cmd = sub.add_parser("init", help="add code-airlock rules and optional pre-commit hook")
    init_cmd.add_argument("--pre-commit", action="store_true", help="install .git/hooks/pre-commit")
    init_cmd.add_argument("--config", action="store_true", help="create a starter .airlock.toml")
    init_cmd.add_argument("--target", choices=(*HARNESSES, "all"), help="harness to initialize (default: auto-detect)")
    install_cmd = sub.add_parser("install", help="register code-airlock globally for OpenCode, Claude Code, and Cursor")
    install_cmd.add_argument("--target", choices=(*HARNESSES, "all"),
                             help="harness to configure globally (default: all)")
    scan_cmd = sub.add_parser("scan", help="scan files or staged changes for secrets")
    scan_cmd.add_argument("--staged", action="store_true", help="scan files staged in git")
    scan_cmd.add_argument("--deep", action="store_true", help="enable Stage 2 GLiNER detection")
    scan_cmd.add_argument("paths", nargs="*", default=["."], help="files or directories to scan")
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
        return init(args.pre_commit, args.config, _detect_harness(args.target))
    if args.command == "install":
        return install(args.target)
    if args.command == "scan":
        from .scanner import scan
        return scan(args.paths, staged=args.staged, deep=args.deep)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
