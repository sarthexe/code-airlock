# 🛡️ code-airlock

[![PyPI version](https://img.shields.io/pypi/v/code-airlock.svg)](https://pypi.org/project/code-airlock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Benchmark](https://img.shields.io/badge/Benchmark-100%25%20Recall%20%2F%20Precision-brightgreen)](https://huggingface.co/datasets/sarthexe/pii-airlock-bench)
[![Runtime](https://img.shields.io/badge/Runtime-Pure%20ONNX%20(Zero--Torch)-orange)](#architecture)

**Zero-trust PII & secret airlock for AI coding agents (Claude Code, OpenCode, Cursor, Windsurf, Cline).**

`code-airlock` sits between your local codebase and LLM agents as both a **FastMCP Server** and an **OpenAI-compatible SSE Proxy**. It replaces live API keys, database passwords, and PII with reversible, session-consistent placeholders (`<API_KEY_1>`, `<AUTH_TOKEN_1>`, `<PERSON_1>`) before text enters LLM context—and restores them byte-exact on disk or inside child test processes without the AI ever seeing the raw values.

- **Lightweight & Universal (~60 MB):** Powered by a two-stage deterministic Regex + **Pure ONNX Runtime (`gliner_small-v2.1`)** cascade. No `torch` bloat, no GPU required, and **100% offline** after initial model warmup.
- **Sub-Millisecond Stage 1 (`0.20 ms` p50):** Instant secret detection and Git pre-commit scanning.
- **Safe Subprocess Execution (`airlock_exec`):** Run `pytest` or scripts against live `.env` credentials while automatically scrubbing secrets from `stdout` and `stderr` before logs return to the agent.

---

## ⚡ Quickstart (Add to Your Agent Harness in 10 Seconds)

### 🤖 One-Prompt Agent Install (OpenCode / Claude Code / Cursor)

Tell your coding agent:

> `Install https://github.com/sarthexe/code-airlock`

Or run:

```bash
pip install -U code-airlock && python -m code_airlock install
```

`code-airlock` automatically detects your active harness (OpenCode, Claude Code, or Cursor), registers its MCP server in that harness's config without overwriting existing servers, and generates only the matching instruction file (`AGENTS.md`, `CLAUDE.md`, or `.cursorrules`). It also warms up the ONNX model, creates `.airlock.toml`, and installs the Git pre-commit hook when run inside a repository.

Override detection with `--target opencode|claude|cursor|all`. Restart the agent afterward to load the seven `airlock_*` tools.

You can run `code-airlock` directly via **`uvx`** (zero install, no virtual environment needed) or install it globally via **`pip`**.

### Option A: Zero-Install via `uvx` (Recommended)

#### 1. Claude Code
```bash
claude mcp add code-airlock -- uvx code-airlock
```

#### 2. OpenCode (`~/.config/opencode/opencode.json`)
```json
{
  "mcp": {
    "code-airlock": {
      "type": "local",
      "command": ["uvx", "code-airlock"]
    }
  }
}
```

#### 3. Cursor / Claude Desktop / Windsurf (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "code-airlock": {
      "command": "uvx",
      "args": ["code-airlock"]
    }
  }
}
```

**Warm up the ONNX model & initialize your repository with `uvx`:**
```bash
# 1. Pre-cache ONNX weights & run a 1-second round-trip self-test
uvx --from code-airlock python -m code_airlock doctor

# 2. Add agent rules (.cursorrules / CLAUDE.md), .airlock.toml, and Git pre-commit hook
uvx --from code-airlock python -m code_airlock init --pre-commit --config
```

---

### Option B: Standard `pip install`

```bash
pip install code-airlock

# Verify installation & warm up local ONNX model cache
python -m code_airlock doctor

# Initialize project guardrails & Git pre-commit secret shield
python -m code_airlock init --pre-commit --config
```

<details>
<summary><b>Click to view MCP JSON configs for standard <code>pip</code> installs</b></summary>

**Claude Code:**
```bash
claude mcp add code-airlock -- python -m code_airlock.mcp_server
```

**OpenCode (`~/.config/opencode/opencode.json`):**
```json
{
  "mcp": {
    "code-airlock": {
      "type": "local",
      "command": ["python", "-m", "code_airlock.mcp_server"]
    }
  }
}
```

**Cursor / Claude Desktop (`.cursor/mcp.json`):**
```json
{
  "mcpServers": {
    "code-airlock": {
      "command": "python",
      "args": ["-m", "code_airlock.mcp_server"]
    }
  }
}
```
</details>

---

## 🛠️ How It Works in Your Daily Workflow

Once added to your harness and initialized via `init --pre-commit`, your coding agent automatically uses `code-airlock` for sensitive operations:

1. **Reading & Refactoring Configs Safely (`airlock_read_file` & `airlock_write_file`):**
   - You ask: *"Read `.env` and generate a production `docker-compose.yml`."*
   - The agent calls `airlock_read_file(".env")` and sees only:
     ```ini
     STRIPE_SECRET_KEY=<API_KEY_1>
     DATABASE_URL=postgres://admin:<AUTH_TOKEN_1>@10.0.4.12:5432/prod
     ```
   - The agent writes the new file using `<API_KEY_1>` and `<AUTH_TOKEN_1>` via `airlock_write_file()`. `code-airlock` rehydrates the real secrets onto disk behind the scenes.
2. **Running Tests Without Leaking `stdout` (`airlock_exec`):**
   - You ask: *"Run `pytest` using `.env` to verify the Stripe webhook."*
   - The agent calls `airlock_exec(command=["pytest", "-v"], env_file=".env")`.
   - `code-airlock` injects the real credentials into the child process memory, executes the test, and scrubs any secret values printed in `stdout` or `stderr` back into `<API_KEY_1>` before returning the output to the LLM.
3. **Blocking Accidental Git Commits (`scan --staged`):**
   - Whenever you or the agent runs `git commit`, the pre-commit hook runs `python -m code_airlock scan --staged` in **`0.20 ms`**, blocking any staged file that contains a live credential.

---

## 🧰 Complete MCP Toolkit (7 Tools)

| MCP Tool | Description |
| :--- | :--- |
| `airlock_read_file(path)` | Reads a file, dehydrates all secrets/PII into `<ENTITY_N>` tokens in the session vault, and returns sanitized text to the agent. |
| `airlock_write_file(path, content)` | Rehydrates `<ENTITY_N>` placeholders (case- and whitespace-tolerant), verifies no hallucinated tokens remain, and writes real values to disk. |
| `airlock_exec(command, env_file="")` | Runs a subprocess (`shell=False`) with real `.env` secrets injected into child memory and scrubs `stdout`/`stderr` before returning to the LLM. |
| `airlock_scrub_text(text, use_ner=False)` | Scrubs in-memory strings, logs, or code snippets directly and registers tokens in the active vault. |
| `airlock_dehydrate(text)` | Converts raw text into sanitized text with `<ENTITY_N>` tokens. |
| `airlock_rehydrate(text)` | Restores `<ENTITY_N>` tokens in a string back to their original values. |
| `airlock_vault_status()` | Returns active token count and categories (`API_KEY`, `AUTH_TOKEN`, etc.) without ever exposing raw values. |

### Built-In Security Guardrails
- **Workspace & System Folder Jailing:** Blocks path traversal and sensitive directories (`.ssh`, `.aws`, `.gnupg`, `.kube`, `/etc`, `System32`). Set `AIRLOCK_WORKSPACE=/path/to/repo` to strictly jail file operations to a single directory.
- **Hallucination-Safe Write Gate:** If an LLM invents a non-existent token (e.g., `<API_KEY_999>`), `airlock_write_file` refuses to write a broken file and returns an `unresolved_tokens` error so the agent can self-correct.
- **Forgiving Rehydration:** Automatically resolves LLM casing or spacing variations (`<api_key_1>` or `< API_KEY_1 >`).
- **Crash-Safe Memory Hygiene:** `VaultSession.__repr__` and `__str__` never expose raw secrets in stack traces or crash logs.
- **Binary & Size Caps:** Rejects non-UTF-8 binary files (`\x00`) and files over `1 MB`.

---

## 💻 CLI Reference

```bash
python -m code_airlock                 # Start FastMCP stdio server (default)
python -m code_airlock install         # Detect harness, register MCP config, init guardrails
python -m code_airlock doctor          # Warm up ONNX model, run self-test & print IDE configs
python -m code_airlock init            # Add agent rules to .cursorrules and CLAUDE.md
python -m code_airlock init --pre-commit --config  # Also install Git hook + starter .airlock.toml
python -m code_airlock scan src/       # Fast Stage-1 secret scan across paths (0.20ms/file)
python -m code_airlock scan --staged   # Scan staged Git changes (exits 1 on findings, masks preview)
python -m code_airlock scan --deep .   # Deep scan with Stage 1 + Stage 2 ONNX NER
python -m code_airlock proxy           # Launch OpenAI-compatible SSE proxy on :8000
```

---

## ⚙️ Project Configuration (`.airlock.toml`)

Drop an `.airlock.toml` file in your project root (or generate one via `python -m code_airlock init --config`) to define custom Stage 1 regex rules and Stage 2 allowlists for your team:

```toml
[allowlist]
terms = ["MyInternalApp", "staging.corp.local"]

[custom_patterns]
EMPLOYEE_ID = 'EMP-[0-9]{6}'
INTERNAL_TICKET = 'JIRA-[0-9]{4,6}'
```

- **`[custom_patterns]`:** Evaluated in Stage 1 (`~0.20 ms`) and mapped to reversible tokens (`<EMPLOYEE_ID_1>`, `<INTERNAL_TICKET_1>`).
- **`[allowlist]`:** Prevents domain-specific terms or internal hostnames from being flagged by Stage 2 NER.

---

## 🌐 OpenAI-Compatible SSE Proxy Mode

Need network-level protection for any OpenAI SDK client or custom agent pipeline? Run the streaming HTTP proxy:

```bash
code-airlock-proxy
# Or: python -m code_airlock proxy
```

Point your client's `OPENAI_BASE_URL` to `http://localhost:8000/v1` and set `UPSTREAM_BASE_URL` (defaults to `https://api.openai.com`).
- **Outbound:** Scrubs all messages in `POST /v1/chat/completions` before forwarding upstream.
- **Inbound Streaming (`StreamRehydrator`):** Buffers only inside open `<...>` brackets across arbitrary network chunks (even 1-byte SSE splits) and restores secrets on the fly with zero latency on regular text.

---

## 📊 Benchmarks (`sarthexe/pii-airlock-bench`)

Evaluated on the open 4-split benchmark dataset ([`sarthexe/pii-airlock-bench`](https://huggingface.co/datasets/sarthexe/pii-airlock-bench)) covering **2,000 rows**, **5,817 entity spans**, **250 hard negatives** (UUIDs, Git SHAs, dummy placeholders, localhost IPs, CLI flags), and **1/2/7-byte adversarial SSE stream splits**:

| Suite | Rows | Recall / Precision / F1 | Token Accuracy | Hard Negatives (0-FP) | Clean Rows (0-FP) | SSE 1/2/7-Byte Round-Trip |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `dev_prompts` | 1,000 | **100.0% / 100.0% / 100.0%** | 100.0% | 0 / 0 | 200 / 200 | 1,000 / 1,000 |
| `git_leaks` | 500 | **100.0% / 100.0% / 100.0%** | 100.0% | 250 / 250 | 100 / 100 | 500 / 500 |
| `mcp_configs` | 250 | **100.0% / 100.0% / 100.0%** | 100.0% | 0 / 0 | 50 / 50 | 250 / 250 |
| `adversarial_sse` | 250 | **100.0% / 100.0% / 100.0%** | 100.0% | 0 / 0 | 0 / 0 | 250 / 250 |
| **Total (`all`)** | **2,000** | **100.0% / 100.0% / 100.0%** | **100.0%** | **250 / 250** | **350 / 350** | **2,000 / 2,000** |

- **Stage 1 Latency (Regex + URI/Key-Value Heuristics):** `0.203 ms` p50
- **Stage 2 Latency (Pure ONNX CPU `gliner_small-v2.1`):** `55.20 ms` p50 (`CUDAExecutionProvider` automatically used when `onnxruntime-gpu` is present)

Reproduce locally:
```bash
python benchmarks/benchmark.py --suite all
```

---

## 📄 License

MIT © [Sarthak Kumar Maurya](https://github.com/sarthexe)