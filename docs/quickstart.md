# late-sast Quickstart Guide

This guide gets you up and running with `late-sast` (the autonomous security auditor) in under 5 minutes.

`late-sast` uses `~/.config/late-sast/` for its config, and falls back to `~/.config/late/` so an existing `late` installation works with zero changes.

---

## late-sast — Autonomous Security Auditor

### Prerequisites

- Docker installed and running (`docker info` should succeed)
- An OpenAI-compatible model endpoint (local or cloud)
- The [codebase-memory MCP server](https://github.com/DeusData/codebase-memory-mcp) — baked into the binary when built with `make build-sast`, otherwise downloaded on first run

### 1. Set your endpoint

```bash
# Local (e.g. llama.cpp)
export OPENAI_BASE_URL="http://localhost:8080"

# Cloud (e.g. OpenRouter, Anthropic, Google)
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="your-model"
```

> **Windows:** Use PowerShell syntax: `$env:OPENAI_BASE_URL="http://localhost:8080"`

### 2. Run a scan

```bash
# Scan a GitHub repository
late-sast https://github.com/owner/repo

# Specify an output directory (created if it doesn't exist)
late-sast --output ~/sast-reports https://github.com/owner/repo

# Scan a local repository (no clone step — directory is mounted into the container)
late-sast --path /path/to/local/repo

# Re-verify a previous report after a developer claims fixes
late-sast --retest ./sast_report_myrepo.md
```

The report path is printed at startup. `late-sast` will:

1. Clone the repository into an isolated `/tmp` working directory
2. Build a full codebase knowledge graph (HTTP routes, auth boundaries, data flows)
3. Spin up a Docker container matching the repo's language
4. Install dependencies and start the application
5. Run a SAST scan across 34 vulnerability classes and grep for hardcoded secrets
6. Run Trivy for lockfile-based CVE detection and query [cve.circl.lu](https://cve.circl.lu/) for live CVE enrichment (CVSS scores, NVD links)
7. Attempt live exploitation for every CONFIRMED or LIKELY finding
8. Write `sast_report_<repo>.md` to the output directory (default: current directory)
9. Remove the container, cloned source, and all temporary files

### 3. Read the report

The report is written to the output directory (default: current directory). Scan mode determines the filename:

| Mode | Output file |
|------|-------------|
| Normal scan | `sast_report_<repo>.md` |
| Retest | `sast_retest_<repo>.md` |

Each finding is classified:

| Status | Meaning |
|--------|---------|
| **CONFIRMED** | Exploited live — PoC returned meaningful response |
| **LIKELY** | Statically confirmed, runtime inconclusive |
| **NEEDS CONTEXT** | Requires credentials or runtime config to verify |
| **FALSE POSITIVE** | Blocked or path unreachable |

In retest mode, findings are re-classified as:

| Status | Meaning |
|--------|--------|
| **FIXED** | Vulnerability no longer reproducible |
| **STILL PRESENT** | Vulnerability persists |
| **CANNOT VERIFY** | Insufficient runtime state to confirm either way |

### Hybrid Model Routing (Recommended)

`late-sast` uses a three-model pipeline. Each role can point at a different endpoint:

```bash
# Orchestrator / scout (large reasoning model)
export OPENAI_MODEL="qwen3.6-35b-a3b"
export OPENAI_BASE_URL="http://localhost:8080"

# Auditor — deep taint analysis, CoT security reasoning (small specialized model)
export LATE_AUDITOR_MODEL="VulnLLM-R-7B"
export LATE_AUDITOR_BASE_URL="http://localhost:8080" # optional, falls back to OPENAI_BASE_URL
export LATE_AUDITOR_API_KEY="..."                   # optional

# Fixer subagent — code generation, patch writing (fast dense model)
export LATE_SUBAGENT_MODEL="qwen3.6-27b-coder"
export LATE_SUBAGENT_BASE_URL="http://10.8.0.2:8080" # optional, falls back to OPENAI_BASE_URL
export LATE_SUBAGENT_API_KEY="your-other-key"        # optional
```

All three fall back to `OPENAI_BASE_URL` / `OPENAI_API_KEY` if not set separately.

---

## Recommended Local Models

`late-sast` is designed for a three-model pipeline: orchestrator, auditor, and fixer.

### Orchestrator — Qwen3.6-35B-A3B-Aggressive

**[HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive](https://huggingface.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive)**

| Property | Value |
|---|---|
| Architecture | MoE 35B params, ~3B active |
| Context | 262 144 tokens |
| VRAM — IQ3_M | ~15 GB (runs with 4–6 GB free VRAM + CPU offload) |
| VRAM — Q4_K_P | ~19 GB (recommended, full GPU) |
| Best for | Security research, exploitation reasoning, ops planning |

```bash
# Required llama.cpp flags for correct thinking-mode output
llama-server -m /models/Qwen3.6-35B-A3B-Q4_K_P.gguf \
  --jinja \
  --reasoning-format deepseek \
  --chat-template-kwargs '{"preserve_thinking": true}'
```

Sampling settings: `temperature: 0.6  top_p: 0.95  top_k: 20`

### Auditor — VulnLLM-R-7B

**[VulnLLM-R-7B](https://huggingface.co/VulnLLM/VulnLLM-R-7B)** (Qwen2.5-7B base, PrimeVul fine-tune)

| Property | Value |
|---|---|
| Architecture | Dense 7B |
| Fine-tune dataset | PrimeVul (real-world vulnerability corpus) |
| VRAM — Q4_K_M | ~5 GB |
| Best for | CoT taint analysis, hotspot scoring, CWE classification |

The auditor runs as a restricted subagent (one tool: `read_file`) so a 7B model is sufficient. It is given `max_tokens: 8192` to produce complete hotspot verdicts without truncation.

```bash
# Minimal llama-server invocation
llama-server -m /models/VulnLLM-R-7B-Q4_K_M.gguf -c 32768 -ngl 99
```

Sampling settings: `temperature: 0.6  top_p: 0.95`

### Fixer Subagent — Qwen3.6-27B-Balanced

**[HauhauCS/Qwen3.6-27B-Uncensored-HauhauCS-Balanced](https://huggingface.co/HauhauCS/Qwen3.6-27B-Uncensored-HauhauCS-Balanced)**

| Property | Value |
|---|---|
| Architecture | Dense 27B |
| Context | 262 144 tokens |
| VRAM — Q4_K_P | ~18 GB (fits a 24 GB GPU) |
| Best for | Agentic coding, long tool-call chains, patch writing |

The "Balanced" variant has more predictable sampling than Aggressive across long subagent loops — fewer hallucinated tool calls at turn 200+.

Sampling settings: `temperature: 0.6  presence_penalty: 1.5`

### Serving Both Models with llama-swap

[**mostlygeek/llama-swap**](https://github.com/mostlygeek/llama-swap) is a Go reverse proxy that manages multiple `llama-server` instances behind a single endpoint. It routes requests by model name — exactly what the `OPENAI_MODEL` / `LATE_SUBAGENT_MODEL` split requires.

```yaml
# llama-swap config snippet
models:
  qwen3.6-35b-a3b:
    proxy: "http://localhost:5801"
    cmd: "llama-server -m /models/Qwen3.6-35B-A3B-Q4_K_P.gguf --jinja --reasoning-format deepseek --chat-template-kwargs '{\"preserve_thinking\": true}' -c 65536 -ngl 99"
  VulnLLM-R-7B:
    proxy: "http://localhost:5803"
    cmd: "llama-server -m /models/VulnLLM-R-7B-Q4_K_M.gguf -c 32768 -ngl 99"
  qwen3.6-27b-balanced:
    proxy: "http://localhost:5802"
    cmd: "llama-server -m /models/Qwen3.6-27B-Balanced-Q4_K_P.gguf -c 65536 -ngl 99"
```

Point `late`/`late-sast` at the swap endpoint:

```bash
export OPENAI_BASE_URL="http://localhost:8080/v1"
export OPENAI_MODEL="qwen3.6-35b-a3b"              # orchestrator
export LATE_AUDITOR_MODEL="VulnLLM-R-7B"           # auditor
export LATE_SUBAGENT_MODEL="qwen3.6-27b-balanced"  # fixer subagent
```

---

## Configuration

`late-sast` stores its config in a JSON file. Set your model endpoint and credentials there to avoid re-exporting environment variables each session.

**Config locations:**
* **Linux/macOS:** `~/.config/late-sast/config.json` (preferred) → falls back to `~/.config/late/config.json`
* **Windows:** `%APPDATA%\late-sast\config.json` → falls back to `%APPDATA%\late\config.json`

> If you already have `late` configured, `late-sast` will pick it up automatically — no migration needed.

**Setting Precedence:**
1. Non-empty environment variables
2. `config.json`
3. Defaults


```json
{
  "openai_base_url": "http://localhost:8080",
  "openai_api_key": "your-api-key",
  "openai_model": "qwen3.6-35b-a3b",
  "auditor_base_url": "http://localhost:8080",
  "auditor_api_key": "",
  "auditor_model": "VulnLLM-R-7B",
  "subagent_base_url": "http://10.8.0.2:8080",
  "subagent_api_key": "your-other-api-key",
  "subagent_model": "qwen3.6-27b-balanced"
}
```

## MCP Integration

`late-sast` loads MCP config from `~/.config/late-sast/mcp_config.json` if it exists, otherwise falls back to `~/.config/late/mcp_config.json`. The project-local `.late-sast/mcp_config.json` takes highest precedence over both.

> **late-sast note:** The codebase-memory MCP server is required for SAST scans and is downloaded automatically on first run. You do not need to add it manually.

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "my-mcp-server"]
    }
  }
}
```

## Agent Skills

[Skills](https://agentskills.io/) are reusable sets of instructions. They are discovered automatically from:
* **Global:** `~/.config/late-sast/skills/`
* **Project:** `.late-sast/skills/`

There is no further setup required. Just add your skills to the directories and they will be discovered automatically.

## Common Flags

| Flag | Description |
| --- | --- |
| `--help` | Show all flags and commands |
| `--version` | Show version information |
| `--output <dir>` | Directory to write the report (default: current directory) |
| `--path <dir>` | Scan a local repository instead of cloning from GitHub |
| `--retest <report>` | Re-verify findings from a previous report after fixes |
| `--timeout <duration>` | Wall-clock scan timeout (e.g. `90m`, `2h`). Default: no limit |
| `--subagent-max-turns <n>` | Maximum turns per subagent (default: 500) |
| `--gemma-thinking` | Inject `<\|think\|>` token for Gemma 4 models |
