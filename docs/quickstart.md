# late-sast Quickstart Guide

This guide gets you up and running with both `late-sast` (the autonomous security auditor) and `late` (the coding agent) in under 5 minutes.

Both binaries share the same MCP server setup. `late-sast` uses `~/.config/late-sast/` for its own config if `~/.config/late-sast/config.json` already exists there, and falls back to `~/.config/late/` so an existing `late` installation works with zero changes.

---

## late-sast — Autonomous Security Auditor

### Prerequisites

- Docker installed and running (`docker info` should succeed)
- An OpenAI-compatible model endpoint (local or cloud)
- The [codebase-memory MCP server](https://github.com/DeusData/codebase-memory-mcp) — downloaded automatically on first run

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
late-sast https://github.com/owner/repo
```

That's it. `late-sast` will:

1. Clone the repository into an isolated `/tmp` working directory
2. Build a full codebase knowledge graph (HTTP routes, auth boundaries, data flows)
3. Spin up a Docker container matching the repo's language
4. Install dependencies and start the application
5. Run a SAST scan across 34 vulnerability classes
6. Attempt live exploitation for every CONFIRMED or LIKELY finding
7. Write `sast_report_<repo>.md` to your current directory
8. Remove the container, cloned source, and all temporary files

### 3. Read the report

The report is written to your current working directory as `sast_report_<repo>.md`. Each finding is classified:

| Status | Meaning |
|--------|---------|
| **CONFIRMED** | Exploited live — PoC returned meaningful response |
| **LIKELY** | Statically confirmed, runtime inconclusive |
| **NEEDS CONTEXT** | Requires credentials or runtime config to verify |
| **FALSE POSITIVE** | Blocked or path unreachable |

### Hybrid Model Routing (Recommended)

Use a large model for planning and a faster model for execution:

```bash
export LATE_SUBAGENT_MODEL="your-fast-model"
export LATE_SUBAGENT_BASE_URL="http://10.8.0.2:8080"  # optional, falls back to OPENAI_BASE_URL
export LATE_SUBAGENT_API_KEY="your-other-key"          # optional, falls back to OPENAI_API_KEY
```

---

## Recommended Local Models

`late-sast` and `late` are designed for hybrid routing — a large reasoning model as orchestrator and a dense model as subagent. The two models below are fine-tuned for security research and long agentic coding loops.

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

### Subagent — Qwen3.6-27B-Balanced

**[HauhauCS/Qwen3.6-27B-Uncensored-HauhauCS-Balanced](https://huggingface.co/HauhauCS/Qwen3.6-27B-Uncensored-HauhauCS-Balanced)**

| Property | Value |
|---|---|
| Architecture | Dense 27B |
| Context | 262 144 tokens |
| VRAM — Q4_K_P | ~18 GB (fits a 24 GB GPU) |
| Best for | Agentic coding, long tool-call chains, stable generation |

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
  qwen3.6-27b-balanced:
    proxy: "http://localhost:5802"
    cmd: "llama-server -m /models/Qwen3.6-27B-Balanced-Q4_K_P.gguf -c 65536 -ngl 99"
```

Point `late`/`late-sast` at the swap endpoint:

```bash
export OPENAI_BASE_URL="http://localhost:8080/v1"
export OPENAI_MODEL="qwen3.6-35b-a3b"        # orchestrator
export LATE_SUBAGENT_MODEL="qwen3.6-27b-balanced"  # subagent
```

---

## late — Coding Agent

### Setup

**1. Set your endpoint** (any OpenAI-compatible API, e.g. llama.cpp, [Google](https://ai.google.dev/gemini-api/docs/openai), [Anthropic](https://platform.claude.com/docs/en/api/openai-sdk), [OpenRouter](https://openrouter.ai/docs/quickstart)):

```bash
# Local (e.g. llama.cpp)
export OPENAI_BASE_URL="http://localhost:8080"

# Cloud (e.g. Google)
export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="your-model"
```

> **Windows:** Use your preferred shell's syntax for all environment variables for example `$env:OPENAI_BASE_URL="http://localhost:8080"` in PowerShell.

**2. Launch Late from your project directory:**

```bash
cd your-project
late
```

> **macOS:** If macOS blocks the binary, run this command in your terminal (adjust the path if needed): `xattr -d com.apple.quarantine ~/.local/bin/late`

**3. Hybrid Routing (Optional):**
By default, Late uses the same model for both the Lead Architect (orchestrator) and the ephemeral workers (subagents). You can mix and match models by setting separate environment variables.
Check the [Configuration](#configuration) section to find out how to persist these settings.

This is useful for using a large, smart model for planning and a fast, cheap model for execution:

```bash
export LATE_SUBAGENT_MODEL="gemma-4-e4b"
export LATE_SUBAGENT_BASE_URL="http://10.8.0.2:8080" # (Optional) falls back to OPENAI_BASE_URL
export LATE_SUBAGENT_API_KEY="your-other-key"        # (Optional) falls back to OPENAI_API_KEY
```

## Interface

Late is a terminal UI with three areas: the **chat viewport** (scrollable history), the **input box** (bottom), and the **status bar** (shows mode, status, token count, and available keybindings).

### Keybindings

| Key | Action |
| --- | --- |
| `Enter` | Send your message |
| `↑` `↓` `PgUp` `PgDn` | Scroll the chat viewport |
| `Tab` | Switch between agent tabs (orchestrator ↔ subagents) |
| `y` / `n` | Approve or deny a tool call when prompted |
| `Ctrl+G` | Stop the current agent (cancel generation) |
| `Esc` / `Ctrl+C` | Quit Late |

### Agent Tabs

When Late spawns subagents, each one gets its own tab. Use `Tab` to cycle through them:

- **Main** — the orchestrator (Lead Architect). It plans and delegates.
- **Subagent tabs** — ephemeral workers executing isolated tasks. They appear when spawned and disappear when finished.

The status bar at the bottom shows which agent you're currently viewing and its state (Idle, Thinking, Streaming, etc.).

> **Tip:** If a subagent seems stuck, switch to it with `Tab` to see what it's doing. You can stop it with `Ctrl+G` without affecting the orchestrator.

## How to Give Good Instructions

Late works best with clear, specific instructions. Some examples:

```
# Good
Add input validation to the CreateUser handler in api/users.go.
Check for empty email and name fields, return 400 with a JSON error.

# Good
Refactor the database package to use connection pooling.
The pool config should come from environment variables.

# Bad
Make the code better.
```

Late will read your codebase, plan the implementation, and ask you for approval. Make sure to read the generated implementation plan (`./implementation_plan.md`) and the intended changes before approving.

## Tool Approval

When the agent wants to run a command or edit a file, you'll see a confirmation prompt:

```
The agent wants to execute a bash command.
   {"command":"npm run build"}
> Press [y] Allow once | [s] Allow always (session) | [p] Allow always (project) | [g] Allow always (global) | [n] Deny
```

- **Read-only commands** (`ls`, `cat`, `grep`, etc.) are auto-approved for speed (Note: the listed commands can still require permission if Late deems the agents activity suspicious)
- **Everything else** requires explicit approval.
- Use **`[y] Allow once`** to approve only this single tool call.
- Use **`[s] Allow always (session)`** to auto-approve matching requests for the rest of the current session.
- Use **`[p] Allow always (project)`** to remember approval for this project.
- Use **`[g] Allow always (global)`** to remember approval across all projects on this machine.
- Use **`[n] Deny`** to block the request.

This keeps one-off actions safe while reducing repetitive prompts when you trust a tool in a broader scope.

### Permission Decay (TTL)

"Always" approvals are not permanent. Late uses TTL (time-to-live) so trust decays over time:

- **Session scope** (`[s]`) lasts **30 minutes**.
- **Project scope** (`[p]`) lasts **30 days**.
- **Global scope** (`[g]`) lasts **30 days**.

When a TTL expires, the approval is automatically ignored and Late will prompt you again. This is intentional: it reduces long-lived stale permissions while keeping day-to-day workflows smooth.

Notes:

- Re-approving a tool/command in the same scope refreshes its TTL.
- Session approvals are in-memory and expire quickly by design.
- Project/global approvals are persisted with an expiry timestamp and checked at load time.

## Configuration

`late` and `late-sast` each have their own config file. Set your model endpoint and credentials in the appropriate file.

**`late-sast` config locations:**
* **Linux/macOS:** `~/.config/late-sast/config.json` (preferred) → falls back to `~/.config/late/config.json`
* **Windows:** `%APPDATA%\late-sast\config.json` → falls back to `%APPDATA%\late\config.json`

**`late` config locations:**
* **Linux/macOS:** `~/.config/late/config.json`
* **Windows:** `%APPDATA%\late\config.json`

> `late-sast` uses its own directory when `~/.config/late-sast/config.json` exists, otherwise it falls back to `~/.config/late/` automatically — no migration needed if you already have `late` configured.

**Setting Precedence:**
1. Non-empty environment variables
2. `config.json`
3. Defaults


```json
{
  "openai_base_url": "http://localhost:8080",
  "openai_api_key": "your-api-key",
  "openai_model": "qwen3.6-35b-a3b",
  "subagent_base_url": "http://10.8.0.2:8080",
  "subagent_api_key": "your-other-api-key",
  "subagent_model": "gemma-4-e4b"
}
```

## MCP Integration

`late-sast` loads MCP config from `{config-dir}/mcp_config.json` where `config-dir` is `~/.config/late-sast/` if `~/.config/late-sast/config.json` exists, otherwise `~/.config/late/`. In both cases the project-local `.late/mcp_config.json` takes highest precedence. `late` always uses `~/.config/late/mcp_config.json`.

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
* **Global:** `~/.config/late/skills/`
* **Project:** `.late/skills/`

There is no further setup required. Just add your skills to the directories and they will be discovered automatically.

## Common Flags

| Flag | Description |
| --- | --- |
| `--help` | Show all flags and commands |
| `--version` | Show version information |
| `--gemma-thinking` | Inject thinking tokens for Gemma 4 models |
| `--subagent-max-turns <n>` | Set max turns per subagent (default: 500) |
| `--append-system-prompt "..."` | Append text to the system prompt (e.g. further instructions) |

## Sessions

Late automatically saves your session history. Resume or manage sessions:

```bash
late session list          # List all saved sessions
late session list -v       # Verbose listing with details
late session load <id>     # Resume a previous session
late session delete <id>   # Delete a session
```

## Git Worktrees

Late is designed for parallel development. You can manage Git worktrees directly to run separate agent instances in isolated environments:

```bash
late worktree list               # List all worktrees
late worktree active             # Show current worktree
late worktree create <path> [br] # Create a new worktree at <path>
late worktree remove <path>      # Remove a worktree
```

> **Tip:** Use worktrees when you want Late to work on a feature in the background while you continue working on another branch.
