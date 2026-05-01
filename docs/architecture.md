# Architecture Map — late-sast

> **Project:** late-sast: Autonomous Security Auditor
> **Base:** Built on mlhher/late agent engine
> **Fork:** late-sast adds Docker sandboxing, live exploitation, CVE enrichment, and SAST pipeline
> **License:** BSL 1.1
> **Generated:** From project index — 2,441 nodes, 5,318 edges, 94 Go source files

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Directory Structure](#3-directory-structure)
4. [Package Dependency Graph](#4-package-dependency-graph)
5. [Core Components Deep Dive](#5-core-components-deep-dive)
6. [SAST Pipeline Architecture](#6-sast-pipeline-architecture)
7. [Agent & Orchestrator Model](#7-agent--orchestrator-model)
8. [Tool System Architecture](#8-tool-system-architecture)
9. [Session & State Management](#9-session--state-management)
10. [Configuration System](#10-configuration-system)
11. [TUI & Event System](#11-tui--event-system)
12. [MCP Integration](#12-mcp-integration)
13. [Key Interfaces](#13-key-interfaces)
14. [Data Flow Diagrams](#14-data-flow-diagrams)
15. [Entry Points](#15-entry-points)
16. [Statistics](#16-statistics)

---

## 1. Executive Summary

late-sast is an autonomous security auditor built on the Late agent engine. It takes a GitHub URL or local path, spins up a throwaway Docker sandbox, performs a full static/dynamic security scan, exploits findings live, and produces a structured markdown report.

### Two Binary Targets

| Binary | Description | Entry Point |
|--------|-------------|-------------|
| `late` | General-purpose AI agent with TUI | `cmd/late/main.go` |
| `late-sast` | Autonomous SAST pipeline, headless | `cmd/late-sast/main.go` |

### Key Differentiators

- **Graph-First:** Builds full codebase knowledge graph before scanning
- **Live Exploitation:** Proves each finding with a real PoC
- **Self-Cleaning:** Docker container + /tmp workspace cleaned on exit
- **Model-Agnostic:** Any OpenAI-compatible endpoint
- **Hybrid Model Routing:** Separate models for orchestrator, subagent, and auditor roles

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                User                                     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
               ┌───────────────▼───────────────┐
               │      Entry Points             │
               │  cmd/late/main.go             │
               │  cmd/late-sast/main.go        │
               │  cmd/mcp-run/main.go          │
               └───────────────┬───────────────┘
                               │
              ┌────────────────▼────────────────┐
              │    Session / Orchestrator       │
              │    ┌────────────────────────┐   │
              │    │  BaseOrchestrator      │   │
              │    │  - Submit/Execute      │   │
              │    │  - Event streaming     │   │
              │    │  - Cancel/Reset        │   │
              │    └────────────────────────┘   │
              │    Tool Registry                │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Client / MCP / Subagent        │
              │  ┌────────────────────────┐     │
              │  │  client.Client         │     │
              │  │  - Streaming API calls │     │
              │  │  - Backend discovery   │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  MCP Client            │     │
              │  │  - External tool RPC   │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  Subagent Orchestrator │     │
              │  │  - Coder/Scanner       │     │
              │  │  - Auditor/Setup       │     │
              │  └────────────────────────┘     │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Config / Assets / Git / TUI    │
              │  ┌────────────────────────┐     │
              │  │  config.Config         │     │
              │  │  - Resolution chain    │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  assets.PromptsFS      │     │
              │  │  (embedded prompts)    │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  tui.Model             │     │
              │  │  (Bubble Tea + Glamour)│     │
              │  └────────────────────────┘     │
              └─────────────────────────────────┘
```

### Layer Descriptions

| Layer | Responsibility |
|-------|---------------|
| **Entry Points** | CLI argument parsing, flag handling, bootstrap sequence |
| **Session/Orchestrator** | Conversation state, tool registry, event streaming, lifecycle management |
| **Client/MCP/Subagent** | LLM API communication, external tool RPC, subagent spawning |
| **Config/Assets/TUI** | Configuration resolution, embedded prompts, terminal rendering |

---

## 3. Directory Structure

```
.
├── .github/
│   ├── CLA.md
│   ├── pull_request_template.md
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── .late/
│   └── mcp_config.json
├── CHANGELOG.md
├── LICENSE
├── Makefile
├── README.md
├── assets/
│   └── late-subagent-handoff.png
├── bin/
│   └── sast_report_govwa.md
├── cmd/
│   ├── late/
│   │   └── main.go                    # Interactive TUI agent
│   ├── late-sast/
│   │   ├── main.go                    # Headless SAST pipeline
│   │   ├── cbm_embed.go               # CBM binary embed (build tag)
│   │   ├── cbm_no_embed.go            # CBM no-embed fallback
│   │   └── embedded/
│   │       ├── .gitkeep
│   │       └── codebase-memory-mcp    # Embedded CBM binary
│   └── mcp-run/
│       └── main.go                    # MCP server runner
├── docs/
│   ├── example_report.md
│   └── quickstart.md
├── go.mod
├── go.sum
└── internal/
    ├── agent/
    │   ├── agent.go                   # Subagent orchestrator creation
    │   └── agent_test.go
    ├── assets/
    │   ├── assets.go                  # Embedded file system (embed.FS)
    │   ├── prompts/
    │   │   ├── instruction-coding.md
    │   │   ├── instruction-planning.md
    │   │   ├── instruction-sast.md
    │   │   ├── instruction-sast-auditor.md
    │   │   ├── instruction-sast-retest.md
    │   │   ├── instruction-sast-scanner.md
    │   │   ├── instruction-sast-scanner-binary.md
    │   │   └── instruction-sast-setup.md
    │   └── sast/
    │       ├── SKILL.md               # SAST skill definition
    │       ├── assets.go              # Embedded SAST skill files
    │       └── references/            # 34 vulnerability class references
    │           ├── arbitrary_file_upload.md
    │           ├── authentication_jwt.md
    │           ├── binary_command_injection.md
    │           ├── brute_force.md
    │           ├── business_logic.md
    │           ├── csrf.md
    │           ├── cve_patterns.md
    │           ├── dangerous_functions.md
    │           ├── default_credentials.md
    │           ├── denial_of_service.md
    │           ├── expression_language_injection.md
    │           ├── format_string.md
    │           ├── graphql_injection.md
    │           ├── http_method_tamper.md
    │           ├── idor.md
    │           ├── information_disclosure.md
    │           ├── insecure_cookie.md
    │           ├── insecure_deserialization.md
    │           ├── integer_overflow.md
    │           ├── jndi_injection.md
    │           ├── memory_corruption.md
    │           ├── mobile_security.md
    │           ├── nosql_injection.md
    │           ├── null_pointer_dereference.md
    │           ├── open_redirect.md
    │           ├── path_traversal_lfi_rfi.md
    │           ├── php_security.md
    │           ├── privilege_escalation.md
    │           ├── privilege_management.md
    │           ├── prototype_pollution.md
    │           ├── race_conditions.md
    │           ├── rce.md
    │           ├── sensitive_memory_exposure.md
    │           ├── session_fixation.md
    │           ├── smuggling_desync.md
    │           ├── sql_injection.md
    │           ├── ssrf.md
    │           ├── ssti.md
    │           ├── trust_boundary.md
    │           ├── use_after_free.md
    │           ├── verification_code_abuse.md
    │           ├── weak_crypto_hash.md
    │           ├── xss.md
    │           └── xxe.md
    ├── client/
    │   ├── client.go                  # LLM client abstraction
    │   └── types.go                   # ChatMessage, ToolCall, Usage types
    ├── common/
    │   ├── interfaces.go              # Orchestrator, Tool, Event interfaces
    │   ├── path_utils.go              # Path utility functions
    │   ├── path_utils_test.go
    │   ├── result.go                  # StreamResult, StreamAccumulator types
    │   ├── tools.go                   # ToolRegistry, Tool interface
    │   ├── utils.go                   # ReplacePlaceholders, etc.
    │   ├── utils_test.go
    │   └── version.go                 # Version constant
    ├── config/
    │   ├── config.go                  # Configuration loading & resolution
    │   └── config_test.go
    ├── executor/
    │   ├── executor.go                # RunLoop, tool execution, stream handling
    │   └── executor_test.go
    ├── git/
    │   ├── worktree.go                # Git worktree management
    │   └── worktree_test.go
    ├── mcp/
    │   ├── client.go                  # MCP client implementation
    │   ├── config.go                  # MCP config loading
    │   └── config_test.go
    ├── orchestrator/
    │   └── base.go                    # BaseOrchestrator implementation
    ├── pathutil/
    │   └── pathutil.go                # Config/skill/cache dir resolution
    ├── session/
    │   ├── models.go                  # Session model & history management
    │   ├── models_test.go
    │   ├── persistence.go             # JSON-based session persistence
    │   ├── session.go                 # Session lifecycle
    │   └── ttystyle.go                # TTY formatting helpers
    ├── skill/
    │   ├── skill.go                   # Skill discovery & metadata
    │   └── skill_test.go
    ├── tool/
    │   ├── analyzer.go                # Bash/PowerShell analysis
    │   ├── ast/
    │   │   ├── feature_flag.go
    │   │   ├── helpers.go
    │   │   ├── ir.go                  # Abstract Syntax Tree IR
    │   │   ├── ir_test.go
    │   │   ├── policy.go              # AST policies
    │   │   ├── policy_test.go
    │   │   ├── ps_bridge.ps1
    │   │   ├── registry.go            # AST adapter registry
    │   │   ├── shadow.go
    │   │   ├── snapshot_test.go
    │   │   ├── snapshot_windows_test.go
    │   │   ├── unix_adapter.go        # Unix AST adapter
    │   │   ├── unix_adapter_test.go
    │   │   ├── windows_adapter.go     # Windows AST adapter
    │   │   └── windows_adapter_test.go
    │   ├── ast_bridge.go              # AST subsystem bridge
    │   ├── ast_mode_test.go
    │   ├── bash_analyzer.go           # Bash command analysis
    │   ├── bash_analyzer_project_test.go
    │   ├── bash_analyzer_sast.go      # SAST-specific bash analysis
    │   ├── bash_analyzer_test.go
    │   ├── compose_patch.go           # Docker Compose YAML patching
    │   ├── compose_patch_test.go
    │   ├── context_index.go           # BM25 context index
    │   ├── context_index_test.go
    │   ├── cve_search.go              # CVE lookup tools
    │   ├── cve_search_test.go
    │   ├── docs_lookup.go             # ProContext documentation lookup
    │   ├── docs_lookup_test.go
    │   ├── implementations.go         # Core tool implementations
    │   ├── implementations_cmd_test.go
    │   ├── implementations_test.go
    │   ├── line_endings_test.go
    │   ├── permissions.go             # Tool permission checks
    │   ├── permissions_test.go
    │   ├── permissions_user_test.go
    │   ├── powershell_analyzer.go     # PowerShell command analysis
    │   ├── reproduce_issue_test.go
    │   ├── sast_tools_test.go
    │   ├── shell_command_test.go
    │   ├── shell_command_unix.go      # Unix shell execution
    │   ├── shell_command_windows.go   # Windows shell execution
    │   ├── skill_tool.go              # Skill activation tool
    │   ├── subagent.go                # Spawn subagent tool
    │   ├── targetEdit.go              # Targeted file editing
    │   ├── targetEdit_test.go
    │   ├── tool.go                    # Tool/Registry type aliases
    │   └── utils.go                   # Tool utilities
    └── tui/
        ├── interactions.go            # TUI interaction handlers
        ├── interactions_test.go
        ├── keys.go                    # Key bindings
        ├── model.go                   # Bubble Tea model
        ├── state.go                   # Generation state management
        ├── styles.go                  # Glamour styling
        ├── theme.go                   # Theme definitions
        ├── update.go                  # Bubble Tea update loop
        └── view.go                    # Bubble Tea view rendering
```

---

## 4. Package Dependency Graph

```
cmd/late              cmd/late-sast          cmd/mcp-run
    │                      │                       │
    ├──────────────────────┼───────────────────────┤
    ▼                      ▼                       ▼
    │              ┌─────────────────────────┐
    │              │  internal/agent         │◄─── NewSubagentOrchestrator
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/orchestrator   │◄─── BaseOrchestrator
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/session       │◄─── Session, persistence
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/executor      │◄─── RunLoop, tool execution
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/client        │◄─── LLM API client
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/tool          │◄─── Tool implementations
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/tool/ast      │◄─── AST subsystem
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/config        │◄─── Config loading/resolution
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/mcp           │◄─── MCP client & config
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/tui           │◄─── Bubble Tea TUI
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/assets        │◄─── Embedded prompts/SKILL.md
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/common        │◄─── Interfaces, utils, types
    │              └─────────────────────────┘
```

### Dependency Summary

| Package | Depends On |
|---------|-----------|
| `cmd/late` | agent, client, common, config, executor, git, mcp, orchestrator, session, tool, tui, assets |
| `cmd/late-sast` | agent, assets, client, common, config, mcp, orchestrator, pathutil, session, tool, tui |
| `internal/agent` | assets, client, common, executor, orchestrator, session, tui |
| `internal/orchestrator` | client, common, executor, session |
| `internal/session` | client, common, pathutil |
| `internal/executor` | client, common, pathutil, session, skill, tool |
| `internal/tool` | common, pathutil, client |
| `internal/client` | common |
| `internal/tui` | client, common, tool |

---

## 5. Core Components Deep Dive

### 5.1 Orchestrator Pattern

The `BaseOrchestrator` (in `internal/orchestrator/base.go`) is the core agent lifecycle manager. It implements the `common.Orchestrator` interface and manages the full conversation lifecycle.

#### Lifecycle

```
NewBaseOrchestrator()
    │
    ├── SetContext(ctx)          ────────── Inject context with InputProvider, approval flags
    ├── SetMiddlewares([]ToolMiddleware)   ── Attach confirmation middleware
    │
    ├── Submit(text) ───────────────────── Async submission (background goroutine)
    │       │
    │       ├── AddUserMessage(text)
    │       ├── eventCh <- StatusEvent("thinking")
    │       └── go o.run()  ── Background execution loop
    │
    └── Execute(text) ──────────────────── Synchronous execution (blocking)
            │
            ├── AddUserMessage(text)
            ├── executor.RunLoop(...)     ── Core inference + tool loop
            │       │
            │       ├── onStartTurn()     ── Reset accumulator, "thinking" event
            │       ├── ConsumeStream()   ── Stream LLM response deltas
            │       ├── AddAssistantMessageWithTools() ── Commit to history
            │       ├── onEndTurn()       ── Emit ContentEvent with usage
            │       └── ExecuteToolCalls() ── Execute via middleware chain
            │
            └── return (result, error)

    ├── Cancel() ──────────────────────── Cancel context, signal stop
    ├── Reset() ───────────────────────── Clear history, persist empty state
    └── AddChild(child) ───────────────── Add subagent, emit ChildAddedEvent
```

#### Key Fields

| Field | Type | Purpose |
|-------|------|---------|
| `id` | `string` | Unique orchestrator identifier |
| `sess` | `*session.Session` | Conversation session |
| `middlewares` | `[]ToolMiddleware` | Tool execution interceptors |
| `eventCh` | `chan Event` | Event stream to TUI |
| `parent` | `Orchestrator` | Parent orchestrator (nil for root) |
| `children` | `[]Orchestrator` | Child/subagent orchestrators |
| `acc` | `StreamAccumulator` | Streaming response accumulator |
| `ctx` | `context.Context` | Cancelable execution context |
| `cancel` | `context.CancelFunc` | Cancellation function |
| `stopCh` | `chan struct{}` | Stop signal channel |
| `maxTurns` | `int` | Maximum conversation turns |

### 5.2 Session Management

Session management (in `internal/session/`) handles conversation history and persistence.

#### Key Operations

```
Session Lifecycle:
    CREATE ──► RUN ──► PERSIST ──► LOAD ──► DELETE
     │          │          │          │          │
     ▼          ▼          ▼          ▼          ▼
  New()     AddUser  SaveHistory  LoadHistory  Remove files
            AddAssistant
            AddToolResult
            ExecuteTool
            StartStream
```

#### Session Types

| Mode | Persistence | Use Case |
|------|-------------|----------|
| Regular (`late`) | Persistent (JSON to `~/.config/late/sessions/`) | Interactive TUI conversations |
| SAST (`late-sast`) | Non-persistent | Headless audit runs |
| Subagent | Non-persistent | Temporary spawned agents |

### 5.3 Client Layer

The LLM client (in `internal/client/`) provides abstraction over OpenAI-compatible endpoints.

#### Key Features

- **Backend Discovery:** Auto-detects API capabilities on first call
- **Streaming:** Real-time token streaming via channels
- **Context Size Tracking:** Dynamically refreshes context window size
- **Multi-Client Support:** Separate clients for main, subagent, and auditor roles

#### Model Routing

```
┌──────────────────────────────────────────────┐
│           Model Routing Matrix              │
├──────────────┬───────────────────────────────┤
│ Role         │ Client / Model Source         │
├──────────────┼───────────────────────────────┤
│ Main         │ OPENAI_BASE_URL / MODEL       │
│ Subagent     │ LATE_SUBAGENT_* env vars      │
│ Auditor      │ LATE_AUDITOR_* env vars       │
└──────────────┴───────────────────────────────┘
```

### 5.4 Tool System

The tool system (in `internal/tool/` and `internal/common/tools.go`) provides a registry-based approach with middleware support.

#### Tool Interface

```go
type Tool interface {
    Name() string
    Description() string
    Parameters() json.RawMessage
    Execute(ctx context.Context, args json.RawMessage) (string, error)
    RequiresConfirmation(args json.RawMessage) bool
    CallString(args json.RawMessage) string
}
```

#### Middleware Chain Pattern

```
User Input → Middleware N → ... → Middleware 1 → Base Runner → Tool.Execute()
                                         ↑
                                   Result flows back through chain
```

Each `ToolMiddleware` wraps the next runner:

```go
type ToolMiddleware func(next ToolRunner) ToolRunner

// TUI confirmation middleware example:
func TUIConfirmMiddleware(p *tea.Program, reg *ToolRegistry) ToolMiddleware {
    return func(next ToolRunner) ToolRunner {
        return func(ctx context.Context, tc ToolCall) (string, error) {
            // Prompt user for confirmation before executing shell commands
            if requiresConfirmation(tc) {
                promptUser(p, tc)
            }
            return next(ctx, tc)
        }
    }
}
```

---

## 6. SAST Pipeline Architecture

The SAST pipeline in `cmd/late-sast/main.go` follows a deterministic 7-step flow:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SAST Pipeline — 7-Step Flow                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: CLEANUP                                                 │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • Reap stale Docker containers (name=sast-)               │  │   │
│  │  │ • Remove stale Docker networks (name=sast-)               │  │   │
│  │  │ • Extract embedded SAST skill files to /tmp/sast-skill    │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 2: CODEBASE MEMORY MCP                                     │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • ensureCBM(): Check PATH → ~/.local/bin → embedded       │  │   │
│  │  │                  → download from GitHub Releases           │  │   │
│  │  │ • Add CBM directory to $PATH                               │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 3: SESSION & TOOL SETUP                                    │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • Create session with SAST system prompt                  │  │   │
│  │  │ • Register core tools (bash, read_file, write_file)       │  │   │
│  │  │ • Register CVE lookup tools (VulnDB native Go)            │  │   │
│  │  │ • Register compose network patching tool                  │  │   │
│  │  │ • Register ProContext doc lookup tools                    │  │   │
│  │  │ • Build BM25 context index (SAST refs + semgrep skills)   │  │   │
│  │  │ • Register context tools (ctx_index, ctx_search, etc.)    │  │   │
│  │  │ • Register MCP tools from config                          │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 4: ORCHESTRATOR SETUP                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • Create TUI renderer (Glamour)                           │  │   │
│  │  │ • Create root orchestrator                                │  │   │
│  │  │ • Create Bubble Tea program                               │  │   │
│  │  │ • Wire context (InputProvider, SkipConfirmation,          │  │   │
│  │  │   ToolApproval for unsupervised SAST runs)                │  │   │
│  │  │ • Wire TUI middleware (confirmation)                      │  │   │
│  │  │ • Wire event forwarding (orchestrator → TUI)              │  │   │
│  │  │ • Auto-submit initial audit task after 300ms delay        │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 5: SUBAGENT ROUTING                                        │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • auditor  → auditorClient (security-specialist model)     │  │   │
│  │  │ • scanner  → subagentClient (code-specialist model)        │  │   │
│  │  │ • setup    → subagentClient                                │  │   │
│  │  │ • binary-scanner → subagentClient                          │  │   │
│  │  │                                                          │  │   │
│  │  │ Auditor special config:                                  │  │   │
│  │  │   - maxTokens=8192 (extra generation budget)             │  │   │
│  │  │   - repeat_penalty=1.15 (prevent repetition loops)       │  │   │
│  │  │   - Tools restricted to read_file only                   │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 6: EXECUTION                                               │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • p.Run() — Bubble Tea main loop                          │  │   │
│  │  │ • LLM inference → tool execution → LLM inference (loop)  │  │   │
│  │  │ • Subagent spawning for scanning/auditing                 │  │   │
│  │  │ • Signal handling (SIGINT/SIGTERM → cleanup)              │  │   │
│  │  │ • Timeout enforcement (if --timeout set)                  │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  STEP 7: CLEANUP                                                 │   │
│  │  ┌────────────────────────────────────────────────────────────┐  │   │
│  │  │ • docker stop -t 5 <container>                             │  │   │
│  │  │ • docker rm -f <container>                                 │  │   │
│  │  │ • docker compose -p <project> down -v --remove-orphans    │  │   │
│  │  │ • Remove sidecar containers (sast-<ts>-*)                  │  │   │
│  │  │ • docker network rm <network>                              │  │   │
│  │  │ • alpine rm -rf /tmp/sast-skill (root-owned files)         │  │   │
│  │  │ • alpine rm -rf /tmp/sast-<timestamp> (workdir)            │  │   │
│  │  └────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Pipeline Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--target` | (required) | GitHub URL to audit |
| `--path` | — | Local repository path (alternative to --target) |
| `--output` | current dir | Report output directory |
| `--timeout` | 0 (no limit) | Wall-clock scan timeout (e.g., 90m, 2h) |
| `--subagent-max-turns` | 500 | Maximum turns per subagent |
| `--retest` | — | Retest previous report findings |
| `--gemma-thinking` | false | Enable Gemma 4 thinking tokens |

---

## 7. Agent & Orchestrator Model

### 7.1 Orchestrator Hierarchy

```
                    ┌─────────────────┐
                    │  Root Agent     │
                    │  (BaseOrchestrator)│
                    │  id: "main"     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │ Subagent   │ │ Subagent   │ │ Subagent   │
       │ (scanner)  │ │ (auditor)  │ │ (coder)    │
       │ id: "sub-1"│ │ id: "sub-2"│ │ id: "sub-3"│
       └────────────┘ └────────────┘ └────────────┘
```

### 7.2 Agent Types

| Type | Prompt File | Model | Tools | Max Tokens | Purpose |
|------|------------|-------|-------|------------|---------|
| `coder` | `instruction-coding.md` | Subagent model | Full toolset | Default | Code modifications |
| `scanner` | `instruction-sast-scanner.md` | Subagent model | Full toolset | Default | Vulnerability scanning |
| `binary-scanner` | `instruction-sast-scanner-binary.md` | Subagent model | Full toolset | Default | Binary security scanning |
| `auditor` | `instruction-sast-auditor.md` | Auditor model | read_file only | 8192 | Finding verification |
| `setup` | `instruction-sast-setup.md` | Subagent model | Full toolset | Default | Environment setup |

### 7.3 Auditor Special Configuration

The auditor agent receives special treatment due to its smaller model size (typically ~7B parameters):

```go
if agentType == "auditor" {
    sess.SetMaxTokens(8192)                      // Extra generation budget
    sess.SetExtraBody(map[string]any{
        "repeat_penalty": 1.15,                  // Prevent repetition loops
        "repeat_last_n": 512,                    // Context window for penalty
    })
    // Tools restricted to read_file only (prevents context collapse)
    if agentType == "auditor" && name != "read_file" {
        continue  // Skip all other tools
    }
}
```

### 7.4 Prompt Loading

Prompts are embedded via Go's `embed.FS` and loaded by agent type:

```go
switch agentType {
case "coder":
    content, _ := assets.PromptsFS.ReadFile("prompts/instruction-coding.md")
case "scanner":
    content, _ := assets.PromptsFS.ReadFile("prompts/instruction-sast-scanner.md")
case "auditor":
    content, _ := assets.PromptsFS.ReadFile("prompts/instruction-sast-auditor.md")
case "setup":
    content, _ := assets.PromptsFS.ReadFile("prompts/instruction-sast-setup.md")
// ... etc
}
```

---

## 8. Tool System Architecture

### 8.1 Tool Categories

| Category | Tools | Location |
|----------|-------|----------|
| **Core Tools** | `read_file`, `write_file`, `target_edit`, `bash` | `internal/tool/implementations.go` |
| **CVE Tools** | `vuln_vendor_product_cve`, `vuln_cve_search`, `vuln_vendor_products`, `vuln_last_cves` | `internal/tool/cve_search.go` |
| **Infrastructure Tools** | `patch_compose_network` | `internal/tool/compose_patch.go` |
| **Context Knowledge Base** | `ctx_index`, `ctx_search`, `ctx_fetch_and_index`, `ctx_index_file` | `internal/tool/context_index.go` |
| **Documentation Lookup** | `docs_resolve`, `docs_read`, `docs_search` | `internal/tool/docs_lookup.go` |
| **Skill Tools** | `activate_skill` | `internal/tool/skill_tool.go` |
| **Subagent Tools** | `spawn_subagent` | `internal/tool/subagent.go` |
| **MCP Tools** | Dynamic (from MCP servers) | `internal/mcp/client.go` |

### 8.2 AST Subsystem

The AST (Abstract Syntax Tree) subsystem in `internal/tool/ast/` provides structured shell command analysis:

```
┌─────────────────────────────────────────────────────────────┐
│                      AST Subsystem                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  ir.go       │    │  policy.go   │    │  registry.go │   │
│  │  IR types    │    │  Policies    │    │  Adapter     │   │
│  │  (tokens,    │    │  (rules for  │    │  Registry    │   │
│  │   nodes,     │    │   validation)│    │  (adapter    │   │
│  │   tree)      │    │              │    │   discovery) │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                    │                    │          │
│         └────────────────────┼────────────────────┘          │
│                              │                               │
│              ┌───────────────▼───────────────┐               │
│              │    Platform Adapters          │               │
│              │  ┌────────────┐ ┌───────────┐ │               │
│              │  │ unix_      │ │ windows_  │ │               │
│              │  │ adapter.go │ │ adapter.go│ │               │
│              │  │ (bash/zsh) │ │ (pwsh)    │ │               │
│              │  └────────────┘ └───────────┘ │               │
│              └───────────────────────────────┘               │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  feature_flag.go  │  helpers.go  │  shadow.go        │    │
│  │  (AST mode toggle)│  (utilities) │  (type shadows)   │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.3 Bash Analysis Pipeline

```
Shell Command
      │
      ▼
┌───────────────┐
│ BashAnalyzer  │  ← Platform-specific (unix_adapter / windows_adapter)
│ (AST parse)   │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Policy Check  │  ← Security policy evaluation
│  (policy.go)   │
└───────┬───────┘
        │
        ▼
┌───────────────┐     ┌──────────────────┐
│ Requires       │YES→ │ Prompt User      │
│ Confirmation?  │     │ for Approval     │
└───────┬───────┘     └──────────────────┘
        │NO
        ▼
┌───────────────┐
│ Execute Command│  ← Shell execution with timeout
└───────────────┘
```

### 8.4 SAST Bash Analyzer

The SAST-specific analyzer (`bash_analyzer_sast.go`) extends the base analyzer with:
- Permissive path handling (`SkipSafePath: true`)
- 2-minute command timeout (prevents curl/docker exec from blocking)
- Docker-specific command awareness

---

## 9. Session & State Management

### 9.1 Session Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Session Lifecycle                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────┐     ┌──────────┐     ┌───────────┐     ┌────────┐    │
│   │ CREATE  │────►│   RUN    │────►│  PERSIST  │────►│  LOAD  │    │
│   │         │     │          │     │           │     │        │    │
│   │ New()   │     │ AddMsg() │     │SaveHistory│     │Load    │    │
│   │         │     │Stream()  │     │(JSON)     │     │History │    │
│   └─────────┘     └──────────┘     └───────────┘     └───┬────┘    │
│         │                │                      ┌────────┼─────┐   │
│         │                └──────────────────────┤        │     │   │
│         │                                      ▼        │     │   │
│         │                                 ┌──────────┐  │     │   │
│         └────────────────────────────────►│  DELETE  │◄─┘     │   │
│                                           │(Remove  │         │   │
│                                           │ files)  │         │   │
│                                           └──────────┘         │   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 9.2 Session Persistence

| Session Type | Persistence | Storage Path |
|-------------|-------------|--------------|
| Interactive (`late`) | Yes | `~/.config/late/sessions/session-{timestamp}.json` |
| SAST (`late-sast`) | No | In-memory only |
| Subagent | No | In-memory only |

### 9.3 History Format

Session history is stored as JSON arrays of `ChatMessage` objects:

```json
[
  {"role": "system", "content": "You are a security scanner..."},
  {"role": "user", "content": "Perform a complete security audit of: https://github.com/owner/repo"},
  {"role": "assistant", "content": "Starting analysis...", "tool_calls": [...]},
  {"role": "tool", "content": "...", "tool_call_id": "call_abc123"}
]
```

---

## 10. Configuration System

### 10.1 Resolution Chain

Configuration follows a 3-layer priority chain (highest to lowest):

```
CLI Flags  ───►  Environment Variables  ───►  App Config File  ───►  Defaults
    │                  │                        │                    │
    ▼                  ▼                        ▼                    ▼
  --model        OPENAI_MODEL          config.json        localhost:8080
  --help         OPENAI_API_KEY        (auto-created)
  --version      OPENAI_BASE_URL
                 LATE_SUBAGENT_*
                 LATE_AUDITOR_*
```

### 10.2 Configuration Structure

```go
type Config struct {
    EnabledTools    map[string]bool `json:"enabled_tools"`
    OpenAIBaseURL   string          `json:"openai_base_url,omitempty"`
    OpenAIAPIKey    string          `json:"openai_api_key,omitempty"`
    OpenAIModel     string          `json:"openai_model,omitempty"`
    SubagentBaseURL string          `json:"subagent_base_url,omitempty"`
    SubagentAPIKey  string          `json:"subagent_api_key,omitempty"`
    SubagentModel   string          `json:"subagent_model,omitempty"`
    AuditorBaseURL  string          `json:"auditor_base_url,omitempty"`
    AuditorAPIKey   string          `json:"auditor_api_key,omitempty"`
    AuditorModel    string          `json:"auditor_model,omitempty"`
    SkillsDir       string          `json:"skills_dir,omitempty"`
}
```

### 10.3 Key Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `OPENAI_BASE_URL` | LLM endpoint URL | `http://localhost:8080` |
| `OPENAI_API_KEY` | API authentication | (none) |
| `OPENAI_MODEL` | Model identifier | (none) |
| `LATE_SUBAGENT_BASE_URL` | Subagent LLM endpoint | Inherits from OPENAI |
| `LATE_SUBAGENT_API_KEY` | Subagent API key | Inherits from OPENAI |
| `LATE_SUBAGENT_MODEL` | Subagent model | Inherits from OPENAI |
| `LATE_AUDITOR_BASE_URL` | Auditor LLM endpoint | Inherits from OPENAI |
| `LATE_AUDITOR_API_KEY` | Auditor API key | Inherits from OPENAI |
| `LATE_AUDITOR_MODEL` | Auditor model | Inherits from OPENAI |
| `LATE_SYSTEM_PROMPT` | Override system prompt | Embedded default |

### 10.4 Config File Locations

| Binary | Config Directory |
|--------|-----------------|
| `late` | `~/.config/late/config.json` |
| `late-sast` | `~/.config/late-sast/config.json` (falls back to `~/.config/late/config.json`) |

### 10.5 Security

- Config directory permissions: `0700`
- Config file permissions: `0600`
- Permissions are enforced on every config load (not just creation)

---

## 11. TUI & Event System

### 11.1 TUI Architecture

The TUI is built on **Bubble Tea** (The Elm Architecture in Go) with **Glamour** for markdown rendering.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Bubble Tea TUI                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐ │
│  │  model.go  │  │ update.go  │  │  view.go   │  │ keys.go  │ │
│  │  (State    │  │ (Msg       │  │ (Render    │  │ (Key     │ │
│  │   machine) │  │  handling) │  │  output)   │  │  binds)  │ │
│  └────────────┘  └────────────┘  └────────────┘  └──────────┘ │
│         │                │                │              │       │
│         ▼                ▼                ▼              ▼       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  state.go  (GenerationState — streaming state management)   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  interactions.go  (User input, prompts, confirmations)      │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  styles.go + theme.go  (Glamour theme, styling)             │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 Event Types

| Event Type | Description | Payload |
|-----------|-------------|---------|
| `ContentEvent` | Streaming content update | `ID`, `Content`, `ReasoningContent`, `ToolCalls`, `Usage` |
| `StatusEvent` | State change notification | `ID`, `Status` ("thinking"/"idle"/"error"/"closed"), `Error` |
| `ChildAddedEvent` | New subagent spawned | `ParentID`, `Child` orchestrator reference |
| `StopRequestedEvent` | Stop signal received | `ID` |

### 11.3 Input Methods

| Method | Description |
|--------|-------------|
| **Keyboard Input** | Standard TUI keyboard interaction |
| **PromptRequest** | Modal prompts for user data (JSON Schema validated) |
| **AutoSubmit** | Auto-submission of initial tasks (used in SAST mode) |

### 11.4 Event Flow

```
Orchestrator Event
       │
       ▼
┌─────────────────────────┐
│ ForwardOrchestratorEvents│
│ (recursive event wiring) │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ p.Send(TUI Message)     │  ← Bubble Tea program channel
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ TUI Model.Update()      │  ← Elm update function
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ TUI Model.View()        │  ← Elm view function
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Terminal Render         │  ← Glamour markdown rendering
└─────────────────────────┘
```

### 11.5 Recursive Event Forwarding

The event forwarding system recursively wires all orchestrator events to the TUI:

```go
func ForwardOrchestratorEvents(p *tea.Program, o common.Orchestrator) {
    go func() {
        for event := range o.Events() {
            p.Send(tui.OrchestratorEventMsg{Event: event})
            // Recursively wire child orchestrator events
            if added, ok := event.(common.ChildAddedEvent); ok {
                ForwardOrchestratorEvents(p, added.Child)
            }
        }
    }()
}
```

---

## 12. MCP Integration

### 12.1 MCP Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MCP Integration                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  MCP Config Loading                                     │    │
│  │  ┌───────────────────────────────────────────────────┐  │    │
│  │  │ Primary: ~/.config/late*/config.json              │  │    │
│  │  │ Fallback: ~/.config/mcp/config.json               │  │    │
│  │  │ Late-specific: .late/mcp_config.json              │  │    │
│  │  └───────────────────────────────────────────────────┘  │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  MCP Client                                             │    │
│  │  ┌───────────────────────────────────────────────────┐  │    │
│  │  │ • ConnectFromConfig(ctx, config)                  │  │    │
│  │  │ • GetTools() → []Tool                             │  │    │
│  │  │ • Close()                                         │  │    │
│  │  └───────────────────────────────────────────────────┘  │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Tool Registration                                      │    │
│  │  ┌───────────────────────────────────────────────────┐  │    │
│  │  │ for _, t := range mcpClient.GetTools() {          │  │    │
│  │  │     sess.Registry.Register(t)                     │  │    │
│  │  │ }                                                 │  │    │
│  │  └───────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 12.2 codebase-memory-mcp

The `codebase-memory-mcp` is a critical SAST dependency that provides codebase graph intelligence:

| Aspect | Detail |
|--------|--------|
| **Purpose** | Builds full codebase knowledge graph for security scanning |
| **Acquisition** | Embedded binary → PATH check → ~/.local/bin → GitHub Releases download |
| **Embedded Build** | `-tags cbm_embedded` bakes binary into the Go executable |
| **GitHub Release** | `https://github.com/DeusData/codebase-memory-mcp/releases/latest/` |
| **Supported Platforms** | linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64 |
| **Installation** | Extracted to `~/.local/bin/codebase-memory-mcp` |

---

## 13. Key Interfaces

### 13.1 Orchestrator Interface

```go
// common/interfaces.go
type Orchestrator interface {
    // Identity & State
    ID() string
    Context() context.Context
    History() []client.ChatMessage
    
    // Execution
    Submit(text string) error           // Async (background goroutine)
    Execute(text string) (string, error) // Sync (blocking)
    Cancel()
    Reset() error
    
    // Events & Streaming
    Events() <-chan Event
    
    // Configuration
    SetMaxTurns(int)
    RefreshContextSize(context.Context)
    MaxTokens() int
    
    // Tool System
    Middlewares() []ToolMiddleware
    Registry() *ToolRegistry
    SystemPrompt() string
    ToolDefinitions() []client.ToolDefinition
    
    // Hierarchy
    Children() []Orchestrator
    Parent() Orchestrator
}
```

### 13.2 Event Interface

```go
// common/interfaces.go
type Event interface {
    OrchestratorID() string
}

type ContentEvent struct {
    ID               string
    Content          string
    ReasoningContent string
    ToolCalls        []client.ToolCall
    Usage            client.Usage
}

type StatusEvent struct {
    ID     string
    Status string  // "thinking", "idle", "error", "closed"
    Error  error
}

type ChildAddedEvent struct {
    ParentID string
    Child    Orchestrator
}

type StopRequestedEvent struct {
    ID string
}
```

### 13.3 Tool Interface

```go
// common/tools.go
type Tool interface {
    Name() string
    Description() string
    Parameters() json.RawMessage
    Execute(ctx context.Context, args json.RawMessage) (string, error)
    RequiresConfirmation(args json.RawMessage) bool
    CallString(args json.RawMessage) string
}
```

### 13.4 Tool Middleware Pattern

```go
// common/interfaces.go
type ToolRunner func(ctx context.Context, tc ToolCall) (string, error)
type ToolMiddleware func(next ToolRunner) ToolRunner
```

### 13.5 InputProvider Interface

```go
// common/interfaces.go
type InputProvider interface {
    Prompt(ctx context.Context, req PromptRequest) (json.RawMessage, error)
}

type PromptRequest struct {
    ID          string
    Title       string
    Description string
    Schema      json.RawMessage  // JSON Schema for validation
}
```

### 13.6 Context Keys

```go
// common/interfaces.go
const (
    InputProviderKey      contextKey = "input_provider"
    OrchestratorIDKey     contextKey = "orchestrator_id"
    SkipConfirmationKey   contextKey = "skip_confirmation"
    ToolApprovalKey       contextKey = "tool_approval"
)
```

---

## 14. Data Flow Diagrams

### 14.1 SAST Run Data Flow

```
┌──────────────┐
│  GitHub URL  │
│  or local    │
│  path        │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SAST Pipeline                              │
│                                                                 │
│  ┌──────────┐    ┌───────────┐    ┌───────────────────────┐    │
│  │ Clone/   │───►│  Docker   │───►│  Knowledge Graph      │    │
│  │ Load     │    │  Sandbox  │    │  (codebase-memory-mcp)│    │
│  │ Repo     │    │  Setup    │    │                       │    │
│  └──────────┘    └───────────┘    └───────────┬───────────┘    │
│                                               │                 │
│                                               ▼                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Subagent: Scanner                                      │   │
│  │  • Index code with BM25 (ctx_index)                     │   │
│  │  • Scan for vulnerabilities using reference library      │   │
│  │  • CVE enrichment (vuln_cve_search)                     │   │
│  │  • Generate initial findings report                     │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Subagent: Auditor (VulnLLM-R-7B)                       │   │
│  │  • Verify each finding                                   │   │
│  │  • Confirm / Reject / Classify severity                  │   │
│  │  • Taint-chain analysis (read_file only)                 │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Report Generation                                      │   │
│  │  • Structured markdown report                           │   │
│  │  • Written to: <output_dir>/sast_report_<repo>.md        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────┐
│  Markdown Report  │
│  (sast_report_   │
│   <repo>.md)     │
└──────────────────┘
```

### 14.2 Orchestrator Execution Flow

```
User Input (text)
       │
       ▼
┌──────────────────┐
│ Orchestrator     │
│ .Submit() or     │
│ .Execute()       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ AddUserMessage() │  → session history
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ StatusEvent      │────►│ TUI (thinking)   │
│ "thinking"       │     └──────────────────┘
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│           RunLoop (executor)            │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ 1. StartStream() → LLM API     │   │
│  │    ┌─────────────────────────┐ │   │
│  │    │ ConsumeStream()         │ │   │
│  │    │ • Accumulate deltas     │ │   │
│  │    │ • onChunk → TUI events  │ │   │
│  │    │ • Check ctx.Done()      │ │   │
│  │    └─────────────────────────┘ │   │
│  │                                │   │
│  │ 2. AddAssistantMessageWithTools│   │
│  │    (commit to session history) │   │
│  │                                │   │
│  │ 3. Check for tool calls       │   │
│  │    ┌──────────┐  ┌─────────┐ │   │
│  │    │ 0 calls  │  │ >0 calls│ │   │
│  │    │ → Return │  │         │ │   │
│  │    └──────────┘  └────┬────┘ │   │
│  │                       │      │   │
│  │                       ▼      │   │
│  │ 4. ExecuteToolCalls()│      │   │
│  │    Middleware chain  │      │   │
│  │    → Loop back to 1  │      │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ ContentEvent     │────►│ TUI (render      │
│ (content + usage)│     │  final output)   │
└──────────────────┘     └──────────────────┘
         │
         ▼
┌──────────────────┐
│ StatusEvent      │
│ "idle" / "closed"│
└──────────────────┘
```

### 14.3 Subagent Spawning Flow

```
Parent Orchestrator
       │
       │  Needs specialized work
       │
       ▼
┌─────────────────────────────┐
│ spawn_subagent tool         │
│ (SpawnSubagentTool.Runner)  │
│                             │
│ Inputs:                     │
│   • goal string             │
│   • ctxFiles []string       │
│   • agentType string        │
│                             │
│ Routing:                    │
│   "auditor" → auditorClient │
│   others  → subagentClient  │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ NewSubagentOrchestrator()   │
│                             │
│ 1. Load prompt by agentType │
│ 2. Create non-persistent    │
│    session                  │
│ 3. Inherit tools from       │
│    parent registry          │
│ 4. Apply agent-specific     │
│    constraints              │
│ 5. Create BaseOrchestrator  │
│ 6. AddChild() → event       │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ child.Execute(goal)         │
│ (blocking, returns result)  │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Result returned to parent   │
│ (string with subagent output)│
└─────────────────────────────┘
```

---

## 15. Entry Points

### 15.1 `cmd/late/main.go` — Interactive TUI Agent

**Purpose:** General-purpose AI coding agent with terminal UI.

**CLI Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--help` | Show help | false |
| `--system-prompt` | Literal system prompt | embedded default |
| `--system-prompt-file` | System prompt from file | — |
| `--use-tools` | Enable tool usage | true |
| `--enable-bash` | Enable bash tool | true |
| `--inject-cwd` | Replace `${{CWD}}` placeholder | true |
| `--enable-subagents` | Enable subagent spawning | true |
| `--subagent-max-turns` | Max turns for subagents | 500 |
| `--append-system-prompt` | Append text to system prompt | — |
| `--version` | Show version | — |
| `--gemma-thinking` | Gemma 4 thinking tokens | false |
| `--i-promise-i-have-backups-and-will-not-file-issues` | Unsupervised mode | false |

**Subcommands:**
- `late session list [-v]` — List saved sessions
- `late session load <id>` — Load a session by ID
- `late session delete <id>` — Delete a session
- `late worktree list` — List git worktrees
- `late worktree create <path> [branch]` — Create a worktree
- `late worktree remove <path>` — Remove a worktree
- `late worktree active` — Show current worktree

### 15.2 `cmd/late-sast/main.go` — Headless SAST Pipeline

**Purpose:** Autonomous security audit pipeline with Docker sandboxing.

**CLI Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--target` | GitHub URL to audit | — |
| `--path` | Local repository path | — |
| `--output` | Report output directory | current dir |
| `--timeout` | Scan timeout (e.g., 90m) | 0 (no limit) |
| `--subagent-max-turns` | Max turns per subagent | 500 |
| `--retest` | Retest previous report | — |
| `--gemma-thinking` | Gemma 4 thinking tokens | false |
| `--version` | Show version | — |

**Modes:**
1. **New Scan:** `--target https://github.com/owner/repo` or `--path /local/repo`
2. **Retest:** `--retest ./sast_report_repo.md` (retests previous findings)

### 15.3 `cmd/mcp-run/main.go` — MCP Server Runner

**Purpose:** Standalone MCP server runner for external tool integration.

---

## 16. Statistics

### Index Metrics

| Metric | Value |
|--------|-------|
| **Total Nodes** | 2,441 |
| **Total Edges** | 5,318 |
| **Go Source Files** | 94 |
| **Index Size** | 7.4 MB |

### Node Distribution

| Label | Count |
|-------|-------|
| Section | 1,177 |
| Function | 490 |
| Method | 204 |
| File | 156 |
| Module | 156 |
| Class | 115 |
| Variable | 102 |
| Folder | 26 |
| Interface | 8 |
| Route | 4 |
| Type | 2 |
| Project | 1 |

### Edge Distribution

| Type | Count |
|------|-------|
| DEFINES | 2,254 |
| CALLS | 1,082 |
| USAGE | 746 |
| SEMANTICALLY_RELATED | 496 |
| TESTS | 377 |
| CONTAINS_FILE | 156 |
| FILE_CHANGES_WITH | 76 |
| SIMILAR_TO | 51 |
| DEFINES_METHOD | 29 |
| CONTAINS_FOLDER | 24 |
| TESTS_FILE | 22 |
| HTTP_CALLS | 5 |

### Package Statistics

| Package | Source Files | Functions/Methods |
|---------|-------------|-------------------|
| `cmd/late` | 1 | 10+ |
| `cmd/late-sast` | 3 | 15+ |
| `cmd/mcp-run` | 1 | — |
| `internal/agent` | 2 | 2 |
| `internal/assets` | 2 | 1 |
| `internal/assets/sast` | 1 | — |
| `internal/client` | 2 | — |
| `internal/common` | 6 | 8 |
| `internal/config` | 2 | 12 |
| `internal/executor` | 2 | 5 |
| `internal/git` | 2 | 6 |
| `internal/mcp` | 3 | — |
| `internal/orchestrator` | 1 | 22 |
| `internal/pathutil` | 1 | — |
| `internal/session` | 5 | — |
| `internal/skill` | 2 | — |
| `internal/tool` | 26 | 40+ |
| `internal/tool/ast` | 14 | 25+ |
| `internal/tui` | 10 | 30+ |

### SAST Vulnerability References

The SAST skill includes **34 vulnerability class reference files**:

1. `arbitrary_file_upload.md`
2. `authentication_jwt.md`
3. `binary_command_injection.md`
4. `brute_force.md`
5. `business_logic.md`
6. `csrf.md`
7. `cve_patterns.md`
8. `dangerous_functions.md`
9. `default_credentials.md`
10. `denial_of_service.md`
11. `expression_language_injection.md`
12. `format_string.md`
13. `graphql_injection.md`
14. `http_method_tamper.md`
15. `idor.md`
16. `information_disclosure.md`
17. `insecure_cookie.md`
18. `insecure_deserialization.md`
19. `integer_overflow.md`
20. `jndi_injection.md`
21. `memory_corruption.md`
22. `mobile_security.md`
23. `nosql_injection.md`
24. `null_pointer_dereference.md`
25. `open_redirect.md`
26. `path_traversal_lfi_rfi.md`
27. `php_security.md`
28. `privilege_escalation.md`
29. `privilege_management.md`
30. `prototype_pollution.md`
31. `race_conditions.md`
32. `rce.md`
33. `sensitive_memory_exposure.md`
34. `session_fixation.md`
35. `smuggling_desync.md`
36. `sql_injection.md`
37. `ssrf.md`
38. `ssti.md`
39. `trust_boundary.md`
40. `use_after_free.md`
41. `verification_code_abuse.md`
42. `weak_crypto_hash.md`
43. `xss.md`
44. `xxe.md`

---

*Document generated from project source code analysis. Last updated based on index with 2,441 nodes and 5,318 edges.*
