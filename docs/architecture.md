# Architecture Map — late-sast

> **Project:** late-sast: Autonomous Security Auditor
> **Base:** Built on mlhher/late agent engine
> **Fork:** late-sast adds Docker sandboxing, live exploitation, CVE enrichment, SAST pipeline, and Fyne v2 GUI
> **License:** BSL 1.1
> **Generated:** Repository index snapshot plus manual maintenance
> **Last updated:** 2026-05-05 (v2.0.1)

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
11. [GUI & Event System](#11-gui--event-system)
12. [MCP Integration](#12-mcp-integration)
13. [Key Interfaces](#13-key-interfaces)
14. [Data Flow Diagrams](#14-data-flow-diagrams)
15. [Entry Points](#15-entry-points)
16. [Statistics](#16-statistics)

---

## 1. Executive Summary

late-sast is an autonomous security auditor built on the Late agent engine. It audits a GitHub target or local repository by cloning or reusing a workspace, preparing a disposable Docker environment, indexing the codebase through MCP-backed analysis tools, running structured secrets/SAST/CVE scans, replaying exploit attempts, and emitting a normalized Markdown report. The primary operator surface is a Fyne v2 GUI, while small helper binaries exist for MCP serving and direct tool invocation.

### Binary Targets

| Binary | Description | Entry Point |
|--------|-------------|-------------|
| `late-sast` | Main GUI-driven autonomous SAST application | `cmd/late-sast/main.go` |
| `mcp-run` | MCP server runner for external tool backends | `cmd/mcp-run/main.go` |
| `run-tools` | Small flag-driven utility for targeted tool execution | `cmd/run-tools/main.go` |

### Key Differentiators

- **Graph-First:** Builds full codebase knowledge graph before scanning
- **Live Exploitation:** Proves each finding with a real PoC
- **Deterministic Toolchain:** Setup, readiness, scanning, replay, cleanup, and report generation are first-class tools rather than ad-hoc shell loops
- **Self-Cleaning:** Docker container, sidecars, network, and temp workspace are cleaned through a dedicated teardown tool
- **Model-Agnostic:** Any OpenAI-compatible endpoint
- **Hybrid Model Routing:** Separate models for orchestrator, subagent, and auditor roles
- **Language-Weighted Budgets:** Turn/timeout budgets scale with primary language (C/C++ 1.5×, Rust 1.3×, Python 0.8×, etc.)
- **Async GPU Coordination:** Channel-semaphore ensures single-GPU hosts run one LLM inference at a time across all concurrent agents
- **Shared Tool Cache:** Read-heavy idempotent tools are cached across orchestrator and subagents, with invalidation on workspace mutation
- **Structured Reports:** Findings flow through `write_sast_report`, giving stable report sections and machine-friendly counts

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                User                                     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
               ┌───────────────▼───────────────┐
               │      Entry Points             │
               │  cmd/late-sast/main.go        │
               │  cmd/mcp-run/main.go          │
               │  cmd/run-tools/main.go        │
               └───────────────┬───────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  UI Layer                       │
              │  ┌────────────────────────┐     │
              │  │  internal/gui (Fyne v2)│     │  ← GUI mode (default)
              │  │  - App, ChatPanel      │     │
              │  │  - Confirm dialogs     │     │
              │  │  - SASTPickerDialog    │     │
              │  └────────────────────────┘     │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │    Session / Orchestrator       │
              │    ┌────────────────────────┐   │
              │    │  BaseOrchestrator      │   │
              │    │  - Submit/Execute      │   │
              │    │  - GPU coordination    │   │
              │    │  - Turn counter        │   │
              │    │  - PushEvent()         │   │
              │    └────────────────────────┘   │
              │    ┌────────────────────────┐   │
              │    │  Blackboard            │   │
              │    │  - Inter-agent KV store│   │
              │    └────────────────────────┘   │
              │    ┌────────────────────────┐   │
              │    │  Dynamic Budget        │   │
              │    │  - LanguageMultiplier  │   │
              │    │  - CalculateTurns      │   │
              │    └────────────────────────┘   │
              │    Tool Registry                │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Executor / Coordinator         │
              │  ┌────────────────────────┐     │
              │  │  RunLoop               │     │
              │  │  - GPU lock acquire    │     │
              │  │  - Stream LLM          │     │
              │  │  - GPU lock release    │     │
              │  │  - Execute tool calls  │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  ResourceCoordinator   │     │
              │  │  - channel semaphore   │     │
              │  │  - AcquireGPULock      │     │
              │  └────────────────────────┘     │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Client / MCP / Subagent        │
              │  ┌────────────────────────┐     │
              │  │  client.Client         │     │
              │  │  - Streaming API calls │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  MCP Client            │     │
              │  │  - get_architecture    │     │
              │  │  - search_graph, etc.  │     │
              │  └────────────────────────┘     │
              │  ┌────────────────────────┐     │
              │  │  Subagent Orchestrator │     │
              │  │  + role middleware     │     │
              │  └────────────────────────┘     │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │  Config / Assets / Git          │
              └─────────────────────────────────┘
```

### Layer Descriptions

| Layer | Responsibility |
|-------|---------------|
| **Entry Points** | CLI argument parsing, flag handling, bootstrap sequence |
| **UI Layer** | Fyne v2 GUI; chat panes, confirmation flows, SAST picker, report-written rescan handoff |
| **Session/Orchestrator** | Conversation state, event fan-out, phase machine, turn counters, blackboard state |
| **Executor/Coordinator** | RunLoop, per-tool deadlines, shared cache, GPU serialization, tool runtime telemetry |
| **Client/MCP/Subagent** | LLM API transport, MCP discovery/execution, role-specific subagent orchestration and middleware |
| **Config/Assets** | Configuration resolution, embedded prompts, SAST reference material, release/build assets |

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
│   ├── late-sast/
│   │   ├── main.go                    # Main GUI-driven SAST application
│   │   ├── cbm_embed.go               # CBM binary embed (build tag)
│   │   ├── cbm_no_embed.go            # CBM no-embed fallback
│   │   └── embedded/
│   │       ├── .gitkeep
│   │       └── codebase-memory-mcp    # Embedded CBM binary
│   └── mcp-run/
│       └── main.go                    # MCP server runner
│   └── run-tools/
│       └── main.go                    # Flag-driven direct tool runner
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
    ├── gui/
    │   ├── app.go                     # App struct, main window, tab manager
    │   ├── chat.go                    # ChatPanel: message bubbles, thinking accordion
    │   ├── confirm.go                 # GUIConfirmMiddleware: Fyne dialog for tool approval
    │   ├── context.go                 # Context utilities for GUI input provider
    │   ├── events.go                  # startEventLoop: GPU-status tab labels, turn counter
    │   ├── icon.go                    # App icon (embedded SVG → PNG)
    │   ├── input.go                   # InputPanel: text entry widget
    │   ├── markdown.go                # Markdown rendering helper
    │   ├── provider.go                # GUIInputProvider: JSON-schema dialog prompts
    │   ├── sast_picker.go             # SASTPickerResult: target/path/output picker dialog
    │   ├── sessions.go                # Session management dialog
    │   ├── settings.go                # Settings dialog (model, keys, debug toggle)
    │   └── theme.go                   # lateTheme: Fyne v2 custom theme
    ├── executor/
    │   ├── coordinator.go             # ResourceCoordinator: channel-semaphore GPU lock
    │   ├── executor.go                # RunLoop, StreamAccumulator, tool execution
    │   └── executor_test.go
    ├── git/
    │   ├── worktree.go                # Git worktree management
    │   └── worktree_test.go
    ├── mcp/
    │   ├── client.go                  # MCP client implementation
    │   ├── config.go                  # MCP config loading
    │   └── config_test.go
    ├── orchestrator/
    │   ├── base.go                    # BaseOrchestrator: run loop, turn counter, PushEvent
    │   ├── blackboard.go              # Blackboard KV store (inter-agent comms)
    │   ├── limits.go                  # LanguageMultiplier, ComplexityMeta, CalculateTurns/Timeout
    │   ├── state_machine.go           # PLAN/EXPLORE/EXECUTE/FEEDBACK/STOP transitions
    │   └── limits_test.go
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
    └── tool/

```
cmd/late-sast          cmd/mcp-run            cmd/run-tools
    │                      │                       │
    ├──────────────────────┼───────────────────────┤
    ▼                      ▼                       ▼
    │              ┌─────────────────────────┐
    │              │  internal/gui           │◄─── Fyne v2 (GUI mode only)
    │              │  - App, ChatPanel       │
    │              │  - SASTPickerDialog     │
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/agent         │◄─── NewSubagentOrchestrator
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/orchestrator  │◄─── BaseOrchestrator, Blackboard,
    │              │                         │      LanguageMultiplier, Phase state machine
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/session       │◄─── Session, persistence
    │              └──────────┬──────────────┘
    │                         │
    │              ┌──────────▼──────────────┐
    │              │  internal/executor      │◄─── RunLoop, ResourceCoordinator
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
    │              │  internal/assets        │◄─── Embedded prompts/SKILL.md
    │              └─────────────────────────┘
    │
    │              ┌─────────────────────────┐
    │              │  internal/common        │◄─── Interfaces, utils, event types
    │              └─────────────────────────┘
```

### Dependency Summary

| Package | Depends On |
|---------|-----------|
| `cmd/late-sast` | agent, assets, client, common, config, executor, gui, mcp, orchestrator, pathutil, session, tool |
| `cmd/mcp-run` | mcp |
| `cmd/run-tools` | tool |
| `internal/gui` | client, common, session |
| `internal/agent` | assets, client, common, executor, orchestrator, session |
| `internal/orchestrator` | client, common, executor, session |
| `internal/session` | client, common, pathutil |
| `internal/executor` | client, common, pathutil, session, skill, tool |
| `internal/tool` | common, pathutil, client |
| `internal/client` | common |

---

## 5. Core Components Deep Dive

### 5.1 Orchestrator Pattern

The `BaseOrchestrator` (in `internal/orchestrator/base.go`) is the core agent lifecycle manager. It implements the `common.Orchestrator` interface and manages the full conversation lifecycle.

#### Lifecycle

```
NewBaseOrchestrator()
    │
    ├── SetContext(ctx)           ── Inject context with InputProvider, approval flags
    ├── SetMiddlewares([])        ── Attach middleware chain (confirm + role/tool policy + etc.)
    ├── SetCoordinator(ResourceCoordinator)  ── GPU lock for single-GPU hosts
    │
    ├── Submit(text) ────────────────── Async submission (background goroutine)
    │       │
    │       ├── atomic.StoreInt64(&o.turnCurrent, 0)  ── Reset turn counter
    │       ├── AddUserMessage(text)
    │       ├── eventCh <- StatusEvent("queued")
    │       └── go o.run()  ── Background execution loop
    │
    └── Execute(text) ─────────────── Synchronous execution (blocking)
            │
            ├── AddUserMessage(text)
            └── executor.RunLoop(...)    ── Core inference + tool loop
                    │
                    ├── onStartTurn()
                    │   ├── atomic.AddInt64(&o.turnCurrent, 1)  ← turn counter
                    │   ├── AcquireGPULock(ctx)  ← blocks if GPU busy
                    │   └── eventCh <- StatusEvent{Status:"queued"/"thinking",
                    │                               Turn: N, MaxTurns: M}
                    │
                    ├── ConsumeStream()   ── Stream LLM response deltas
                    │   └── Emits ContentEvent per chunk
                    │
                    ├── AddAssistantMessageWithTools() ── Commit to history
                    ├── onEndTurn()       ── Emit ContentEvent(usage)
                    │
                    ├── ReleaseGPULock() ← returns lock BEFORE tool calls
                    │   └── eventCh <- StatusEvent("working")
                    │
                    └── ExecuteToolCalls()  ── Execute via middleware chain
                        └── loop back to onStartTurn
```

#### Key Fields

| Field | Type | Purpose |
|-------|------|---------|
| `id` | `string` | Unique orchestrator identifier |
| `sess` | `*session.Session` | Conversation session |
| `middlewares` | `[]ToolMiddleware` | Tool execution interceptors |
| `eventCh` | `chan Event` (buf=100) | Event stream to UI |
| `parent` | `Orchestrator` | Parent orchestrator (nil for root) |
| `children` | `[]Orchestrator` | Child/subagent orchestrators |
| `coordinator` | `*executor.ResourceCoordinator` | GPU lock (nil = uncoordinated) |
| `acc` | `StreamAccumulator` | Streaming response accumulator |
| `ctx` | `context.Context` | Cancelable execution context |
| `cancel` | `context.CancelFunc` | Cancellation function |
| `stopCh` | `chan struct{}` | Stop signal channel |
| `maxTurns` | `int` | Maximum conversation turns |
| `turnCurrent` | `int64` (atomic) | Monotonically-incrementing turn index, reset on Submit/Execute |

#### GPU-Coordinated Status Lifecycle

```
            ┌──── AcquireGPULock ────┐
            │                        │
"queued"    │   "thinking"           │   "working"
 (waiting)  │   (streaming LLM)      │   (executing tools)
────────────►────────────────────────►────────────────────────►  next turn
                                  ReleaseGPULock
```

Without a coordinator the lifecycle collapses to `"thinking"` only (backwards-compatible).

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
| Regular (`late`) | Persistent (JSON to `~/.config/late/sessions/`) | Interactive GUI conversations |
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

// GUI confirmation middleware example:
func GUIConfirmMiddleware(app *gui.App, reg *ToolRegistry) ToolMiddleware {
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

### 5.5 Resource Coordinator (GPU Lock)

`internal/executor/coordinator.go` implements the `ResourceCoordinator` type — a channel-based semaphore that serialises LLM inference across all concurrent agents on a single-GPU host.

```
                   ┌────────────────────────────────────────┐
                   │       ResourceCoordinator               │
                   │                                         │
                   │  ch = make(chan struct{}, 1)            │
                   │  ch <- token  // GPU is initially free  │
                   │                                         │
                   │  AcquireGPULock(ctx) ──────────────────►│── blocks on ch
                   │                                         │   or ctx.Done()
                   │  ReleaseGPULock()   ──────────────────►│── returns token
                   │                          panic on over- │   to ch (panics
                   │                          release        │   on double)
                   └────────────────────────────────────────┘
```

- `GlobalGPU` is the default singleton; passed to every orchestrator via `SetCoordinator(executor.GlobalGPU)`.
- The lock is held **only** during `StartStream` + `ConsumeStream`, released immediately after streaming ends — tool calls run without the lock so sibling agents can think.
- Context cancellation (Ctrl-C, timeout) unblocks waiting agents cleanly.

### 5.6 Blackboard (Inter-Agent Communication)

`internal/orchestrator/blackboard.go` implements the **Blackboard architectural pattern** — a thread-safe key-value store for sharing findings between concurrent agents.

```go
// Write findings:
orchestrator.GlobalBlackboard.Write("vulnerable_library", "log4j-2.14.1")
orchestrator.GlobalBlackboard.Write("entry_points", []string{"/api/search", "/api/exec"})

// Read in another agent:
if lib, ok := orchestrator.GlobalBlackboard.Read("vulnerable_library"); ok {
    // taint-analysis agent starts from this library
}
```

Keys populated by `fetchMetaOnce` at scan start:

| Key | Value |
|-----|-------|
| `primary_language` | Detected language string (e.g. `"go"`) |
| `language_multiplier` | Float64 budget multiplier (e.g. `1.0`) |
| `complexity_meta` | Full `ComplexityMeta` struct |

### 5.7 Dynamic Budget Allocator

`internal/orchestrator/limits.go` provides a heuristic engine that computes per-subagent turn and timeout budgets from `get_architecture` metadata.

#### Language Multipliers

| Language(s) | Multiplier | Rationale |
|-------------|------------|-----------|
| C, C++ | 1.5× | Deep call stacks, manual memory, pointer aliasing |
| Rust | 1.3× | Ownership complexity, unsafe blocks |
| Go, Java, C#, Kotlin, Swift | 1.0× | Baseline |
| TypeScript | 0.9× | Slightly simpler control flow than Java |
| Python, JavaScript, PHP, Ruby | 0.8× | Flat module structures, fewer turns needed |

#### Formulas

```
turns   = (50 + 5×routeCount + 10×hotspotCount) × languageMultiplier
           capped at maxTurnsCeiling (default 500)

timeout = 5m + (2s × fileCount) + (5s × hotspotCount)
           capped at maxTimeoutCeiling (default 60m)
```

#### Budget Precedence

```
Explicit CLI flag   ──►  beats dynamic  ──►  beats static fallback
(--subagent-max-turns)   (from get_arch)     (150 turns / 15m)
```

`flag.Visit` detection: if the user explicitly passed `--subagent-max-turns` or `--subagent-timeout`, those values win even when dynamic data is available.

### 5.8 Architecture Metadata & Budgeting

`get_architecture` still feeds runtime planning. Parsed `common.ArchitectureData` and `orchestrator.ComplexityMeta` are used to:

- identify primary language and hotspot counts
- scale dynamic turn and timeout budgets
- enrich blackboard context for subagent planning
- provide summary information for debugging and operator visibility

The architecture response is therefore part of runtime planning, not a dedicated GUI visualization feature.

---

## 6. SAST Pipeline Architecture

The SAST pipeline in `cmd/late-sast/main.go` follows a deterministic flow with a **Fyne v2 GUI** interface.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SAST Pipeline — Boot Sequence                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  STEP 1: CLEANUP                                                        │
│  • Reap stale Docker containers/networks (name=sast-)                   │
│  • Extract embedded SAST skill files to /tmp/sast-skill                 │
│                                    ▼                                    │
│  STEP 2: CODEBASE MEMORY MCP                                            │
│  • ensureCBM(): Check PATH → ~/.local/bin → embedded → GitHub Release   │
│  • Add CBM directory to $PATH                                           │
│                                    ▼                                    │
│  STEP 3: SESSION & TOOL SETUP                                           │
│  • Create session with SAST system prompt                               │
│  • Register core tools (bash, read_file, write_file)                    │
│  • Register CVE lookup tools (VulnDB native Go)                         │
│  • Register compose network patching tool                               │
│  • Register ProContext doc lookup tools                                 │
│  • Build BM25 context index (SAST refs + semgrep skills)                │
│  • Register context tools (ctx_index, ctx_search, etc.)                 │
│  • Register MCP tools from config (incl. codebase-memory-mcp)           │
│                                    ▼                                    │
│  STEP 4: ORCHESTRATOR SETUP                                             │
│  • Create root BaseOrchestrator                                         │
│  • Wire ResourceCoordinator (GPU lock) via SetCoordinator               │
│  • Auto-submit initial audit task after 300ms delay                     │
│                                    ▼                                    │
│  STEP 5: UI LAUNCH                                                      │
│  ┌──────────────────────────┐                                            │
│  │  GUI mode (Fyne v2)      │                                            │
│  │  gui.App.Run()           │                                            │
│  │  - SASTPickerDialog      │                                            │
│  │    (if no --target)      │                                            │
│  │  - GUIConfirm MW         │                                            │
│  │  - live phase/tool UI    │                                            │
│  │  - report-written hook   │                                            │
│  └──────────────────────────┘                                            │
│                                    ▼                                    │
│  STEP 6: SUBAGENT ROUTING (on first SpawnSubagentTool call)             │
│  • fetchMetaOnce (sync.Once): calls get_architecture, caches result     │
│    - Writes primary_language, language_multiplier, complexity_meta      │
│      to GlobalBlackboard                                                │
│  • resolveBudget(): CLI override > dynamic > static fallback            │
│  • auditor  → auditorClient (security-specialist model)                 │
│  • scanner  → subagentClient (code-specialist model)                    │
│  • role-specific middleware enforces setup/scanner tool ordering        │
│                                    ▼                                    │
│  STEP 7: EXECUTION                                                      │
│  • LLM inference → tool execution → LLM inference (loop)               │
│  • GPU lock serialises inference (ResourceCoordinator)                  │
│  • Subagent spawning for scanning/auditing                              │
│  • Signal handling (SIGINT/SIGTERM → cleanup)                           │
│  • Timeout enforcement (if --timeout set)                               │
│                                    ▼                                    │
│  STEP 8: CLEANUP                                                        │
│  • cleanup_scan_environment(container, compose_project, network, workdir)│
│  • Removes primary container, sidecars, compose stack, network, image   │
│  • Removes /tmp/sast-skill and mounted workdir cleanup helpers          │
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
| `--subagent-max-turns` | 300 | Maximum turns per subagent (CLI override) |
| `--subagent-timeout` | 45m | Wall-clock timeout per subagent |
| `--max-turns-ceiling` | 500 | Upper cap for dynamic turn budget |
| `--max-timeout-ceiling` | 60m | Upper cap for dynamic timeout budget |
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

## 11. GUI & Event System

### 11.1 GUI Architecture (Fyne v2)

The GUI is built on **Fyne v2** with a custom amethyst dark theme.

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Fyne v2 GUI                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  App (app.go)                                                │  │
│  │  ┌──────────────────┐  ┌──────────────────────────────────┐ │  │
│  │  │ "Main" Tab       │  │ Runtime Status / Subagents       │ │  │
│  │  │ ┌──────────────┐ │  ┌──────────────────────────────────┐ │  │
│  │  │ │ ChatPanel    │ │  │ Subagent Tabs (dynamic)          │ │  │
│  │  │ │ (chat.go)    │ │  │ - "⚙ Testing Codebase (42/150)" │ │  │
│  │  │ │  - bubbles   │ │  │ - phase + tool runtime state     │ │  │
│  │  │ │  - thinking  │ │  └──────────────────────────────────┘ │  │
│  │  │ │    accordion │ │                                       │  │
│  │  │ └──────────────┘ │  ┌──────────────────────────────────┐ │  │
│  │  │ ┌──────────────┐ │  │ Top Bar / Status Strip           │ │  │
│  │  │ │ InputPanel   │ │  │ - status label                   │ │  │
│  │  │ │ (input.go)   │ │  │ - context usage                  │ │  │
│  │  │ └──────────────┘ │  │ - current phase                  │ │  │
│  │  └──────────────────┘  │ - rescan after report write      │ │  │
│  │                        └──────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  SASTPickerDialog (sast_picker.go)                           │  │
│  │  Shown when no --target supplied; user picks URL/path/output │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Settings / Confirm dialogs                                  │  │
│  │  (settings.go, confirm.go)                                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Tab Label State Machine

```
Subagent spawned ──► "Testing Codebase"
                         │
         StatusEvent.Turn/MaxTurns > 0
                         │
                         ▼
"⏳ Testing Codebase (1/150)"   ← queued (waiting for GPU)
"🧠 Testing Codebase (3/150)"   ← thinking (streaming LLM)
"⚙ Testing Codebase (3/150)"   ← working (executing tools)
"Testing Codebase"               ← idle/closed (base label restored)
```

#### Main GUI responsibilities

- Render the primary chat and input flow
- Show subagent tabs with queued/thinking/working/idle states
- Surface current phase and currently running tool
- Collect user confirmations and JSON-schema-backed prompt responses
- Notify when reports are written and expose a `Rescan` action

### 11.3 Event Types

| Event Type | Description | Key Payload |
|-----------|-------------|-------------|
| `ContentEvent` | Streaming content / reasoning delta | `ID`, `Content`, `ReasoningContent`, `ToolCalls`, `Usage` |
| `StatusEvent` | State change | `ID`, `Status`, `Error`, `Turn` (1-based), `MaxTurns` |
| `ChildAddedEvent` | New subagent spawned | `ParentID`, `Child`, `AgentType` |
| `ToolRuntimeEvent` | Tool start/stop state | `ID`, `Tool`, `Running` |
| `PhaseEvent` | High-level execution phase transition | `ID`, `From`, `To`, `Reason`, `Turn` |
| `StopRequestedEvent` | Stop signal | `ID` |

#### Status Values

| Status | Meaning | Tab Prefix |
|--------|---------|-----------|
| `queued` | Waiting for GPU lock | ⏳ |
| `thinking` | Streaming from LLM | 🧠 |
| `working` | Executing tool calls | ⚙ |
| `idle` | Turn complete, awaiting input | (restored) |
| `closed` | Subagent finished and tab removed | — |
| `error` | Fatal error, tab removed + notification | — |

### 11.4 Input Methods

| Method | Description |
|--------|-------------|
| **GUI Input** | Fyne dialog-based input for user data |
| **PromptRequest** | Modal prompts for user data (JSON Schema validated) |
| **AutoSubmit** | Auto-submission of initial tasks (used in SAST mode) |
| **SASTPickerDialog** | Collects URL, local path, output dir, retest report |

### 11.5 Event Flow (GUI mode)

```
Orchestrator Event
       │
       ▼
┌─────────────────────────┐
│ App.startEventLoop()    │  ← goroutine per orchestrator
│ (events.go)             │
└───────────┬─────────────┘
            │
   ┌────────┴────────────────────────────┐
   │                                     │
   ▼                                     ▼
ContentEvent                          StatusEvent
   │                                     │
   fyne.Do(panel.AppendMessage/       fyne.Do(tabItem.Text =
           UpdateLastMessage/               "🧠 X (N/M)")
           StartThinking/...)
                                                 ToolRuntimeEvent / PhaseEvent
                                                     │
                                                 fyne.Do(update status strip,
                                                            tool timer,
                                                            current phase)
```

### 11.6 Recursive Event Forwarding

The event forwarding system recursively wires all orchestrator events:

```go
func ForwardOrchestratorEvents(app *gui.App, o common.Orchestrator) {
    go func() {
        for event := range o.Events() {
            app.SendEvent(event)
            if added, ok := event.(common.ChildAddedEvent); ok {
                ForwardOrchestratorEvents(app, added.Child)
            }
        }
    }()
}
```

In GUI mode the equivalent logic is `App.startEventLoop` which dispatches directly to Fyne widgets via `fyne.Do`; it also recursively calls itself for `ChildAddedEvent`.

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
    MaxTurns() int          // Returns the configured max turns ceiling
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
    ID       string
    Status   string  // "queued", "thinking", "working", "idle", "error", "closed"
    Error    error
    Turn     int     // 1-based current turn index (0 = not yet known)
    MaxTurns int     // Configured max turns (0 = not yet known)
}

type ChildAddedEvent struct {
    ParentID  string
    Child     Orchestrator
    AgentType string
}

type StopRequestedEvent struct {
    ID string
}

// ArchitectureCluster is one cluster of related files from get_architecture.
type ArchitectureCluster struct {
    ID        string
    Label     string
    Files     []string
    IsHotspot bool
}

// ArchitectureData holds the full result of get_architecture.
type ArchitectureData struct {
    Clusters   []ArchitectureCluster
    Hotspots   []string
    Language   string
    FileCount  int
    NodeCount  int
    EdgeCount  int
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
│ StatusEvent      │────►│ GUI (thinking)   │
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
│  │    │ • onChunk → GUI events  │ │   │
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
│ ContentEvent     │────►│ GUI (render      │
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

### 15.1 `cmd/late-sast/main.go` — Autonomous SAST Pipeline

**Purpose:** Autonomous security audit pipeline with Docker sandboxing and Fyne v2 GUI.

**CLI Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--target` | GitHub URL to audit | — |
| `--path` | Local repository path | — |
| `--output` | Report output directory | current dir |
| `--timeout` | Scan timeout (e.g., 90m) | 0 (no limit) |
| `--subagent-max-turns` | Max turns per subagent (explicit override) | 300 |
| `--subagent-timeout` | Timeout per subagent | 45m |
| `--max-turns-ceiling` | Upper cap for dynamic turn budget | 500 |
| `--max-timeout-ceiling` | Upper cap for dynamic timeout budget | 60m |
| `--retest` | Retest previous report | — |
| `--gemma-thinking` | Gemma 4 thinking tokens | false |
| `--version` | Show version | — |

**Modes:**
1. **New Scan (GUI):** Default. Opens Fyne window with SAST Picker dialog if `--target`/`--path` omitted.
2. **Retest:** `--retest ./sast_report_repo.md` (retests previous findings).

### 15.2 `cmd/mcp-run/main.go` — MCP Server Runner

**Purpose:** Standalone MCP server runner for external tool integration.

### 15.3 `cmd/run-tools/main.go` — Direct Tool Runner

**Purpose:** Minimal operator utility for invoking a single tool with explicit JSON arguments.

**CLI Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--tool` | Tool name to execute | — |
| `--args` | JSON object of tool arguments | — |

---

## 16. Statistics

### Index Metrics

| Metric | Value |
|--------|-------|
| **Total Nodes** | 2,600+ |
| **Total Edges** | 5,500+ |
| **Go Source Files** | 107+ |
| **Index Size** | 7.4 MB |

### Package File Counts (v2.0.1 snapshot)

| Package | Source Files |
|---------|-------------|
| `internal/tool` | 30 |
| `internal/gui` | 14 |
| `internal/session` | 6 |
| `internal/common` | 7 |
| `internal/orchestrator` | 6+ |
| `internal/executor` | 3 (executor, coordinator, executor_test) |
| `internal/config` | 2 |
| `internal/mcp` | 3 |
| `internal/agent` | 2 |
| `cmd/late-sast` | 6 |
| `cmd/mcp-run` | 1 |
| `cmd/run-tools` | 1 |

### Node Distribution

| Label | Count |
|-------|-------|
| Section | 1,200+ |
| Function | 520+ |
| Method | 220+ |
| File | 170+ |
| Module | 170+ |
| Class | 120+ |
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
| `cmd/late-sast` | 3 | 15+ |
| `cmd/mcp-run` | 1 | — |
| `cmd/run-tools` | 1 | — |
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
