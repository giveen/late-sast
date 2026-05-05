# Changelog — late-sast

All notable changes to **late-sast** ([giveen/late-sast](https://github.com/giveen/late-sast)) are documented here.

`late-sast` is a fork of [mlhher/late](https://github.com/mlhher/late). Changes to the upstream agent engine (TUI, orchestrator, session persistence, skill infrastructure) are not listed here — see the upstream repository for that history.

---

## [v2.0.1] — 2026-05-05

### Added

- **Rescan button** (`internal/gui/app.go`):
  - New `rescanBtn *widget.Button` field on `App`; initially hidden.
  - `buildMainLayout` stores the root orchestrator in a new `rootAgent common.Orchestrator` field.
  - `NotifyReportWritten` shows the Rescan button and wires it to re-submit the root orchestrator on click.
  - Rescan errors are surfaced in the main chat as `✗ Rescan failed: <reason>` rather than being silently dropped.

### Fixed

- **Nil panic in MCP client on process kill** (`internal/mcp/client.go`): the context-cancel goroutine called `cmd.Process.Kill()` unconditionally. If the subprocess failed to start, `cmd.Process` is nil and the call panics. Now guarded with `if cmd.Process != nil`.
- **`DiscoverBackend` probe failure was silent** (`internal/mcp/client.go`): when the HTTP probe for context size failed, the error was discarded. Now logs to stderr: `[client] DiscoverBackend: probe failed (<err>), context size unknown`.
- **Allowlist persistence errors silently discarded** (`internal/gui/confirm.go`): `SaveAllowedCommand` and `SaveAllowedTool` errors were assigned to `_`. Now passed to `fyne.LogError` so failures are surfaced in the Fyne log.
- **`cleanup_scan_environment` duplicated in `cmd/late-sast/main.go`**: the `cleanupContainer()` helper reimplemented ~30 lines of manual `docker rm/kill` exec calls that `CleanupScanEnvironmentTool` already handles correctly. Replaced with a single `tool.CleanupScanEnvironmentTool{}.Execute(...)` delegation.
- **`cmd/run-tools/main.go` build broken**: `tool.NewAssessDisclosureContextTool()` constructor does not exist; corrected to `tool.AssessDisclosureContextTool{}`.

### Removed

- **`App.HighlightNode()` dead method** (`internal/gui/app.go`): exported no-op with no live Go callers; removed.

### Changed

- **`FormatSessionDisplay` simplified** (`internal/session/ttystyle.go`): removed an intermediate `result` variable and a redundant `len([]rune(last)) > 50` check; now calls `truncateUTF8` directly. Also fixed a misaligned `return` that appeared to be outside the `if verbose` block.
- **`spawn_subagent` stale TODO removed** (`internal/tool/subagent.go`): `// TODO: add reviewer, committer` comment removed from `Parameters()`. The `reviewer` and `committer` agent types have no instruction files, no dispatch in `buildMissionTurnGoal`, and no runner config; the comment was aspirational and stale.
- **`docs_*` vs `ctx_*` tool descriptions clarified** (`internal/tool/docs_lookup.go`, `internal/tool/context_index.go`): all six description strings now state the decision rule explicitly — `docs_resolve/read/search` for named libraries via the ProContext registry; `ctx_fetch_and_index` for arbitrary URLs; `ctx_index` for content already in memory; `ctx_index_file` for large local files; `ctx_search` for querying anything previously indexed.

---

## [v2.0.0] — 2026-05-04

### Removed

- **Bubble Tea TUI** — the `--tui` flag and all terminal UI code have been deleted from both `cmd/late` and `cmd/late-sast`. The Fyne v2 GUI is now the sole interface. The `internal/tui` package (`model.go`, `view.go`, `update.go`, `state.go`, `keys.go`, `theme.go`, `styles.go`, `interactions.go`) has been deleted; `charm.land/bubbletea/v2` and `charm.land/glamour/v2` are no longer imported by either binary.
- **`ForwardOrchestratorEvents` helper** removed from both entry points (was TUI-only bridge between orchestrator event stream and Bubble Tea program).
- **`docs/gui_porting_plan.md`** removed — planning document describing the TUI → GUI migration, now superseded and obsolete.

### Added

- **GUI report-written hook** (`internal/gui/app.go`, `internal/tool/write_sast_report.go`, `cmd/late-sast/main.go`):
  - `write_sast_report` now exposes an `OnWritten` callback; `late-sast` wires this to a buffered channel and notifies the GUI whenever a report is written.
  - Added `NotifyReportWritten(...)` in the GUI so successful report writes are surfaced in-chat with the latest report path.
  - This provides a deterministic handoff point for follow-up scan actions while preserving the current run state.

- **Tool result cache** (`internal/executor/toolcache.go`):
  - SHA-256-keyed, TTL-based in-process cache for idempotent tool calls. Created once per scan session and shared across the root orchestrator plus all spawned subagents.
  - TTLs by tool: `run_opengrep_scan` / `run_semgrep_scan` / `run_trivy_scan` / `run_secrets_scanner` → 10 min; `docs_lookup` / `docs_read` / `docs_search` / `docs_resolve` / `cve_search` / `get_architecture` → 15 min; `ctx_search` / `search_code` / `search_graph` / `get_code_snippet` / `trace_path` / `list_files` / `read_file` / `search_codebase` / `context_index` → 5 min; `index_repository` / `index_status` / `list_projects` → 3 min.
  - Side-effectful tools (`bash`, `write_file`, `spawn_subagent`, `compose_patch`, `write_sast_report`, `implementations`, `ctx_fetch_and_index`, `ctx_index_file`) are never cached.
  - Cache hits emit a `TOOL_CACHE_HIT` debug event and serve the stored result with zero execution overhead.
  - Eliminates repeat re-execution of expensive tools (observed 895 `TOOL_CALL` events vs ~300–400 expected in baseline debug logs).

- **Per-tool execution timeouts** (`internal/executor/toolcache.go`, `internal/executor/executor.go`):
  - Each tool call now receives an additional `context.WithTimeout` layered on top of the per-turn deadline.
  - Timeouts: `run_opengrep_scan` / `run_semgrep_scan` → 12 min; `run_trivy_scan` / `run_secrets_scanner` / `bootstrap_scan_toolchain` / `bash` → 5 min; `docs_lookup` / `docs_read` / `docs_search` / `docs_resolve` / CVE lookup tools → 45 s; `ctx_search` / `search_code` / `search_graph` / `get_code_snippet` / `trace_path` → 30 s; `get_architecture` → 60 s; `index_repository` → 3 min.
  - `spawn_subagent` is exempt (it manages its own internal deadline).
  - Cancel function is called immediately after the runner returns — no per-iteration defer-accumulation in the tool loop.

- **Subagent heartbeat throttle** (`internal/tool/subagent.go`):
  - New `HeartbeatThrottle int` field on `SpawnSubagentTool`. Default value is 10, meaning the `Heartbeat` callback fires once every 10 ticker ticks rather than every tick.
  - Reduces `SUBAGENT_HEARTBEAT` debug events from ~267 per scan to ~27, eliminating log noise that was masking real events.

- **Subagent stall warning** (`internal/tool/subagent.go`):
  - `runAttempt` now emits a single `SUBAGENT_STALL_WARNING` event when a subagent has consumed ≥ 80% of its allowed timeout without completing.
  - Event includes `elapsed_ms`, `timeout_ms`, and `pct_elapsed` for diagnostics.
  - Fires at most once per attempt (guarded by `stallWarned bool`), so it does not add further noise on healthy short-lived agents.

- **Subagent retry telemetry** (`internal/tool/subagent.go`):
  - `SUBAGENT_RETRY_ATTEMPT` — emitted at the start of every execution attempt, including first.
  - `SUBAGENT_RETRY_BACKOFF` — emitted when an empty-stream retry is scheduled, with `retry_backoff_ms` and `trigger` fields.
  - `SUBAGENT_RETRY_FINAL` — emitted when the subagent loop exits for any reason (`success`, `error`, `retry_exhausted`, `canceled`, `completed_non_retryable`).
  - All events wired to `RetryLog SubagentRetryLogger` callback; `late-sast` forwards them to the debug logger.

- **JSON tool-call argument repair** (`internal/session/session.go`):
  - `AddAssistantMessageWithTools` attempts to repair truncated/invalid JSON tool-call arguments before discarding them.
  - `repairToolCallArguments` applies heuristics: trailing-comma removal, unclosed string/array/object completion.
  - Successfully repaired calls emit a `MALFORMED_TOOL_CALL_REPAIRED` debug event; irreparable calls are dropped and logged as `MALFORMED_TOOL_CALL`.

- **`run_trivy_scan` tool** (`internal/tool/run_trivy_scan.go`):
  - Structured Trivy SCA/CVE scanning inside scan containers — replaces ad-hoc `bash` `trivy fs --format table | head -60` patterns in scanner prompts.
  - Auto-installs Trivy via the official install script when absent; no manual pre-install required.
  - Returns full JSON output (no `head -60` truncation), parsed into typed `[]TrivyFinding` records with `cve`, `package`, `installed_version`, `fixed_version`, `cvss`, `severity`, `description`, and `link` fields.
  - Deduplicates by CVE ID + package pair; sorts findings by CVSS score descending.
  - Supports `cvss_threshold` filtering (e.g. `7.0` for HIGH+ only) and explicit `severity_filter`.
  - Output `findings` array matches `write_sast_report`'s `cve_findings` schema for direct pass-through.
  - Uses CVSS V3 score, falling back to V2 when V3 is absent.
  - Returns `status: skipped` (non-fatal) when Trivy is unavailable and cannot be installed.
  - Registered in `cmd/late-sast/main.go`. Added 9 tests in `internal/tool/run_trivy_scan_test.go`.

- **`run_semgrep_scan` / `run_opengrep_scan` tool** (`internal/tool/run_semgrep_scan.go`):
  - Structured SAST scanning inside scan containers — replaces ad-hoc `bash` semgrep blocks with inline Python JSON parsing in scanner prompts.
  - Auto-detects project language (Go, Rust, Python, JavaScript, TypeScript, Java, C/C++, Ruby, PHP) and selects appropriate rule packs.
  - Explicit `rule_packs` parameter overrides auto-selection.
  - Returns structured findings with `check_id`, `path`, `line`, `col`, `severity`, `message`, `cwe`, `owasp`, `fix`, and `rule_url` fields.
  - Supports `severity_filter` (default: `ERROR`, `WARNING`) and `max_findings` cap.
  - Originally shipped as semgrep-backed; subsequently switched to OpenGrep (see Changed section). All 9 scanner tests updated and passing.

- **`run_secrets_scanner` tool** (`internal/tool/run_secrets_scanner.go`):
  - Structured TruffleHog-powered secrets scanning inside scan containers — replaces ad-hoc two-pass grep blocks in scanner prompts.
  - Auto-installs TruffleHog via the upstream install script when absent; no manual pre-install required.
  - Returns normalized findings with `detector`, `verified`, `file`, `line`, `redacted`, `source`, and `category` fields.
  - Supports `only_verified`, `max_findings`, and bounded execution timeout controls.
  - Deduplicates repeated detector/path/line matches and reports verified vs unverified counts.
  - Returns `status: skipped` (non-fatal) when TruffleHog is unavailable and cannot be installed.
  - Registered in `cmd/late-sast/main.go`. Added tests in `internal/tool/run_secrets_scanner_test.go`.

- **`bootstrap_scan_toolchain` tool** (`internal/tool/bootstrap_scan_toolchain.go`):
  - New deterministic setup primitive to install scan/build essentials in one call after container launch.
  - Bootstraps core utilities, conditionally installs JDK/Node based on repo markers, and attempts scanner installs (Trivy, Semgrep/OpenGrep, Checksec, Gosec, cargo-audit).
  - Returns structured package-manager detection, language-marker detection, and post-install tool availability summary.
  - Registered in `cmd/late-sast/main.go`. Added tests in `internal/tool/bootstrap_scan_toolchain_test.go`.

- **`resolve_install_strategy` tool** (`internal/tool/resolve_install_strategy.go`):
  - New deterministic Step 0 setup resolver for GitHub targets that inspects README quick-install commands and latest release assets.
  - Returns one of three strategies: `quick_install`, `release_asset`, or `source_clone`.
  - `quick_install` includes normalized `ecosystem`, `image`, and `command` for direct `setup_container(...)` use.
  - `release_asset` returns the best Linux asset match for architecture (`.deb` → `.AppImage` → `.snap` → `.flatpak`) plus install command plan.
  - Registered in `cmd/late-sast/main.go` and enabled by default in SAST tool policy. Added tests in `internal/tool/resolve_install_strategy_test.go`.

- **`assess_disclosure_context` tool** (`internal/tool/assess_disclosure_context.go`):
  - New deterministic disclosure context primitive that combines local security policy scanning with paginated GitHub Security Advisory correlation.
  - Inputs: `repo_path`, optional `github_url`, and current `findings` array.
  - Outputs structured `policy.matches` and `advisories.matches` for direct report annotation.
  - Advisories are fetched across pages until empty response, then matched against findings using multi-signal correlation (class/component/CVE).
  - Registered in `cmd/late-sast/main.go` and enabled by default in SAST tool policy. Added tests in `internal/tool/assess_disclosure_context_test.go`.

- **`cleanup_scan_environment` tool** (`internal/tool/cleanup_scan_environment.go`):
  - New deterministic teardown primitive replacing repeated multi-command cleanup shell blocks.
  - Handles container remove, compose down, sidecar cleanup, network removal, image removal, and temp workdir cleanup in one call.
  - Returns structured per-step results with `status: ok|partial` so agents can proceed safely when some resources are already absent.
  - Registered in `cmd/late-sast/main.go` and enabled by default in SAST tool policy. Added tests in `internal/tool/cleanup_scan_environment_test.go`.

- **Strategist/Explorer/Executor role system**:
  - New subagent role prompts: `instruction-sast-strategist.md`, `instruction-sast-explorer.md`, `instruction-sast-executor.md`.
  - `spawn_subagent` `agent_type` enum extended to include `strategist`, `explorer`, and `executor`.
  - Role-specific prompt resolution and strict tool allowlists in `internal/agent/agent.go`:
    - Strategist: `read_file` only
    - Explorer: graph/snippet tools + `read_file`
    - Executor: `bash` + `read_file`

- **Orchestrator phase state machine + events**:
  - New `StateMachine` with explicit phases and validated transitions in `internal/orchestrator/state_machine.go`: `PLAN`, `EXPLORE`, `EXECUTE`, `FEEDBACK`, `STOP`.
  - New `PhaseEvent` in `internal/common/interfaces.go` emitted from `BaseOrchestrator` at real runtime transition points: submit/execute/start turn/GPU acquired/GPU released/end turn/idle-closed-error.
  - Added comprehensive tests in `internal/orchestrator/state_machine_test.go`.

- **Typed blackboard exploit-history contract** (`internal/orchestrator/blackboard.go`):
  - Structured keys: `exploit_history`, `strategist_constraints`, `current_hypothesis`, `explorer_evidence`, `latest_executor_attempt`.
  - `ExploitHistoryEntry` contract type.
  - Helper APIs: `AppendExploitHistory`, `ExploitHistory`, `LatestExecutorAttempt`, `AddStrategistConstraint`, `StrategistConstraints`, `SetCurrentHypothesis`, `CurrentHypothesis`, `SetExplorerEvidence`, `ExplorerEvidence`, `ResetExploitState`.
  - Added tests in `internal/orchestrator/blackboard_test.go`.

- **`wait_for_target_ready` tool** (`internal/tool/wait_for_target_ready.go`):
  - New one-call runtime gate to verify container readiness before scanner/exploit phases.
  - Bounded polling with structured checks (container state, TCP, HTTP), explicit statuses (`ready`, `not_ready`, `crashed`), endpoint discovery from Docker inspect, and log-tail diagnostics.
  - Registered by default in `cmd/late-sast/main.go` and enabled in tool policy. Added tests in `internal/tool/wait_for_target_ready_test.go`.

- **`run_exploit_replay` tool** (`internal/tool/run_exploit_replay.go`):
  - New one-call replay primitive for live PoC verification with bounded retries/timeouts.
  - Supports request shaping (method/path/query/headers/body), success/block indicators, and optional in-container side-effect checks.
  - Returns normalized verdicts (`exploited`, `blocked`, `unreachable`, `inconclusive`) with structured evidence payloads.
  - Registered by default in `cmd/late-sast/main.go` and enabled in tool policy. Added tests in `internal/tool/run_exploit_replay_test.go`.

- **`write_sast_report` tool** (`internal/tool/write_sast_report.go`):
  - New first-class tool that accepts normalized finding records and produces a consistently structured Markdown SAST report every time. Manual freeform markdown report writing is now prohibited by prompt.
  - Enforced invariants: empty section suppression (severity headers only emitted when findings exist); `NEEDS_CONTEXT` deduplication; enum normalization; finding deduplication by (location, CWE); CVE deduplication; auto-generated Executive Summary and Remediation Priority.
  - Returns structured JSON: `{ "status": "ok", "output_path": "...", "findings": N, "needs_context": N, "cve_findings": N, "counts": {...}, "exploited": N }`.
  - Registered in `cmd/late-sast/main.go` as a first-class tool; enabled by default. Added 10 tests in `internal/tool/write_sast_report_test.go`.

- **Language-weighted resource heuristics** (`internal/orchestrator/limits.go`):
  - `LanguageMultiplier(language string) float64` — per-language turn-budget multiplier: C/C++ → 1.5×; Rust → 1.3×; Go/Java/C#/Kotlin/Swift → 1.0×; TypeScript → 0.9×; Python/JavaScript/PHP/Ruby → 0.8×.
  - `ComplexityMeta.PrimaryLanguage` field carries the detected language through the heuristic pipeline.
  - `--max-turns-ceiling` (default 500) and `--max-timeout-ceiling` (default 60m) CLI flags to cap the dynamic budget.
  - CLI override precedence: explicitly supplied `--subagent-max-turns` / `--subagent-timeout` always win over dynamic values (`flag.Visit` detection).
  - Language multiplier and `primary_language` written to `GlobalBlackboard` at first subagent spawn.

- **Dynamic Resource Allocator — `get_architecture` integration** (`cmd/late-sast/main.go`):
  - `fetchComplexityMeta` helper calls the `get_architecture` MCP tool with the cloned repo path and parses the response JSON (handles multiple field-name variants across codebase-memory-mcp versions).
  - `sync.Once` lazy-fetch: called on the first `SpawnSubagentTool.Runner` invocation; result cached for all subsequent subagents in the same scan.
  - `resolveBudget()` returns `(turns, timeout)` respecting CLI override precedence, dynamic value, or static fallback.

- **Turn-progress counter in tab labels** (`internal/orchestrator/base.go`, `internal/gui/events.go`):
  - `StatusEvent.Turn` / `StatusEvent.MaxTurns` populated by `onStartTurn` via an atomic counter reset at each `Submit`/`Execute`.
  - `setTabStatus` renders `"🧠 Testing Codebase (42/150)"` whenever `Turn > 0`.

- **`BaseOrchestrator.MaxTurns() int`** — satisfies updated `common.Orchestrator` interface (was missing, causing build failure).
- **`BaseOrchestrator.PushEvent(Event)`** — non-blocking external event injection for orchestrator event channel integration points.

### Changed

- **SAST scanner switched from semgrep to OpenGrep** (`internal/tool/run_semgrep_scan.go`):
  - `ensureSemgrep()` replaced with `ensureOpenGrep()` — downloads the prebuilt musl static binary from `github.com/opengrep/opengrep/releases/download/v1.20.0/opengrep-1.20.0-x86_64-unknown-linux-musl` via `curl -sSfL`. No Python, pip, or pipx dependency.
  - Invocation changed from `semgrep --json` to `opengrep scan --json`. Output schema is identical — zero changes to the finding parser.
  - JSON parser renamed `parseOpenGrepJSON` (was `parseSemgrepJSON`).
  - Eliminates Python version conflicts and pip failure modes in minimal scan containers.

- **`ExecuteToolCallsWithStats` signature** (`internal/executor/executor.go`):
  - Added `cache *ToolResultCache` parameter (last argument). Existing callers passing `nil` are unaffected.
  - `ExecuteToolCalls` wrapper updated to pass `nil`.

- **Scanner prompts updated for structured tool calls**:
  - `instruction-sast-scanner.md` Steps 1c (CVE scan) and 1f (SAST) now use `run_trivy_scan(...)` and `run_semgrep_scan(...)` / `run_opengrep_scan(...)` respectively, replacing bash blocks with inline Python JSON parsing.
  - Step 1b (secrets discovery) now uses `run_secrets_scanner(...)` in both `instruction-sast-scanner.md` and `instruction-sast-scanner-binary.md`.
  - `instruction-sast-scanner-binary.md` Steps 1c and 2a updated to use `run_trivy_scan(...)` and `run_semgrep_scan(...)`.
  - `instruction-sast-setup.md` Step 5 now prefers `bootstrap_scan_toolchain(...)` as the first deterministic tool call for build/scanner bootstrap.
  - `instruction-sast-setup.md` Step 0 now uses `resolve_install_strategy(...)` as a strict tool-only gate (no manual README/release parsing fallback).
  - `instruction-sast.md` Step 3 and `instruction-sast-retest.md` Step 4 now call `assess_disclosure_context(...)` instead of inline shell/API loops.
  - Cleanup sections in `instruction-sast.md` and `instruction-sast-retest.md` replaced with a single `cleanup_scan_environment(...)` call.
  - `instruction-sast.md` Step 4 updated to use `write_sast_report(...)` — manual freeform markdown report writing is prohibited.
  - `instruction-sast-scanner.md` Step 7 now prefers `run_exploit_replay(...)` for live exploit attempts and replay evidence capture.

- **Scanner/setup orchestration middleware** (`internal/agent/agent.go`, `cmd/late-sast/main.go`):
  - Scanner and binary-scanner subagents are nudged to run `run_secrets_scanner` before `trace_path` taint tracing.
  - Scanner and binary-scanner subagents block raw localhost `bash` exploit PoCs (`docker exec` + `wget/curl`) unless a matching `run_exploit_replay(...)` attempt exists for the same normalized finding candidate.
  - Cleanup preference middleware nudges setup/root flows to call `cleanup_scan_environment` instead of ad-hoc docker cleanup bash.

- **Mission-turn orchestration now actively reads/writes blackboard contract state** (`cmd/late-sast/main.go`):
  - Before spawning `strategist` / `explorer` / `executor`, goals are enriched with current blackboard context.
  - After each role completes, JSON output is parsed and persisted back into blackboard.
  - Root scan startup resets exploit mission state via `GlobalBlackboard.ResetExploitState()`.

- **GUI phase visibility improvements**:
  - Child tabs now include live phase labels (`... · PLAN/EXPLORE/EXECUTE/FEEDBACK/STOP`) derived from `PhaseEvent` transitions.
  - Main footer shows `Current Phase` from real orchestrator state transitions.

- **SAST setup launch detection updated for monorepos** (`instruction-sast-setup.md`):
  - Compose/Dockerfile detection changed from root-only to bounded recursive search.
  - Selection rules prefer the service directory found by monorepo entrypoint analysis; prevents false "no docker" conclusions when Docker assets live in subdirectories.

- **Setup/scanner readiness flow now uses a dedicated tool**:
  - `instruction-sast-setup.md` gates startup state through `wait_for_target_ready(...)` after launch.
  - `instruction-sast-scanner.md` prefers `wait_for_target_ready(...)` for bounded readiness evidence over ad-hoc shell polling loops.

- **Report-write lifecycle is now visible in the GUI** (`internal/gui/app.go`, `cmd/late-sast/main.go`):
  - Successful `write_sast_report(...)` calls now emit a user-visible confirmation line in the main chat.
  - This makes report completion explicit during long scans/retests and improves operator feedback while testing.

### Fixed

- **Scan-session cache reuse and malformed empty-arg execution** (`internal/executor/executor.go`, `internal/orchestrator/base.go`, `cmd/late-sast/main.go`, `internal/session/session.go`):
  - MCP-backed codebase tools such as `ctx_search`, `search_graph`, `search_code`, `get_code_snippet`, `trace_path`, `index_repository`, `index_status`, `list_projects`, and `get_architecture` are now covered by the cache/timeout tables instead of falling through to uncached defaults.
  - The tool cache is now reused across root and child orchestrators in a single scan, eliminating repeated cold-cache subagent loops.
  - Repairs that collapse malformed tool-call arguments to `{}` are now dropped for tools with required parameters, with `MALFORMED_TOOL_CALL_DROPPED` logged instead of executing a broken empty-argument call.

- **Retest crash on invalid report file** (`cmd/late-sast/main.go`, `internal/gui/sast_picker.go`):
  - Previously, `buildScan` called `os.Exit(1)` for user-triggered errors (bad report path, missing `Target:` header, unreadable file). When called from a GUI goroutine, this killed the entire process with no dialog — the program just vanished.
  - `buildScan` now returns `(sessionResult, error)`. All `os.Exit(1)` calls within it are replaced with `return sessionResult{}, fmt.Errorf(...)`.
  - `setupFn` updated to `func(SASTPickerResult) (common.Orchestrator, string, error)`.
  - `RunSAST` / `transition` in `sast_picker.go`: on a non-nil error, a Fyne error dialog is shown and the picker is re-rendered so the user can correct the selection and try again without relaunching the app.

- **Retest report header parser rejected valid reports** (`cmd/late-sast/main.go`):
  - `parseReportHeader` only matched the bare prefix `Target: `. Reports generated by `late-sast` use bold markdown `**Target:** <url>`, which was never matched.
  - Parser now tries both `"Target: "` and `"**Target:** "` prefixes.

- **`launch_docker` host-port conflict hardening** (`internal/tool/launch_docker.go`, `cmd/late-sast/main.go`):
  - Added reserved host-port protection so scan launches avoid clobbering local model endpoints (e.g. llama-swap on `localhost:8080`).
  - Tool now accepts `reserved_host_ports` and returns structured `status: port_conflict` when a launched target binds a reserved port; on conflict the launched target is cleaned up automatically.
  - `late-sast` auto-populates default reserved ports from configured OpenAI/Subagent/Auditor base URLs.
  - Docker asset discovery now performs a broader nested sweep and detects variant filenames (`docker/compose.dev.yaml`, `Dockerfile.dev`, `Containerfile*`) before launch selection.
  - Added regression tests for compose and Dockerfile conflict paths in `internal/tool/launch_docker_test.go`.

- **Setup primitive registration in scan sessions** (`cmd/late-sast/main.go`):
  - Explicitly registers `setup_container`, `launch_docker`, `wait_for_target_ready`, and `bootstrap_scan_toolchain` in the SAST session registry.
  - Prevents setup flows from falling back to brittle ad-hoc shell paths when these tools were previously unavailable.

- **Scanner/setup long-wait behavior hardened**:
  - Added bounded readiness-polling guidance in prompts (`instruction-sast-scanner.md`, `instruction-sast-setup.md`).
  - Runtime SAST shell policy now blocks: single `sleep` > 15 s; cumulative sleep > 90 s.
  - New tests in `internal/tool/sast_tools_test.go` cover long-sleep and cumulative-sleep blocks.

- **Empty-output diagnostics no longer claim context overflow by default**:
  - `spawn_subagent` empty output message reports likely early termination/empty stream without asserting overflow.
  - Added regression test for wording.

- **Executor observability and failure classification**:
  - Added explicit debug events: `CONTEXT_LIMIT`, `OUTPUT_BUDGET_HIT`, `EMPTY_STREAM`.
  - Turn summaries now include token accounting and `n_ctx`.
  - Duplicate-plan reset logic now also resets after policy-blocked turns.

---

## [v1.8.2] — 2026-05-02


### Added
- **Async multi-agent GPU coordination** ([#7](https://github.com/giveen/late-sast/pull/7)):
  - `ResourceCoordinator` (`internal/executor/coordinator.go`) — channel-semaphore (capacity 1) so `AcquireGPULock(ctx)` respects context cancellation. `ReleaseGPULock()` panics on double-release (fail-loud, like `sync.Mutex`). `GlobalGPU` singleton wired to the root orchestrator at startup via `SetCoordinator(executor.GlobalGPU)`.
  - `RunLoop` extended with `coordinator`, `onGPUAcquired`, `onGPUReleased` — lock is held **only** during `StartStream`+`ConsumeStream`, released immediately after streaming. `onGPUReleased` ("working") is deferred to just before `ExecuteToolCallsWithStats` so the ⚙ status only appears when tool calls are actually about to run, never on stream errors or no-tool turns. Coordinator auto-propagates parent → child in `NewSubagentOrchestrator`.
  - Status lifecycle: with coordinator — `queued` → `thinking` → `working` → `queued` …; without coordinator — legacy `thinking` only (fully backward-compatible).
- **Blackboard inter-agent communication** (`internal/orchestrator/blackboard.go`) — thread-safe key-value store (`Write`/`Read`/`ReadAll`/`Delete`) for passing findings between concurrent agents (e.g. Dependency Agent writes a vulnerable library; Taint-Analysis Agent reads it to prioritise entry points). `GlobalBlackboard` singleton provided for default runs.
- **Live GPU-state tab labels** (`internal/gui/events.go`) — tab label updated on every status transition via `setTabStatus`; no new widget types required:

  | Status | Tab prefix |
  |--------|-----------|
  | `queued` | ⏳ |
  | `thinking` | 🧠 |
  | `working` | ⚙ |
  | `idle` / `closed` / `error` | *(base label restored)* |

- **Setup agent: Step 0 — smart install detection** (`instruction-sast-setup.md`):
  - Before cloning, the setup agent now fetches the project README and attempts two quick-install passes.
  - **Pass A — package-manager one-liners**: recognises `go install …@latest`, `pip install`, `pipx install`, `npm install -g`, `cargo install`, `gem install`. When found, spins up a minimal toolchain container (`golang:1.23`, `python:3.11-slim`, `node:20-slim`, `rust:1.80-slim`) and runs the command directly, skipping clone and build entirely. For projects like Fabric this cuts ~35 turn shell loops down to a single `go install` call.
  - **Pass B — GitHub release binary assets**: if no one-liner is found, checks the README for `.deb` / `.AppImage` / `.snap` / `.flatpak` mentions or a releases page link, then queries `api.github.com/repos/<owner>/<repo>/releases/latest` to discover downloadable assets. Preference order: `.deb` (amd64) → `.AppImage` (x86_64) → `.snap` → `.flatpak`. For `.deb` files starts `ubuntu:22.04` and runs `dpkg -i` + `apt-get install -f`. For `.AppImage` files starts `debian:bookworm-slim` and uses `--appimage-extract` to unpack without FUSE. Covers projects like `open-webui/desktop` that ship pre-built binaries only.
- **`spawn_subagent` empty-output detection** (`internal/tool/subagent.go`): when a runner returns `("", nil)` (e.g. model hit `finish_reason=stop` with empty content and no tool calls), instead of forwarding a misleading `"Subagent completed. Result:\n\n"` to the orchestrator, a descriptive string is now returned — `"subagent '<type>' completed but returned empty output — possible context window overflow or unexpected termination"` — so the orchestrator can distinguish stall from "no findings".
- **pipx preferred over `pip --break-system-packages`** (`instruction-sast-setup.md` Step 5):
  - `pipx` is now included in the `apt-get` and `apk` package lists during Step 5a bootstrap.
  - Step 5c installs semgrep and checksec via `pipx install` first (isolated venv per tool, no PEP 668 `externally-managed-environment` conflict). Falls back to `pip install --break-system-packages` only if pipx itself could not be installed. `PIPX_BIN_DIR=/usr/local/bin` is exported so installed binaries land on PATH without needing `pipx ensurepath`.

### Fixed
- **Shell tool hangs on `docker exec` timeout** (`internal/tool/implementations.go`, `shell_command_unix.go`): the `bash` tool previously used `cmd.CombinedOutput()` which blocks on pipe-draining. When the per-call timeout fired and killed the host `bash` process, child processes (e.g. `docker exec`) inherited the pipe and kept it open, so `CombinedOutput()` never returned — the subagent stalled with only heartbeats and no TOOL_RESULT. Fixed by:
  - Placing each shell command in its own process group (`SysProcAttr{Setpgid: true}` on Linux) and using `Start`+`Wait` with a select loop; on context deadline `killProcessGroup` sends `SIGKILL(-pgid)` to the entire group, closing all inherited pipes and allowing `Wait` to return promptly.
  - Increasing the `ShellTool` timeout from 2 min → **5 min** in `cmd/late-sast/main.go` to give more headroom for legitimate `docker exec` operations (Trivy download, semgrep install, etc.) before timing out.
- **Setup Step 5a: unconditional JDK/Node.js install** (`instruction-sast-setup.md`): `default-jdk-headless` (200–400 MB) and `nodejs npm` were installed unconditionally on every project, frequently exceeding the former 2-minute shell timeout. Fixes:
  - Step 5a now installs only lightweight core utilities (curl, wget, bash, procps, git, jq, build-essential, gcc, g++, make, python3, python3-pip, python3-venv, pipx).
  - **Step 5a-ii (conditional JDK)**: JDK is installed only when the repo contains Java project markers (`*.java`, `*.kt`, `*.kts`, `pom.xml`, `*.gradle`). Non-Java projects (Electron, Go, Python, Rust, etc.) skip the 200–400 MB download entirely.
  - **Step 5a-iii (conditional Node.js)**: `nodejs npm` is installed only if `node` is absent in the container AND the repo has a `package.json` or JS/TS sources.
- **Prompt correctness improvements** (5 issues across `instruction-sast*.md`):
  - **`instruction-sast-retest.md` Step 2 — field name mismatch**: extraction instructions now reference the actual report field names (`**Location:**`, `[SEVERITY]` heading prefix, `**Taint Path:**`, `**Reproduce:**`) instead of phantom fields (`**File:**`, `**Vuln class:**`, `**Taint path:**`) that have never existed in the report template.
  - **`instruction-sast-setup.md` Constraints**: `patch_compose_network` added to the allowed-tools list; it is called in Path A Step 2 but was previously omitted.
  - **`instruction-sast-scanner.md` Step 3**: `trace_path` example now includes `from=` and `to=` params, consistent with the binary scanner. Previously the web scanner example omitted both required parameters.
  - **`instruction-sast-setup.md` Step 5c**: removed a misleading comment block that implied a `pip_install` shell helper function was defined — no such function ever existed; each tool block already inlines the full fallback chain.
  - **`instruction-sast.md` Step 2.5**: collapsed redundant triple-restatement of the mandatory `spawn_subagent` guard into a single clear sentence.
- **MCP tools not available to any subagent** (`cmd/late-sast/main.go`): `ensureCBM()` correctly downloads and extracts `codebase-memory-mcp`, but the binary was never injected into the MCP server config — `mcp_config.json` remained `{"mcpServers":{}}`. `ConnectFromConfig` was therefore never called (early-return on empty map), so all 14 graph tools (`index_repository`, `get_architecture`, `search_graph`, `trace_call_path`, etc.) were silently absent from every agent's tool list. After `ensureCBM()` succeeds, the binary path is now auto-injected into the in-memory config under the key `"codebase-memory-mcp"` if not already present, before `ConnectFromConfig` is called. Users who have manually added their own `codebase-memory-mcp` entry in `mcp_config.json` are unaffected.
- **Empty model response not detected as error** (`internal/executor/executor.go`): when the model returned `finish_reason=""` with empty content and no tool calls, the executor silently returned `("", nil)`. This is now detected and returned as an explicit error: `"model returned empty response on turn N (possible context window overflow or stream failure)"`.
- **Error subagent tabs left open** (`internal/gui/events.go`): the `"error"` event case previously kept the subagent tab open ("so the user can read the error") but the error is already visible in the main tab as the `spawn_subagent` tool result. Error tabs now close automatically and fire a system notification, same as successful subagent completion.
- **Tool result debug log accuracy** — `LogDebugToolResult` is now called after error-wrapping so the debug log records the final error string seen by the orchestrator rather than the raw pre-wrap message.
- **Subagent execution budget defaults increased for long scans** (`cmd/late-sast/main.go`):
  - `--subagent-max-turns` default raised from 150 → **300** to reduce premature turn-limit termination on larger targets.
  - New `--subagent-timeout` flag added (default **45m**), and wired into both TUI and GUI `spawn_subagent` registrations. This replaces the previous hardcoded 20-minute subagent timeout and makes long-running setup/scanner passes configurable from CLI.
- **GPU coordination — Copilot review fixes** ([#7](https://github.com/giveen/late-sast/pull/7)):
  - **`Submit()` initial status flicker**: `Submit()` now emits `"queued"` (not `"thinking"`) when a coordinator is attached, consistent with `Execute()`. Eliminates the `thinking→queued→thinking` flash in GUI tabs when a new session is submitted while waiting for the GPU.
  - **TUI `queued`/`working` statuses unhandled**: `update.go` now maps `"queued"` → `StateThinking` + "Queued..." and `"working"` → `StateThinking` + "Working..." so the TUI shows the correct spinner text when a coordinator is active outside the GUI.
  - **Go error style**: `AcquireGPULock` error string lowercased to `"gpu lock acquisition canceled: ..."` per Go conventions.
  - **Flaky timing test**: `TestResourceCoordinator_BlocksThenSucceeds` replaced `time.Sleep(30ms)` with a channel handshake — goroutine signals just before blocking on `AcquireGPULock`, then main releases; no scheduler-dependent delay.

### Changed
- **History compaction gated on context pressure** (`internal/session/session.go`): `compactHistoryForContext` now only runs when `lastTokenCount / contextSize ≥ 0.75` (75% threshold). When the context window size is unknown (backend does not report it), compaction still runs as before on every save. Token count is populated after each turn via `SetLastTokenCount`.
- **GUI Thoughts scroll behaviour** (`internal/gui/chat.go`): `UpdateThinking` no longer calls `ScrollToBottom()` when the Thoughts accordion is open, preventing it from hijacking the user's scroll position while they are reading the chain-of-thought stream. Auto-scroll still fires when the accordion is collapsed.

---

## [v1.8.1] — 2026-05-01

### Added
- **Structured execution telemetry** in debug logs:
  - `TOOL_RESULT` now supports structured metadata (`duration_ms`, `status`, `classification`, `exit_code`, `output_bytes`, `truncated`).
  - New `TURN_SUMMARY` event captures per-turn workflow stats (tool count, failures, blocked/timeouts, duplicate tool-turn detection, token/content sizing).
- **Subagent timeout + heartbeat controls** in `spawn_subagent`:
  - Default/per-agent timeout policies (`coder`, `scanner`, `binary-scanner`, `auditor`, `setup`).
  - Periodic heartbeat callback support for long-running child agents.
  - `late-sast` emits `SUBAGENT_HEARTBEAT` debug events while subagents are running.
- **Workflow/CI Make targets**:
  - `quick-test`, `test-race`, `coverage`, `fmt`, `fmt-check`, `vet`, `lint`, `ci`.
- **New tests** for the above systems:
  - `internal/debug/logger_test.go` for structured log schema.
  - Executor loop/stats tests for blocked counting and signature stability.
  - Subagent timeout/heartbeat tests.
  - CVE cache/retry behavior tests.

### Fixed
- **GUI context tracking reliability**:
  - Context usage now updates even when backend usage chunks omit token fields (fallback to in-session token estimation).
  - Main tab now initializes context usage immediately instead of staying at `Context: –` until first usage payload.
  - Subagent tabs now also initialize context usage immediately.
- **Subagent context visibility**:
  - Subagent tabs now display explicit context usage in the same style as the main tab (`Context: used / max (pct%)`).
- **Shell failure typing**:
  - Timeout and cancellation results are now emitted as explicit shell outcomes (not only generic command errors), improving classification fidelity.
- **Duplicate tool-call blocker over-aggressive on retries**:
  - The duplicate detection now resets when a turn had tool failures or timeouts, allowing legitimate retries after subagent timeouts without triggering the blocker.
  - Only counts as a duplicate loop if the same plan repeats AFTER a successful turn.
- **Malformed JSON tool call arguments**:
  - Tool calls with invalid JSON arguments are now filtered out gracefully with debug logging instead of failing the entire stream.
  - Prevents "unexpected end of input" errors from crashing the executor when the LLM generates truncated or incomplete JSON.
- **HTTP 500 JSON parse errors from persisted history**:
  - Outgoing chat requests are now sanitised before sending: tool_call entries with invalid JSON arguments are stripped from all `assistant` messages in the request payload.
  - When the backend still returns an HTTP 500 "failed to parse tool call arguments as JSON" error (e.g. from corrupted persisted history), the client now performs one automatic retry with all tool definitions and tool_calls removed, allowing the turn to complete as a plain text response rather than hard-failing.
  - End-to-end regression test added using an `httptest` mock server.
- **Stale shell working directory**:
  - The shell tool no longer crashes with `chdir <path>: no such file or directory` when a requested `cwd` was a temporary directory that has since been cleaned up (common between SAST scan phases).
  - Falls back silently to the current process working directory and continues execution.

### Changed
- **Session history compaction**:
  - Older assistant messages no longer accumulate full chain-of-thought reasoning in persisted history: reasoning is stripped from messages beyond the most recent turn to reduce context window cost on long scans.
  - Tool result messages are compacted: messages beyond the most recent 10 turns are truncated to 1 200 characters (head + tail preserved); more recent tool results are capped at 4 000 characters.
  - The most recent reasoning block is capped at 1 200 characters.
  - Compaction runs automatically in `saveAndNotify` before each persistence write, with no manual intervention required.
- **Executor control loop hardening**:
  - Added per-turn tool-call budget guardrails.
  - Added repeated-identical-tool-plan detection to prevent loop churn.
  - Added per-turn tool-execution time budget.
  - Tool execution now aggregates per-turn stats for logging/observability.
- **CVE lookup tooling**:
  - CVE API calls are now context-aware and retry transient failures with backoff.
  - Added in-memory TTL response cache to reduce duplicate network latency during scans.
- **Project hygiene**:
  - `docs/gui_porting_plan.md` is now untracked and ignored (`.gitignore`) to keep local planning notes out of release diffs.

---

## [v1.8.0] — 2026-05-01

### Added
- **Graphical user interface (Fyne v2)** — a full desktop GUI replaces the terminal as the primary interface.
  - **Target picker screen** — on first launch with no flags, a compact window lets you enter a GitHub URL, browse for a local repository, and choose an output directory before starting the scan. Supplying `--target` / `--path` / `--output` via CLI skips the picker as before.
  - **Streaming chat panel** — assistant messages render incrementally as they stream. Markdown is parsed with goldmark (bold, italic, headings, code blocks, lists, horizontal rules) and displayed as `widget.RichText` segments using a custom dark amethyst theme.
  - **Per-subagent tabs** — each spawned subagent (Setup, Testing Codebase, Live Exploit, Making Report) opens in its own tab with a dedicated **■ Stop** button and a live token counter (`used / max`) in the tab header. Completed tabs close automatically.
  - **Reasoning / thinking accordion** — chain-of-thought reasoning streams into a collapsible "Thinking…" section above the response. The section starts collapsed and is never reopened automatically — click it at any time to read the model's reasoning. Renamed to "Thoughts" once the turn ends.
  - **Context window usage bar** — the bottom of the main tab shows `Context: N / M (X%)` token counts, updated after each model response.
  - **Stop & Quit button** — top-left of the main tab. Cancels the running agent, runs container cleanup, then closes the window. Button text changes to "Stopping…" and disables on first click (idempotent via `sync.Once`).
  - **Tool-confirmation dialogs** — all tool-approval prompts (allow once / allow for session / allow for project / allow always / deny) use native Fyne dialog boxes instead of TUI key presses.
  - **Custom dark theme** — amethyst palette (`#9B59B6`), near-black background (`#191919`), `ECF0F1` text. Applied globally via a `fyne.Theme` implementation.
  - **Window icon** — purple shield-and-bug SVG icon embedded in the binary and set as the window icon (`window.SetIcon`). Displays in title bar and taskbar while the app is running.
- **`make install-desktop`** — installs a `.desktop` launcher entry and the SVG icon to `~/.local/share/applications` and `~/.local/share/icons/hicolor/scalable/apps` so `late-sast` appears in the system application launcher.
- **GUI log file** — all stdout/stderr (including Fyne internals, docker output, and agent logs) is redirected to `~/.cache/late-sast/late-sast.log` so the launching terminal stays silent.

### Fixed
- **`LANG=C` locale error** — Fyne's locale parser rejects the `C` and `POSIX` pseudo-locales. `$LANG` is now normalised to `en_US.UTF-8` at startup when it is empty, `C`, or `POSIX`.
- **Fyne thread warnings at shutdown** — goroutines that stream events were calling `fyne.Do` after the Fyne event loop had drained, causing "Error in Fyne call thread" log spam. Fixed by wiring `window.SetCloseIntercept` → `rootAgent.Cancel()` so event-loop goroutines are stopped before Fyne shuts down.

### Changed
- **`make install`** now reliably installs `late-sast` without being clobbered by `install-late`. The `late` binary remains optional compatibility tooling from the upstream engine, but this fork's primary target is `late-sast`.
- **`fetch-cbm`** skips the network download when the embedded binary already exists (avoids a multi-second stall on every `make install`).
- **`ChildAddedEvent`** carries an `AgentType string` field so the GUI can label subagent tabs correctly without a separate lookup.
- **`ContentEvent`** carries a `client.Usage` field (PromptTokens, CompletionTokens, TotalTokens) for real-time context window tracking.
- **`NewSubagentOrchestrator`** — the `tui.Messenger` parameter replaced with a generic `agent.MiddlewareFactory` function type, eliminating the circular `agent → tui` import and allowing the GUI to inject its own confirmation middleware without forking the agent package.

---


## [v1.7.2.2] — 2026-04-30

### Fixed
- **Auditor repetition loop on long reasoning chains** — VulnLLM-R-7B (llama.cpp) would enter an infinite "code. code. code." repetition loop when processing multi-hotspot SAST reports because no `repeat_penalty` was sent to the server. Added `repeat_penalty: 1.15` and `repeat_last_n: 512` to the auditor session via a new `Session.SetExtraBody` method. These parameters are flattened to the request root by `marshalFlattened` so llama.cpp applies them natively.
- **`Session.SetExtraBody`** — new method on `Session` allows per-session default `extra_body` parameters (merged into every `StartStream` call; caller-supplied values take precedence).

---

## [v1.7.2.1] — 2026-04-30

### Fixed
- **Makefile `VERSION` was stale** — `make install-sast` was injecting `1.2.1` via `-ldflags` regardless of `internal/common/version.go`. `VERSION` in the Makefile is now kept in sync with the Go constant.
- **GitHub Actions release workflow not triggering on tag push** — the workflow previously used `release: types: [created]`, which only fires when a Release object is created through the GitHub UI/API, not when a git tag is pushed directly. Changed trigger to `push: tags: ['v*']` so CI builds binaries automatically for every version tag.

---

## [v1.7.2] — 2026-04-30

### Added
- **Help overlay (`?`)** — pressing `?` when the input field is empty opens a full-screen key binding reference rendered with the `bubbles/v2/help` bubble. Lists all shortcuts (send, stop, tab, back, allow-once/session/project/global, deny, quit) in two columns styled with the app's amethyst palette. `?` or `Esc` closes the overlay.
- **Key bindings** — all key bindings declared as typed `key.Binding` entries with `ShortHelp`/`FullHelp` support.

---

## [v1.7.1] — 2026-04-30

### Fixed
- **`finish_reason: "length"` false context abort** — the agent no longer treats a model hitting its per-turn generation budget (`n_predict`) as an unrecoverable context-window-full error. When llama.cpp returns `finish_reason: "length"`, the runner now calls `/props` to fetch the live `n_ctx` value and compares it against `total_tokens` (with a 5-token rounding margin). A genuine context overflow (prompt fills the window) still raises the hard error; hitting `n_predict` mid-output filters truncated tool calls and continues the run loop normally. Falls back to the content/tool-call heuristic for non-llama.cpp backends that don't expose a context size.


## [v1.7.0] — 2026-04-30

### Added
- **`--retest <report>` flag** — re-verify a previous `sast_report_*.md` after a developer claims fixes. Parses the original report header (repo, target URL, findings) and re-runs live exploitation for each finding. Outputs `sast_retest_<repo>.md` with updated statuses: `FIXED`, `STILL PRESENT`, `CANNOT VERIFY`.
- **`--path <dir>` flag** — scan a local repository without cloning from GitHub. The directory is mounted into the container as-is; no network clone step.
- **Auditor `max_tokens: 8192`** — VulnLLM-R-7B auditor session now requests `max_tokens: 8192` to prevent mid-JSON truncation on verbose hotspot verdicts.
- **`MaxTokens` field in `ChatCompletionRequest`** — API request struct now carries `max_tokens` so any session can cap generation budget at the request level.
- **HTML tag stripping in streaming tail renderer** — `htmlTagRe` now applied to the live-streaming tail path in addition to the already-cleaned completed-chunk path. Prevents `</pre></li></ol>` bleed from model training data appearing in the TUI.
- **`instruction-sast-retest.md`** — new system prompt for the retest workflow.

### Changed
- README and quickstart updated with three-model pipeline docs, VulnLLM-R-7B auditor section, retest workflow, `--path` and `--retest` flag documentation, `LATE_AUDITOR_MODEL` / `LATE_AUDITOR_BASE_URL` env vars, llama-swap config snippet.

---

## [v1.6.1] — 2026-04-30

### Fixed
- **Binary scanner Step 7 — `UNREACHABLE` false negatives** — three pre-checks added before live exploit attempts:
  - **Pre-check A (platform constraints)** — detects `_windows.go` / `_darwin.go` build-constrained files and marks them `PLATFORM_SPECIFIC` instead of `UNREACHABLE`. Verdict is based on code analysis; the code is still classified CONFIRMED/LIKELY.
  - **Pre-check B (code-only verifiable findings)** — integer type truncations, unguarded sign conversions, and structural race conditions are now classified `CODE_CONFIRMED` without requiring live execution. Eliminates false `UNREACHABLE` on CWE-190 and CWE-764 findings.
  - **Pre-check C (CLI flag attack surface)** — for CLI tools, reads `--help`, cross-references flags that accept command strings (`--preview`, `--execute`, `--bind`, `--become`, etc.) against Step 2 grep hits, and probes each flag with a command-injection payload before falling back to generic stdin/argv tests. Catches flag-driven shell injection that generic overflow tests miss.
- Exploit status vocabulary extended: `CODE_CONFIRMED`, `PLATFORM_SPECIFIC` added alongside existing `EXPLOITED`, `BLOCKED`, `UNREACHABLE`. `UNREACHABLE` is now reserved exclusively for dead code or truly unreachable taint paths.

---

## [v1.6.0] — 2026-04-30

### Added
- **Path C — Dockerfile-based container launch** — setup now detects a `Dockerfile` at the repo root when no compose file is present and builds it directly (`docker build -t <container>-image`). The source tree is still mounted at `/app` for full static analysis access. Port is auto-detected from `docker inspect` / `EXPOSE` lines. Falls through to Path B on build failure. Built image tag is recorded in `notes` and removed during orchestrator cleanup (`docker rmi`).
- **`cargo audit --json`** — installed in setup Step 5 when `cargo` is present; run in binary scanner Step 1e for Rust targets. Advisories with CVSS ≥ 7.0 reported under Dependency Vulnerabilities.
- **Step 1e in binary scanner** — CVE remediation enrichment via `docs_resolve` + `ctx_fetch_and_index` (matches the web scanner's Step 1e). Go and Rust library upgrade guides are pulled into the BM25 index; only relevant snippets reach the context window.
- **Language-specific semgrep rule packs** — binary scanner Step 2a now selects `p/golang` (net/http taint, os/exec patterns) for Go targets and `p/rust` (unsafe block patterns) for Rust targets instead of the generic `p/c` pack.

### Changed
- Orchestrator cleanup (Step 3) removes the custom-built image (`docker rmi <container>-image`) when Path C was used.

---

## [v1.5.1] — 2026-04-30

### Added
- **JSON-output static analysis tools installed in scan containers** — setup Step 5 now installs `semgrep`, `checksec`, and `gosec` (all non-fatal, degrade gracefully).
- **Binary scanner Step 2a — Structured tool scan** — `checksec --output=json` per compiled binary (canary/PIE/NX/RELRO flags directly inform severity escalation); `semgrep --json` structured SAST findings; `gosec -fmt json` Go-specific rules (G101 hardcoded creds, G201/202 SQLi, G304 path traversal, G401–501 weak crypto).
- **Web scanner Step 1f** — `semgrep --config=p/default --json` structured pre-pass; `ERROR`-severity findings fed into Step 2 graph map as LIKELY candidates.

---

## [v1.5.0] — 2026-04-30

### Added
- **Binary/native-code SAST pipeline** — new `binary-scanner` subagent type for C, C++, Go CLI, and Rust targets with no HTTP server. Automatically selected when `project_type == "binary"` (C/C++ always; Go/Rust when `entry_points == 0` and no HTTP framework detected in `go.mod`).
- **9-class binary vulnerability reference library** — pre-indexed into the BM25 knowledge base alongside the 34 existing web classes (43 total). Grounded in the 2025 CWE Top 25 and OWASP Secure Coding Practices checklist §Memory Management:
  - `memory_corruption.md` — CWE-787 #5 / CWE-125 #8 / CWE-121 #14 / CWE-122 #16 (stack/heap buffer overflow, OOB read/write)
  - `use_after_free.md` — CWE-416 #7 (14 KEV CVEs)
  - `integer_overflow.md` — CWE-190/191/680 overflow→allocation sizing
  - `dangerous_functions.md` — CWE-676/120 #11 (`gets`, `strcpy`, `sprintf`, `scanf`)
  - `format_string.md` — CWE-134 `printf(user_input)`
  - `binary_command_injection.md` — CWE-78 #9 (20 KEV CVEs) `system()`/`popen()`/`exec.Command`
  - `privilege_management.md` — CWE-250/272/732 root without privilege drop, SUID misuse
  - `null_pointer_dereference.md` — CWE-476 #13 unchecked `malloc`/`fopen`, nil panics in Go
  - `sensitive_memory_exposure.md` — CWE-226/200/401 passwords not zeroed (`explicit_bzero`), fd leaks, Heartbleed-class over-reads
- **Grep-first binary scanner workflow** — Step 2 searches for dangerous function sinks (`gets`, `strcpy`, `system`, `printf` with non-literal first arg) across all `.c`/`.cpp`/`.go`/`.rs` files before invoking the graph. Taint traces from `argv`/`stdin`/`recv()`/`getenv()` to sinks via `trace_path`.
- **Binary invocation exploit verification** — Step 7 invokes the compiled binary directly with oversized input and checks exit codes: `139` (SIGSEGV) = overflow confirmed, `134` (SIGABRT) = stack canary / heap corruption, `136` (SIGFPE) = integer exception. Format string PoC: `%p.%p.%p.%p` pipeline. Command injection PoC: writes `/tmp/rce_proof`.
- **Privilege audit step** (Step 6 in binary scanner) — checks for root without `setuid`/`setgid` drop, SUID binaries (`find -perm -4000`), world-writable file creation (`O_CREAT` with `0666`/`0777`), and missing `explicit_bzero`/`memset_s` on credential buffers.
- **`project_type` field in `SETUP_COMPLETE`** — setup subagent now emits `"project_type": "web" | "binary"` in its JSON handoff, enabling the orchestrator to route deterministically.

### Changed
- Orchestrator (`instruction-sast.md`) branches on `project_type` to spawn `agent_type: "binary-scanner"` vs `agent_type: "scanner"`.
- `SKILL.md` vulnerability class table updated to 43 classes with new Binary/Native row.

---

## [v1.4.0] — 2026-04-30

### Added
- **Native ProContext documentation tools** (`docs_resolve`, `docs_read`, `docs_search`) — native Go reimplementation of the [ProContext](https://github.com/procontexthq/procontext) MCP server. Downloads the public ProContext registry (~2,100 libraries) once at startup and exposes library documentation lookup without any external process, Python, or MCP handshake. SSRF protection built in (domain allowlist from registry). Non-fatal: if the registry is unreachable the scan continues without docs tools. 26 tests.
- **In-session knowledge base** (`ctx_index`, `ctx_search`, `ctx_fetch_and_index`) — native Go port of the core concepts from [context-mode](https://github.com/mksglu/context-mode). Indexes large documents (advisories, HTML pages, markdown) into an in-memory BM25 inverted index; retrieves only relevant snippets via ranked search. Raw content never enters the context window: a 100 KB advisory becomes ~35 bytes on index and ~400 bytes on retrieval (~99% context reduction). `ctx_fetch_and_index` includes a 24-hour TTL cache and an SSRF-safe custom dialer that rejects private/loopback IPs at dial time. 23 tests.

### Changed
- `cmd/late-sast/main.go` — both tool suites registered at startup; ProContext registration is non-fatal (warns to stderr if registry unreachable).

---

## [v1.3.0] — 2026-04-30

### Added
- **`patch_compose_network` tool** — deterministic YAML-AST-based Docker Compose network patching using `gopkg.in/yaml.v3` Node API. Replaces the previous LLM-driven compose file editing. Handles sequence-style, mapping-style, and absent `networks:` blocks; idempotent; preserves comments and formatting. 10 tests.
- **CVE vendor normalisation map** — 80-entry `cveVendorMap` in `cve_search.go` maps common package names (`express`, `django`, `log4j`, `spring-boot`, etc.) to the CPE vendor strings expected by `cve.circl.lu`. Silent false-negatives from wrong vendor names are eliminated.
- **`${{VERSION}}` placeholder** — version is now injected into the SAST report header at runtime (`Analyzer: late-sast 1.3.0`), replacing the hardcoded `v1` string.
- **Two-pass secrets grep** (Step 1b) — pass 1 catches quoted `KEY="value"` patterns across 19 file extensions (added `.conf`, `.cfg`, `.ini`, `.properties`, `.xml`, `.jsx`, `.tsx`, `.cs`, `.env.*`); pass 2 catches bare `KEY=value` patterns in dotenv and config files. Both passes filter common placeholder noise.
- **JSON-structured `SETUP_COMPLETE` handoff** — the setup subagent now emits a typed JSON object (`key_routes` as array, `entry_points` as integer, `app_started` as boolean) instead of freeform text, making orchestrator extraction deterministic.

### Fixed
- CI `go-version` corrected to `'1.26'` to match local development environment (go.mod minimum: 1.25.8).

### Changed
- Setup prompt Path A step 2 replaced with a single `patch_compose_network(...)` call — 20 lines of "adjust indentation" instructions removed.
- README and quickstart updated to reflect all new `late-sast`-specific features.

---

## [v1.2.0] — 2026-04-29 *(initial late-sast hardening release)*

### Added
- **Native Go CVE tools** — replaced Python-based `cve-search_mcp` server with 4 native Go tools (`vul_vendor_product_cve`, `vul_cve_search`, `vul_vendor_products`, `vul_last_cves`) making direct HTTP calls to `cve.circl.lu`. No Python, no uv, no external processes. 26 tests.
- **`codebase-memory-mcp` baked into binary** — embedded via `go:embed` under the `cbm_embedded` build tag. `make build-sast` downloads the CBM binary for the current platform and bakes it in. Falls back to runtime download when built without the tag.
- **CI release workflow** — `release.yml` builds 6 matrix targets (linux/darwin/windows × amd64/arm64) with CBM embedded and version injected via `-ldflags`.
- **`--timeout` flag** — hard wall-clock scan timeout with clean container/network teardown on expiry.
- **Stale container reaping** — on startup, any leftover `sast-*` containers and networks from crashed previous runs are removed automatically.
- **`--subagent-max-turns`** — configurable scanner depth (default 500).
- **`--gemma-thinking`** — prepends `<|think|>` token for Gemma 4 thinking-mode models.
- **CVE Findings table** in report output — columns: CVE, Package, CVSS, Severity, Description, NVD link.

### Fixed
- **3 HIGH CVEs in `go-sdk`** (GO-2026-4773, GO-2026-4770, GO-2026-4569) — upgraded `github.com/modelcontextprotocol/go-sdk` from v1.2.0 to v1.4.1.
- Root-owned workdir cleanup — uses a throwaway Alpine container to `rm -rf` bind-mounted directories written as root inside the scan container.
- Version bumped to `1.0.0` in Makefile (was `dev`).

### Changed
- `late-sast` now uses `~/.config/late-sast/` for its own config, falling back to `~/.config/late/` for compatibility with existing `late` installations.
- README rewritten to describe `late-sast`-specific features; removed upstream `late` feature descriptions (git worktrees, stateful session history, agent skills).
- Quickstart simplified to `late-sast` only; removed upstream `late` usage guide, tool approval TTL docs, and keybindings section.
- Build targets corrected: `make build-sast` / `make install-sast` (was `make build` / `make install`).

---

## [v1.1.x] — upstream mlhher/late releases

See [mlhher/late](https://github.com/mlhher/late) for changes to the underlying agent engine (AST-based analysis, token counting fixes, context window estimation, skills support, TUI improvements).

---

## [v1.0.0] — initial fork from mlhher/late

### Added (late-sast-specific)
- **`late-sast` binary** (`cmd/late-sast/`) — autonomous SAST orchestrator with three-subagent pipeline: setup → scanner → report.
- **Docker sandbox pipeline** — clones target into `/tmp`, spins up a language-appropriate container, mounts source, installs deps, starts app, runs scan, tears everything down on exit.
- **34-class vulnerability reference library** — embedded from [SunWeb3Sec/llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner) (MIT); loaded selectively per language.
- **Graph-first taint tracing** — uses `codebase-memory-mcp` to map HTTP entry points → data flows → sinks before any code reading.
- **Live exploitation** — for every CONFIRMED/LIKELY finding, real PoC via `docker exec sh -c "wget ..."`.
- **Hardcoded secrets grep** — pre-scan pass before static analysis.
- **Trivy CVE scan** — lockfile-based CVE detection inside the container.
- **Multi-container / sidecar support** — detects and starts postgres, redis, mysql, mongo, rabbitmq, elasticsearch sidecars as needed.
- **Monorepo detection** — identifies monorepo layouts and focuses scan on the primary HTTP service.
- **Structured Markdown report** — findings classified CONFIRMED / LIKELY / NEEDS CONTEXT / FALSE POSITIVE with severity, evidence snippet, exploit result, and remediation priority list.
- **`LATE_SUBAGENT_MODEL` / `LATE_SUBAGENT_BASE_URL` / `LATE_SUBAGENT_API_KEY`** — hybrid model routing (large reasoning model as orchestrator, fast dense model as scanner).
