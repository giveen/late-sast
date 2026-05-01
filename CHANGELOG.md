# Changelog — late-sast

All notable changes to **late-sast** ([giveen/late-sast](https://github.com/giveen/late-sast)) are documented here.

`late-sast` is a fork of [mlhher/late](https://github.com/mlhher/late). Changes to the upstream agent engine (TUI, orchestrator, session persistence, skill infrastructure) are not listed here — see the upstream repository for that history.

---

## [v1.7.2.1] — 2026-04-30

### Fixed
- **Makefile `VERSION` was stale** — `make install-sast` was injecting `1.2.1` via `-ldflags` regardless of `internal/common/version.go`. `VERSION` in the Makefile is now kept in sync with the Go constant.
- **GitHub Actions release workflow not triggering on tag push** — the workflow previously used `release: types: [created]`, which only fires when a Release object is created through the GitHub UI/API, not when a git tag is pushed directly. Changed trigger to `push: tags: ['v*']` so CI builds binaries automatically for every version tag.

---

## [v1.7.2] — 2026-04-30

### Added
- **Help overlay (`?`)** — pressing `?` when the input field is empty opens a full-screen key binding reference rendered with the `bubbles/v2/help` bubble. Lists all shortcuts (send, stop, tab, back, allow-once/session/project/global, deny, quit) in two columns styled with the app's amethyst palette. `?` or `Esc` closes the overlay.
- **Typed `KeyMap`** (`internal/tui/keys.go`) — all TUI key bindings are now declared as `key.Binding` entries, replacing the scattered hard-coded string literals. Implements `help.KeyMap` (`ShortHelp`/`FullHelp`) so the help bubble renders them automatically.
- **Dynamic terminal window title** — `View()` now sets `view.WindowTitle` based on agent state: `late`, `late — thinking…`, `late — streaming…`, or `late — confirm tool`. Updates live as the agent works.
- **`? Help` hint in status bar** — a `? Help` key hint is now shown in the status bar alongside `Ctrl+g Stop`.

---

## [v1.7.1] — 2026-04-30

### Fixed
- **`finish_reason: "length"` false context abort** — the agent no longer treats a model hitting its per-turn generation budget (`n_predict`) as an unrecoverable context-window-full error. When llama.cpp returns `finish_reason: "length"`, the runner now calls `/props` to fetch the live `n_ctx` value and compares it against `total_tokens` (with a 5-token rounding margin). A genuine context overflow (prompt fills the window) still raises the hard error; hitting `n_predict` mid-output filters truncated tool calls and continues the run loop normally. Falls back to the content/tool-call heuristic for non-llama.cpp backends that don't expose a context size.

---

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
