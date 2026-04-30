# Changelog — late-sast

All notable changes to **late-sast** ([giveen/late-sast](https://github.com/giveen/late-sast)) are documented here.

`late-sast` is a fork of [mlhher/late](https://github.com/mlhher/late). Changes to the upstream agent engine (TUI, orchestrator, session persistence, skill infrastructure) are not listed here — see the upstream repository for that history.

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
