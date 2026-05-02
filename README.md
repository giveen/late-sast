# late-sast: Autonomous Security Auditor

[![CI](https://github.com/giveen/late-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/giveen/late-sast/actions/workflows/ci.yml)
[![Release](https://github.com/giveen/late-sast/actions/workflows/release.yml/badge.svg)](https://github.com/giveen/late-sast/actions/workflows/release.yml)

> **late-sast** is maintained at [giveen/late-sast](https://github.com/giveen/late-sast). It is built on the [mlhher/late](https://github.com/mlhher/late) agent engine — the original orchestration engine, subagent dispatch, and tool infrastructure are the work of **mlhher**. The `late-sast` binary, Docker sandboxing, live exploitation pipeline, CVE enrichment, and vulnerability reporting are original additions in this fork.

**late-sast** is an autonomous security auditor built on top of the [Late](https://github.com/mlhher/late) agent engine. It takes a GitHub URL, spins up a throwaway Docker sandbox, installs and runs the target application, performs a full static and dynamic security scan, then attacks its own findings live — and cleans up after itself completely.

```bash
late-sast https://github.com/owner/repo
```

No configuration. No manual setup. One command, one report.

> **Built on Late:** The orchestration engine, ephemeral subagent dispatch, and tool infrastructure are the work of **mlhher** at [mlhher/late](https://github.com/mlhher/late). `late-sast` extends that foundation with an autonomous security pipeline.

## 🔥 Why late-sast?

### 1. Static Analysis Alone is Not Enough

Every SAST tool on the market stops at the code. They flag a potential path traversal and call it a day — leaving you to figure out whether it's actually reachable, whether the sanitization works, and whether a real attacker could exploit it.

`late-sast` doesn't stop at the code. After the static scan, it installs and runs the target application, then attempts a live proof-of-concept against every finding. Each result is classified as **CONFIRMED** (exploited live), **LIKELY** (statically confirmed, runtime inconclusive), **NEEDS CONTEXT** (requires credentials or config), or **FALSE POSITIVE** (blocked or unreachable). You get signal, not noise.

### 2. Fully Autonomous — Zero Manual Steps

Standard security workflows require a human to clone the repo, figure out the build system, install dependencies, start the app, and hand-craft exploit attempts. `late-sast` does all of this autonomously:

- Detects the language and framework from the codebase graph
- Picks the right Docker base image and runs the correct install commands
- Reads the project README to understand how to start the application
- Discovers the listening port automatically
- Runs the full scan and exploitation pipeline without interruption

### 3. Graph-First, Not Grep-First

Instead of pattern-matching source files, `late-sast` builds a full codebase knowledge graph first — mapping every HTTP entry point, authentication boundary, data flow, and dangerous sink. Taint traces follow data through the call graph to find where user-controlled input reaches exploitable operations. This eliminates the false positives that plague regex-based scanners.

### 4. Isolated & Self-Cleaning

Every scan runs inside a throwaway Docker container and a timestamped `/tmp` directory. When the scan completes (or if you hit Ctrl-C), everything is removed: the container, the cloned source, the temporary files. Nothing accumulates on your machine.

### 5. Local-First & Model Agnostic

Runs on any OpenAI-compatible endpoint — local or cloud. The ephemeral agent architecture keeps VRAM and context usage flat regardless of repo size. Tested on a local `Qwen3.6-35B-A3B` at ~30 tokens/sec on 5GB VRAM.


## 🚀 Quick Start (Zero Dependencies)

**1. Download the Binary**
Grab the latest single-binary release for your OS (Linux/macOS/Windows) from the [Releases](https://github.com/giveen/late-sast/releases) page.

```bash
chmod +x late-sast-linux-amd64  # (Adjust for your downloaded filename)
mv late-sast-linux-amd64 ~/.local/bin/late-sast  # Ensure ~/.local/bin is in your system's $PATH
```

**2. Point to Your Model**
Point `late-sast` to any OpenAI-compatible API endpoint (local or cloud).

```bash
export OPENAI_BASE_URL="http://localhost:8080"
```

> **Note for Windows users:** Use your shell's native export command (e.g. `$env:OPENAI_BASE_URL="http://localhost:8080"` in PowerShell).

**3. Execute**

```bash
late-sast https://github.com/owner/repo
```

📖 Next Steps: See the **[Quickstart Guide](docs/quickstart.md)** for advanced setup (e.g. API keys, subagent models, persistent configuration), keyboard shortcuts, and more features (including MCP integration).

## 🔨 Build from Source

Requires Go and Docker:

```bash
git clone https://github.com/giveen/late-sast.git
cd late-sast
make build-sast   # downloads + embeds codebase-memory-mcp, produces ./bin/late-sast
make install-sast # installs to ~/.local/bin/late-sast
```

> `make build-sast` automatically fetches the `codebase-memory-mcp` binary for your platform and bakes it into the `late-sast` binary — no separate install step needed.

### Development Targets

For developers, the Makefile includes a complete CI/test suite:

```bash
make quick-test    # Run unit tests locally (fast, no race detection)
make test-race     # Run all tests with -race flag (detects data races)
make coverage      # Generate test coverage report (outputs ./coverage/index.html)
make fmt           # Auto-format all Go code with gofmt
make fmt-check     # Check formatting without modifying files (CI gate)
make vet           # Run go vet static analysis
make lint          # Run golangci-lint (requires installation)
make ci            # Run all CI gates: fmt-check → vet → lint → test-race → coverage
```

The `ci` target is what runs in GitHub Actions and is useful for local pre-commit validation.

## 🔍 late-sast: Autonomous Security Auditor

`late-sast` is the primary addition in this fork. It turns Late's agent engine into a fully autonomous SAST (Static Application Security Testing) tool. Point it at any public GitHub repository and it will clone, build, run, attack, and report — without any manual steps.

```bash
late-sast https://github.com/owner/repo  # Requires Docker
```

### How It Works

`late-sast` runs a fixed, deterministic pipeline entirely inside a throwaway Docker container:

| Step | What happens |
|------|-------------|
| **1. Clone** | The target repository is cloned into an isolated `/tmp` working directory |
| **2. Index** | The codebase graph is built via MCP — all HTTP routes, auth boundaries, data flows, and sinks are mapped without reading individual files |
| **3. Sandbox** | A Docker container matching the repo's language (Go, Python, Node, Java, etc.) is created and the source is mounted inside |
| **4. Install** | Dependencies are installed inside the container exactly as documented in the repo's README |
| **5. Launch** | The application is started inside the container and its listening port is discovered |
| **6. SAST Scan** | The agent runs a full vulnerability scan across 34 vulnerability classes (see below), tracing taint paths from every HTTP entry point to dangerous sinks. Hardcoded secrets are grepped separately. |
| **6b. CVE Lookup** | Trivy scans lockfiles for CVEs; built-in CVE tools query [cve.circl.lu](https://cve.circl.lu/) directly for live CVSS scores and NVD links — no external dependencies |
| **7. Live Exploitation** | For every CONFIRMED or LIKELY finding, a real proof-of-concept is attempted against the running application — each finding is marked **EXPLOITED**, **BLOCKED**, or **UNREACHABLE** |
| **8. Report + Cleanup** | A structured Markdown report (`sast_report_<repo>.md`) is written to the current directory, then the Docker container, cloned source, and all temporary files are removed |

### Findings Classification

Every finding goes through a Judge step before it reaches the report:

- **CONFIRMED** — the vulnerability is reachable, unsanitized, and the live PoC returned a meaningful response
- **LIKELY** — statically confirmed but not fully exploitable in the test environment
- **NEEDS CONTEXT** — requires runtime configuration or credentials to verify
- **FALSE POSITIVE** — the live exploit was blocked or the path is unreachable

> **Scope note:** `late-sast` scans unauthenticated attack surface only — it does not log in to the application. Vulnerabilities that exist exclusively behind authenticated routes will be flagged as **NEEDS CONTEXT** rather than **CONFIRMED** or **LIKELY**. Post-auth vulnerabilities (IDOR, privilege escalation, auth bypass) require a session token to verify live; the static taint analysis still runs for them.

### Retest Mode

After a developer claims they've fixed the reported vulnerabilities, rerun the scan against the previous report to verify:

```bash
late-sast --retest ./sast_report_myrepo.md
```

`late-sast` re-reads the report, re-clones the repository at HEAD, and re-verifies each finding — without running a full scan from scratch. Each finding is re-classified as **FIXED**, **STILL PRESENT**, or **CANNOT VERIFY**, and a new `sast_retest_<repo>.md` report is written to the current directory.

### Scan a Local Repository

```bash
late-sast --path /path/to/local/repo
```

Skips the clone step — the local directory is mounted into the Docker container directly. Useful for auditing work-in-progress code before pushing.

### Vulnerability Coverage

`late-sast` covers all 34 vulnerability classes from the [llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner) reference library (MIT License, © SunWeb3Sec), including:

SQL Injection · XSS · SSRF · RCE · Path Traversal / LFI · IDOR · Authentication / JWT · CSRF · XXE · Command Injection · Prototype Pollution · Deserialization · Open Redirect · Mass Assignment · Insecure Direct Object Reference · Timing Attacks · and more.

> **Credit:** The vulnerability reference files embedded in `late-sast` are derived from [SunWeb3Sec/llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner), released under the MIT License. The agent orchestration, Docker sandboxing, live exploitation pipeline, and reporting workflow are original to this project.

### Build late-sast

```bash
make build-sast    # produces ./bin/late-sast
make install-sast  # builds and installs to ~/.local/bin/late-sast
```

Requires Docker to be installed and running. No other dependencies.

> **Note:** `make install-sast` moves the binary to `~/.local/bin/` — use `make build-sast` if you want to keep it in `./bin/` for local testing.

### Clean Execution Guarantee

Every run is fully isolated and self-cleaning:
- The cloned repository lives in `/tmp/sast-<timestamp>/` and is deleted on exit
- The Docker container is stopped and removed on exit (including on Ctrl-C / SIGTERM)
- The extracted skill files at `/tmp/sast-skill/` are removed on exit
- Nothing is written outside the current working directory except the final report

---

## 🛠️ Advanced Features

### Hybrid Model Routing
Use a large reasoning model as the orchestrator, a security-specialized model as the auditor, and a faster dense model for the fixer subagent:
```bash
export OPENAI_MODEL="qwen3.6-35b-a3b"              # orchestrator/scout
export LATE_SUBAGENT_MODEL="qwen3.6-27b-coder"     # fixer subagent
export LATE_SUBAGENT_BASE_URL="http://10.8.0.2:8080"  # optional
export LATE_SUBAGENT_API_KEY="your-other-key"          # optional
```

For taint analysis, `late-sast` uses a dedicated **auditor** model. Configure it separately:
```bash
export LATE_AUDITOR_MODEL="VulnLLM-R-7B"           # security-specialized 7B
export LATE_AUDITOR_BASE_URL="http://localhost:8080" # optional
export LATE_AUDITOR_API_KEY="..."                   # optional
```
See the [Quickstart Guide](docs/quickstart.md) for recommended model configurations.

### Multi-Container Support
`late-sast` detects and starts compose-based applications (postgres, redis, etc.) automatically. It patches the compose file to join the scan network, then spins up any required sidecars (MySQL, MongoDB, RabbitMQ, Elasticsearch) if the app needs them.

### Live CVE Enrichment
Dependency files (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Gemfile`) are scanned by Trivy for lockfile CVEs, then enriched via the built-in CVE tools (querying [cve.circl.lu](https://cve.circl.lu/)) for live CVSS scores and NVD links. No external tooling required.

> **v1.8.1+ Improvements:** CVE API responses are now cached for 24 hours to reduce latency during repeated scans against the same dependencies. Transient API failures (429/503 errors) are automatically retried with exponential backoff, making the scan more resilient to temporary network issues.

### Library Documentation Lookup
When a CVE or vulnerable dependency is found, the scanner can resolve authoritative remediation documentation without leaving the context window. Three native Go tools implement the [ProContext](https://github.com/procontexthq/procontext) documentation protocol:

| Tool | What it does |
|---|---|
| `docs_resolve(query, language?)` | Resolves a package/library name to its documentation index URL using the ProContext public registry (~2,100 libraries) |
| `docs_read(url, offset?, limit?)` | Reads a windowed slice of a documentation page with line numbers |
| `docs_search(url, query)` | Greps a documentation page for a keyword or regex, returning matching lines |

### Context-Efficient Knowledge Base
Large documents — security advisories, HTML pages, CVE reports — can be indexed once and queried by relevance, keeping raw content out of the context window entirely:

| Tool | What it does |
|---|---|
| `ctx_index(source, content)` | Chunks markdown/text by heading boundaries and indexes it with BM25 |
| `ctx_search(query, max_results?)` | Returns BM25-ranked snippets — never raw document dumps |
| `ctx_fetch_and_index(url, force?)` | Fetches a URL (HTML or plain text), converts to text, indexes; 24h TTL cache |

A 100 KB advisory becomes ~35 bytes on index call and ~400 bytes on retrieval. SSRF protection blocks private/loopback IP ranges at dial time.

### Secrets Detection
A dedicated pre-scan step greps the entire codebase for hardcoded credentials, API keys, and private key material before the SAST scan begins. Findings are classified CRITICAL and appear at the top of the report.

### Scan Timeout
Prevent runaway scans with `--timeout`:
```bash
late-sast --timeout 45m https://github.com/owner/repo
```

> **v1.8.1+ Improvements:** Individual subagents now have intelligent timeout policies to prevent hanging:
> - **Auditor** (taint analysis): 20 minutes
> - **Scanner** (static analysis): 15 minutes
> - **Binary Scanner** / **Setup**: 15 minutes
> - **Coder** (exploitation/fixer): 10 minutes
>
> These defaults are overridable via environment variables if you need to customize per-agent timeouts. Long-running subagents emit heartbeat signals every 30 seconds to help operators monitor progress in long scans.

### MCP Server Integration
Any MCP server configured in `~/.config/late-sast/mcp_config.json` is automatically connected and its tools are available to the agent during the scan.

## 📜 Upstream Credit

The core `late` agent (orchestrator, TUI, subagent dispatch, session persistence, tool infrastructure) is the original work of **mlhher** at [mlhher/late](https://github.com/mlhher/late), released under BSL 1.1.

The SAST extensions in this fork (`late-sast` binary, Docker sandbox pipeline, live exploitation workflow, embedded vulnerability references) are original additions by [giveen](https://github.com/giveen), also released under BSL 1.1.

**[codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)** by DeusData — graph-based code intelligence MCP server used by `late-sast` for architecture extraction, taint tracing, and vulnerability mapping.

CVE data is sourced from the [cve.circl.lu](https://cve.circl.lu/) public API (operated by CIRCL, no auth required), implemented natively in Go within `late-sast`. Inspired by [roadwy/cve-search_mcp](https://github.com/roadwy/cve-search_mcp) (MIT License).

**[llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner)** by SunWeb3Sec — vulnerability reference library and LLM-driven SAST workflow that powers the scanner subagent.

**[ProContext](https://github.com/procontexthq/procontext)** by [@procontexthq](https://github.com/procontexthq) — the documentation registry protocol and `known-libraries.json` public registry (~2,100 libraries) that powers the `docs_resolve`, `docs_read`, and `docs_search` tools. The native Go implementation in `late-sast` faithfully reimplements the ProContext MCP server API without requiring a subprocess or network call to a ProContext instance.

**[context-mode](https://github.com/mksglu/context-mode)** by [@mksglu](https://github.com/mksglu) (Mert Köseoğlu) — the sandbox-index-search pattern, 24h fetch cache, and intent-driven BM25 retrieval architecture that inspired the `ctx_index`, `ctx_search`, and `ctx_fetch_and_index` tools. The native Go implementation in `late-sast` adapts this approach for the scanner's in-memory workload without requiring Node.js or SQLite.

---

## 📜 License: BSL 1.1

`late-sast` is released under the Business Source License 1.1. You are free to use it for any personal or commercial project of your own. The restrictions only apply to packaging `late-sast` itself as a product or service.

* **Free for Security Engineers:** Use `late-sast` freely to audit any codebase, including client engagements and internal security programmes.
* **Commercial Restrictions:** You may not resell, wrap, or host `late-sast` as a paid scanning service or embed it as infrastructure in a commercial SaaS product without a separate agreement.

*Converts to open-source GPLv2 on February 21, 2030.*
