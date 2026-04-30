# late-sast: Autonomous Security Auditor — forked from Late

> This is **[giveen/late-sast](https://github.com/giveen/late-sast)**, a fork of [mlhher/late](https://github.com/mlhher/late) extended with an autonomous SAST pipeline. The original `late` agent, its architecture, and the core orchestration engine are the work of **mlhher**. The `late-sast` binary, Docker sandboxing workflow, live exploitation pipeline, and vulnerability reporting are original additions in this fork.

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

If you prefer to compile Late yourself (requires Go):

```bash
git clone https://github.com/giveen/late-sast.git
cd late-sast
make build
make install
```

> The original `late` agent (without SAST) is maintained upstream at [mlhher/late](https://github.com/mlhher/late).

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

### Vulnerability Coverage

`late-sast` covers all 34 vulnerability classes from the [llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner) reference library (MIT License, © SunWeb3Sec), including:

SQL Injection · XSS · SSRF · RCE · Path Traversal / LFI · IDOR · Authentication / JWT · CSRF · XXE · Command Injection · Prototype Pollution · Deserialization · Open Redirect · Mass Assignment · Insecure Direct Object Reference · Timing Attacks · and more.

> **Credit:** The vulnerability reference files embedded in `late-sast` are derived from [SunWeb3Sec/llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner), released under the MIT License. The agent orchestration, Docker sandboxing, live exploitation pipeline, and reporting workflow are original to this project.

### Build late-sast

```bash
make build-sast    # produces ./bin/late-sast
make install-sast  # installs to ~/.local/bin/late-sast
```

Requires Docker to be installed and running. No other dependencies.

### Clean Execution Guarantee

Every run is fully isolated and self-cleaning:
- The cloned repository lives in `/tmp/sast-<timestamp>/` and is deleted on exit
- The Docker container is stopped and removed on exit (including on Ctrl-C / SIGTERM)
- The extracted skill files at `/tmp/sast-skill/` are removed on exit
- Nothing is written outside the current working directory except the final report

---

## 🛠️ Advanced Features

* **Native MCP Integration:** Dynamically map external MCP servers directly into Late via standard I/O.
* **Stateful Resilience:** The Orchestrator maintains continuous, newest-first session history on disk (`~/.local/share/late`), ensuring perfect context retention across runs.
* **Git Worktree Support:** Run independent, parallel Late instances across multiple Git worktrees for isolated feature development without context switching.
* **Agent Skills:** Full support for [Agent Skills](https://agentskills.io/) for reusable sets of instructions and scripts.

For more information, check out the [quickstart guide](docs/quickstart.md).

## 📜 Upstream Credit

The core `late` agent (orchestrator, TUI, subagent dispatch, session persistence, tool infrastructure) is the original work of **mlhher** at [mlhher/late](https://github.com/mlhher/late), released under BSL 1.1.

The SAST extensions in this fork (`late-sast` binary, Docker sandbox pipeline, live exploitation workflow, embedded vulnerability references) are original additions by [giveen](https://github.com/giveen), also released under BSL 1.1.

**[codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)** by DeusData — graph-based code intelligence MCP server used by `late-sast` for architecture extraction, taint tracing, and vulnerability mapping.

CVE data is sourced from the [cve.circl.lu](https://cve.circl.lu/) public API (operated by CIRCL, no auth required), implemented natively in Go within `late-sast`. Inspired by [roadwy/cve-search_mcp](https://github.com/roadwy/cve-search_mcp) (MIT License).

**[llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner)** by SunWeb3Sec — vulnerability reference library and LLM-driven SAST workflow that powers the scanner subagent.

---

## 📜 License: BSL 1.1

We built this to generate real engineering leverage, not to supply free backend infrastructure for AI startups.

* **Free for Builders:** You may use Late freely to write code for any project, including your own commercial startups. We do not restrict your output.
* **Commercial Restrictions:** You may not monetize Late itself (e.g., wrapping our orchestration engine into a paid AI service), nor deploy Late as internal infrastructure within enterprise environments without a commercial agreement.

*Late safely converts to an open-source GPLv2 license on February 21, 2030.*
