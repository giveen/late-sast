// Package tool implements the tool system for late-sast.
//
// Tool Organization:
//
// # Core Interfaces & Registry
// - tool.go: Tool and Registry interfaces
// - implementations.go: Basic tools (bash, read_file, write_file)
//
// # Code Analyzers
// - analyzer.go: General code analysis (AST, imports, symbols)
// - bash_analyzer.go: Bash script analysis
// - bash_analyzer_sast.go: SAST-specific bash analysis
// - powershell_analyzer.go: PowerShell script analysis
//
// # Docker & Containerization
// - launch_docker.go: Start Docker containers
// - setup_container.go: Container environment setup
// - wait_for_target_ready.go: Container readiness checks
// - compose_patch.go: Docker Compose network patching
//
// # Data Lookup & Search
// - context_index.go: BM25 full-text index for codebase context
// - cve_search.go: CVE database search
// - docs_lookup.go: ProContext documentation lookup
//
// # SAST & Report Generation
// - write_sast_report.go: Final security report formatting
// - assess_disclosure_context.go: GHSA/CWE classification
//
// # Execution & Coordination
// - run_trivy_scan.go: Container image vulnerability scanning
// - run_semgrep_scan.go: SAST rule-based scanning
// - run_exploit_replay.go: Exploit verification tool
// - run_secrets_scanner.go: Secret detection
//
// # Utilities & Helpers
// - utils.go: Shared utility functions
// - tool.go: Tool registry and type aliases
// - skill_tool.go: Skill activation tool
// - subagent.go: Subagent spawning
// - permissions.go: Unix permission analysis
// - resolve_install_strategy.go: Dependency resolution strategy
// - targetEdit.go: Targeted file editing with AST
// - shell_command_*.go: Platform-specific shell invocation
// - line_endings_test.go: Line ending normalization
// - ast/: AST utilities and analysis
// - internal/: SAST-specific skill assets
package tool
