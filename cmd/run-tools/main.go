package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"late/internal/tool"
)

func main() {
	ctx := context.Background()

	// Step 1: assess_disclosure_context
	fmt.Println("=== Step 1: assess_disclosure_context ===")
	assessTool := tool.NewAssessDisclosureContextTool()
	assessArgs, _ := json.Marshal(map[string]interface{}{
		"repo_path":   "/tmp/sast-20260504-100406/repo",
		"github_url":  "https://github.com/giveen/late-sast",
		"findings": []map[string]interface{}{
			{"id": "H1", "title": "Command Injection — ShellTool.executeShellCommand", "cwe": 78, "severity": "CRITICAL", "impact": "Remote command execution via unsanitized shell command"},
			{"id": "H2", "title": "Command Injection — write_sast_report.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized report path in write_sast_report tool"},
			{"id": "H3", "title": "SSRF — CtxFetchAndIndexTool.Execute", "cwe": 918, "severity": "HIGH", "impact": "Server-side request forgery — access to internal services"},
			{"id": "H4", "title": "Command Injection — run_exploit_replay.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized curl command"},
			{"id": "H5", "title": "Command Injection — run_semgrep_scan.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized semgrep config URL"},
			{"id": "H6", "title": "Command Injection — run_trivy_scan.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized trivy repository path"},
			{"id": "H7", "title": "Command Injection — launch_docker.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized docker arguments"},
			{"id": "H8", "title": "Command Injection — setup_container.go Execute", "cwe": 78, "severity": "HIGH", "impact": "Remote command execution via unsanitized docker setup arguments"},
			{"id": "H9", "title": "Command Injection — run_git_command.go Execute", "cwe": 78, "severity": "MEDIUM", "impact": "Remote command execution via unsanitized git arguments"},
		},
	})
	result, err := assessTool.Execute(ctx, assessArgs)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("Result:\n%s\n", result)
	}

	// Step 2: cleanup_scan_environment
	fmt.Println("\n=== Step 2: cleanup_scan_environment ===")
	cleanupTool := tool.CleanupScanEnvironmentTool{}
	cleanupArgs, _ := json.Marshal(map[string]interface{}{
		"container":       "sast-20260504-100406",
		"compose_project": "none",
		"network":         "sast-20260504-100406-net",
		"workdir":         "/tmp/sast-20260504-100406",
		"image_tag":       "sast-20260504-100406-image",
	})
	result, err = cleanupTool.Execute(ctx, cleanupArgs)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("Result:\n%s\n", result)
	}

	// Step 3: write_sast_report
	fmt.Println("\n=== Step 3: write_sast_report ===")
	reportTool := tool.WriteSASTReportTool{}
	reportArgs, _ := json.Marshal(map[string]interface{}{
		"output_path":      "/tmp/late-scan-check/sast_report_late.md",
		"target":           "https://github.com/giveen/late-sast",
		"repo_name":        "late",
		"app_version":      "latest",
		"analyzer_version": "v2.0.0",
		"findings": []map[string]interface{}{
			{"id": "H1", "title": "Command Injection — ShellTool.executeShellCommand", "location": "internal/tool/implementations.go:126-145", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → ShellTool.executeShellCommand() → exec.CommandContext() → bash", "severity": "CRITICAL", "reproduce": "late --path /path/to/repo;echo injected", "impact": "Remote command execution via unsanitized shell command"},
			{"id": "H2", "title": "Command Injection — write_sast_report.go Execute", "location": "internal/tool/write_sast_report.go:430", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → WriteSASTReportTool.Execute() → exec.CommandContext() → go run .", "severity": "HIGH", "reproduce": "late --report-path foo;echo injected", "impact": "Remote command execution via unsanitized report path in write_sast_report tool"},
			{"id": "H3", "title": "SSRF — CtxFetchAndIndexTool.Execute", "location": "internal/tool/context_index.go", "cwe": 918, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → CtxFetchAndIndexTool.Execute() → http.Client.Get(url)", "severity": "HIGH", "reproduce": "late --url http://127.0.0.1:2375/v1.24/containers/json", "impact": "Server-side request forgery — access to internal services"},
			{"id": "H4", "title": "Command Injection — run_exploit_replay.go Execute", "location": "internal/tool/run_exploit_replay.go:220", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → RunExploitReplayTool.Execute() → exec.CommandContext() → curl", "severity": "HIGH", "reproduce": "late --base-url http://example.com;echo injected", "impact": "Remote command execution via unsanitized curl command"},
			{"id": "H5", "title": "Command Injection — run_semgrep_scan.go Execute", "location": "internal/tool/run_semgrep_scan.go:200", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → RunSemgrepScanTool.Execute() → exec.CommandContext() → semgrep", "severity": "HIGH", "reproduce": "late --semgrep-rule-url http://example.com;echo injected", "impact": "Remote command execution via unsanitized semgrep config URL"},
			{"id": "H6", "title": "Command Injection — run_trivy_scan.go Execute", "location": "internal/tool/run_trivy_scan.go:130", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → RunTrivyScanTool.Execute() → exec.CommandContext() → trivy", "severity": "HIGH", "reproduce": "late --repo-path /tmp/test;echo injected", "impact": "Remote command execution via unsanitized trivy repository path"},
			{"id": "H7", "title": "Command Injection — launch_docker.go Execute", "location": "internal/tool/launch_docker.go:60", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → LaunchDockerTool.Execute() → exec.CommandContext() → docker", "severity": "HIGH", "reproduce": "late --docker-args run --rm -v /tmp:/tmp ubuntu", "impact": "Remote command execution via unsanitized docker arguments"},
			{"id": "H8", "title": "Command Injection — setup_container.go Execute", "location": "internal/tool/setup_container.go:70", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → SetupContainerTool.Execute() → exec.CommandContext() → docker", "severity": "HIGH", "reproduce": "late --docker-args run --rm -v /tmp:/tmp ubuntu", "impact": "Remote command execution via unsanitized docker setup arguments"},
			{"id": "H9", "title": "Command Injection — run_git_command.go Execute", "location": "internal/tool/run_git_command.go:220", "cwe": 78, "auditor_verdict": "CONFIRMED", "taint_path": "AI agent → RunGitCommandTool.Execute() → exec.CommandContext() → git", "severity": "MEDIUM", "reproduce": "late --parts git log --all", "impact": "Remote command execution via unsanitized git arguments"},
		},
		"cve_findings": []map[string]interface{}{},
		"previously_disclosed": []map[string]interface{}{},
		"scan_coverage": map[string]interface{}{
			"languages":           "Go",
			"entry_points":        6,
			"functions_analyzed":  150,
		},
	})
	result, err = reportTool.Execute(ctx, reportArgs)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("Result:\n%s\n", result)
	}

	// Verify report was written
	content, err := os.ReadFile("/tmp/late-scan-check/sast_report_late.md")
	if err != nil {
		fmt.Printf("\nReport read error: %v\n", err)
	} else {
		fmt.Printf("\nReport file exists, size: %d bytes\n", len(content))
	}
}
