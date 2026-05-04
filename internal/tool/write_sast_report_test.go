package tool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testWriteReport(t *testing.T, args any) (string, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return WriteSASTReportTool{}.Execute(t.Context(), json.RawMessage(raw))
}

func baseFinding(severity, exploit, verdict string) ReportFinding {
	return ReportFinding{
		ID:             "H1",
		Title:          "SSRF — RemoteController",
		Location:       "Api.cs:100 — GetImage",
		CWE:            918,
		AuditorVerdict: verdict,
		Severity:       severity,
		ExploitStatus:  exploit,
		Impact:         "Attacker can reach internal services",
		Fix:            "Validate and restrict outbound URLs to an allowlist",
	}
}

// TestWriteSASTReport_BasicOutput validates that the report is written to disk
// and returns a structured JSON result.
func TestWriteSASTReport_BasicOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	result, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"app_version": "1.0.0",
		"findings": []ReportFinding{
			baseFinding("HIGH", "EXPLOITED", "CONFIRMED"),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		t.Fatalf("result is not JSON: %v\nresult: %s", err, result)
	}
	if out["status"] != "ok" {
		t.Errorf("expected status ok, got %v", out["status"])
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	md := string(content)
	if !strings.Contains(md, "# SAST Security Report — app") {
		t.Error("missing report heading")
	}
	if !strings.Contains(md, "## High Findings") {
		t.Error("expected High Findings section")
	}
}

// TestWriteSASTReport_EmptySectionsOmitted verifies that severity sections with
// no findings are never emitted, even if other sections are non-empty.
func TestWriteSASTReport_EmptySectionsOmitted(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings": []ReportFinding{
			baseFinding("MEDIUM", "UNREACHABLE", "LIKELY"),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)

	for _, empty := range []string{"## Critical Findings", "## High Findings", "## Low Findings"} {
		if strings.Contains(md, empty) {
			t.Errorf("empty section %q should not appear in report", empty)
		}
	}
	if !strings.Contains(md, "## Medium Findings") {
		t.Error("expected Medium Findings section")
	}
}

// TestWriteSASTReport_NeedsContextDeduplication checks that NEEDS_CONTEXT findings
// appear only in "Unverifiable Findings" and not also in severity sections.
func TestWriteSASTReport_NeedsContextDeduplication(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	needsCtx := baseFinding("HIGH", "INCONCLUSIVE", "NEEDS_CONTEXT")
	needsCtx.Notes = "Requires access to auth headers"

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings":    []ReportFinding{needsCtx},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)

	if strings.Contains(md, "## High Findings") {
		t.Error("NEEDS_CONTEXT finding should not appear in severity section")
	}
	if !strings.Contains(md, "## Unverifiable Findings (NEEDS CONTEXT)") {
		t.Error("expected Unverifiable Findings section")
	}
}

// TestWriteSASTReport_ExploitStatusNormalization checks that lowercase replay
// verdicts from run_exploit_replay are normalized to uppercase in the report.
func TestWriteSASTReport_ExploitStatusNormalization(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	f := baseFinding("HIGH", "unreachable", "CONFIRMED") // lowercase input
	f.ReplayVerdict = "unreachable"                      // as returned by run_exploit_replay

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings":    []ReportFinding{f},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)

	if strings.Contains(md, "unreachable") && !strings.Contains(md, "UNREACHABLE") {
		t.Error("exploit status should be normalized to uppercase UNREACHABLE")
	}
}

// TestWriteSASTReport_SeverityNormalization checks that lowercase severity is
// accepted and normalized to uppercase in the output.
func TestWriteSASTReport_SeverityNormalization(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	f := baseFinding("high", "EXPLOITED", "CONFIRMED")

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings":    []ReportFinding{f},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)
	if !strings.Contains(md, "HIGH") {
		t.Error("severity should be normalized to uppercase HIGH")
	}
}

// TestWriteSASTReport_MissingRequiredField checks that a missing required field
// returns an error.
func TestWriteSASTReport_MissingRequiredField(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	f := baseFinding("HIGH", "EXPLOITED", "CONFIRMED")
	f.Fix = "" // remove required field

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings":    []ReportFinding{f},
	})
	if err == nil {
		t.Fatal("expected validation error for missing fix field")
	}
	if !strings.Contains(err.Error(), "fix") {
		t.Errorf("expected error to mention 'fix', got: %v", err)
	}
}

// TestWriteSASTReport_CVEDeduplication verifies that duplicate CVEs (same ID)
// appear only once in the CVE table.
func TestWriteSASTReport_CVEDeduplication(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	cve := ReportCVE{CVE: "CVE-2024-1234", Package: "lib@1.0", CVSS: 8.0, Severity: "HIGH", Description: "RCE via deserialization", Link: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}

	_, err := testWriteReport(t, map[string]any{
		"output_path":  outPath,
		"target":       "https://github.com/example/app",
		"repo_name":    "app",
		"findings":     []ReportFinding{baseFinding("HIGH", "EXPLOITED", "CONFIRMED")},
		"cve_findings": []ReportCVE{cve, cve}, // duplicate
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)
	// Count table rows containing this CVE (lines starting with "| CVE-2024-1234").
	tableRows := 0
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| CVE-2024-1234") {
			tableRows++
		}
	}
	if tableRows != 1 {
		t.Errorf("CVE-2024-1234 appears in %d table rows; expected exactly 1 (duplicate input should be deduped)", tableRows)
	}
}

// TestWriteSASTReport_RemediationPriorityOrdering validates that auto-generated
// remediation is ordered CRITICAL → HIGH → MEDIUM → LOW.
func TestWriteSASTReport_RemediationPriorityOrdering(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings": []ReportFinding{
			{ID: "H3", Title: "XSS", Location: "view.js:5", CWE: 79, AuditorVerdict: "CONFIRMED", Severity: "LOW", ExploitStatus: "EXPLOITED", Impact: "...", Fix: "Escape output"},
			{ID: "H1", Title: "SSRF", Location: "api.cs:10", CWE: 918, AuditorVerdict: "CONFIRMED", Severity: "CRITICAL", ExploitStatus: "EXPLOITED", Impact: "...", Fix: "Validate URLs"},
			{ID: "H2", Title: "SQLi", Location: "db.py:20", CWE: 89, AuditorVerdict: "CONFIRMED", Severity: "HIGH", ExploitStatus: "BLOCKED", Impact: "...", Fix: "Use parameterized queries"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)

	remedSection := md[strings.Index(md, "## Remediation Priority"):]
	criticalPos := strings.Index(remedSection, "CRITICAL")
	highPos := strings.Index(remedSection, "HIGH")
	lowPos := strings.Index(remedSection, "LOW")

	if criticalPos == -1 || highPos == -1 || lowPos == -1 {
		t.Error("expected all severity levels to appear in Remediation Priority")
	}
	if criticalPos > highPos {
		t.Error("CRITICAL should appear before HIGH in Remediation Priority")
	}
	if highPos > lowPos {
		t.Error("HIGH should appear before LOW in Remediation Priority")
	}
}

// TestWriteSASTReport_FindingDeduplication verifies that two findings at the same
// location+CWE are collapsed to one (keeping the higher severity).
func TestWriteSASTReport_FindingDeduplication(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	f1 := baseFinding("MEDIUM", "UNREACHABLE", "LIKELY")
	f2 := baseFinding("HIGH", "EXPLOITED", "CONFIRMED") // same location+CWE, higher severity

	_, err := testWriteReport(t, map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings":    []ReportFinding{f1, f2},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(outPath)
	md := string(content)

	// Should have High section (kept) but not Medium (deduped away).
	if !strings.Contains(md, "## High Findings") {
		t.Error("expected High Findings section after deduplication")
	}
	if strings.Contains(md, "## Medium Findings") {
		t.Error("Medium finding should have been deduped (same location+CWE, lower severity)")
	}
}

// TestWriteSASTReport_MissingOutputPath validates required parameter check.
func TestWriteSASTReport_MissingOutputPath(t *testing.T) {
	_, err := testWriteReport(t, map[string]any{
		"target":    "https://github.com/example/app",
		"repo_name": "app",
		"findings":  []ReportFinding{},
	})
	if err == nil {
		t.Fatal("expected error for missing output_path")
	}
}
