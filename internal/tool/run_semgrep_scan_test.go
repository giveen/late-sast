package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// semgrepReportJSON builds a minimal semgrep JSON report.
func semgrepReportJSON(checkID, path string, line int, severity, message, cwe string) string {
	return fmt.Sprintf(`{
		"results": [{
			"check_id": %q,
			"path": %q,
			"start": {"line": %d, "col": 1},
			"extra": {
				"message": %q,
				"severity": %q,
				"metadata": {"cwe": %q, "owasp": "A01:2021"},
				"fix": ""
			}
		}],
		"errors": []
	}`, checkID, path, line, message, severity, cwe)
}

func TestRunSemgrepScan_BasicParsing(t *testing.T) {
	report := semgrepReportJSON(
		"go.lang.security.audit.xss.no-direct-write-to-responsewriter",
		"/app/handler.go",
		42,
		"ERROR",
		"Potential XSS: direct write to ResponseWriter without sanitization",
		"CWE-79",
	)
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "ok", nil
		}
		if containsStr(joined, "go.mod") {
			return "go", nil // simulate detectLanguage returning "go"
		}
		if containsStr(joined, "opengrep scan") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name": "test-container",
		"language":       "go",
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", result["status"])
	}
	if int(result["total"].(float64)) != 1 {
		t.Errorf("expected 1 finding, got %v", result["total"])
	}
	findings := result["findings"].([]any)
	f := findings[0].(map[string]any)
	if f["check_id"] != "go.lang.security.audit.xss.no-direct-write-to-responsewriter" {
		t.Errorf("unexpected check_id: %v", f["check_id"])
	}
	if f["severity"] != "ERROR" {
		t.Errorf("expected ERROR severity, got %v", f["severity"])
	}
	if f["cwe"] != "CWE-79" {
		t.Errorf("expected CWE-79, got %v", f["cwe"])
	}
	if int(f["line"].(float64)) != 42 {
		t.Errorf("expected line 42, got %v", f["line"])
	}
}

func TestRunSemgrepScan_SeverityFilter(t *testing.T) {
	// Report has ERROR + INFO — only ERROR should pass the filter.
	report := `{
		"results": [
			{
				"check_id": "rule.error",
				"path": "/app/main.go",
				"start": {"line": 10, "col": 1},
				"extra": {"message": "critical issue", "severity": "ERROR", "metadata": {}}
			},
			{
				"check_id": "rule.info",
				"path": "/app/main.go",
				"start": {"line": 20, "col": 1},
				"extra": {"message": "style note", "severity": "INFO", "metadata": {}}
			}
		],
		"errors": []
	}`
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "ok", nil
		}
		if containsStr(joined, "opengrep scan") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name":  "c",
		"language":        "go",
		"severity_filter": []string{"ERROR"},
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if int(result["total"].(float64)) != 1 {
		t.Errorf("expected 1 finding (ERROR only), got %v", result["total"])
	}
}

func TestRunSemgrepScan_MaxFindings(t *testing.T) {
	// Build a report with 5 ERROR findings.
	results := ""
	for i := 0; i < 5; i++ {
		if i > 0 {
			results += ","
		}
		results += fmt.Sprintf(`{
			"check_id": "rule.%d",
			"path": "/app/main.go",
			"start": {"line": %d, "col": 1},
			"extra": {"message": "issue %d", "severity": "ERROR", "metadata": {}}
		}`, i, i+1, i)
	}
	report := `{"results": [` + results + `], "errors": []}`

	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "ok", nil
		}
		if containsStr(joined, "opengrep scan") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name": "c",
		"language":       "go",
		"max_findings":   3,
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if int(result["total"].(float64)) != 3 {
		t.Errorf("expected 3 findings (max_findings=3), got %v", result["total"])
	}
}

func TestRunSemgrepScan_DefaultRulePacks(t *testing.T) {
	tests := []struct {
		lang          string
		expectedFirst string
	}{
		{"go", "p/golang"},
		{"rust", "p/rust"},
		{"python", "p/python"},
		{"javascript", "p/javascript"},
		{"typescript", "p/typescript"},
		{"java", "p/java"},
		{"unknown", "p/security-audit"},
	}
	for _, tt := range tests {
		packs := defaultRulePacks(tt.lang)
		if len(packs) == 0 || packs[0] != tt.expectedFirst {
			t.Errorf("lang=%q: expected first pack %q, got %v", tt.lang, tt.expectedFirst, packs)
		}
	}
}

func TestRunSemgrepScan_AutoInstallAndRetry(t *testing.T) {
	report := semgrepReportJSON("rule.x", "/app/file.go", 1, "ERROR", "test", "CWE-1")
	callCount := 0
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			callCount++
			if callCount == 1 {
				return "missing", nil
			}
			return "ok", nil
		}
		if containsStr(joined, "curl") || containsStr(joined, "wget") {
			return "", nil
		}
		if containsStr(joined, "opengrep scan") {
			return report, nil
		}
		return "", nil
	}
	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name": "c",
		"language":       "go",
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "ok" {
		t.Errorf("expected ok after binary download, got %v", result["status"])
	}
}

func TestRunSemgrepScan_SemgrepUnavailableAndInstallFails(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "missing", nil
		}
		return "", nil
	}
	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "skipped" {
		t.Errorf("expected skipped when opengrep unavailable, got %v", result["status"])
	}
}

func TestRunSemgrepScan_MissingContainerName(t *testing.T) {
	tool := RunSemgrepScanTool{}
	args, _ := json.Marshal(map[string]any{})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for missing container_name")
	}
}

func TestRunSemgrepScan_ExplicitRulePacks(t *testing.T) {
	// Verify that explicit rule_packs override auto-detection.
	report := `{"results": [], "errors": []}`
	var capturedCmd string
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "ok", nil
		}
		if containsStr(joined, "opengrep scan") {
			capturedCmd = joined
			return report, nil
		}
		return "", nil
	}
	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name": "c",
		"rule_packs":     []string{"p/trailofbits", "p/cwe-top-25"},
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "ok" {
		t.Errorf("expected ok, got %v", result["status"])
	}
	if !containsStr(capturedCmd, "p/trailofbits") {
		t.Errorf("expected p/trailofbits in command, got: %s", capturedCmd)
	}
	if !containsStr(capturedCmd, "p/cwe-top-25") {
		t.Errorf("expected p/cwe-top-25 in command, got: %s", capturedCmd)
	}
}

func TestRunSemgrepScan_CWEArrayMetadata(t *testing.T) {
	// Semgrep sometimes returns CWE as an array of strings.
	report := `{
		"results": [{
			"check_id": "rule.sqli",
			"path": "/app/db.go",
			"start": {"line": 55, "col": 3},
			"extra": {
				"message": "SQL injection risk",
				"severity": "ERROR",
				"metadata": {"cwe": ["CWE-89: Improper Neutralization"], "owasp": "A03:2021"}
			}
		}],
		"errors": []
	}`
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v opengrep") {
			return "ok", nil
		}
		if containsStr(joined, "opengrep scan") {
			return report, nil
		}
		return "", nil
	}
	tool := RunSemgrepScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c", "language": "go"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	findings := result["findings"].([]any)
	f := findings[0].(map[string]any)
	if f["cwe"] != "CWE-89: Improper Neutralization" {
		t.Errorf("expected CWE from array, got %v", f["cwe"])
	}
}
