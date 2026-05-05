package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// mockRunner is a simple helper that returns canned responses keyed by a
// substring of the shell command argument.
type trivyMockRunner struct {
	responses map[string]string
	calls     []string
}

func (m *trivyMockRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	// Build a joined string of all args for matching.
	joined := name
	for _, a := range args {
		joined += " " + a
	}
	m.calls = append(m.calls, joined)
	for key, resp := range m.responses {
		if containsStr(joined, key) {
			return resp, nil
		}
	}
	return "", nil
}

func containsStr(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || len(s) > 0 && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

// minimalTrivyJSON builds a minimal Trivy JSON report with one vulnerability.
func minimalTrivyJSON(cveID, pkg, severity string, v3 float64) string {
	return fmt.Sprintf(`{
		"SchemaVersion": 2,
		"ArtifactName": "/app",
		"Results": [{
			"Target": "go.sum",
			"Vulnerabilities": [{
				"VulnerabilityID": %q,
				"PkgName": %q,
				"InstalledVersion": "1.0.0",
				"FixedVersion": "1.0.1",
				"Severity": %q,
				"Title": "Test vuln",
				"Description": "A test vulnerability.",
				"CVSS": {"nvd": {"V3Score": %f}},
				"References": ["https://nvd.nist.gov/vuln/detail/%s"]
			}]
		}]
	}`, cveID, pkg, severity, v3, cveID)
}

func TestRunTrivyScan_BasicParsing(t *testing.T) {
	report := minimalTrivyJSON("CVE-2023-1234", "example-pkg", "HIGH", 7.5)
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{
		"container_name": "test-container",
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
	if total, _ := result["total"].(float64); int(total) != 1 {
		t.Errorf("expected total=1, got %v", total)
	}
	findings, _ := result["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f, _ := findings[0].(map[string]any)
	if f["cve"] != "CVE-2023-1234" {
		t.Errorf("unexpected CVE ID: %v", f["cve"])
	}
	if f["severity"] != "HIGH" {
		t.Errorf("unexpected severity: %v", f["severity"])
	}
}

func TestRunTrivyScan_CVSSThreshold(t *testing.T) {
	// Build a report with two vulns: one CVSS 9.8, one CVSS 4.3.
	report := `{
		"SchemaVersion": 2,
		"Results": [{
			"Target": "go.sum",
			"Vulnerabilities": [
				{
					"VulnerabilityID": "CVE-2023-HIGH",
					"PkgName": "pkg-a",
					"InstalledVersion": "1.0",
					"Severity": "CRITICAL",
					"Title": "Critical vuln",
					"CVSS": {"nvd": {"V3Score": 9.8}}
				},
				{
					"VulnerabilityID": "CVE-2023-LOW",
					"PkgName": "pkg-b",
					"InstalledVersion": "1.0",
					"Severity": "MEDIUM",
					"Title": "Medium vuln",
					"CVSS": {"nvd": {"V3Score": 4.3}}
				}
			]
		}]
	}`
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{
		"container_name": "test-container",
		"cvss_threshold": 7.0,
	})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)

	if int(result["total"].(float64)) != 1 {
		t.Errorf("expected 1 finding above threshold, got %v", result["total"])
	}
	if int(result["skipped_low_cvss"].(float64)) != 1 {
		t.Errorf("expected 1 skipped finding, got %v", result["skipped_low_cvss"])
	}
	findings := result["findings"].([]any)
	f := findings[0].(map[string]any)
	if f["cve"] != "CVE-2023-HIGH" {
		t.Errorf("unexpected CVE: %v", f["cve"])
	}
}

func TestRunTrivyScan_CVEDeduplication(t *testing.T) {
	// Same CVE appears across two result targets.
	report := `{
		"SchemaVersion": 2,
		"Results": [
			{
				"Target": "go.sum",
				"Vulnerabilities": [{
					"VulnerabilityID": "CVE-2023-DUP",
					"PkgName": "pkg-dup",
					"InstalledVersion": "1.0",
					"Severity": "HIGH",
					"Title": "Dup vuln",
					"CVSS": {"nvd": {"V3Score": 8.1}}
				}]
			},
			{
				"Target": "vendor/modules.txt",
				"Vulnerabilities": [{
					"VulnerabilityID": "CVE-2023-DUP",
					"PkgName": "pkg-dup",
					"InstalledVersion": "1.0",
					"Severity": "HIGH",
					"Title": "Dup vuln",
					"CVSS": {"nvd": {"V3Score": 8.1}}
				}]
			}
		]
	}`
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if int(result["total"].(float64)) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %v", result["total"])
	}
}

func TestRunTrivyScan_EmptyResults(t *testing.T) {
	report := `{"SchemaVersion": 2, "Results": []}`
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "ok" {
		t.Errorf("expected ok, got %v", result["status"])
	}
	if int(result["total"].(float64)) != 0 {
		t.Errorf("expected 0 findings, got %v", result["total"])
	}
}

func TestRunTrivyScan_AutoInstallAndRetry(t *testing.T) {
	report := minimalTrivyJSON("CVE-2023-INSTALL", "newpkg", "CRITICAL", 9.0)
	callCount := 0
	// First "command -v trivy" returns "missing"; after install returns "ok".
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trivy") {
			callCount++
			if callCount == 1 {
				return "missing", nil
			}
			return "ok", nil
		}
		if containsStr(joined, "install.sh") {
			return "", nil
		}
		if containsStr(joined, "trivy fs") {
			return report, nil
		}
		return "", nil
	}
	tool := RunTrivyScanTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "ok" {
		t.Errorf("expected ok after install, got %v", result["status"])
	}
}

func TestRunTrivyScan_SortedByCVSS(t *testing.T) {
	report := `{
		"SchemaVersion": 2,
		"Results": [{
			"Target": "go.sum",
			"Vulnerabilities": [
				{"VulnerabilityID": "CVE-LOW", "PkgName": "p", "InstalledVersion": "1", "Severity": "MEDIUM", "CVSS": {"nvd": {"V3Score": 4.0}}},
				{"VulnerabilityID": "CVE-HIGH", "PkgName": "p2", "InstalledVersion": "1", "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Score": 9.8}}}
			]
		}]
	}`
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, _ := tool.Execute(context.Background(), args)
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	findings := result["findings"].([]any)
	first := findings[0].(map[string]any)
	if first["cve"] != "CVE-HIGH" {
		t.Errorf("expected highest CVSS first, got %v", first["cve"])
	}
}

func TestRunTrivyScan_TrivyUnavailableAndInstallFails(t *testing.T) {
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "missing",
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "skipped" {
		t.Errorf("expected skipped when trivy unavailable, got %v", result["status"])
	}
}

func TestRunTrivyScan_MissingContainerName(t *testing.T) {
	tool := RunTrivyScanTool{}
	args, _ := json.Marshal(map[string]any{})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for missing container_name")
	}
}

func TestRunTrivyScan_V2FallbackScore(t *testing.T) {
	// Only V2Score present (older advisory).
	report := `{
		"SchemaVersion": 2,
		"Results": [{
			"Target": "requirements.txt",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2021-V2",
				"PkgName": "legacy-pkg",
				"InstalledVersion": "0.9",
				"Severity": "HIGH",
				"Title": "Legacy vuln",
				"CVSS": {"nvd": {"V2Score": 7.5}}
			}]
		}]
	}`
	mock := &trivyMockRunner{
		responses: map[string]string{
			"command -v trivy": "ok",
			"trivy fs":         report,
		},
	}
	tool := RunTrivyScanTool{Runner: mock.run}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, _ := tool.Execute(context.Background(), args)
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	findings := result["findings"].([]any)
	f := findings[0].(map[string]any)
	if f["cvss"].(float64) != 7.5 {
		t.Errorf("expected V2 score 7.5 as fallback, got %v", f["cvss"])
	}
}
