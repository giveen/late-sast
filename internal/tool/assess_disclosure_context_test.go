package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAssessDisclosureContextTool_PolicyAndAdvisoryCorrelation(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "SECURITY.md"), []byte(`# Security Policy
Out of scope: SQL injection in legacy admin import endpoints.
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/security-advisories":
			page := r.URL.Query().Get("page")
			if page == "1" {
				_, _ = w.Write([]byte(`[
					{
						"ghsa_id": "GHSA-1111-2222-3333",
						"cve_id": "CVE-2024-1111",
						"summary": "SQL injection in admin import parser",
						"severity": "high",
						"published_at": "2024-03-01T00:00:00Z",
						"html_url": "https://github.com/advisories/GHSA-1111-2222-3333",
						"vulnerabilities": [{"package": {"name": "admin/import"}}]
					}
				]`))
				return
			}
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tool := AssessDisclosureContextTool{
		HTTPClient:       srv.Client(),
		GitHubAPIBaseURL: srv.URL,
		UserAgent:        "late-test",
	}
	args := json.RawMessage(`{
		"repo_path": "` + repoDir + `",
		"github_url": "https://github.com/owner/repo",
		"findings": [
			{
				"id": "H1",
				"title": "SQL Injection - Admin Import",
				"location": "internal/admin/import/handler.go:42",
				"cve": "CVE-2024-1111"
			}
		]
	}`)

	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("response not json: %v", err)
	}

	policy, _ := resp["policy"].(map[string]any)
	if policy["status"] != "found" {
		t.Fatalf("expected policy status found, got: %v", policy["status"])
	}
	if policy["match_count"] != float64(1) {
		t.Fatalf("expected one policy match, got: %v", policy["match_count"])
	}

	advisories, _ := resp["advisories"].(map[string]any)
	if advisories["checked"] != true {
		t.Fatalf("expected advisories checked=true, got: %v", advisories["checked"])
	}
	if advisories["count"] != float64(1) {
		t.Fatalf("expected advisories count 1, got: %v", advisories["count"])
	}
	if advisories["match_count"] != float64(1) {
		t.Fatalf("expected advisory match_count 1, got: %v", advisories["match_count"])
	}
}

func TestAssessDisclosureContextTool_LocalOnlyWhenNoGitHubURL(t *testing.T) {
	repoDir := t.TempDir()
	tool := AssessDisclosureContextTool{}
	out, err := tool.Execute(context.Background(), json.RawMessage(`{
		"repo_path": "`+repoDir+`",
		"findings": [{"id":"H1","title":"XSS","location":"web/ui.js:9"}]
	}`))
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("response not json: %v", err)
	}
	advisories, _ := resp["advisories"].(map[string]any)
	if advisories["checked"] != false {
		t.Fatalf("expected advisories checked=false, got: %v", advisories["checked"])
	}
}

func TestAssessDisclosureContextTool_InvalidGitHubURL(t *testing.T) {
	tool := AssessDisclosureContextTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{
		"repo_path": "/tmp/repo",
		"github_url": "https://example.com/not-gh/repo",
		"findings": []
	}`))
	if err != nil {
		t.Fatalf("invalid GitHub URL should not fail whole tool, got: %v", err)
	}
}
