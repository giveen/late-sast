package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Test registry ──────────────────────────────────────────────────────────────

func testRegistry(srv *httptest.Server) []pcEntry {
	readmeURL := srv.URL + "/readme"
	return []pcEntry{
		{
			ID:          "express",
			Name:        "Express",
			Description: "Fast web framework for Node.js",
			LLMSTxtURL:  srv.URL + "/llms.txt",
			Aliases:     []string{"expressjs"},
			Packages: []pcPackage{
				{
					Ecosystem:    "npm",
					Languages:    []string{"javascript", "typescript"},
					PackageNames: []string{"express"},
					ReadmeURL:    &readmeURL,
				},
			},
		},
		{
			ID:          "django",
			Name:        "Django",
			Description: "Python web framework",
			LLMSTxtURL:  srv.URL + "/django-llms.txt",
			Packages:    []pcPackage{},
		},
		{
			ID:          "fastapi",
			Name:        "FastAPI",
			Description: "Modern Python web framework",
			LLMSTxtURL:  srv.URL + "/fastapi-llms.txt",
			Packages: []pcPackage{
				{
					Ecosystem:    "pypi",
					Languages:    []string{"python"},
					PackageNames: []string{"fastapi"},
				},
			},
		},
	}
}

func setupDocsSrv(t *testing.T, docContent string) (*httptest.Server, *ProContextClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(docContent)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	client := newTestProContextClient(testRegistry(srv))
	// Swap httpClient to use the test server's transport
	client.httpClient = srv.Client()
	return srv, client
}

// ── DocsResolveTool ─────────────────────────────────────────────────────────────

func TestDocsResolveTool_Metadata(t *testing.T) {
	srv, c := setupDocsSrv(t, "")
	_ = srv
	tool := DocsResolveTool{Client: c}

	if tool.Name() != "docs_resolve" {
		t.Errorf("unexpected name: %q", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description should not be empty")
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
	var p map[string]any
	if err := json.Unmarshal(tool.Parameters(), &p); err != nil {
		t.Fatalf("Parameters() is not valid JSON: %v", err)
	}
}

func TestDocsResolveTool_ExactPackageName(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"express"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result.Matches))
	}
	m := result.Matches[0]
	if m.LibraryID != "express" {
		t.Errorf("expected library_id=express, got %q", m.LibraryID)
	}
	if m.MatchedVia != "package_name" {
		t.Errorf("expected matched_via=package_name, got %q", m.MatchedVia)
	}
	if m.Relevance != 1.0 {
		t.Errorf("expected relevance=1.0, got %f", m.Relevance)
	}
	if !strings.Contains(m.IndexURL, "/llms.txt") {
		t.Errorf("IndexURL should point to llms.txt, got %q", m.IndexURL)
	}
}

func TestDocsResolveTool_ExactLibraryID(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"django"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) != 1 || result.Matches[0].LibraryID != "django" {
		t.Errorf("expected django match, got %v", result.Matches)
	}
	if result.Matches[0].MatchedVia != "library_id" {
		t.Errorf("expected matched_via=library_id, got %q", result.Matches[0].MatchedVia)
	}
}

func TestDocsResolveTool_ExactAlias(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"expressjs"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) != 1 || result.Matches[0].MatchedVia != "alias" {
		t.Errorf("expected alias match for 'expressjs', got %v", result.Matches)
	}
}

func TestDocsResolveTool_CaseInsensitive(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	// express package is "express" lowercase; querying "Express" (capitalised) should still match
	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"Express"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) == 0 {
		t.Error("should match Express case-insensitively")
	}
}

func TestDocsResolveTool_Fuzzy(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	// "fasapi" is a typo for "fastapi" — similarity ~= 6/7 = 0.857
	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"fasapi"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) == 0 {
		t.Error("expected fuzzy match for 'fasapi' → fastapi")
	}
	if result.Matches[0].MatchedVia != "fuzzy" {
		t.Errorf("expected matched_via=fuzzy, got %q", result.Matches[0].MatchedVia)
	}
	if result.Matches[0].Relevance < pcFuzzyThreshold {
		t.Errorf("expected relevance >= %f, got %f", pcFuzzyThreshold, result.Matches[0].Relevance)
	}
}

func TestDocsResolveTool_NoMatch(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"query":"xyzzy-nonexistent-lib"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) != 0 {
		t.Errorf("expected empty matches for unknown library, got %v", result.Matches)
	}
}

func TestDocsResolveTool_EmptyQuery(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsResolveTool{Client: c}

	_, err := tool.Execute(context.Background(), json.RawMessage(`{"query":""}`))
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestDocsResolveTool_LanguageSort(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	// Add a library with multiple ecosystems to test language sorting
	extras := append(c.entries, pcEntry{
		ID:         "openai",
		Name:       "OpenAI",
		LLMSTxtURL: c.entries[0].LLMSTxtURL, // reuse allowed domain
		Packages: []pcPackage{
			{Ecosystem: "npm", Languages: []string{"javascript"}, PackageNames: []string{"openai"}},
			{Ecosystem: "pypi", Languages: []string{"python"}, PackageNames: []string{"openai"}},
		},
	})
	c.setEntries(extras)

	tool := DocsResolveTool{Client: c}
	out, _ := tool.Execute(context.Background(), json.RawMessage(`{"query":"openai","language":"python"}`))
	var result struct {
		Matches []pcResolveMatch `json:"matches"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	pkgs := result.Matches[0].Packages
	if len(pkgs) < 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Ecosystem != "pypi" {
		t.Errorf("python language hint should sort pypi first, got %q", pkgs[0].Ecosystem)
	}
}

func TestDocsResolveTool_CallString(t *testing.T) {
	tool := DocsResolveTool{}
	s := tool.CallString(json.RawMessage(`{"query":"express"}`))
	if !strings.Contains(s, "express") {
		t.Errorf("CallString should include query, got %q", s)
	}
}

// ── DocsReadTool ─────────────────────────────────────────────────────────────────

func TestDocsReadTool_Metadata(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsReadTool{Client: c}

	if tool.Name() != "docs_read" {
		t.Errorf("unexpected name: %q", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description should not be empty")
	}
	var p map[string]any
	if err := json.Unmarshal(tool.Parameters(), &p); err != nil {
		t.Fatalf("Parameters() is not valid JSON: %v", err)
	}
}

func TestDocsReadTool_BasicRead(t *testing.T) {
	content := "line one\nline two\nline three\n"
	srv, c := setupDocsSrv(t, content)
	tool := DocsReadTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Content    string `json:"content"`
		TotalLines int    `json:"total_lines"`
		HasMore    bool   `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !strings.Contains(result.Content, "1:line one") {
		t.Errorf("content should include line numbers, got:\n%s", result.Content)
	}
	if result.HasMore {
		t.Error("has_more should be false for short page with default limit")
	}
}

func TestDocsReadTool_Pagination(t *testing.T) {
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, "line "+string(rune('0'+i)))
	}
	content := strings.Join(lines, "\n")
	srv, c := setupDocsSrv(t, content)
	tool := DocsReadTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "offset": 1, "limit": 5})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		HasMore    bool `json:"has_more"`
		NextOffset int  `json:"next_offset"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if !result.HasMore {
		t.Error("has_more should be true when there are more lines")
	}
	if result.NextOffset <= 5 {
		t.Errorf("next_offset should be > 5, got %d", result.NextOffset)
	}
}

func TestDocsReadTool_SSRFRejected(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsReadTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": "https://internal.example.com/secret"})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected SSRF rejection for non-registry domain")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("error should mention allowlist, got: %v", err)
	}
}

func TestDocsReadTool_PageCached(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write([]byte("cached content")) //nolint:errcheck
	}))
	defer srv.Close()
	c := newTestProContextClient(testRegistry(srv))
	c.httpClient = srv.Client()
	tool := DocsReadTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt"})
	tool.Execute(context.Background(), args) //nolint:errcheck
	tool.Execute(context.Background(), args) //nolint:errcheck

	if fetchCount != 1 {
		t.Errorf("expected 1 HTTP fetch (cached on second call), got %d", fetchCount)
	}
}

func TestDocsReadTool_CallString(t *testing.T) {
	tool := DocsReadTool{}
	s := tool.CallString(json.RawMessage(`{"url":"https://docs.example.com/page"}`))
	if !strings.Contains(s, "docs_read") {
		t.Errorf("CallString should start with docs_read, got %q", s)
	}
}

// ── DocsSearchTool ────────────────────────────────────────────────────────────────

func TestDocsSearchTool_Metadata(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsSearchTool{Client: c}

	if tool.Name() != "docs_search" {
		t.Errorf("unexpected name: %q", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description should not be empty")
	}
	var p map[string]any
	if err := json.Unmarshal(tool.Parameters(), &p); err != nil {
		t.Fatalf("Parameters() is not valid JSON: %v", err)
	}
}

func TestDocsSearchTool_BasicMatch(t *testing.T) {
	content := "## Security\nSee CVE-2021-44228 for details.\n## Installation\nRun npm install."
	srv, c := setupDocsSrv(t, content)
	tool := DocsSearchTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": "cve"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		Matches string `json:"matches"`
		HasMore bool   `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !strings.Contains(result.Matches, "CVE-2021-44228") {
		t.Errorf("matches should contain CVE line, got %q", result.Matches)
	}
}

func TestDocsSearchTool_SmartCaseLower(t *testing.T) {
	content := "Security Advisory\nsECURITY fix\nSECURITY patch"
	srv, c := setupDocsSrv(t, content)
	tool := DocsSearchTool{Client: c}

	// All-lowercase query → case-insensitive
	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": "security"})
	out, _ := tool.Execute(context.Background(), args)
	var result struct{ Matches string `json:"matches"` }
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if strings.Count(result.Matches, "\n") < 2 {
		t.Errorf("lowercase query should match all 3 case variants, got:\n%s", result.Matches)
	}
}

func TestDocsSearchTool_SmartCaseMixed(t *testing.T) {
	content := "Security Advisory\nsECURITY fix\nSECURITY patch"
	srv, c := setupDocsSrv(t, content)
	tool := DocsSearchTool{Client: c}

	// Mixed-case query → case-sensitive
	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": "Security"})
	out, _ := tool.Execute(context.Background(), args)
	var result struct{ Matches string `json:"matches"` }
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	lines := strings.Split(strings.TrimSpace(result.Matches), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "Security Advisory") {
		t.Errorf("mixed-case query should match only 'Security Advisory', got:\n%s", result.Matches)
	}
}

func TestDocsSearchTool_NoMatch(t *testing.T) {
	content := "## Installation\nRun npm install."
	srv, c := setupDocsSrv(t, content)
	tool := DocsSearchTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": "xyzzy_no_match"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct{ Matches string `json:"matches"` }
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	if result.Matches != "" {
		t.Errorf("expected empty matches for no-match query, got %q", result.Matches)
	}
}

func TestDocsSearchTool_MaxResults(t *testing.T) {
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, "keyword occurrence")
	}
	content := strings.Join(lines, "\n")
	srv, c := setupDocsSrv(t, content)
	tool := DocsSearchTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": "keyword", "max_results": 5})
	out, _ := tool.Execute(context.Background(), args)
	var result struct {
		Matches string `json:"matches"`
		HasMore bool   `json:"has_more"`
	}
	json.Unmarshal([]byte(out), &result) //nolint:errcheck
	got := strings.Count(result.Matches, "\n")
	if got > 5 {
		t.Errorf("max_results=5 should cap at 5 lines, got %d", got)
	}
	if !result.HasMore {
		t.Error("has_more should be true when results were capped")
	}
}

func TestDocsSearchTool_SSRFRejected(t *testing.T) {
	_, c := setupDocsSrv(t, "")
	tool := DocsSearchTool{Client: c}

	args, _ := json.Marshal(map[string]any{"url": "https://evil.com/docs", "query": "secret"})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected SSRF rejection")
	}
}

func TestDocsSearchTool_EmptyQuery(t *testing.T) {
	srv, c := setupDocsSrv(t, "content")
	tool := DocsSearchTool{Client: c}
	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/llms.txt", "query": ""})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestDocsSearchTool_CallString(t *testing.T) {
	tool := DocsSearchTool{}
	s := tool.CallString(json.RawMessage(`{"url":"https://docs.example.com","query":"CVE"}`))
	if !strings.Contains(s, "docs_search") {
		t.Errorf("CallString should start with docs_search, got %q", s)
	}
	if !strings.Contains(s, "CVE") {
		t.Errorf("CallString should include query, got %q", s)
	}
}

// ── Levenshtein ───────────────────────────────────────────────────────────────

func TestLevenshteinSimilarity(t *testing.T) {
	tests := []struct {
		a, b    string
		wantMin float64
		wantMax float64
	}{
		{"fastapi", "fastapi", 1.0, 1.0},
		{"fasapi", "fastapi", 0.70, 1.0},  // one missing char
		{"express", "expres", 0.85, 1.0},  // one missing char
		{"abc", "xyz", 0.0, 0.34},          // completely different
		{"", "", 1.0, 1.0},
	}
	for _, tt := range tests {
		got := pcLevenshteinSimilarity(tt.a, tt.b)
		if got < tt.wantMin || got > tt.wantMax {
			t.Errorf("similarity(%q, %q) = %f, want [%f, %f]", tt.a, tt.b, got, tt.wantMin, tt.wantMax)
		}
	}
}
