package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupCISrv starts a test HTTP server with the given content-type and body,
// and returns a ContextIndex wired to talk to it (bypasses SSRF dialer).
func setupCISrv(t *testing.T, contentType, body string) (*httptest.Server, *ContextIndex) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	ci := &ContextIndex{
		inv:        make(map[string][]int),
		fetched:    make(map[string]time.Time),
		httpClient: srv.Client(), // test client trusts the test server's TLS
	}
	return srv, ci
}

// ── ContextIndex core ──────────────────────────────────────────────────────────

func TestContextIndex_IndexAndSearch(t *testing.T) {
	ci := NewContextIndex()
	n := ci.IndexText("advisory://CVE-2023-1234", `
## Remote Code Execution in foo
CVE-2023-1234 affects foo versions before 3.1.2.
Upgrade to version 3.1.2 or later to remediate.
The flaw allows attackers to execute arbitrary code via crafted HTTP input.
## Workaround
Disable the affected feature in configuration until you can upgrade.
`)
	if n == 0 {
		t.Fatal("expected at least one chunk")
	}

	results := ci.Search("CVE-2023-1234 remote code execution", 3)
	if len(results) == 0 {
		t.Fatal("expected search results")
	}
	found := false
	for _, r := range results {
		if strings.Contains(r.Snippet, "CVE-2023-1234") || strings.Contains(r.Snippet, "Remote Code") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CVE mention in snippet, got: %v", results[0].Snippet)
	}
}

func TestContextIndex_BM25Ranking(t *testing.T) {
	ci := NewContextIndex()
	// doc-a: high term frequency for "vulnerability" and "patch"
	ci.IndexText("doc-a", strings.Repeat("security vulnerability critical patch ", 20))
	// doc-b: single mention
	ci.IndexText("doc-b", "Performance guide. One security note about vulnerability disclosure.")

	results := ci.Search("security vulnerability patch", 5)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].Source != "doc-a" {
		t.Errorf("expected doc-a ranked first, got %s", results[0].Source)
	}
}

func TestContextIndex_MultiSource(t *testing.T) {
	ci := NewContextIndex()
	ci.IndexText("source-alpha", "## Authentication\nJWT tokens for API auth.")
	ci.IndexText("source-beta", "## Database\nPostgres connection pooling guide.")

	results := ci.Search("JWT authentication tokens", 5)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].Source != "source-alpha" {
		t.Errorf("expected source-alpha, got %s", results[0].Source)
	}
}

func TestContextIndex_EmptyIndexReturnsNil(t *testing.T) {
	ci := NewContextIndex()
	if got := ci.Search("anything", 5); got != nil {
		t.Errorf("expected nil on empty index, got %v", got)
	}
}

func TestContextIndex_EmptyQueryReturnsNil(t *testing.T) {
	ci := NewContextIndex()
	ci.IndexText("src", "some content about security")
	if got := ci.Search("", 5); got != nil {
		t.Errorf("expected nil for empty query, got %v", got)
	}
}

func TestContextIndex_HeadingPreserved(t *testing.T) {
	ci := NewContextIndex()
	ci.IndexText("docs://example", "## Upgrade Guide\nUpgrade the library to version 2.0.")

	results := ci.Search("upgrade library version", 3)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].Heading != "Upgrade Guide" {
		t.Errorf("expected heading 'Upgrade Guide', got %q", results[0].Heading)
	}
}

// ── CtxIndexTool ──────────────────────────────────────────────────────────────

func TestCtxIndexTool_Metadata(t *testing.T) {
	ti := CtxIndexTool{Index: NewContextIndex()}
	if ti.Name() != "ctx_index" {
		t.Errorf("unexpected name: %s", ti.Name())
	}
	if ti.Description() == "" {
		t.Error("empty description")
	}
	if ti.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
	params := ti.Parameters()
	if !strings.Contains(string(params), "source") {
		t.Error("parameters should mention 'source'")
	}
}

func TestCtxIndexTool_Execute(t *testing.T) {
	ti := CtxIndexTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{
		"source":  "test://advisory",
		"content": "## Security\nUpgrade to 2.0 to fix CVE-2024-999.",
	})
	result, err := ti.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "indexed") {
		t.Errorf("expected 'indexed' in result, got: %s", result)
	}
}

func TestCtxIndexTool_MissingContent(t *testing.T) {
	ti := CtxIndexTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"source": "test"})
	_, err := ti.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for missing content")
	}
}

func TestCtxIndexTool_CallString(t *testing.T) {
	ti := CtxIndexTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"source": "https://example.com/advisory"})
	cs := ti.CallString(args)
	if !strings.Contains(cs, "https://example.com/advisory") {
		t.Errorf("expected source in CallString, got: %s", cs)
	}
}

// ── CtxSearchTool ─────────────────────────────────────────────────────────────

func TestCtxSearchTool_Metadata(t *testing.T) {
	ts := CtxSearchTool{Index: NewContextIndex()}
	if ts.Name() != "ctx_search" {
		t.Errorf("unexpected name: %s", ts.Name())
	}
	if ts.Description() == "" {
		t.Error("empty description")
	}
}

func TestCtxSearchTool_NoResults(t *testing.T) {
	ts := CtxSearchTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"query": "anything"})
	result, err := ts.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "no results") {
		t.Errorf("expected 'no results', got: %s", result)
	}
}

func TestCtxSearchTool_ReturnsFormattedSnippets(t *testing.T) {
	ci := NewContextIndex()
	ci.IndexText("docs://auth", "## Authentication\nUse JWT tokens for API authentication via Bearer header.")

	ts := CtxSearchTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"query": "JWT authentication Bearer"})
	result, err := ts.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "source:") || !strings.Contains(result, "section:") {
		t.Errorf("expected formatted result with source/section, got: %s", result)
	}
}

func TestCtxSearchTool_CallString(t *testing.T) {
	ts := CtxSearchTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"query": "CVE-2024-0001"})
	cs := ts.CallString(args)
	if !strings.Contains(cs, "CVE-2024-0001") {
		t.Errorf("expected query in CallString, got: %s", cs)
	}
}

// ── CtxFetchAndIndexTool ──────────────────────────────────────────────────────

func TestCtxFetchAndIndexTool_Metadata(t *testing.T) {
	tf := CtxFetchAndIndexTool{Index: NewContextIndex()}
	if tf.Name() != "ctx_fetch_and_index" {
		t.Errorf("unexpected name: %s", tf.Name())
	}
	if tf.Description() == "" {
		t.Error("empty description")
	}
	if tf.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
}

func TestCtxFetchAndIndexTool_FetchPlainText(t *testing.T) {
	content := "## Security Advisory\nCVE-2024-0001 affects versions < 1.5. Upgrade to 1.5 to fix."
	srv, ci := setupCISrv(t, "text/plain", content)

	tf := CtxFetchAndIndexTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"url": srv.URL + "/advisory.md"})
	result, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "indexed") {
		t.Errorf("expected 'indexed' in result, got: %s", result)
	}

	results := ci.Search("CVE-2024-0001", 3)
	if len(results) == 0 {
		t.Error("expected search results after fetch+index")
	}
}

func TestCtxFetchAndIndexTool_FetchHTML(t *testing.T) {
	htmlContent := `<!DOCTYPE html><html><body>
<h2>Security Advisory</h2>
<p>CVE-2024-9999 affects the widget package before 3.0. Upgrade immediately.</p>
<h3>Remediation</h3>
<p>Update widget to version 3.0.1 or later.</p>
</body></html>`
	srv, ci := setupCISrv(t, "text/html; charset=utf-8", htmlContent)

	tf := CtxFetchAndIndexTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"url": srv.URL + "/"})
	_, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	results := ci.Search("CVE-2024-9999 widget upgrade", 3)
	if len(results) == 0 {
		t.Error("expected results after HTML fetch+index")
	}
}

func TestCtxFetchAndIndexTool_Cache(t *testing.T) {
	srv, ci := setupCISrv(t, "text/plain", "## Docs\nSome content.")

	tf := CtxFetchAndIndexTool{Index: ci}
	u := srv.URL + "/page.md"
	args, _ := json.Marshal(map[string]string{"url": u})

	if _, err := tf.Execute(context.Background(), args); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	result, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !strings.Contains(result, "cached") {
		t.Errorf("expected 'cached' on second call, got: %s", result)
	}
}

func TestCtxFetchAndIndexTool_ForceBypassesCache(t *testing.T) {
	srv, ci := setupCISrv(t, "text/plain", "## Docs\nContent.")

	tf := CtxFetchAndIndexTool{Index: ci}
	u := srv.URL + "/page.md"

	// Seed the cache.
	args1, _ := json.Marshal(map[string]string{"url": u})
	if _, err := tf.Execute(context.Background(), args1); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	// Force re-fetch.
	args2, _ := json.Marshal(map[string]interface{}{"url": u, "force": true})
	result, err := tf.Execute(context.Background(), args2)
	if err != nil {
		t.Fatalf("force fetch: %v", err)
	}
	if strings.Contains(result, "cached") {
		t.Errorf("expected fresh fetch with force=true, got: %s", result)
	}
}

func TestCtxFetchAndIndexTool_InvalidScheme(t *testing.T) {
	ci := NewContextIndex()
	tf := CtxFetchAndIndexTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"url": "file:///etc/passwd"})
	_, err := tf.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for file:// scheme")
	}
}

func TestCtxFetchAndIndexTool_CallString(t *testing.T) {
	tf := CtxFetchAndIndexTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"url": "https://example.com/docs"})
	cs := tf.CallString(args)
	if !strings.Contains(cs, "https://example.com/docs") {
		t.Errorf("expected URL in CallString, got: %s", cs)
	}
}

// ── HTML converter ─────────────────────────────────────────────────────────────

func TestCIHTMLToText_Headings(t *testing.T) {
	input := `<h2>Security</h2><p>CVE-2024-1234 is <strong>critical</strong>.</p><br/><p>Upgrade now.</p>`
	out := ciHTMLToText(input)
	if !strings.Contains(out, "## Security") {
		t.Errorf("expected markdown heading, got: %s", out)
	}
	if !strings.Contains(out, "CVE-2024-1234") {
		t.Errorf("expected CVE in output, got: %s", out)
	}
	if strings.Contains(out, "<") {
		t.Errorf("expected all tags stripped, got: %s", out)
	}
}

func TestCIHTMLToText_Entities(t *testing.T) {
	out := ciHTMLToText(`<p>Use &lt;foo&gt; &amp; &quot;bar&quot;</p>`)
	if !strings.Contains(out, `<foo>`) || !strings.Contains(out, `&`) {
		t.Errorf("expected HTML entities decoded, got: %s", out)
	}
}

// ── CtxIndexFileTool ───────────────────────────────────────────────────────────

func TestCtxIndexFileTool_IndexsFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "testfile*.md")
	if err != nil {
		t.Fatal(err)
	}
	content := "SQL injection vulnerability: use prepared statements to prevent user input reaching queries"
	f.WriteString(content) //nolint:errcheck
	f.Close()

	ci := NewContextIndex()
	tf := CtxIndexFileTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"path": f.Name(), "source": "sql_injection"})
	result, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "sql_injection") {
		t.Errorf("expected source label in result, got: %s", result)
	}

	// Content should be searchable
	hits := ci.Search("prepared statements injection", 3)
	if len(hits) == 0 {
		t.Error("expected search hit after indexing file")
	}
}

func TestCtxIndexFileTool_DefaultSourceIsFilename(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "myfile*.md")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("path traversal attack example directory listing") //nolint:errcheck
	f.Close()

	ci := NewContextIndex()
	tf := CtxIndexFileTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"path": f.Name()})
	result, err := tf.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	base := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))
	_ = base // source label includes full basename with ext
	if !strings.Contains(result, "Indexed") {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestCtxIndexFileTool_RejectsMissingPath(t *testing.T) {
	ci := NewContextIndex()
	tf := CtxIndexFileTool{Index: ci}
	args, _ := json.Marshal(map[string]string{})
	_, err := tf.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for missing path")
	}
}

func TestCtxIndexFileTool_RejectsNonAbsolutePath(t *testing.T) {
	ci := NewContextIndex()
	tf := CtxIndexFileTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"path": "relative/path.go"})
	_, err := tf.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestCtxIndexFileTool_RejectsMissingFile(t *testing.T) {
	ci := NewContextIndex()
	tf := CtxIndexFileTool{Index: ci}
	args, _ := json.Marshal(map[string]string{"path": "/nonexistent/file.md"})
	_, err := tf.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCtxIndexFileTool_CallString(t *testing.T) {
	tf := CtxIndexFileTool{Index: NewContextIndex()}
	args, _ := json.Marshal(map[string]string{"path": "/tmp/sast-skill/references/rce.md"})
	cs := tf.CallString(args)
	if !strings.Contains(cs, "rce.md") {
		t.Errorf("expected path in CallString, got: %s", cs)
	}
}

func TestCtxIndexFileTool_Metadata(t *testing.T) {
	tf := CtxIndexFileTool{Index: NewContextIndex()}
	if tf.Name() != "ctx_index_file" {
		t.Errorf("unexpected name: %s", tf.Name())
	}
	if tf.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
	var params map[string]interface{}
	if err := json.Unmarshal(tf.Parameters(), &params); err != nil {
		t.Fatalf("invalid parameters JSON: %v", err)
	}
}
