package executor

import (
	"testing"
	"time"
)

func TestToolResultCacheInvalidateAll(t *testing.T) {
	cache := NewToolResultCache()
	cache.Set("read_file", `{"path":"a.go"}`, "contents")

	if _, ok := cache.Get("read_file", `{"path":"a.go"}`); !ok {
		t.Fatal("expected cache entry to exist before invalidation")
	}

	cache.InvalidateAll()

	if _, ok := cache.Get("read_file", `{"path":"a.go"}`); ok {
		t.Fatal("expected cache entry to be removed after invalidation")
	}
}

func TestMutatesWorkspace(t *testing.T) {
	for _, toolName := range []string{"write_file", "compose_patch", "implementations", "bash"} {
		if !mutatesWorkspace(toolName) {
			t.Fatalf("expected %q to be treated as workspace-mutating", toolName)
		}
	}
	if mutatesWorkspace("read_file") {
		t.Fatal("did not expect read_file to be treated as workspace-mutating")
	}
}

func TestToolTimeoutFor_RunSecretsScanner(t *testing.T) {
	if got := toolTimeoutFor("run_secrets_scanner"); got != 10*time.Minute {
		t.Fatalf("expected run_secrets_scanner timeout 10m, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// cacheTTLFor — full branch coverage
// ---------------------------------------------------------------------------

func TestCacheTTLFor_ScanTools(t *testing.T) {
	for _, name := range []string{"run_opengrep_scan", "run_semgrep_scan", "run_trivy_scan", "run_secrets_scanner"} {
		if ttl := cacheTTLFor(name); ttl <= 0 {
			t.Errorf("cacheTTLFor(%q) = %v, want > 0", name, ttl)
		}
	}
}

func TestCacheTTLFor_DocsAndCVETools(t *testing.T) {
	tools := []string{
		"docs_lookup", "docs_read", "docs_search", "docs_resolve",
		"cve_search", "vul_cve_search", "vul_vendor_product_cve", "vul_vendor_products", "vul_last_cves",
		"get_architecture",
	}
	for _, name := range tools {
		if ttl := cacheTTLFor(name); ttl <= 0 {
			t.Errorf("cacheTTLFor(%q) = %v, want > 0", name, ttl)
		}
	}
}

func TestCacheTTLFor_CodebaseMemoryTools(t *testing.T) {
	tools := []string{
		"ctx_search", "search_code", "search_graph",
		"get_code_snippet", "trace_path",
		"list_files", "read_file", "search_codebase", "context_index",
		"index_status", "list_projects", "index_repository",
	}
	for _, name := range tools {
		if ttl := cacheTTLFor(name); ttl <= 0 {
			t.Errorf("cacheTTLFor(%q) = %v, want > 0", name, ttl)
		}
	}
}

func TestCacheTTLFor_WriteToolsZero(t *testing.T) {
	for _, name := range []string{
		"spawn_subagent", "bash", "write_file", "write_sast_report",
		"compose_patch", "implementations",
		"ctx_fetch_and_index", "ctx_index_file", "ctx_index",
	} {
		if ttl := cacheTTLFor(name); ttl != 0 {
			t.Errorf("cacheTTLFor(%q) = %v, want 0 (never cache)", name, ttl)
		}
	}
}

func TestCacheTTLFor_UnknownToolZero(t *testing.T) {
	if ttl := cacheTTLFor("completely_unknown_tool"); ttl != 0 {
		t.Errorf("cacheTTLFor(unknown) = %v, want 0", ttl)
	}
}

// ---------------------------------------------------------------------------
// toolTimeoutFor — full branch coverage
// ---------------------------------------------------------------------------

func TestToolTimeoutFor_ScanTools(t *testing.T) {
	for _, name := range []string{
		"run_opengrep_scan", "run_semgrep_scan",
		"run_trivy_scan", "bootstrap_scan_toolchain",
	} {
		if to := toolTimeoutFor(name); to <= 0 {
			t.Errorf("toolTimeoutFor(%q) = %v, want > 0", name, to)
		}
	}
}

func TestToolTimeoutFor_DocsCVETools(t *testing.T) {
	tools := []string{
		"docs_lookup", "docs_read", "docs_search", "docs_resolve",
		"cve_search", "vul_cve_search", "vul_vendor_product_cve", "vul_vendor_products", "vul_last_cves",
		"get_architecture",
	}
	for _, name := range tools {
		if to := toolTimeoutFor(name); to <= 0 {
			t.Errorf("toolTimeoutFor(%q) = %v, want > 0", name, to)
		}
	}
}

func TestToolTimeoutFor_CodebaseMemoryTools(t *testing.T) {
	for _, name := range []string{
		"ctx_search", "search_code", "search_graph",
		"get_code_snippet", "trace_path",
		"index_repository", "index_status", "list_projects",
	} {
		if to := toolTimeoutFor(name); to <= 0 {
			t.Errorf("toolTimeoutFor(%q) = %v, want > 0", name, to)
		}
	}
}

func TestToolTimeoutFor_BashHasTimeout(t *testing.T) {
	if to := toolTimeoutFor("bash"); to <= 0 {
		t.Errorf("toolTimeoutFor(bash) = %v, want > 0", to)
	}
}

func TestToolTimeoutFor_SpawnSubagentZero(t *testing.T) {
	if to := toolTimeoutFor("spawn_subagent"); to != 0 {
		t.Errorf("toolTimeoutFor(spawn_subagent) = %v, want 0", to)
	}
}

func TestToolTimeoutFor_UnknownToolZero(t *testing.T) {
	if to := toolTimeoutFor("completely_unknown_tool"); to != 0 {
		t.Errorf("toolTimeoutFor(unknown) = %v, want 0", to)
	}
}

func TestToolTimeoutFor_IndexRepositoryLong(t *testing.T) {
	if to := toolTimeoutFor("index_repository"); to < time.Minute {
		t.Errorf("toolTimeoutFor(index_repository) = %v, want >= 1m", to)
	}
}
