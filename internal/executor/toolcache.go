package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ToolResultCache is a thread-safe, TTL-based cache for tool execution results.
// It prevents redundant re-execution of expensive idempotent tools (e.g.
// opengrep scans) within a single RunLoop session.
type ToolResultCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	result    string
	expiresAt time.Time
}

// NewToolResultCache returns a ready-to-use ToolResultCache.
func NewToolResultCache() *ToolResultCache {
	return &ToolResultCache{
		entries: make(map[string]cacheEntry),
	}
}

// Get returns the cached result for (toolName, args) if it exists and has not
// expired. The second return value is true on a cache hit.
func (c *ToolResultCache) Get(toolName, args string) (string, bool) {
	key := cacheKey(toolName, args)
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return "", false
	}
	return entry.result, true
}

// Set stores a tool result with the TTL appropriate for that tool.
// Tools with TTL == 0 are not cached.
func (c *ToolResultCache) Set(toolName, args, result string) {
	ttl := cacheTTLFor(toolName)
	if ttl == 0 {
		return
	}
	key := cacheKey(toolName, args)
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// cacheKey returns a stable sha256-based key for the (toolName, args) pair.
func cacheKey(toolName, args string) string {
	h := sha256.New()
	h.Write([]byte(toolName))
	h.Write([]byte("\x00"))
	h.Write([]byte(args))
	return hex.EncodeToString(h.Sum(nil))
}

// cacheTTLFor returns the cache TTL for a given tool name.
// A zero TTL means the tool result is never cached.
func cacheTTLFor(toolName string) time.Duration {
	switch toolName {
	// Scan tools — expensive, results stable for the duration of a scan.
	case "run_opengrep_scan", "run_semgrep_scan":
		return 10 * time.Minute
	case "run_trivy_scan", "run_secrets_scanner":
		return 10 * time.Minute

	// Documentation / CVE lookups — remote reads, stable within a session.
	case "docs_lookup", "docs_read", "docs_search", "docs_resolve":
		return 15 * time.Minute
	case "cve_search", "vul_cve_search", "vul_vendor_product_cve", "vul_vendor_products", "vul_last_cves":
		return 15 * time.Minute
	case "get_architecture":
		return 15 * time.Minute

	// Codebase-memory MCP tools — read-only graph/code queries, stable for scan.
	case "ctx_search", "search_code", "search_graph":
		return 5 * time.Minute
	case "get_code_snippet", "trace_path":
		return 5 * time.Minute

	// File / index read tools.
	case "list_files", "read_file", "search_codebase", "context_index":
		return 5 * time.Minute

	// Index metadata — can change briefly after a re-index, short TTL is enough.
	case "index_status", "list_projects", "index_repository":
		return 3 * time.Minute

	// Side-effectful or write operations — never cache.
	case "spawn_subagent", "bash", "write_file", "write_sast_report",
		"compose_patch", "implementations",
		"ctx_fetch_and_index", "ctx_index_file", "ctx_index":
		return 0
	default:
		return 0
	}
}

// toolTimeoutFor returns a per-tool execution deadline. A zero value means no
// additional timeout beyond the per-turn context deadline.
func toolTimeoutFor(toolName string) time.Duration {
	switch toolName {
	case "run_opengrep_scan", "run_semgrep_scan":
		return 12 * time.Minute
	case "run_trivy_scan", "run_secrets_scanner", "bootstrap_scan_toolchain":
		return 5 * time.Minute
	case "bash":
		return 5 * time.Minute
	case "docs_lookup", "docs_read", "docs_search", "docs_resolve",
		"cve_search", "vul_cve_search", "vul_vendor_product_cve", "vul_vendor_products", "vul_last_cves":
		return 45 * time.Second
	case "get_architecture":
		return 60 * time.Second
	case "ctx_search", "search_code", "search_graph":
		return 30 * time.Second
	case "get_code_snippet", "trace_path":
		return 30 * time.Second
	case "index_repository":
		return 3 * time.Minute
	case "index_status", "list_projects":
		return 15 * time.Second
	// spawn_subagent manages its own timeout internally.
	case "spawn_subagent":
		return 0
	default:
		return 0
	}
}
