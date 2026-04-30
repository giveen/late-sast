package tool

// Native ProContext-compatible documentation lookup tools.
//
// Three tools give the scanner the same capability as the ProContext MCP server
// but as plain Go code — no Python, no subprocess, no MCP handshake:
//
//   docs_resolve(query, language?) → registry matches + index_url
//   docs_read(url, offset?, limit?) → windowed page content with line numbers
//   docs_search(url, query, max_results?) → matching lines with line numbers
//
// The ProContext public registry (~2100 libraries) is fetched once at startup
// from https://procontexthq.github.io/known-libraries.json and cached in memory.
// SSRF protection: docs_read and docs_search only fetch URLs whose hostname
// appears in the registry (i.e. known documentation domains).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Registry types ─────────────────────────────────────────────────────────────

type pcPackage struct {
	Ecosystem    string   `json:"ecosystem"`
	Languages    []string `json:"languages"`
	PackageNames []string `json:"package_names"`
	ReadmeURL    *string  `json:"readme_url"`
	RepoURL      *string  `json:"repo_url"`
}

type pcEntry struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	LLMSTxtURL  string      `json:"llms_txt_url"`
	Aliases     []string    `json:"aliases"`
	Packages    []pcPackage `json:"packages"`
}

// ── Page cache ─────────────────────────────────────────────────────────────────

type pcPage struct {
	lines     []string
	fetchedAt time.Time
}

// ── Client ─────────────────────────────────────────────────────────────────────

const (
	pcRegistryURL    = "https://procontexthq.github.io/known-libraries.json"
	pcPageCacheTTL   = 1 * time.Hour
	pcFuzzyThreshold = 0.70
	pcPageSizeCap    = 2 << 20 // 2 MB per page
)

// ProContextClient manages the registry, allowlist, and page cache.
// Construct with NewProContextClient (live registry) or newTestProContextClient.
type ProContextClient struct {
	entries        []pcEntry
	allowedDomains map[string]bool
	pageCache      sync.Map // string → *pcPage
	mu             sync.RWMutex
	httpClient     *http.Client
}

// NewProContextClient downloads the registry and returns a ready client.
// Returns an error if the registry is unreachable or unparseable.
func NewProContextClient() (*ProContextClient, error) {
	c := &ProContextClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	if err := c.refreshRegistry(); err != nil {
		return nil, err
	}
	return c, nil
}

// newTestProContextClient creates a client with a hand-crafted registry — for tests.
func newTestProContextClient(entries []pcEntry) *ProContextClient {
	c := &ProContextClient{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	c.setEntries(entries)
	return c
}

func (c *ProContextClient) refreshRegistry() error {
	resp, err := c.httpClient.Get(pcRegistryURL)
	if err != nil {
		return fmt.Errorf("docs registry fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docs registry returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("docs registry read failed: %w", err)
	}
	var entries []pcEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("docs registry parse error: %w", err)
	}
	c.setEntries(entries)
	return nil
}

func (c *ProContextClient) setEntries(entries []pcEntry) {
	domains := make(map[string]bool)
	for _, e := range entries {
		if u, err := url.Parse(e.LLMSTxtURL); err == nil && u.Hostname() != "" {
			domains[u.Hostname()] = true
		}
		for _, pkg := range e.Packages {
			if pkg.ReadmeURL != nil {
				if u, err := url.Parse(*pkg.ReadmeURL); err == nil {
					domains[u.Hostname()] = true
				}
			}
		}
	}
	c.mu.Lock()
	c.entries = entries
	c.allowedDomains = domains
	c.mu.Unlock()
}

// isAllowed returns true when the URL's hostname is a known documentation domain.
func (c *ProContextClient) isAllowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	c.mu.RLock()
	ok := c.allowedDomains[u.Hostname()]
	c.mu.RUnlock()
	return ok
}

// ── Resolve ─────────────────────────────────────────────────────────────────────

type pcResolveMatch struct {
	LibraryID   string      `json:"library_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	IndexURL    string      `json:"index_url"`
	Packages    []pcPackage `json:"packages"`
	MatchedVia  string      `json:"matched_via"`
	Relevance   float64     `json:"relevance"`
}

func (c *ProContextClient) resolve(query, language string) []pcResolveMatch {
	c.mu.RLock()
	entries := c.entries
	c.mu.RUnlock()

	q := strings.TrimSpace(strings.ToLower(query))
	var exact, fuzzy []pcResolveMatch
	seen := make(map[string]bool)

	addMatch := func(e pcEntry, via string, relevance float64, target *[]pcResolveMatch) {
		if seen[e.ID] {
			return
		}
		seen[e.ID] = true
		pkgs := e.Packages
		if language != "" {
			pkgs = pcSortedPackages(pkgs, language)
		}
		*target = append(*target, pcResolveMatch{
			LibraryID:   e.ID,
			Name:        e.Name,
			Description: e.Description,
			IndexURL:    e.LLMSTxtURL,
			Packages:    pkgs,
			MatchedVia:  via,
			Relevance:   relevance,
		})
	}

	for _, e := range entries {
		var via string

		// Step 1: exact package name
	outer:
		for _, pkg := range e.Packages {
			for _, pname := range pkg.PackageNames {
				if strings.ToLower(pname) == q {
					via = "package_name"
					break outer
				}
			}
		}

		// Step 2: exact library ID or display name
		if via == "" && (strings.ToLower(e.ID) == q || strings.ToLower(e.Name) == q) {
			via = "library_id"
		}

		// Step 3: alias
		if via == "" {
			for _, a := range e.Aliases {
				if strings.ToLower(a) == q {
					via = "alias"
					break
				}
			}
		}

		if via != "" {
			addMatch(e, via, 1.0, &exact)
		}
	}

	if len(exact) > 0 {
		return exact
	}

	// Step 4: fuzzy fallback (Levenshtein ≥ 70%)
	for _, e := range entries {
		candidates := []string{strings.ToLower(e.ID), strings.ToLower(e.Name)}
		for _, a := range e.Aliases {
			candidates = append(candidates, strings.ToLower(a))
		}
		for _, pkg := range e.Packages {
			for _, pname := range pkg.PackageNames {
				candidates = append(candidates, strings.ToLower(pname))
			}
		}
		best := 0.0
		for _, cand := range candidates {
			if s := pcLevenshteinSimilarity(q, cand); s > best {
				best = s
			}
		}
		if best >= pcFuzzyThreshold {
			addMatch(e, "fuzzy", best, &fuzzy)
		}
	}

	sort.Slice(fuzzy, func(i, j int) bool { return fuzzy[i].Relevance > fuzzy[j].Relevance })
	return fuzzy
}

func pcSortedPackages(pkgs []pcPackage, language string) []pcPackage {
	lang := strings.ToLower(language)
	out := make([]pcPackage, len(pkgs))
	copy(out, pkgs)
	sort.SliceStable(out, func(i, j int) bool {
		iMatch := pcContainsLang(out[i].Languages, lang)
		jMatch := pcContainsLang(out[j].Languages, lang)
		return iMatch && !jMatch
	})
	return out
}

func pcContainsLang(langs []string, lang string) bool {
	for _, l := range langs {
		if strings.ToLower(l) == lang {
			return true
		}
	}
	return false
}

// ── Page fetch ──────────────────────────────────────────────────────────────────

func (c *ProContextClient) fetchPage(rawURL string) (*pcPage, error) {
	if !c.isAllowed(rawURL) {
		return nil, fmt.Errorf("URL not in documentation allowlist: %s", rawURL)
	}
	if cached, ok := c.pageCache.Load(rawURL); ok {
		p := cached.(*pcPage)
		if time.Since(p.fetchedAt) < pcPageCacheTTL {
			return p, nil
		}
	}
	resp, err := c.httpClient.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("page not found: %s", rawURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pcPageSizeCap))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}
	p := &pcPage{
		lines:     strings.Split(string(body), "\n"),
		fetchedAt: time.Now(),
	}
	c.pageCache.Store(rawURL, p)
	return p, nil
}

// ── Levenshtein helpers ─────────────────────────────────────────────────────────

func pcLevenshteinSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	dist := pcLevenshteinDist(a, b)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(dist)/float64(maxLen)
}

func pcLevenshteinDist(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([]int, lb+1)
	for i := range dp {
		dp[i] = i
	}
	for i := 1; i <= la; i++ {
		prev := i - 1
		dp[0] = i
		for j := 1; j <= lb; j++ {
			temp := dp[j]
			if a[i-1] == b[j-1] {
				dp[j] = prev
			} else {
				dp[j] = 1 + pcMin3(prev, dp[j], dp[j-1])
			}
			prev = temp
		}
	}
	return dp[lb]
}

func pcMin3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// ── DocsResolveTool ─────────────────────────────────────────────────────────────

// DocsResolveTool resolves a library name to its documentation index URL
// using the ProContext registry (2100+ libraries).
type DocsResolveTool struct {
	Client *ProContextClient
}

func (t DocsResolveTool) Name() string { return "docs_resolve" }
func (t DocsResolveTool) Description() string {
	return "Resolve a library or package name to its official documentation index URL using the ProContext registry (2100+ libraries). Call this first when looking up remediation guidance, migration docs, or security advisories for any detected vulnerability. Returns index_url — pass it to docs_read or docs_search."
}
func (t DocsResolveTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": {
				"type": "string",
				"description": "Library name, package name, or alias. Examples: 'express', 'django', 'log4j', 'spring-boot', 'lodash'."
			},
			"language": {
				"type": "string",
				"description": "Optional language hint to sort results. E.g. 'python', 'javascript', 'java', 'go'."
			}
		},
		"required": ["query"]
	}`)
}

func (t DocsResolveTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query    string `json:"query"`
		Language string `json:"language"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(params.Query) == "" {
		return "", fmt.Errorf("query must not be empty")
	}
	matches := t.Client.resolve(params.Query, params.Language)
	out, err := json.Marshal(map[string]any{"matches": matches})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t DocsResolveTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t DocsResolveTool) CallString(args json.RawMessage) string {
	q := getToolParam(args, "query")
	if q == "" {
		q = "unknown"
	}
	return fmt.Sprintf("docs_resolve(%s)", q)
}

// ── DocsReadTool ────────────────────────────────────────────────────────────────

// DocsReadTool fetches a windowed slice of a documentation page.
type DocsReadTool struct {
	Client *ProContextClient
}

func (t DocsReadTool) Name() string { return "docs_read" }
func (t DocsReadTool) Description() string {
	return "Fetch a documentation page or llms.txt index and return a windowed slice of its content with line numbers. Use the index_url from docs_resolve. Set offset to jump to a specific section; limit controls how many lines are returned. Use docs_search when looking for a specific keyword."
}
func (t DocsReadTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Documentation URL from docs_resolve (index_url or a link found in the index)."
			},
			"offset": {
				"type": "integer",
				"description": "1-based line number to start reading from. Defaults to 1.",
				"default": 1
			},
			"limit": {
				"type": "integer",
				"description": "Maximum number of lines to return. Defaults to 100.",
				"default": 100
			}
		},
		"required": ["url"]
	}`)
}

func (t DocsReadTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		URL    string `json:"url"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}
	params.Offset = 1
	params.Limit = 100
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	page, err := t.Client.fetchPage(params.URL)
	if err != nil {
		return "", err
	}
	total := len(page.lines)
	offset := params.Offset
	if offset < 1 {
		offset = 1
	}
	limit := params.Limit
	if limit < 1 {
		limit = 1
	}
	start := offset - 1 // 0-based
	if start >= total {
		start = total - 1
	}
	end := start + limit
	if end > total {
		end = total
	}
	var sb strings.Builder
	for i, line := range page.lines[start:end] {
		fmt.Fprintf(&sb, "%d:%s\n", start+i+1, line)
	}
	hasMore := end < total
	nextOffset := 0
	if hasMore {
		nextOffset = end + 1
	}
	result := map[string]any{
		"url":         params.URL,
		"total_lines": total,
		"offset":      offset,
		"limit":       limit,
		"content":     sb.String(),
		"has_more":    hasMore,
		"next_offset": nextOffset,
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t DocsReadTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t DocsReadTool) CallString(args json.RawMessage) string {
	u := getToolParam(args, "url")
	if u == "" {
		u = "unknown"
	}
	return fmt.Sprintf("docs_read(%s)", truncate(u, 60))
}

// ── DocsSearchTool ──────────────────────────────────────────────────────────────

// DocsSearchTool searches a documentation page for lines matching a keyword.
type DocsSearchTool struct {
	Client *ProContextClient
}

func (t DocsSearchTool) Name() string { return "docs_search" }
func (t DocsSearchTool) Description() string {
	return "Search a documentation page for lines matching a keyword or regex. Returns matching lines with line numbers. Use the index_url or any linked URL from docs_resolve. Smart case: lowercase query = case-insensitive; mixed-case = case-sensitive. Ideal for finding security advisories, CVE remediations, and migration guides."
}
func (t DocsSearchTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Documentation URL from docs_resolve."
			},
			"query": {
				"type": "string",
				"description": "Keyword or regex to search for. Lowercase = case-insensitive (smart case)."
			},
			"max_results": {
				"type": "integer",
				"description": "Maximum number of matching lines to return. Defaults to 20.",
				"default": 20
			}
		},
		"required": ["url", "query"]
	}`)
}

func (t DocsSearchTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		URL        string `json:"url"`
		Query      string `json:"query"`
		MaxResults int    `json:"max_results"`
	}
	params.MaxResults = 20
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(params.Query) == "" {
		return "", fmt.Errorf("query must not be empty")
	}
	page, err := t.Client.fetchPage(params.URL)
	if err != nil {
		return "", err
	}

	// Smart case: all-lowercase query → case-insensitive match
	caseInsensitive := params.Query == strings.ToLower(params.Query)
	pattern := regexp.QuoteMeta(params.Query)
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid query pattern: %w", err)
	}

	var matchLines []string
	hasMore := false
	for i, line := range page.lines {
		if re.MatchString(line) {
			if len(matchLines) >= params.MaxResults {
				hasMore = true
				break
			}
			matchLines = append(matchLines, fmt.Sprintf("%d:%s", i+1, line))
		}
	}
	result := map[string]any{
		"url":      params.URL,
		"query":    params.Query,
		"matches":  strings.Join(matchLines, "\n"),
		"has_more": hasMore,
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t DocsSearchTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t DocsSearchTool) CallString(args json.RawMessage) string {
	u := getToolParam(args, "url")
	q := getToolParam(args, "query")
	return fmt.Sprintf("docs_search(%s, %q)", truncate(u, 40), q)
}
