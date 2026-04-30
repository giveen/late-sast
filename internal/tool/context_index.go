package tool

// Native context-window-efficient knowledge base — inspired by context-mode.
//
// Three tools let the scanner index large documents once and query only what's
// relevant, keeping raw content out of the context window entirely:
//
//   ctx_index(source, content)             — chunk + index text/markdown
//   ctx_search(query, max_results?)        — BM25-ranked snippet retrieval
//   ctx_fetch_and_index(url, force?)       — fetch URL, convert, index; 24h TTL
//
// Architecture:
//   - In-memory inverted index with per-chunk BM25 scoring (k1=1.5, b=0.75)
//   - Chunking at heading boundaries; oversized chunks split by word count
//   - Lightweight HTML→text converter (no external deps)
//   - SSRF protection: custom dialer rejects private/loopback IPs at dial time
//   - Thread-safe: all mutations protected by sync.Mutex

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ciWordsPerChunk = 350
	ciFetchCacheTTL = 24 * time.Hour
	ciFetchBodyCap  = 4 << 20 // 4 MB
	ciBM25K1        = 1.5
	ciBM25B         = 0.75
	ciDefaultMax    = 5
	ciSnippetWords  = 80
)

// ── Core types ─────────────────────────────────────────────────────────────────

type ciChunk struct {
	source  string
	heading string
	text    string
	tokens  []string
	tf      map[string]int
}

// ciSearchResult is one BM25-ranked result returned by Search.
type ciSearchResult struct {
	Source  string
	Heading string
	Snippet string
	Score   float64
}

// ContextIndex is an in-memory BM25 knowledge base scoped to one agent session.
// Index large documents once; retrieve only relevant snippets via Search.
// All operations are safe for concurrent use.
type ContextIndex struct {
	mu         sync.Mutex
	chunks     []ciChunk
	inv        map[string][]int // term → chunk IDs
	sumLen     int              // total token count (for avgdl)
	fetched    map[string]time.Time
	httpClient *http.Client
}

// NewContextIndex returns a ContextIndex backed by an SSRF-safe HTTP client.
func NewContextIndex() *ContextIndex {
	return &ContextIndex{
		inv:        make(map[string][]int),
		fetched:    make(map[string]time.Time),
		httpClient: newCIHTTPClient(),
	}
}

// newCIHTTPClient builds an HTTP client whose custom dialer rejects private,
// loopback, and link-local IPs — preventing SSRF via DNS rebinding.
func newCIHTTPClient() *http.Client {
	baseDialer := &net.Dialer{Timeout: 10 * time.Second}
	t := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, s := range ips {
				ip := net.ParseIP(s)
				if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
					return nil, fmt.Errorf("ctx_fetch_and_index: host %q resolves to private/loopback address — blocked", host)
				}
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return fmt.Errorf("redirect to scheme %q not allowed", req.URL.Scheme)
			}
			if len(via) > 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// ── Public methods ─────────────────────────────────────────────────────────────

// IndexText chunks content and adds it to the index. Returns the chunk count.
// source is an arbitrary label (URL, file path, descriptive name).
func (ci *ContextIndex) IndexText(source, content string) int {
	chunks := ciChunkText(source, content)
	if len(chunks) == 0 {
		return 0
	}
	ci.mu.Lock()
	defer ci.mu.Unlock()
	base := len(ci.chunks)
	for i, ch := range chunks {
		id := base + i
		for term := range ch.tf {
			ci.inv[term] = append(ci.inv[term], id)
		}
		ci.sumLen += len(ch.tokens)
	}
	ci.chunks = append(ci.chunks, chunks...)
	return len(chunks)
}

// Search returns up to maxResults BM25-ranked snippets matching query.
// Returns nil when the index is empty or query has no searchable terms.
func (ci *ContextIndex) Search(query string, maxResults int) []ciSearchResult {
	queryTokens := ciTokenize(query)
	if len(queryTokens) == 0 {
		return nil
	}
	if maxResults <= 0 {
		maxResults = ciDefaultMax
	}

	ci.mu.Lock()
	defer ci.mu.Unlock()

	n := len(ci.chunks)
	if n == 0 {
		return nil
	}
	avgdl := float64(ci.sumLen) / float64(n)
	if avgdl == 0 {
		avgdl = 1
	}

	scores := make(map[int]float64, n)
	for _, term := range queryTokens {
		postings := ci.inv[term]
		if len(postings) == 0 {
			continue
		}
		df := float64(len(postings))
		idf := math.Log((float64(n)-df+0.5)/(df+0.5) + 1.0)
		for _, id := range postings {
			ch := &ci.chunks[id]
			tf := float64(ch.tf[term])
			dl := float64(len(ch.tokens))
			scores[id] += idf * tf * (ciBM25K1 + 1) / (tf + ciBM25K1*(1-ciBM25B+ciBM25B*dl/avgdl))
		}
	}

	type kv struct {
		id    int
		score float64
	}
	ranked := make([]kv, 0, len(scores))
	for id, sc := range scores {
		ranked = append(ranked, kv{id, sc})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	if len(ranked) > maxResults {
		ranked = ranked[:maxResults]
	}

	out := make([]ciSearchResult, 0, len(ranked))
	for _, r := range ranked {
		ch := ci.chunks[r.id]
		out = append(out, ciSearchResult{
			Source:  ch.source,
			Heading: ch.heading,
			Snippet: ciSnippet(ch.text, queryTokens),
			Score:   r.score,
		})
	}
	return out
}

// FetchAndIndex fetches rawURL, converts the body to text, and indexes it.
// Returns a concise summary — the raw page content never enters context.
// Cached results are returned immediately (24h TTL); use force=true to bypass.
func (ci *ContextIndex) FetchAndIndex(rawURL string, force bool) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("scheme %q not allowed; only http/https are supported", u.Scheme)
	}

	// Cache check.
	ci.mu.Lock()
	if t, ok := ci.fetched[rawURL]; ok && !force && time.Since(t) < ciFetchCacheTTL {
		ci.mu.Unlock()
		age := time.Since(t).Round(time.Minute)
		return fmt.Sprintf("cached (indexed %s ago) — use ctx_search to retrieve", age), nil
	}
	ci.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "late-sast/1.0 (ctx_fetch_and_index; +https://github.com/giveen/late-sast)")

	resp, err := ci.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, ciFetchBodyCap))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	text := string(body)
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		text = ciHTMLToText(text)
	}

	n := ci.IndexText(rawURL, text)

	ci.mu.Lock()
	ci.fetched[rawURL] = time.Now()
	ci.mu.Unlock()

	return fmt.Sprintf("indexed %d chunks from %s (%d bytes) — use ctx_search to retrieve", n, rawURL, len(body)), nil
}

// ── Chunking & tokenisation ────────────────────────────────────────────────────

// ciChunkText splits content at markdown heading boundaries, then by word count.
func ciChunkText(source, content string) []ciChunk {
	lines := strings.Split(content, "\n")
	var out []ciChunk
	var curHeading string
	var buf []string

	flush := func() {
		text := strings.TrimSpace(strings.Join(buf, "\n"))
		buf = buf[:0]
		if text == "" {
			return
		}
		words := strings.Fields(text)
		for i := 0; i < len(words); i += ciWordsPerChunk {
			end := i + ciWordsPerChunk
			if end > len(words) {
				end = len(words)
			}
			chText := strings.Join(words[i:end], " ")
			toks := ciTokenize(chText)
			tf := make(map[string]int, len(toks))
			for _, t := range toks {
				tf[t]++
			}
			out = append(out, ciChunk{
				source:  source,
				heading: curHeading,
				text:    chText,
				tokens:  toks,
				tf:      tf,
			})
		}
	}

	for _, line := range lines {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "#") {
			flush()
			idx := strings.IndexFunc(s, func(r rune) bool { return r != '#' })
			if idx >= 0 {
				curHeading = strings.TrimSpace(s[idx:])
			}
		}
		buf = append(buf, line)
	}
	flush()
	return out
}

var (
	ciHTMLHeadRE  = regexp.MustCompile(`(?is)<h([1-6])[^>]*>(.*?)</h[1-6]>`)
	ciHTMLBlockRE = regexp.MustCompile(`(?i)</?(?:p|div|br|li|tr|td|th|blockquote|pre|section|article|header|footer|nav|main)[^>]*>`)
	ciHTMLTagRE   = regexp.MustCompile(`<[^>]+>`)
	ciMultiNLRE   = regexp.MustCompile(`\n{3,}`)
	ciMultiSPRE   = regexp.MustCompile(`[ \t]+`)
)

// ciHTMLToText converts HTML to plain text suitable for indexing.
// Headings become markdown headings; block elements become newlines.
func ciHTMLToText(src string) string {
	text := ciHTMLHeadRE.ReplaceAllStringFunc(src, func(m string) string {
		g := ciHTMLHeadRE.FindStringSubmatch(m)
		if len(g) < 3 {
			return "\n"
		}
		lvl := int(g[1][0] - '0')
		inner := ciHTMLTagRE.ReplaceAllString(g[2], "")
		return "\n" + strings.Repeat("#", lvl) + " " + strings.TrimSpace(inner) + "\n"
	})
	text = ciHTMLBlockRE.ReplaceAllString(text, "\n")
	text = ciHTMLTagRE.ReplaceAllString(text, "")
	text = html.UnescapeString(text)
	text = ciMultiNLRE.ReplaceAllString(text, "\n\n")
	text = ciMultiSPRE.ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

var ciNonAlphaRE = regexp.MustCompile(`[^a-z0-9]+`)

var ciStopWords = map[string]bool{
	"a": true, "an": true, "the": true, "is": true, "in": true, "it": true,
	"of": true, "to": true, "and": true, "or": true, "for": true, "on": true,
	"at": true, "by": true, "be": true, "as": true, "with": true, "from": true,
	"this": true, "that": true, "are": true, "was": true, "were": true,
	"has": true, "have": true, "had": true, "not": true, "you": true,
	"your": true, "can": true, "use": true, "its": true, "if": true,
}

// ciTokenize lowercases text, removes non-alphanumerics, and strips stop words.
func ciTokenize(text string) []string {
	lower := strings.ToLower(text)
	clean := ciNonAlphaRE.ReplaceAllString(lower, " ")
	fields := strings.Fields(clean)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) >= 2 && !ciStopWords[f] {
			out = append(out, f)
		}
	}
	return out
}

// ciSnippet returns a window of words around the first query term match.
func ciSnippet(text string, queryTokens []string) string {
	words := strings.Fields(text)
	if len(words) <= ciSnippetWords {
		return text
	}
	lower := make([]string, len(words))
	for i, w := range words {
		lower[i] = strings.ToLower(w)
	}
	best := 0
outer:
	for _, t := range queryTokens {
		for i, w := range lower {
			if strings.Contains(w, t) {
				best = i
				break outer
			}
		}
	}
	start := best - ciSnippetWords/4
	if start < 0 {
		start = 0
	}
	end := start + ciSnippetWords
	if end > len(words) {
		end = len(words)
		start = end - ciSnippetWords
		if start < 0 {
			start = 0
		}
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "…"
	}
	if end < len(words) {
		suffix = "…"
	}
	return prefix + strings.Join(words[start:end], " ") + suffix
}

// ── Tool wrappers ──────────────────────────────────────────────────────────────

// CtxIndexTool indexes text content into the shared knowledge base.
type CtxIndexTool struct{ Index *ContextIndex }

func (t CtxIndexTool) Name() string { return "ctx_index" }
func (t CtxIndexTool) Description() string {
	return "Index text content (markdown, documentation, advisories) into the in-session knowledge base. Raw content never enters the context window — follow with ctx_search to retrieve only relevant sections."
}
func (t CtxIndexTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source": { "type": "string", "description": "Label for this content (URL, file path, or descriptive name)" },
			"content": { "type": "string", "description": "Text content to index (markdown or plain text)" }
		},
		"required": ["source", "content"]
	}`)
}
func (t CtxIndexTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t CtxIndexTool) CallString(args json.RawMessage) string {
	var p struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(args, &p) == nil && p.Source != "" {
		return fmt.Sprintf("ctx_index(%q)", p.Source)
	}
	return "ctx_index(...)"
}
func (t CtxIndexTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Source  string `json:"source"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Source == "" {
		return "", fmt.Errorf("source is required")
	}
	if p.Content == "" {
		return "", fmt.Errorf("content is required")
	}
	n := t.Index.IndexText(p.Source, p.Content)
	return fmt.Sprintf("indexed %d chunks from %q — search with ctx_search", n, p.Source), nil
}

// CtxSearchTool searches the shared knowledge base using BM25 ranking.
type CtxSearchTool struct{ Index *ContextIndex }

func (t CtxSearchTool) Name() string { return "ctx_search" }
func (t CtxSearchTool) Description() string {
	return "Search the in-session knowledge base (populated by ctx_index or ctx_fetch_and_index) using BM25 ranking. Returns relevant snippets only — never raw document dumps."
}
func (t CtxSearchTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": { "type": "string", "description": "Search query — keywords, CVE ID, package name, or natural language" },
			"max_results": { "type": "integer", "description": "Maximum results to return (default 5)" }
		},
		"required": ["query"]
	}`)
}
func (t CtxSearchTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t CtxSearchTool) CallString(args json.RawMessage) string {
	var p struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(args, &p) == nil && p.Query != "" {
		return fmt.Sprintf("ctx_search(%q)", p.Query)
	}
	return "ctx_search(...)"
}
func (t CtxSearchTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Query      string `json:"query"`
		MaxResults int    `json:"max_results"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Query == "" {
		return "", fmt.Errorf("query is required")
	}
	results := t.Index.Search(p.Query, p.MaxResults)
	if len(results) == 0 {
		return "no results — index content first with ctx_index or ctx_fetch_and_index", nil
	}
	var sb strings.Builder
	for i, r := range results {
		heading := r.Heading
		if heading == "" {
			heading = "(top-level)"
		}
		fmt.Fprintf(&sb, "[%d] source: %s | section: %s | score: %.2f\n%s\n",
			i+1, r.Source, heading, r.Score, r.Snippet)
		if i < len(results)-1 {
			sb.WriteByte('\n')
		}
	}
	return sb.String(), nil
}

// CtxFetchAndIndexTool fetches a URL, converts it to text, and indexes it.
type CtxFetchAndIndexTool struct{ Index *ContextIndex }

func (t CtxFetchAndIndexTool) Name() string { return "ctx_fetch_and_index" }
func (t CtxFetchAndIndexTool) Description() string {
	return "Fetch a URL (HTML page or plain text), convert to text, and index into the knowledge base. Raw page content never enters context. 24h TTL cache — repeat calls skip the network. Use ctx_search to retrieve relevant sections."
}
func (t CtxFetchAndIndexTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": { "type": "string", "description": "URL to fetch and index (https or http)" },
			"force": { "type": "boolean", "description": "Bypass 24h cache and re-fetch (default false)" }
		},
		"required": ["url"]
	}`)
}
func (t CtxFetchAndIndexTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t CtxFetchAndIndexTool) CallString(args json.RawMessage) string {
	var p struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(args, &p) == nil && p.URL != "" {
		return fmt.Sprintf("ctx_fetch_and_index(%q)", p.URL)
	}
	return "ctx_fetch_and_index(...)"
}
func (t CtxFetchAndIndexTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		URL   string `json:"url"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.URL == "" {
		return "", fmt.Errorf("url is required")
	}
	return t.Index.FetchAndIndex(p.URL, p.Force)
}

// CtxIndexFileTool reads a local file from disk and indexes it into the BM25
// knowledge base without the file content ever entering the conversation context.
type CtxIndexFileTool struct{ Index *ContextIndex }

func (t CtxIndexFileTool) Name() string { return "ctx_index_file" }
func (t CtxIndexFileTool) Description() string {
	return "Read a local file from disk and index it into the BM25 knowledge base. The file's raw content never enters the conversation context — only search results (via ctx_search) do. Use instead of read_file for large files (source code, logs, configs, lockfiles) you need to analyse without spending context budget."
}
func (t CtxIndexFileTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": { "type": "string", "description": "Absolute path to the local file to index" },
			"source": { "type": "string", "description": "Short label for this content in search results (e.g. 'main.go', 'sql_injection'). Defaults to the filename." }
		},
		"required": ["path"]
	}`)
}
func (t CtxIndexFileTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (t CtxIndexFileTool) CallString(args json.RawMessage) string {
	var p struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(args, &p) == nil && p.Path != "" {
		return fmt.Sprintf("ctx_index_file(%q)", p.Path)
	}
	return "ctx_index_file(...)"
}
func (t CtxIndexFileTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Path   string `json:"path"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	// Validate path is absolute and does not escape via traversal
	clean := filepath.Clean(p.Path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path must be absolute")
	}
	content, err := os.ReadFile(clean)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", clean, err)
	}
	source := p.Source
	if source == "" {
		source = filepath.Base(clean)
	}
	n := t.Index.IndexText(source, string(content))
	return fmt.Sprintf("Indexed %q into knowledge base: %d chunks", source, n), nil
}
