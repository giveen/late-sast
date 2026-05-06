package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var cveBaseURL = "https://cve.circl.lu/api/"

var cveHTTPClient = &http.Client{Timeout: 15 * time.Second}

var (
	cveCacheMu sync.RWMutex
	cveCache   = make(map[string]cveCacheEntry)
)

type cveCacheEntry struct {
	body      string
	expiresAt time.Time
}

const (
	cveCacheTTL         = 10 * time.Minute
	cveMaxRetryAttempts = 3
)

var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ─── CVE 5.x record types ────────────────────────────────────────────────────

// cve5Record is the minimal subset of a CVE 5.x record we care about.
type cve5Record struct {
	CVEMetadata struct {
		CVEID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5CNA `json:"cna"`
	} `json:"containers"`
}

type cve5CNA struct {
	Title        string          `json:"title"`
	Descriptions []cve5LangValue `json:"descriptions"`
	Affected     []cve5Affected  `json:"affected"`
	Metrics      []cve5Metric    `json:"metrics"`
	References   []cve5Reference `json:"references"`
}

type cve5LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cve5Affected struct {
	Vendor      string        `json:"vendor"`
	Product     string        `json:"product"`
	PackageName string        `json:"packageName"`
	Versions    []cve5Version `json:"versions"`
}

type cve5Version struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	LessThan    string `json:"lessThan"`
	VersionType string `json:"versionType"`
}

// cve5Metric holds any CVSS version block. We only decode the scalar we need.
type cve5Metric struct {
	CVSSV2_0 *cve5CVSSScore `json:"cvssV2_0"`
	CVSSV3_0 *cve5CVSSScore `json:"cvssV3_0"`
	CVSSV3_1 *cve5CVSSScore `json:"cvssV3_1"`
	CVSSV4_0 *cve5CVSSScore `json:"cvssV4_0"`
}

type cve5CVSSScore struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type cve5Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// ParsedCVEFinding is the structured output of the CVE tools, ready for direct
// use as a write_sast_report cve_findings entry.
type ParsedCVEFinding struct {
	CVE              string   `json:"cve"`
	Package          string   `json:"package"`
	CVSS             float64  `json:"cvss"`
	CVSSVector       string   `json:"cvss_vector,omitempty"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Link             string   `json:"link"`
	AffectedVersions []string `json:"affected_versions,omitempty"`
}

// ─── CVE 5.x parsing helpers ─────────────────────────────────────────────────

// extractCVSS returns the best available CVSS score and severity.
// Preference order: V3.1 > V4.0 > V3.0 > V2.0.
func extractCVSS(metrics []cve5Metric) (score float64, severity, vector string) {
	pick := func(s *cve5CVSSScore) {
		if s != nil && s.BaseScore > score {
			score = s.BaseScore
			severity = s.BaseSeverity
			vector = s.VectorString
		}
	}
	for _, m := range metrics {
		pick(m.CVSSV3_1)
	}
	if score > 0 {
		return
	}
	for _, m := range metrics {
		pick(m.CVSSV4_0)
	}
	if score > 0 {
		return
	}
	for _, m := range metrics {
		pick(m.CVSSV3_0)
		pick(m.CVSSV2_0)
	}
	return
}

// extractDescription returns a single-line description ≤ 200 chars.
func extractDescription(cna cve5CNA) string {
	for _, d := range cna.Descriptions {
		if strings.EqualFold(d.Lang, "en") && d.Value != "" {
			v := d.Value
			// collapse newlines → spaces
			v = strings.Join(strings.Fields(v), " ")
			if len(v) > 200 {
				v = v[:197] + "..."
			}
			return v
		}
	}
	if cna.Title != "" {
		return cna.Title
	}
	return ""
}

// extractPackage derives a package identifier from affected entries.
func extractPackage(affected []cve5Affected, vendorHint, productHint string) string {
	for _, a := range affected {
		if a.PackageName != "" && a.PackageName != "n/a" {
			return a.PackageName
		}
		if a.Product != "" && a.Product != "n/a" {
			v := a.Vendor
			if v == "n/a" || v == "" {
				v = vendorHint
			}
			if v != "" && v != "n/a" && !strings.EqualFold(v, a.Product) {
				return v + ":" + a.Product
			}
			return a.Product
		}
	}
	if productHint != "" {
		if vendorHint != "" && !strings.EqualFold(vendorHint, productHint) {
			return vendorHint + ":" + productHint
		}
		return productHint
	}
	return ""
}

// extractAffectedVersions returns human-readable affected version ranges.
func extractAffectedVersions(affected []cve5Affected) []string {
	var out []string
	for _, a := range affected {
		for _, v := range a.Versions {
			if v.Status != "affected" {
				continue
			}
			if v.LessThan != "" {
				out = append(out, fmt.Sprintf(">= %s, < %s", v.Version, v.LessThan))
			} else if v.Version != "" && v.Version != "n/a" {
				out = append(out, v.Version)
			}
		}
	}
	return out
}

// inferSeverity returns a severity string from a CVSS score when the record
// does not include one.
func inferSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}

// parseCVE5RecordToFinding converts a decoded cve5Record into a ParsedCVEFinding.
func parseCVE5RecordToFinding(cveID string, rec cve5Record, vendorHint, productHint string) ParsedCVEFinding {
	cna := rec.Containers.CNA
	score, severity, vector := extractCVSS(cna.Metrics)
	if severity == "" {
		severity = inferSeverity(score)
	}

	id := cveID
	if id == "" {
		id = rec.CVEMetadata.CVEID
	}
	id = strings.ToUpper(id)

	return ParsedCVEFinding{
		CVE:              id,
		Package:          extractPackage(cna.Affected, vendorHint, productHint),
		CVSS:             score,
		CVSSVector:       vector,
		Severity:         strings.ToUpper(severity),
		Description:      extractDescription(cna),
		Link:             "https://nvd.nist.gov/vuln/detail/" + id,
		AffectedVersions: extractAffectedVersions(cna.Affected),
	}
}

// parseCVE5SearchResponse parses the /api/search/{vendor}/{product} response.
// The API returns {"results": {"nvd": [["cve-id", {CVE5 record}], ...], ...}, "total_count": N}
func parseCVE5SearchResponse(body, vendor, product string) ([]ParsedCVEFinding, int, error) {
	var resp struct {
		Results struct {
			NVD []json.RawMessage `json:"nvd"`
		} `json:"results"`
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, 0, fmt.Errorf("parse search response: %w", err)
	}

	seen := make(map[string]bool)
	var findings []ParsedCVEFinding
	for _, raw := range resp.Results.NVD {
		var pair [2]json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			continue
		}
		var cveID string
		if err := json.Unmarshal(pair[0], &cveID); err != nil {
			continue
		}
		cveID = strings.ToUpper(cveID)
		if seen[cveID] {
			continue
		}
		seen[cveID] = true

		var rec cve5Record
		if err := json.Unmarshal(pair[1], &rec); err != nil {
			continue
		}
		findings = append(findings, parseCVE5RecordToFinding(cveID, rec, vendor, product))
	}
	return findings, resp.TotalCount, nil
}

// parseCVE5SingleResponse parses the /api/cve/{CVE_ID} response (single record).
func parseCVE5SingleResponse(body string) (ParsedCVEFinding, error) {
	var rec cve5Record
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		return ParsedCVEFinding{}, fmt.Errorf("parse CVE record: %w", err)
	}
	cveID := rec.CVEMetadata.CVEID
	if cveID == "" {
		return ParsedCVEFinding{}, fmt.Errorf("CVE record missing cveId")
	}
	return parseCVE5RecordToFinding(cveID, rec, "", ""), nil
}

// parseCVE5LastResponse parses the /api/last/{N} response (list of CVE5 records).
func parseCVE5LastResponse(body string) ([]ParsedCVEFinding, error) {
	var recs []cve5Record
	if err := json.Unmarshal([]byte(body), &recs); err != nil {
		return nil, fmt.Errorf("parse last CVEs response: %w", err)
	}
	var findings []ParsedCVEFinding
	for _, rec := range recs {
		cveID := rec.CVEMetadata.CVEID
		if cveID == "" {
			continue
		}
		findings = append(findings, parseCVE5RecordToFinding(cveID, rec, "", ""))
	}
	return findings, nil
}

// cveVendorMap normalises common package/library names to the CPE vendor string
// used by cve.circl.lu. Keys are lowercase package names or common vendor guesses;
// values are the exact CPE vendor strings the API expects.
//
// If a caller passes a vendor not listed here it is used as-is (existing behaviour).
var cveVendorMap = map[string]string{
	// Node.js / npm
	"express":      "expressjs",
	"nextjs":       "vercel",
	"next.js":      "vercel",
	"next":         "vercel",
	"react":        "facebook",
	"angular":      "google",
	"vue":          "vuejs",
	"nuxt":         "nuxtjs",
	"lodash":       "lodash",
	"axios":        "axios-http",
	"jsonwebtoken": "auth0",
	"passport":     "jaredhanson",
	"sequelize":    "sequelize",
	"mongoose":     "mongoosejs",
	"nestjs":       "nestjs",
	"@nestjs/core": "nestjs",
	"fastify":      "fastify",
	"koa":          "koajs",
	"hapi":         "hapi",
	"helmet":       "helmetjs",
	"multer":       "expressjs",
	"ws":           "websockets",
	"socket.io":    "socket",
	"socketio":     "socket",
	// Python
	"django":       "djangoproject",
	"flask":        "palletsprojects",
	"werkzeug":     "palletsprojects",
	"jinja2":       "palletsprojects",
	"fastapi":      "tiangolo",
	"starlette":    "encode",
	"sqlalchemy":   "sqlalchemy",
	"celery":       "celeryproject",
	"requests":     "python-requests",
	"pydantic":     "pydantic",
	"cryptography": "cryptography",
	"paramiko":     "paramiko",
	"pillow":       "python",
	"pyjwt":        "jwt",
	"twisted":      "twistedmatrix",
	// Java
	"log4j":               "apache",
	"log4j2":              "apache",
	"log4j-core":          "apache",
	"struts":              "apache",
	"struts2":             "apache",
	"spring":              "vmware",
	"spring-core":         "vmware",
	"spring-boot":         "vmware",
	"spring-framework":    "vmware",
	"spring-security":     "vmware",
	"spring-web":          "vmware",
	"jackson":             "fasterxml",
	"jackson-databind":    "fasterxml",
	"commons-collections": "apache",
	"commons-lang":        "apache",
	"shiro":               "apache",
	"hibernate":           "redhat",
	"netty":               "netty",
	"tomcat":              "apache",
	// Ruby
	"rails":         "rubyonrails",
	"activerecord":  "rubyonrails",
	"activesupport": "rubyonrails",
	"devise":        "heartcombo",
	"nokogiri":      "nokogiri",
	// Go
	"gin":         "gin-gonic",
	"echo":        "labstack",
	"fiber":       "gofiber",
	"beego":       "beego",
	"gorilla/mux": "gorilla",
	"chi":         "go-chi",
	// PHP
	"laravel":   "laravel",
	"symfony":   "sensiolabs",
	"wordpress": "wordpress",
	"drupal":    "drupal",
	"guzzle":    "guzzlephp",
	"twig":      "twig",
	// Generic / infra
	"openssl":    "openssl",
	"libssl":     "openssl",
	"curl":       "haxx",
	"libcurl":    "haxx",
	"nginx":      "nginx",
	"redis":      "redis",
	"mongodb":    "mongodb",
	"mysql":      "oracle",
	"postgresql": "postgresql",
}

// normalizeCVEVendor maps a package/library name to the canonical CPE vendor
// string expected by cve.circl.lu. Falls back to the input if not found.
func normalizeCVEVendor(vendor string) string {
	// Try exact match first (lowercase)
	lower := strings.ToLower(vendor)
	if mapped, ok := cveVendorMap[lower]; ok {
		return mapped
	}
	return vendor
}

func cveGet(ctx context.Context, path string) (string, error) {
	reqURL := cveBaseURL + path

	cveCacheMu.RLock()
	if entry, ok := cveCache[reqURL]; ok && time.Now().Before(entry.expiresAt) {
		cveCacheMu.RUnlock()
		return entry.body, nil
	}
	cveCacheMu.RUnlock()

	var lastErr error
	for attempt := 1; attempt <= cveMaxRetryAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(250*(1<<(attempt-2))) * time.Millisecond
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return "", fmt.Errorf("CVE API request build failed: %w", err)
		}

		resp, err := cveHTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("CVE API request failed: %w", err)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("CVE API read failed: %w", readErr)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyStr := string(body)
			cveCacheMu.Lock()
			cveCache[reqURL] = cveCacheEntry{body: bodyStr, expiresAt: time.Now().Add(cveCacheTTL)}
			cveCacheMu.Unlock()
			return bodyStr, nil
		}

		lastErr = fmt.Errorf("CVE API returned HTTP %d for %s", resp.StatusCode, reqURL)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < http.StatusInternalServerError {
			break
		}
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("CVE API request failed")
}

// ─── vul_vendor_product_cve ──────────────────────────────────────────────────

// VulVendorProductCVETool lists all CVEs for a specific vendor+product pair.
type VulVendorProductCVETool struct{}

func (VulVendorProductCVETool) Name() string { return "vul_vendor_product_cve" }
func (VulVendorProductCVETool) Description() string {
	return "Get CVEs for a specific vendor and product from cve.circl.lu. Returns structured findings with cve, package, cvss, severity, description, link, and affected_versions fields ready for direct use in write_sast_report cve_findings. The vendor name is automatically normalised (e.g. 'express' → 'expressjs', 'django' → 'djangoproject')."
}
func (VulVendorProductCVETool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"vendor":   {"type": "string", "description": "Vendor name, e.g. 'apache', 'nodejs', 'expressjs', 'django'"},
			"product":  {"type": "string", "description": "Product/package name, e.g. 'log4j', 'express', 'django', 'struts'"},
			"limit":    {"type": "integer", "description": "Maximum findings to return (default 50, max 200)"},
			"min_cvss": {"type": "number",  "description": "Minimum CVSS score to include (default 0 = all; use 7.0 for HIGH+ only)"}
		},
		"required": ["vendor", "product"]
	}`)
}
func (VulVendorProductCVETool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Vendor  string  `json:"vendor"`
		Product string  `json:"product"`
		Limit   int     `json:"limit"`
		MinCVSS float64 `json:"min_cvss"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Vendor == "" || p.Product == "" {
		return "", fmt.Errorf("vendor and product are required")
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 200 {
		p.Limit = 200
	}
	p.Vendor = normalizeCVEVendor(p.Vendor)

	body, err := cveGet(ctx, "search/"+url.PathEscape(p.Vendor)+"/"+url.PathEscape(p.Product))
	if err != nil {
		return "", err
	}

	findings, total, parseErr := parseCVE5SearchResponse(body, p.Vendor, p.Product)
	if parseErr != nil {
		// Parsing failed (unexpected API shape); return raw body as fallback.
		return body, nil
	}

	// Apply min_cvss filter and limit.
	var filtered []ParsedCVEFinding
	for _, f := range findings {
		if f.CVSS >= p.MinCVSS {
			filtered = append(filtered, f)
		}
		if len(filtered) >= p.Limit {
			break
		}
	}

	result := map[string]any{
		"vendor":   p.Vendor,
		"product":  p.Product,
		"total":    total,
		"returned": len(filtered),
		"findings": filtered,
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}
func (VulVendorProductCVETool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (VulVendorProductCVETool) CallString(args json.RawMessage) string {
	var p struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	return fmt.Sprintf("vul_vendor_product_cve(vendor=%q, product=%q)", p.Vendor, p.Product)
}

// ─── vul_cve_search ──────────────────────────────────────────────────────────

// VulCVESearchTool fetches full details for a specific CVE ID.
type VulCVESearchTool struct{}

func (VulCVESearchTool) Name() string { return "vul_cve_search" }
func (VulCVESearchTool) Description() string {
	return "Get structured details for a specific CVE ID from cve.circl.lu: cve, package, cvss, severity, description, link, and affected_versions. Ready for direct use as a write_sast_report cve_findings entry."
}
func (VulCVESearchTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"cve_id": {"type": "string", "description": "CVE identifier, e.g. 'CVE-2021-44228'"}
		},
		"required": ["cve_id"]
	}`)
}
func (VulCVESearchTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if !cveIDRegex.MatchString(p.CVEID) {
		return "", fmt.Errorf("invalid CVE ID format %q (expected CVE-YYYY-NNNNN)", p.CVEID)
	}
	body, err := cveGet(ctx, "cve/"+p.CVEID)
	if err != nil {
		return "", err
	}
	finding, parseErr := parseCVE5SingleResponse(body)
	if parseErr != nil {
		return body, nil
	}
	out, _ := json.Marshal(finding)
	return string(out), nil
}
func (VulCVESearchTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (VulCVESearchTool) CallString(args json.RawMessage) string {
	var p struct {
		CVEID string `json:"cve_id"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	return fmt.Sprintf("vul_cve_search(cve_id=%q)", p.CVEID)
}

// ─── vul_vendor_products ─────────────────────────────────────────────────────

// VulVendorProductsTool lists all products for a given vendor.
type VulVendorProductsTool struct{}

func (VulVendorProductsTool) Name() string { return "vul_vendor_products" }
func (VulVendorProductsTool) Description() string {
	return "List all products associated with a vendor in the cve.circl.lu database. The vendor name is automatically normalised to the CPE vendor string."
}
func (VulVendorProductsTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"vendor": {"type": "string", "description": "Vendor name to look up"}
		},
		"required": ["vendor"]
	}`)
}
func (VulVendorProductsTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Vendor string `json:"vendor"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Vendor == "" {
		return "", fmt.Errorf("vendor is required")
	}
	p.Vendor = normalizeCVEVendor(p.Vendor)
	return cveGet(ctx, "browse/"+url.PathEscape(p.Vendor))
}
func (VulVendorProductsTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (VulVendorProductsTool) CallString(args json.RawMessage) string {
	var p struct {
		Vendor string `json:"vendor"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	return fmt.Sprintf("vul_vendor_products(vendor=%q)", p.Vendor)
}

// ─── vul_last_cves ───────────────────────────────────────────────────────────

// VulLastCVEsTool returns the most recently published CVEs.
type VulLastCVEsTool struct{}

func (VulLastCVEsTool) Name() string { return "vul_last_cves" }
func (VulLastCVEsTool) Description() string {
	return "Get the most recently published CVEs (up to 100). Returns structured findings with cve, package, cvss, severity, description, link, and affected_versions fields."
}
func (VulLastCVEsTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"number": {"type": "integer", "description": "How many recent CVEs to return (default 5, max 100)"}
		}
	}`)
}
func (VulLastCVEsTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Number int `json:"number"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	if p.Number <= 0 {
		p.Number = 5
	}
	if p.Number > 100 {
		p.Number = 100
	}
	body, err := cveGet(ctx, fmt.Sprintf("last/%d", p.Number))
	if err != nil {
		return "", err
	}
	findings, parseErr := parseCVE5LastResponse(body)
	if parseErr != nil {
		return body, nil
	}
	result := map[string]any{
		"count":    len(findings),
		"findings": findings,
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}
func (VulLastCVEsTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (VulLastCVEsTool) CallString(args json.RawMessage) string {
	var p struct {
		Number int `json:"number"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	if p.Number <= 0 {
		p.Number = 5
	}
	return fmt.Sprintf("vul_last_cves(number=%d)", p.Number)
}
