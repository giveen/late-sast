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
	return "Get all CVEs for a specific vendor and product from the cve.circl.lu database. Returns JSON with CVE IDs, CVSS scores, summaries, and affected versions. The vendor name is automatically normalised to the CPE vendor string (e.g. 'express' → 'expressjs', 'django' → 'djangoproject'), so passing the package name directly works."
}
func (VulVendorProductCVETool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"vendor":  {"type": "string", "description": "Vendor name, e.g. 'apache', 'nodejs', 'expressjs', 'django'"},
			"product": {"type": "string", "description": "Product/package name, e.g. 'log4j', 'express', 'django', 'struts'"}
		},
		"required": ["vendor", "product"]
	}`)
}
func (VulVendorProductCVETool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Vendor == "" || p.Product == "" {
		return "", fmt.Errorf("vendor and product are required")
	}
	p.Vendor = normalizeCVEVendor(p.Vendor)
	return cveGet(ctx, "search/"+url.PathEscape(p.Vendor)+"/"+url.PathEscape(p.Product))
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
	return "Get full details for a specific CVE ID from cve.circl.lu, including CVSS score, description, CWE, CPE, CAPEC, references, and affected versions."
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
	return cveGet(ctx, "cve/"+p.CVEID)
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
	return "Get the most recently published CVEs (up to 100), including CAPEC, CWE, and CPE expansions."
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
	return cveGet(ctx, fmt.Sprintf("last/%d", p.Number))
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
