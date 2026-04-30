package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var cveBaseURL = "https://cve.circl.lu/api/"

var cveHTTPClient = &http.Client{Timeout: 15 * time.Second}

var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func cveGet(path string) (string, error) {
	reqURL := cveBaseURL + path
	//nolint:gosec // URL is constructed from a hardcoded base and validated/escaped inputs only
	resp, err := cveHTTPClient.Get(reqURL) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("CVE API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CVE API returned HTTP %d for %s", resp.StatusCode, reqURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("CVE API read failed: %w", err)
	}
	return string(body), nil
}

// ─── vul_vendor_product_cve ──────────────────────────────────────────────────

// VulVendorProductCVETool lists all CVEs for a specific vendor+product pair.
type VulVendorProductCVETool struct{}

func (VulVendorProductCVETool) Name() string { return "vul_vendor_product_cve" }
func (VulVendorProductCVETool) Description() string {
	return "Get all CVEs for a specific vendor and product from the cve.circl.lu database. Returns JSON with CVE IDs, CVSS scores, summaries, and affected versions."
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
func (VulVendorProductCVETool) Execute(_ context.Context, args json.RawMessage) (string, error) {
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
	return cveGet("search/" + url.PathEscape(p.Vendor) + "/" + url.PathEscape(p.Product))
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
func (VulCVESearchTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if !cveIDRegex.MatchString(p.CVEID) {
		return "", fmt.Errorf("invalid CVE ID format %q (expected CVE-YYYY-NNNNN)", p.CVEID)
	}
	return cveGet("cve/" + p.CVEID)
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
	return "List all products associated with a vendor in the cve.circl.lu database."
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
func (VulVendorProductsTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Vendor string `json:"vendor"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.Vendor == "" {
		return "", fmt.Errorf("vendor is required")
	}
	return cveGet("browse/" + url.PathEscape(p.Vendor))
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
func (VulLastCVEsTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
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
	return cveGet(fmt.Sprintf("last/%d", p.Number))
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
