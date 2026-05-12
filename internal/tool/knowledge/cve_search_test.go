package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── CVE5 test fixtures ───────────────────────────────────────────────────────

// testCVE5SearchBody is a minimal /api/search/{vendor}/{product} response.
const testCVE5SearchBody = `{
	"results": {
		"nvd": [
			["CVE-2021-44228", {
				"cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
				"containers": {"cna": {
					"title": "Log4Shell RCE",
					"descriptions": [{"lang": "en", "value": "Log4Shell RCE vulnerability in log4j-core allows remote code execution."}],
					"metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
					"affected": [{"vendor": "apache", "product": "log4j", "packageName": "log4j-core",
						"versions": [{"status": "affected", "version": "2.0", "lessThan": "2.15.0", "versionType": "maven"}]}],
					"references": [{"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": ["vendor-advisory"]}]
				}}
			}]
		],
		"cvelistv5": []
	},
	"total_count": 1,
	"page_size": 50,
	"page": 1
}`

// testCVE5SingleBody is a minimal /api/cve/{CVE_ID} response (single CVE5 record).
const testCVE5SingleBody = `{
	"cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
	"containers": {"cna": {
		"title": "Log4Shell RCE",
		"descriptions": [{"lang": "en", "value": "Log4Shell RCE vulnerability in log4j-core."}],
		"metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
		"affected": [{"vendor": "apache", "product": "log4j", "packageName": "log4j-core",
			"versions": [{"status": "affected", "version": "2.0", "lessThan": "2.15.0"}]}]
	}}
}`

// testCVE5LastBody is a minimal /api/last/{N} response (list of CVE5 records).
const testCVE5LastBody = `[{
	"cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED"},
	"containers": {"cna": {
		"title": "Test CVE",
		"descriptions": [{"lang": "en", "value": "A test vulnerability."}],
		"metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
		"affected": [{"vendor": "testvendor", "product": "testpkg", "packageName": "testpkg"}]
	}}
}]`

// setupCVETestServer creates a mock httptest server and redirects cveGet to use it.
// The returned cleanup function restores the originals.
func setupCVETestServer(t *testing.T, handler http.HandlerFunc) (cleanup func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	origBase := cveBaseURL
	origClient := cveHTTPClient
	origCache := cveCache
	cveBaseURL = srv.URL + "/"
	cveHTTPClient = srv.Client()
	cveCacheMu.Lock()
	cveCache = make(map[string]cveCacheEntry)
	cveCacheMu.Unlock()
	return func() {
		cveBaseURL = origBase
		cveHTTPClient = origClient
		cveCacheMu.Lock()
		cveCache = origCache
		cveCacheMu.Unlock()
		srv.Close()
	}
}

// ─── CVE5 parser unit tests ──────────────────────────────────────────────────

func TestExtractCVSS_PrefersV3_1(t *testing.T) {
	metrics := []cve5Metric{
		{CVSSV2_0: &cve5CVSSScore{BaseScore: 6.5, BaseSeverity: "MEDIUM"}},
		{CVSSV3_1: &cve5CVSSScore{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
		{CVSSV4_0: &cve5CVSSScore{BaseScore: 8.0, BaseSeverity: "HIGH"}},
	}
	score, severity, _ := extractCVSS(metrics)
	if score != 9.8 || severity != "CRITICAL" {
		t.Fatalf("expected V3.1 score 9.8/CRITICAL, got %.1f/%s", score, severity)
	}
}

func TestExtractCVSS_FallsBackToV4(t *testing.T) {
	metrics := []cve5Metric{
		{CVSSV4_0: &cve5CVSSScore{BaseScore: 8.0, BaseSeverity: "HIGH"}},
	}
	score, severity, _ := extractCVSS(metrics)
	if score != 8.0 || severity != "HIGH" {
		t.Fatalf("expected V4 score 8.0/HIGH, got %.1f/%s", score, severity)
	}
}

func TestExtractCVSS_EmptyMetrics(t *testing.T) {
	score, severity, _ := extractCVSS(nil)
	if score != 0 || severity != "" {
		t.Fatalf("expected zero score, got %.1f/%s", score, severity)
	}
}

func TestExtractDescription_EnglishPreferred(t *testing.T) {
	cna := cve5CNA{
		Descriptions: []cve5LangValue{
			{Lang: "es", Value: "descripción en español"},
			{Lang: "en", Value: "English description"},
		},
	}
	if got := extractDescription(cna); got != "English description" {
		t.Fatalf("expected English description, got %q", got)
	}
}

func TestExtractDescription_FallsBackToTitle(t *testing.T) {
	cna := cve5CNA{Title: "Fallback Title"}
	if got := extractDescription(cna); got != "Fallback Title" {
		t.Fatalf("expected title fallback, got %q", got)
	}
}

func TestExtractDescription_Truncates(t *testing.T) {
	long := strings.Repeat("A", 300)
	cna := cve5CNA{Descriptions: []cve5LangValue{{Lang: "en", Value: long}}}
	got := extractDescription(cna)
	if len(got) > 200 {
		t.Fatalf("expected truncation to 200 chars, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected '...' suffix, got %q", got[len(got)-5:])
	}
}

func TestExtractPackage_UsesPackageName(t *testing.T) {
	affected := []cve5Affected{{Vendor: "apache", Product: "log4j", PackageName: "log4j-core"}}
	if got := extractPackage(affected, "apache", "log4j"); got != "log4j-core" {
		t.Fatalf("expected log4j-core, got %q", got)
	}
}

func TestExtractPackage_FallsBackToVendorProduct(t *testing.T) {
	affected := []cve5Affected{{Vendor: "apache", Product: "struts"}}
	if got := extractPackage(affected, "apache", "struts"); got != "apache:struts" {
		t.Fatalf("expected apache:struts, got %q", got)
	}
}

func TestExtractPackage_UsesHintWhenEmpty(t *testing.T) {
	if got := extractPackage(nil, "myvendor", "mypkg"); got != "myvendor:mypkg" {
		t.Fatalf("expected myvendor:mypkg, got %q", got)
	}
}

func TestParseCVE5SearchResponse_ParsesFindings(t *testing.T) {
	findings, total, err := parseCVE5SearchResponse(testCVE5SearchBody, "apache", "log4j")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total_count=1, got %d", total)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CVE != "CVE-2021-44228" {
		t.Errorf("unexpected CVE: %q", f.CVE)
	}
	if f.Package != "log4j-core" {
		t.Errorf("unexpected package: %q", f.Package)
	}
	if f.CVSS != 10.0 {
		t.Errorf("unexpected CVSS: %f", f.CVSS)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("unexpected severity: %q", f.Severity)
	}
	if f.Link != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" {
		t.Errorf("unexpected link: %q", f.Link)
	}
	if len(f.AffectedVersions) == 0 {
		t.Error("expected at least one affected version")
	}
}

func TestParseCVE5SingleResponse_ParsesFinding(t *testing.T) {
	f, err := parseCVE5SingleResponse(testCVE5SingleBody)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.CVE != "CVE-2021-44228" || f.CVSS != 10.0 || f.Package != "log4j-core" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestParseCVE5SingleResponse_MissingCveIdErrors(t *testing.T) {
	body := `{"cveMetadata": {}, "containers": {"cna": {}}}`
	_, err := parseCVE5SingleResponse(body)
	if err == nil {
		t.Error("expected error for missing cveId")
	}
}

func TestParseCVE5LastResponse_ParsesFindings(t *testing.T) {
	findings, err := parseCVE5LastResponse(testCVE5LastBody)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CVE != "CVE-2026-0001" {
		t.Errorf("unexpected CVE: %q", findings[0].CVE)
	}
	if findings[0].CVSS != 7.5 {
		t.Errorf("expected CVSS 7.5, got %f", findings[0].CVSS)
	}
}

// ─── HTTP infrastructure tests ───────────────────────────────────────────────

func TestCVEGet_RetrysOnServerError(t *testing.T) {
	attempts := 0
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer cleanup()

	res, err := cveGet(context.Background(), "cve/CVE-2021-44228")
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if !strings.Contains(res, `"ok":true`) {
		t.Fatalf("unexpected response: %s", res)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestCVEGet_UsesCache(t *testing.T) {
	hits := 0
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"cached":true}`))
	})
	defer cleanup()

	for i := 0; i < 2; i++ {
		if _, err := cveGet(context.Background(), "last/5"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if hits != 1 {
		t.Fatalf("expected one upstream hit due to cache, got %d", hits)
	}
}

// ─── VulVendorProductCVETool ─────────────────────────────────────────────────

func TestVulVendorProductCVETool_Metadata(t *testing.T) {
	tool := VulVendorProductCVETool{}
	if tool.Name() != "vul_vendor_product_cve" {
		t.Errorf("unexpected name: %s", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description should not be empty")
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
	var params map[string]any
	if err := json.Unmarshal(tool.Parameters(), &params); err != nil {
		t.Fatalf("Parameters() is not valid JSON: %v", err)
	}
}

func TestVulVendorProductCVETool_Execute_Success(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/search/apache/log4j") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testCVE5SearchBody))
	})
	defer cleanup()

	tool := VulVendorProductCVETool{}
	args := json.RawMessage(`{"vendor":"apache","product":"log4j"}`)
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "CVE-2021-44228") {
		t.Errorf("expected CVE ID in result, got: %s", result)
	}
	// Verify parsed fields are present.
	if !strings.Contains(result, `"cvss":10`) {
		t.Errorf("expected cvss field, got: %s", result)
	}
	if !strings.Contains(result, `"package":"log4j-core"`) {
		t.Errorf("expected package field, got: %s", result)
	}
}

func TestVulVendorProductCVETool_Execute_MissingArgs(t *testing.T) {
	tool := VulVendorProductCVETool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"vendor":"apache"}`))
	if err == nil {
		t.Error("expected error when product is missing")
	}
}

func TestVulVendorProductCVETool_Execute_HTTPError(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	tool := VulVendorProductCVETool{}
	args := json.RawMessage(`{"vendor":"unknown","product":"unknown"}`)
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Error("expected error on HTTP 404")
	}
}

func TestVulVendorProductCVETool_Execute_URLEncoding(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// vendor "my vendor" should be percent-encoded in the URL path
		if !strings.Contains(r.URL.RawPath+r.URL.Path, "my%20vendor") &&
			!strings.Contains(r.URL.String(), "my+vendor") &&
			!strings.Contains(r.URL.String(), "my%20vendor") {
			t.Errorf("vendor not URL-encoded, path: %s", r.URL.String())
		}
		w.WriteHeader(http.StatusOK)
		// Return minimal valid search response (no nvd results = empty findings).
		w.Write([]byte(`{"results":{"nvd":[]},"total_count":0}`))
	})
	defer cleanup()

	tool := VulVendorProductCVETool{}
	args := json.RawMessage(`{"vendor":"my vendor","product":"my product"}`)
	_, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVulVendorProductCVETool_CallString(t *testing.T) {
	tool := VulVendorProductCVETool{}
	s := tool.CallString(json.RawMessage(`{"vendor":"apache","product":"log4j"}`))
	if !strings.Contains(s, "apache") || !strings.Contains(s, "log4j") {
		t.Errorf("CallString missing expected content: %s", s)
	}
}

// ─── VulCVESearchTool ─────────────────────────────────────────────────────────

func TestVulCVESearchTool_Metadata(t *testing.T) {
	tool := VulCVESearchTool{}
	if tool.Name() != "vul_cve_search" {
		t.Errorf("unexpected name: %s", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description should not be empty")
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
}

func TestVulCVESearchTool_Execute_Success(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/CVE-2021-44228" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testCVE5SingleBody))
	})
	defer cleanup()

	tool := VulCVESearchTool{}
	args := json.RawMessage(`{"cve_id":"CVE-2021-44228"}`)
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Log4Shell") {
		t.Errorf("expected description in result, got: %s", result)
	}
	if !strings.Contains(result, `"cvss":10`) {
		t.Errorf("expected cvss field, got: %s", result)
	}
}

func TestVulCVESearchTool_Execute_InvalidID(t *testing.T) {
	tests := []struct {
		name  string
		cveID string
	}{
		{"empty", ""},
		{"no year", "CVE-44228"},
		{"too short number", "CVE-2021-123"},
		{"bad prefix", "CWE-2021-44228"},
		{"injection attempt", "CVE-2021-44228/../../../etc/passwd"},
	}
	tool := VulCVESearchTool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := json.RawMessage(`{"cve_id":"` + tt.cveID + `"}`)
			_, err := tool.Execute(context.Background(), args)
			if err == nil {
				t.Errorf("expected validation error for cve_id=%q", tt.cveID)
			}
		})
	}
}

func TestVulCVESearchTool_Execute_ValidIDFormats(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	})
	defer cleanup()

	tool := VulCVESearchTool{}
	validIDs := []string{"CVE-2021-44228", "CVE-1999-0001", "CVE-2023-123456"}
	for _, id := range validIDs {
		args := json.RawMessage(`{"cve_id":"` + id + `"}`)
		_, err := tool.Execute(context.Background(), args)
		if err != nil {
			t.Errorf("valid CVE ID %q rejected: %v", id, err)
		}
	}
}

func TestVulCVESearchTool_CallString(t *testing.T) {
	tool := VulCVESearchTool{}
	s := tool.CallString(json.RawMessage(`{"cve_id":"CVE-2021-44228"}`))
	if !strings.Contains(s, "CVE-2021-44228") {
		t.Errorf("CallString missing CVE ID: %s", s)
	}
}

// ─── VulVendorProductsTool ───────────────────────────────────────────────────

func TestVulVendorProductsTool_Metadata(t *testing.T) {
	tool := VulVendorProductsTool{}
	if tool.Name() != "vul_vendor_products" {
		t.Errorf("unexpected name: %s", tool.Name())
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
}

func TestVulVendorProductsTool_Execute_Success(t *testing.T) {
	const responseBody = `{"vendor":"apache","product":["log4j","struts","tomcat"]}`
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/browse/apache" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	})
	defer cleanup()

	tool := VulVendorProductsTool{}
	args := json.RawMessage(`{"vendor":"apache"}`)
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "apache") {
		t.Errorf("expected vendor in result, got: %s", result)
	}
}

func TestVulVendorProductsTool_Execute_MissingVendor(t *testing.T) {
	tool := VulVendorProductsTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Error("expected error when vendor is empty")
	}
}

func TestVulVendorProductsTool_CallString(t *testing.T) {
	tool := VulVendorProductsTool{}
	s := tool.CallString(json.RawMessage(`{"vendor":"apache"}`))
	if !strings.Contains(s, "apache") {
		t.Errorf("CallString missing vendor: %s", s)
	}
}

// ─── VulLastCVEsTool ─────────────────────────────────────────────────────────

func TestVulLastCVEsTool_Metadata(t *testing.T) {
	tool := VulLastCVEsTool{}
	if tool.Name() != "vul_last_cves" {
		t.Errorf("unexpected name: %s", tool.Name())
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
}

func TestVulLastCVEsTool_Execute_Default(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/last/5" {
			t.Errorf("expected /last/5, got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testCVE5LastBody))
	})
	defer cleanup()

	tool := VulLastCVEsTool{}
	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "CVE-2026-0001") {
		t.Errorf("expected CVE ID in result, got: %s", result)
	}
}

func TestVulLastCVEsTool_Execute_CustomNumber(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/last/20" {
			t.Errorf("expected /last/20, got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	defer cleanup()

	tool := VulLastCVEsTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"number":20}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVulLastCVEsTool_Execute_ClampMax(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/last/100" {
			t.Errorf("expected /last/100 (clamped), got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	defer cleanup()

	tool := VulLastCVEsTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"number":9999}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVulLastCVEsTool_Execute_NegativeDefaultsToFive(t *testing.T) {
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/last/5" {
			t.Errorf("expected /last/5 for negative input, got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	defer cleanup()

	tool := VulLastCVEsTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"number":-1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVulLastCVEsTool_CallString(t *testing.T) {
	tool := VulLastCVEsTool{}
	s := tool.CallString(json.RawMessage(`{"number":10}`))
	if !strings.Contains(s, "10") {
		t.Errorf("CallString missing number: %s", s)
	}
}
