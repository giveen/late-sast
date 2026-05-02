package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	const responseBody = `[{"id":"CVE-2021-44228","cvss":10.0,"summary":"Log4Shell"}]`
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/search/apache/log4j") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
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
		w.Write([]byte(`[]`))
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
	const responseBody = `{"id":"CVE-2021-44228","cvss":10.0,"summary":"Log4Shell RCE"}`
	cleanup := setupCVETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/CVE-2021-44228" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	})
	defer cleanup()

	tool := VulCVESearchTool{}
	args := json.RawMessage(`{"cve_id":"CVE-2021-44228"}`)
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Log4Shell") {
		t.Errorf("expected summary in result, got: %s", result)
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
		w.Write([]byte(`[{"id":"CVE-2026-0001"}]`))
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
