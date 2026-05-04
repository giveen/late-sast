package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveInstallStrategyTool_QuickInstall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/HEAD/README.md":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Install with: go install github.com/owner/repo/cmd/repo@latest\n"))
		case "/repos/owner/repo/releases/latest":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"assets":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tool := ResolveInstallStrategyTool{
		HTTPClient:        srv.Client(),
		RawContentBaseURL: srv.URL,
		GitHubAPIBaseURL:  srv.URL,
	}
	args := json.RawMessage(`{"github_url":"https://github.com/owner/repo","arch":"amd64"}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if resp["strategy"] != "quick_install" {
		t.Fatalf("expected quick_install strategy, got %v", resp["strategy"])
	}
	qi, _ := resp["quick_install"].(map[string]any)
	if qi["image"] != "golang:1.23" {
		t.Fatalf("expected golang image, got %v", qi["image"])
	}
}

func TestResolveInstallStrategyTool_ReleaseAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/HEAD/README.md":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("No quick install here\n"))
		case "/repos/owner/repo/releases/latest":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"assets": [
					{"name":"repo-v1.0.0-linux-amd64.tar.gz","browser_download_url":"https://example/tar"},
					{"name":"repo-v1.0.0-linux-amd64.deb","browser_download_url":"https://example/deb"},
					{"name":"repo-v1.0.0.AppImage","browser_download_url":"https://example/appimage"}
				]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tool := ResolveInstallStrategyTool{
		HTTPClient:        srv.Client(),
		RawContentBaseURL: srv.URL,
		GitHubAPIBaseURL:  srv.URL,
	}
	args := json.RawMessage(`{"github_url":"https://github.com/owner/repo","arch":"amd64"}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if resp["strategy"] != "release_asset" {
		t.Fatalf("expected release_asset strategy, got %v", resp["strategy"])
	}
	asset, _ := resp["release_asset"].(map[string]any)
	if asset["kind"] != "deb" {
		t.Fatalf("expected deb asset kind, got %v", asset["kind"])
	}
}

func TestResolveInstallStrategyTool_SourceCloneFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	tool := ResolveInstallStrategyTool{
		HTTPClient:        srv.Client(),
		RawContentBaseURL: srv.URL,
		GitHubAPIBaseURL:  srv.URL,
	}
	args := json.RawMessage(`{"github_url":"https://github.com/owner/repo","arch":"arm64"}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if resp["strategy"] != "source_clone" {
		t.Fatalf("expected source_clone strategy, got %v", resp["strategy"])
	}
}

func TestResolveInstallStrategyTool_InvalidURL(t *testing.T) {
	tool := ResolveInstallStrategyTool{}
	args := json.RawMessage(`{"github_url":"https://example.com/notgithub/repo"}`)
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Fatal("expected error for non-github URL")
	}
}
