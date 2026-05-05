package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// ResolveInstallStrategyTool determines the fastest deterministic installation
// path for GitHub-hosted targets by inspecting README quick-install commands
// and release assets.
type ResolveInstallStrategyTool struct {
	HTTPClient        *http.Client
	GitHubAPIBaseURL  string
	RawContentBaseURL string
	UserAgent         string
}

func (t ResolveInstallStrategyTool) Name() string { return "resolve_install_strategy" }

func (t ResolveInstallStrategyTool) Description() string {
	return "Resolve setup install strategy from a GitHub repo: quick-install command, best release asset install plan, or source-clone fallback."
}

func (t ResolveInstallStrategyTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"github_url": {"type": "string", "description": "Target GitHub repository URL"},
			"arch": {"type": "string", "description": "Target architecture (e.g. amd64, arm64)", "default": "amd64"}
		},
		"required": ["github_url"]
	}`)
}

func (t ResolveInstallStrategyTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t ResolveInstallStrategyTool) CallString(args json.RawMessage) string {
	githubURL := getToolParam(args, "github_url")
	if githubURL == "" {
		return "resolve_install_strategy(...)"
	}
	return fmt.Sprintf("resolve_install_strategy(%q)", githubURL)
}

func (t ResolveInstallStrategyTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		GitHubURL string `json:"github_url"`
		Arch      string `json:"arch"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.GitHubURL) == "" {
		return "", fmt.Errorf("github_url is required")
	}
	owner, repo, err := parseGitHubRepo(p.GitHubURL)
	if err != nil {
		return "", err
	}

	arch := normalizeArch(p.Arch)
	if arch == "" {
		arch = "amd64"
	}

	readme, readmeErr := t.fetchREADME(ctx, owner, repo)
	if readmeErr == nil {
		if quick, ok := detectQuickInstall(readme); ok {
			resp := map[string]any{
				"status":   "ok",
				"strategy": "quick_install",
				"github": map[string]any{
					"owner": owner,
					"repo":  repo,
					"url":   fmt.Sprintf("https://github.com/%s/%s", owner, repo),
				},
				"arch": arch,
				"quick_install": map[string]any{
					"ecosystem": quick.Ecosystem,
					"image":     quick.Image,
					"command":   quick.Command,
				},
				"notes": []string{"resolved from README quick-install command"},
			}
			out, _ := json.Marshal(resp)
			return string(out), nil
		}
	}

	release, releaseErr := t.fetchLatestRelease(ctx, owner, repo)
	if releaseErr == nil {
		if asset, ok := selectBestAsset(release.Assets, arch); ok {
			plan := releaseInstallPlan(asset)
			resp := map[string]any{
				"status":   "ok",
				"strategy": "release_asset",
				"github": map[string]any{
					"owner": owner,
					"repo":  repo,
					"url":   fmt.Sprintf("https://github.com/%s/%s", owner, repo),
				},
				"arch": arch,
				"release_asset": map[string]any{
					"name":                  asset.Name,
					"download_url":          asset.BrowserDownloadURL,
					"kind":                  assetKind(asset.Name),
					"container_image":       plan.ContainerImage,
					"install_commands":      plan.InstallCommands,
					"post_install_commands": plan.PostInstallCommands,
				},
				"notes": []string{"resolved from latest GitHub release assets"},
			}
			out, _ := json.Marshal(resp)
			return string(out), nil
		}
	}

	notes := []string{"no quick-install command or suitable release asset found"}
	if readmeErr != nil {
		notes = append(notes, "README fetch failed: "+truncate(readmeErr.Error(), 200))
	}
	if releaseErr != nil {
		notes = append(notes, "release metadata fetch failed: "+truncate(releaseErr.Error(), 200))
	}

	resp := map[string]any{
		"status":   "ok",
		"strategy": "source_clone",
		"github": map[string]any{
			"owner": owner,
			"repo":  repo,
			"url":   fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		},
		"arch":  arch,
		"notes": notes,
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

type quickInstall struct {
	Ecosystem string
	Image     string
	Command   string
}

var quickInstallPatterns = []struct {
	Ecosystem string
	Image     string
	Pattern   *regexp.Regexp
}{
	{Ecosystem: "go", Image: "golang:1.23", Pattern: regexp.MustCompile(`(?i)\bgo\s+install\s+[\w./@:+~-]+`)},
	{Ecosystem: "python", Image: "python:3.11-slim", Pattern: regexp.MustCompile(`(?i)\bpipx\s+install\s+[\w./@:+~-]+`)},
	{Ecosystem: "python", Image: "python:3.11-slim", Pattern: regexp.MustCompile(`(?i)\bpip\s+install\s+[\w./@:+~-]+`)},
	{Ecosystem: "node", Image: "node:20-slim", Pattern: regexp.MustCompile(`(?i)\bnpm\s+install\s+-g\s+[\w./@:+~-]+`)},
	{Ecosystem: "rust", Image: "rust:1.80-slim", Pattern: regexp.MustCompile(`(?i)\bcargo\s+install\s+[\w./@:+~-]+`)},
	{Ecosystem: "ruby", Image: "ruby:3.3-slim", Pattern: regexp.MustCompile(`(?i)\bgem\s+install\s+[\w./@:+~-]+`)},
}

func detectQuickInstall(readme string) (quickInstall, bool) {
	for _, line := range strings.Split(readme, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, p := range quickInstallPatterns {
			if cmd := p.Pattern.FindString(trimmed); cmd != "" {
				return quickInstall{Ecosystem: p.Ecosystem, Image: p.Image, Command: strings.TrimSpace(cmd)}, true
			}
		}
	}
	return quickInstall{}, false
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type latestRelease struct {
	Assets []releaseAsset `json:"assets"`
}

type installPlan struct {
	ContainerImage      string
	InstallCommands     []string
	PostInstallCommands []string
}

func releaseInstallPlan(asset releaseAsset) installPlan {
	kind := assetKind(asset.Name)
	switch kind {
	case "deb":
		return installPlan{
			ContainerImage: "ubuntu:22.04",
			InstallCommands: []string{
				"apt-get update -qq 2>/dev/null",
				"apt-get install -y -qq /workdir/app.deb 2>/dev/null || (dpkg -i /workdir/app.deb 2>/dev/null; apt-get install -f -y -qq 2>/dev/null)",
			},
		}
	case "appimage":
		return installPlan{
			ContainerImage: "debian:bookworm-slim",
			InstallCommands: []string{
				"apt-get update -qq 2>/dev/null && apt-get install -y -qq libfuse2 2>/dev/null || true",
				"chmod +x /workdir/app.AppImage",
				"cd /workdir && ./app.AppImage --appimage-extract 2>/dev/null || true",
			},
			PostInstallCommands: []string{
				"ln -sf /workdir/squashfs-root /workdir/app",
			},
		}
	case "snap":
		return installPlan{
			ContainerImage: "ubuntu:22.04",
			InstallCommands: []string{
				"snap install --dangerous /workdir/app.snap 2>/dev/null || true",
			},
		}
	case "flatpak":
		return installPlan{
			ContainerImage: "debian:bookworm-slim",
			InstallCommands: []string{
				"apt-get update -qq 2>/dev/null && apt-get install -y -qq flatpak 2>/dev/null || true",
				"flatpak install -y /workdir/app.flatpak 2>/dev/null || true",
			},
		}
	default:
		return installPlan{}
	}
}

func selectBestAsset(assets []releaseAsset, arch string) (releaseAsset, bool) {
	if len(assets) == 0 {
		return releaseAsset{}, false
	}
	archTags := archMatchTokens(arch)
	kinds := []string{"deb", "appimage", "snap", "flatpak"}
	for _, kind := range kinds {
		candidates := make([]releaseAsset, 0)
		for _, a := range assets {
			if assetKind(a.Name) != kind {
				continue
			}
			candidates = append(candidates, a)
		}
		if len(candidates) == 0 {
			continue
		}

		for _, a := range candidates {
			if kind == "snap" || kind == "flatpak" {
				return a, true
			}
			if filenameMatchesArch(a.Name, archTags) {
				return a, true
			}
		}

		// Fallback: if no arch marker matched, prefer an asset without any explicit arch marker.
		for _, a := range candidates {
			if !hasAnyArchToken(a.Name) {
				return a, true
			}
		}

		if len(candidates) == 1 {
			return candidates[0], true
		}
	}
	return releaseAsset{}, false
}

func assetKind(name string) string {
	if !isInstallableAssetName(name) {
		return ""
	}
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".deb"):
		return "deb"
	case strings.Contains(n, ".appimage"):
		return "appimage"
	case strings.HasSuffix(n, ".snap"):
		return "snap"
	case strings.HasSuffix(n, ".flatpak"):
		return "flatpak"
	default:
		return ""
	}
}

func isInstallableAssetName(name string) bool {
	n := strings.ToLower(name)
	for _, suffix := range []string{".asc", ".sig", ".minisig", ".sha256", ".sha256sum", ".sha512", ".sha512sum", ".zsync"} {
		if strings.HasSuffix(n, suffix) {
			return false
		}
	}
	return true
}

func hasAnyArchToken(name string) bool {
	n := strings.ToLower(name)
	for _, tag := range []string{"amd64", "x86_64", "x86-64", "x64", "arm64", "aarch64", "armv7", "armhf", "i386", "x86", "386"} {
		if strings.Contains(n, tag) {
			return true
		}
	}
	return false
}

func filenameMatchesArch(name string, tags []string) bool {
	n := strings.ToLower(name)
	for _, tag := range tags {
		if strings.Contains(n, tag) {
			return true
		}
	}
	return false
}

func archMatchTokens(arch string) []string {
	switch arch {
	case "amd64":
		return []string{"amd64", "x86_64", "x86-64", "x64"}
	case "arm64":
		return []string{"arm64", "aarch64", "armv8"}
	default:
		return []string{strings.ToLower(arch)}
	}
}

func normalizeArch(arch string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	switch a {
	case "", "amd64", "x86_64", "x86-64", "x64":
		return "amd64"
	case "arm64", "aarch64", "armv8":
		return "arm64"
	default:
		return a
	}
}

func parseGitHubRepo(githubURL string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(githubURL))
	if err != nil {
		return "", "", fmt.Errorf("invalid github_url: %w", err)
	}
	if !strings.Contains(strings.ToLower(u.Host), "github.com") {
		return "", "", fmt.Errorf("github_url must point to github.com")
	}
	parts := strings.Split(strings.Trim(path.Clean(u.Path), "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("github_url must include owner and repo")
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("github_url must include owner and repo")
	}
	return owner, repo, nil
}

func (t ResolveInstallStrategyTool) fetchREADME(ctx context.Context, owner, repo string) (string, error) {
	base := strings.TrimRight(t.RawContentBaseURL, "/")
	if base == "" {
		base = "https://raw.githubusercontent.com"
	}
	u := fmt.Sprintf("%s/%s/%s/HEAD/README.md", base, owner, repo)
	return t.httpGET(ctx, u)
}

func (t ResolveInstallStrategyTool) fetchLatestRelease(ctx context.Context, owner, repo string) (latestRelease, error) {
	base := strings.TrimRight(t.GitHubAPIBaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	u := fmt.Sprintf("%s/repos/%s/%s/releases/latest", base, owner, repo)
	body, err := t.httpGET(ctx, u)
	if err != nil {
		return latestRelease{}, err
	}
	var rel latestRelease
	if err := json.Unmarshal([]byte(body), &rel); err != nil {
		return latestRelease{}, fmt.Errorf("parse releases/latest JSON: %w", err)
	}
	return rel, nil
}

func (t ResolveInstallStrategyTool) httpGET(ctx context.Context, reqURL string) (string, error) {
	client := t.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	ua := t.UserAgent
	if strings.TrimSpace(ua) == "" {
		ua = "late-sast/1.0 (resolve_install_strategy; +https://github.com/giveen/late-sast)"
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s: status %d: %s", reqURL, resp.StatusCode, truncate(string(data), 200))
	}
	return string(data), nil
}
