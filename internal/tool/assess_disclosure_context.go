package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type AssessDisclosureContextTool struct {
	HTTPClient       *http.Client
	GitHubAPIBaseURL string
	UserAgent        string
}

func (t AssessDisclosureContextTool) Name() string { return "assess_disclosure_context" }

func (t AssessDisclosureContextTool) Description() string {
	return "Assess repo security policy context and correlate findings with prior GitHub security advisories (GHSA)."
}

func (t AssessDisclosureContextTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"repo_path": {"type": "string", "description": "Local repository path"},
			"github_url": {"type": "string", "description": "GitHub repository URL (optional for local-only scans)"},
			"findings": {
				"type": "array",
				"description": "Current findings to correlate",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"title": {"type": "string"},
						"location": {"type": "string"},
						"cwe": {"type": ["string", "number"]},
						"cve": {"type": "string"}
					}
				}
			}
		},
		"required": ["repo_path", "findings"]
	}`)
}

func (t AssessDisclosureContextTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t AssessDisclosureContextTool) CallString(args json.RawMessage) string {
	repoPath := getToolParam(args, "repo_path")
	if repoPath == "" {
		return "assess_disclosure_context(...)"
	}
	return fmt.Sprintf("assess_disclosure_context(repo_path=%q)", repoPath)
}

type disclosureFinding struct {
	ID       string
	Title    string
	Location string
	CWE      string
	CVE      string
}

type ghsaAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Vulns       []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

func (t AssessDisclosureContextTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		RepoPath  string           `json:"repo_path"`
		GitHubURL string           `json:"github_url"`
		Findings  []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.RepoPath) == "" {
		return "", fmt.Errorf("repo_path is required")
	}

	findings := make([]disclosureFinding, 0, len(p.Findings))
	for i, f := range p.Findings {
		df := disclosureFinding{
			ID:       asDisclosureString(f["id"]),
			Title:    asDisclosureString(f["title"]),
			Location: asDisclosureString(f["location"]),
			CWE:      asDisclosureString(f["cwe"]),
			CVE:      strings.ToUpper(strings.TrimSpace(asDisclosureString(f["cve"]))),
		}
		if df.ID == "" {
			df.ID = fmt.Sprintf("F%d", i+1)
		}
		findings = append(findings, df)
	}

	policyPath, policyBody, policyErr := findSecurityPolicy(p.RepoPath)
	policyMatches := correlatePolicy(findings, policyBody)

	advisoryMatches := []map[string]any{}
	advisoryCount := 0
	advisoryChecked := false
	advisoryErr := ""

	owner, repo, parseErr := parseGitHubOwnerRepo(p.GitHubURL)
	if parseErr == nil {
		advisoryChecked = true
		advisories, err := t.fetchAllAdvisories(ctx, owner, repo)
		if err != nil {
			advisoryErr = err.Error()
		} else {
			advisoryCount = len(advisories)
			advisoryMatches = correlateAdvisories(findings, advisories)
		}
	}

	policyStatus := "not_found"
	if policyPath != "" {
		policyStatus = "found"
	}
	if policyErr != nil {
		policyStatus = "error"
	}

	resp := map[string]any{
		"status": "ok",
		"policy": map[string]any{
			"status":      policyStatus,
			"path":        policyPath,
			"error":       errText(policyErr),
			"match_count": len(policyMatches),
			"matches":     policyMatches,
		},
		"advisories": map[string]any{
			"checked":     advisoryChecked,
			"count":       advisoryCount,
			"error":       advisoryErr,
			"match_count": len(advisoryMatches),
			"matches":     advisoryMatches,
		},
	}

	out, _ := json.Marshal(resp)
	return string(out), nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func asDisclosureString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.0f", x)
	case int:
		return fmt.Sprintf("%d", x)
	default:
		return ""
	}
}

func parseGitHubOwnerRepo(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("github_url not provided")
	}
	if strings.HasPrefix(s, "git@github.com:") {
		parts := strings.Split(strings.TrimPrefix(s, "git@github.com:"), "/")
		if len(parts) >= 2 {
			return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
		}
		return "", "", fmt.Errorf("invalid github ssh URL")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(u.Hostname(), "github.com") {
		return "", "", fmt.Errorf("github_url must point to github.com")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("github_url must include owner/repo")
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
}

func findSecurityPolicy(repoPath string) (string, string, error) {
	maxDepth := 4
	var found string
	err := filepath.WalkDir(repoPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, _ := filepath.Rel(repoPath, p)
		if rel == "." {
			return nil
		}
		depth := strings.Count(filepath.ToSlash(rel), "/") + 1
		if d.IsDir() {
			if depth > maxDepth {
				return filepath.SkipDir
			}
			name := strings.ToLower(d.Name())
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > maxDepth {
			return nil
		}
		name := strings.ToLower(d.Name())
		if name == "security.md" || name == "security.txt" || name == "security" {
			found = p
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return "", "", err
	}
	if found == "" {
		return "", "", nil
	}
	b, err := os.ReadFile(found)
	if err != nil {
		return found, "", err
	}
	return found, string(b), nil
}

func correlatePolicy(findings []disclosureFinding, policyText string) []map[string]any {
	if strings.TrimSpace(policyText) == "" {
		return []map[string]any{}
	}
	policyLines := splitRelevantPolicyLines(policyText)
	out := make([]map[string]any, 0)
	for _, f := range findings {
		fClass := classifyVuln(f.Title + " " + f.CWE)
		componentTokens := tokenSet(componentFromLocation(f.Location))
		for _, ln := range policyLines {
			reason := ""
			if containsAll(ln, "out of scope") || containsAll(ln, "out-of-scope") {
				reason = "out_of_scope"
			}
			if reason == "" && (strings.Contains(ln, "accepted risk") || strings.Contains(ln, "won't fix") || strings.Contains(ln, "wont fix")) {
				reason = "accepted_risk"
			}
			if reason == "" {
				continue
			}
			matchesClass := fClass != "" && strings.Contains(ln, strings.ReplaceAll(fClass, "_", " "))
			matchesComp := overlaps(componentTokens, tokenSet(ln))
			if matchesClass || matchesComp {
				out = append(out, map[string]any{
					"finding_id": f.ID,
					"reason":     reason,
					"excerpt":    truncate(strings.TrimSpace(ln), 240),
				})
				break
			}
		}
	}
	return out
}

func splitRelevantPolicyLines(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		t := strings.ToLower(strings.TrimSpace(ln))
		if t == "" {
			continue
		}
		if strings.Contains(t, "out of scope") || strings.Contains(t, "out-of-scope") || strings.Contains(t, "accepted risk") || strings.Contains(t, "won't fix") || strings.Contains(t, "wont fix") {
			out = append(out, t)
		}
	}
	return out
}

func containsAll(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func tokenSet(s string) map[string]struct{} {
	set := map[string]struct{}{}
	re := regexp.MustCompile(`[a-zA-Z0-9_]+`)
	for _, tok := range re.FindAllString(strings.ToLower(s), -1) {
		if len(tok) < 3 {
			continue
		}
		set[tok] = struct{}{}
	}
	return set
}

func overlaps(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

func componentFromLocation(loc string) string {
	if loc == "" {
		return ""
	}
	parts := strings.Split(loc, ":")
	p := strings.TrimSpace(parts[0])
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 {
		return ""
	}
	if len(segs) == 1 {
		return segs[0]
	}
	return segs[len(segs)-2] + " " + segs[len(segs)-1]
}

func classifyVuln(text string) string {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "sql") && strings.Contains(t, "inject"):
		return "sql_injection"
	case strings.Contains(t, "xss") || strings.Contains(t, "cross site scripting"):
		return "xss"
	case strings.Contains(t, "ssrf"):
		return "ssrf"
	case strings.Contains(t, "command") && strings.Contains(t, "inject"):
		return "command_injection"
	case strings.Contains(t, "path traversal") || strings.Contains(t, "directory traversal"):
		return "path_traversal"
	case strings.Contains(t, "open redirect"):
		return "open_redirect"
	case strings.Contains(t, "csrf"):
		return "csrf"
	case strings.Contains(t, "deserial"):
		return "insecure_deserialization"
	case strings.Contains(t, "idor") || strings.Contains(t, "insecure direct object"):
		return "idor"
	default:
		return ""
	}
}

func (t AssessDisclosureContextTool) fetchAllAdvisories(ctx context.Context, owner, repo string) ([]ghsaAdvisory, error) {
	base := strings.TrimRight(t.GitHubAPIBaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	hc := t.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	ua := strings.TrimSpace(t.UserAgent)
	if ua == "" {
		ua = "late-sast/1.0 (assess_disclosure_context; +https://github.com/giveen/late-sast)"
	}

	all := make([]ghsaAdvisory, 0)
	for page := 1; page <= 30; page++ {
		u := fmt.Sprintf("%s/repos/%s/%s/security-advisories?per_page=100&page=%d", base, owner, repo, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", ua)

		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 3<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return []ghsaAdvisory{}, nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("advisories API status %d: %s", resp.StatusCode, truncate(string(body), 180))
		}
		var batch []ghsaAdvisory
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("parse advisories page %d: %w", page, err)
		}
		if len(batch) == 0 {
			break
		}
		all = append(all, batch...)
	}
	return all, nil
}

func correlateAdvisories(findings []disclosureFinding, advisories []ghsaAdvisory) []map[string]any {
	matches := make([]map[string]any, 0)
	for _, f := range findings {
		fClass := classifyVuln(f.Title + " " + f.CWE)
		fComp := tokenSet(componentFromLocation(f.Location))
		for _, a := range advisories {
			score := 0
			reasons := make([]string, 0, 3)
			if f.CVE != "" && strings.EqualFold(f.CVE, strings.TrimSpace(a.CVEID)) {
				score++
				reasons = append(reasons, "same_cve")
			}
			aClass := classifyVuln(a.Summary)
			if fClass != "" && aClass != "" && fClass == aClass {
				score++
				reasons = append(reasons, "same_vuln_class")
			}
			pkgTokens := map[string]struct{}{}
			for _, v := range a.Vulns {
				for tok := range tokenSet(v.Package.Name) {
					pkgTokens[tok] = struct{}{}
				}
			}
			for tok := range tokenSet(a.Summary) {
				pkgTokens[tok] = struct{}{}
			}
			if overlaps(fComp, pkgTokens) {
				score++
				reasons = append(reasons, "same_component")
			}
			if score >= 2 {
				matches = append(matches, map[string]any{
					"finding_id":    f.ID,
					"ghsa_id":       a.GHSAID,
					"cve_id":        a.CVEID,
					"severity":      strings.ToLower(strings.TrimSpace(a.Severity)),
					"published_at":  a.PublishedAt,
					"html_url":      a.HTMLURL,
					"summary":       truncate(strings.TrimSpace(a.Summary), 240),
					"match_reasons": reasons,
				})
			}
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		a := fmt.Sprintf("%v|%v", matches[i]["finding_id"], matches[i]["ghsa_id"])
		b := fmt.Sprintf("%v|%v", matches[j]["finding_id"], matches[j]["ghsa_id"])
		return a < b
	})

	uniq := make([]map[string]any, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		k := fmt.Sprintf("%v|%v", m["finding_id"], m["ghsa_id"])
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, m)
	}
	return uniq
}
