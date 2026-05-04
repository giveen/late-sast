package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// RunSemgrepScanTool runs semgrep inside a scan container and returns structured
// SAST findings ready to feed into write_sast_report. Handles rule-pack selection
// automatically based on detected language and auto-installs semgrep if absent.
type RunSemgrepScanTool struct {
	Runner setupCommandRunner
}

func (t RunSemgrepScanTool) Name() string { return "run_semgrep_scan" }

func (t RunSemgrepScanTool) Description() string {
	return "Run semgrep SAST inside a container and return structured findings. Auto-selects language-appropriate rule packs and installs semgrep when absent."
}

func (t RunSemgrepScanTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_name": {"type": "string", "description": "Scan container name (docker exec target)"},
			"scan_path": {"type": "string", "description": "Path inside container to scan (default: /app)"},
			"language": {"type": "string", "description": "Language hint for rule-pack selection: go, rust, python, javascript, typescript, java, c, ruby, php (default: auto-detect)"},
			"rule_packs": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Explicit semgrep rule packs to use (overrides auto-selection). E.g. ['p/security-audit', 'p/owasp-top-ten']"
			},
			"severity_filter": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Semgrep severity levels to include: ERROR, WARNING, INFO (default: ERROR, WARNING)"
			},
			"max_findings": {"type": "integer", "description": "Maximum findings to return (default: 100)"},
			"timeout_seconds": {"type": "integer", "description": "Semgrep scan timeout in seconds (default: 120, max: 300)"}
		},
		"required": ["container_name"]
	}`)
}

func (t RunSemgrepScanTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t RunSemgrepScanTool) CallString(args json.RawMessage) string {
	var p struct {
		ContainerName string `json:"container_name"`
		ScanPath      string `json:"scan_path"`
	}
	_ = json.Unmarshal(args, &p)
	scanPath := strings.TrimSpace(p.ScanPath)
	if scanPath == "" {
		scanPath = "/app"
	}
	return fmt.Sprintf("run_semgrep_scan(container=%q, path=%q)", p.ContainerName, scanPath)
}

func (t RunSemgrepScanTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		ContainerName  string   `json:"container_name"`
		ScanPath       string   `json:"scan_path"`
		Language       string   `json:"language"`
		RulePacks      []string `json:"rule_packs"`
		SeverityFilter []string `json:"severity_filter"`
		MaxFindings    int      `json:"max_findings"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.ContainerName) == "" {
		return "", fmt.Errorf("container_name is required")
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}

	if strings.TrimSpace(p.ScanPath) == "" {
		p.ScanPath = "/app"
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 120
	}
	if p.TimeoutSeconds > 300 {
		p.TimeoutSeconds = 300
	}
	if p.MaxFindings <= 0 {
		p.MaxFindings = 100
	}
	if len(p.SeverityFilter) == 0 {
		p.SeverityFilter = []string{"ERROR", "WARNING"}
	}

	// Ensure semgrep is available.
	if installed, err := t.ensureSemgrep(ctx, runner, p.ContainerName); err != nil || !installed {
		result := map[string]any{
			"status":    "skipped",
			"reason":    "semgrep not available and could not be installed",
			"findings":  []any{},
			"total":     0,
			"installed": false,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	// Detect language if not specified.
	lang := strings.ToLower(strings.TrimSpace(p.Language))
	if lang == "" {
		lang = t.detectLanguage(ctx, runner, p.ContainerName, p.ScanPath)
	}

	// Select rule packs.
	packs := p.RulePacks
	if len(packs) == 0 {
		packs = defaultRulePacks(lang)
	}

	// Build semgrep command.
	configArgs := ""
	for _, pack := range packs {
		configArgs += fmt.Sprintf(" --config=%s", pack)
	}
	semgrepCmd := fmt.Sprintf(
		"semgrep%s --json --quiet --timeout %d %s 2>/dev/null",
		configArgs,
		p.TimeoutSeconds,
		p.ScanPath,
	)

	raw, err := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", semgrepCmd)
	if err != nil && strings.TrimSpace(raw) == "" {
		result := map[string]any{
			"status":   "error",
			"reason":   fmt.Sprintf("semgrep failed: %v", err),
			"findings": []any{},
			"total":    0,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	findings, parseErr := parseSemgrepJSON(raw, p.SeverityFilter, p.MaxFindings)
	if parseErr != nil {
		result := map[string]any{
			"status":     "partial",
			"reason":     fmt.Sprintf("JSON parse error: %v", parseErr),
			"raw_output": truncate(strings.TrimSpace(raw), 3000),
			"findings":   []any{},
			"total":      0,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	result := map[string]any{
		"status":             "ok",
		"container_name":     p.ContainerName,
		"scan_path":          p.ScanPath,
		"detected_language":  lang,
		"rule_packs_used":    packs,
		"total":              len(findings),
		"counts_by_severity": counts,
		"findings":           findings,
	}
	encoded, _ := json.Marshal(result)
	return string(encoded), nil
}

// ensureSemgrep checks whether semgrep is present and installs it if not.
func (t RunSemgrepScanTool) ensureSemgrep(ctx context.Context, runner setupCommandRunner, container string) (bool, error) {
	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v semgrep >/dev/null 2>&1 && echo ok || echo missing")
	if strings.TrimSpace(out) == "ok" {
		return true, nil
	}

	installCmd := `pipx install semgrep 2>/dev/null || pip install --quiet --break-system-packages semgrep 2>/dev/null || python3 -m pip install --quiet --break-system-packages semgrep 2>/dev/null || true`
	_, _ = runner(ctx, "docker", "exec", container, "sh", "-c", installCmd)

	out2, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v semgrep >/dev/null 2>&1 && echo ok || echo missing")
	return strings.TrimSpace(out2) == "ok", nil
}

// detectLanguage probes common language marker files to choose rule packs.
func (t RunSemgrepScanTool) detectLanguage(ctx context.Context, runner setupCommandRunner, container, scanPath string) string {
	probeCmd := fmt.Sprintf(`
		test -f %s/go.mod             && echo go         && exit 0
		test -f %s/Cargo.toml         && echo rust       && exit 0
		test -f %s/package.json       && echo javascript && exit 0
		test -f %s/tsconfig.json      && echo typescript && exit 0
		test -f %s/requirements.txt   && echo python     && exit 0
		test -f %s/setup.py           && echo python     && exit 0
		test -f %s/pom.xml            && echo java       && exit 0
		test -f %s/build.gradle       && echo java       && exit 0
		test -f %s/Gemfile            && echo ruby       && exit 0
		test -f %s/composer.json      && echo php        && exit 0
		find %s -maxdepth 3 -name '*.c' -o -name '*.cpp' -o -name '*.h' 2>/dev/null | head -1 | grep -q . && echo c && exit 0
		echo unknown
	`, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath, scanPath)

	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", probeCmd)
	lang := strings.TrimSpace(out)
	if lang == "" || lang == "unknown" {
		return "unknown"
	}
	return lang
}

// defaultRulePacks returns the recommended semgrep rule packs for a given language.
func defaultRulePacks(lang string) []string {
	switch lang {
	case "go":
		return []string{"p/golang", "p/security-audit", "p/owasp-top-ten"}
	case "rust":
		return []string{"p/rust", "p/security-audit"}
	case "python":
		return []string{"p/python", "p/security-audit", "p/owasp-top-ten"}
	case "javascript":
		return []string{"p/javascript", "p/security-audit", "p/owasp-top-ten", "p/nodejs"}
	case "typescript":
		return []string{"p/typescript", "p/javascript", "p/security-audit", "p/owasp-top-ten"}
	case "java":
		return []string{"p/java", "p/security-audit", "p/owasp-top-ten"}
	case "ruby":
		return []string{"p/ruby", "p/security-audit"}
	case "php":
		return []string{"p/php", "p/security-audit", "p/owasp-top-ten"}
	case "c", "cpp", "c++":
		return []string{"p/c", "p/security-audit"}
	default:
		return []string{"p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"}
	}
}

// semgrepFinding is the structured output record for one semgrep result.
type semgrepFinding struct {
	CheckID  string `json:"check_id"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"col"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	CWE      string `json:"cwe,omitempty"`
	OWASP    string `json:"owasp,omitempty"`
	Fix      string `json:"fix,omitempty"`
	RuleURL  string `json:"rule_url,omitempty"`
}

// rawSemgrepOutput mirrors the Semgrep JSON output schema we care about.
type rawSemgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		Extra struct {
			Message  string                     `json:"message"`
			Severity string                     `json:"severity"`
			Metadata map[string]json.RawMessage `json:"metadata"`
			Fix      string                     `json:"fix"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func parseSemgrepJSON(raw string, severityFilter []string, maxFindings int) ([]semgrepFinding, error) {
	idx := strings.Index(raw, "{")
	if idx < 0 {
		return nil, fmt.Errorf("no JSON object in semgrep output")
	}
	raw = raw[idx:]

	var out rawSemgrepOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("unmarshal semgrep JSON: %w", err)
	}

	// Build a set of accepted severities.
	severitySet := map[string]bool{}
	for _, s := range severityFilter {
		severitySet[strings.ToUpper(s)] = true
	}

	var findings []semgrepFinding
	for _, r := range out.Results {
		sev := strings.ToUpper(r.Extra.Severity)
		if len(severitySet) > 0 && !severitySet[sev] {
			continue
		}

		cwe := extractMetaString(r.Extra.Metadata, "cwe")
		owasp := extractMetaString(r.Extra.Metadata, "owasp")
		ruleURL := fmt.Sprintf("https://semgrep.dev/r/%s", r.CheckID)

		findings = append(findings, semgrepFinding{
			CheckID:  r.CheckID,
			Path:     r.Path,
			Line:     r.Start.Line,
			Column:   r.Start.Col,
			Severity: sev,
			Message:  truncate(strings.TrimSpace(r.Extra.Message), 300),
			CWE:      cwe,
			OWASP:    owasp,
			Fix:      strings.TrimSpace(r.Extra.Fix),
			RuleURL:  ruleURL,
		})
		if maxFindings > 0 && len(findings) >= maxFindings {
			break
		}
	}
	return findings, nil
}

// extractMetaString pulls a string value from semgrep's metadata map.
// Values can be strings or arrays of strings; we take the first.
func extractMetaString(meta map[string]json.RawMessage, key string) string {
	raw, ok := meta[key]
	if !ok {
		return ""
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try array of strings.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}
	return ""
}
