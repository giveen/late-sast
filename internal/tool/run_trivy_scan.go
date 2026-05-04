package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RunTrivyScanTool runs Trivy inside a scan container and returns structured
// CVE findings ready to pass directly into write_sast_report's cve_findings field.
// Auto-installs Trivy when absent, deduplicates by CVE ID, and filters by CVSS threshold.
type RunTrivyScanTool struct {
	Runner setupCommandRunner
}

func (t RunTrivyScanTool) Name() string { return "run_trivy_scan" }

func (t RunTrivyScanTool) Description() string {
	return "Run Trivy SCA/CVE scan inside a container filesystem and return structured CVE findings for write_sast_report. Auto-installs Trivy if absent."
}

func (t RunTrivyScanTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_name": {"type": "string", "description": "Scan container name (docker exec target)"},
			"scan_path": {"type": "string", "description": "Path inside container to scan (default: /app)"},
			"cvss_threshold": {"type": "number", "description": "Minimum CVSS score to include (default: 0.0 = all; use 7.0 for HIGH+ only)"},
			"severity_filter": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Trivy severity levels to include (default: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN)"
			},
			"include_unfixed": {"type": "boolean", "description": "Include unfixed vulnerabilities (default: true)"},
			"scanners": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Trivy scanner types: vuln, secret, config (default: [vuln])"
			},
			"timeout_seconds": {"type": "integer", "description": "Trivy scan timeout in seconds (default: 120, max: 300)"}
		},
		"required": ["container_name"]
	}`)
}

func (t RunTrivyScanTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t RunTrivyScanTool) CallString(args json.RawMessage) string {
	var p struct {
		ContainerName string `json:"container_name"`
		ScanPath      string `json:"scan_path"`
	}
	_ = json.Unmarshal(args, &p)
	scanPath := strings.TrimSpace(p.ScanPath)
	if scanPath == "" {
		scanPath = "/app"
	}
	return fmt.Sprintf("run_trivy_scan(container=%q, path=%q)", p.ContainerName, scanPath)
}

func (t RunTrivyScanTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		ContainerName  string   `json:"container_name"`
		ScanPath       string   `json:"scan_path"`
		CVSSThreshold  float64  `json:"cvss_threshold"`
		SeverityFilter []string `json:"severity_filter"`
		IncludeUnfixed *bool    `json:"include_unfixed"`
		Scanners       []string `json:"scanners"`
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
	if len(p.SeverityFilter) == 0 {
		p.SeverityFilter = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}
	if len(p.Scanners) == 0 {
		p.Scanners = []string{"vuln"}
	}
	includeUnfixed := true
	if p.IncludeUnfixed != nil {
		includeUnfixed = *p.IncludeUnfixed
	}

	// Ensure Trivy is available.
	if installed, err := t.ensureTrivy(ctx, runner, p.ContainerName); err != nil || !installed {
		result := map[string]any{
			"status":    "skipped",
			"reason":    "trivy not available and could not be installed",
			"findings":  []any{},
			"total":     0,
			"installed": false,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	// Build the trivy command.
	severityArg := strings.Join(p.SeverityFilter, ",")
	scannersArg := strings.Join(p.Scanners, ",")
	unfixedFlag := ""
	if includeUnfixed {
		unfixedFlag = "--include-unfixed"
	}

	trivyCmd := fmt.Sprintf(
		"trivy fs --format json --quiet --timeout %ds --severity %s --scanners %s %s %s 2>/dev/null",
		p.TimeoutSeconds,
		severityArg,
		scannersArg,
		unfixedFlag,
		p.ScanPath,
	)

	out, err := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", trivyCmd)
	if err != nil {
		// Trivy exits non-zero when vulnerabilities are found — treat output as valid.
		if strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("trivy scan failed: %w", err)
		}
	}

	findings, trivyVersion, skippedCount, err := parseTrivyJSON(out, p.CVSSThreshold)
	if err != nil {
		// Fall back to table format for a human-readable summary.
		tableOut, tableErr := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c",
			fmt.Sprintf("trivy fs --format table --quiet --severity %s %s 2>/dev/null | head -80", severityArg, p.ScanPath))
		if tableErr != nil {
			tableOut = ""
		}
		result := map[string]any{
			"status":     "partial",
			"reason":     fmt.Sprintf("JSON parse error (%v) — raw table output follows", err),
			"raw_output": truncate(strings.TrimSpace(tableOut), 4000),
			"findings":   []any{},
			"total":      0,
		}
		out2, _ := json.Marshal(result)
		return string(out2), nil
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	result := map[string]any{
		"status":             "ok",
		"container_name":     p.ContainerName,
		"scan_path":          p.ScanPath,
		"trivy_version":      trivyVersion,
		"cvss_threshold":     p.CVSSThreshold,
		"total":              len(findings),
		"skipped_low_cvss":   skippedCount,
		"counts_by_severity": counts,
		"findings":           findings,
	}
	encoded, _ := json.Marshal(result)
	return string(encoded), nil
}

// ensureTrivy checks whether trivy is present in the container and installs it if not.
// Returns (true, nil) when trivy is available after the call.
func (t RunTrivyScanTool) ensureTrivy(ctx context.Context, runner setupCommandRunner, container string) (bool, error) {
	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v trivy >/dev/null 2>&1 && echo ok || echo missing")
	if strings.TrimSpace(out) == "ok" {
		return true, nil
	}

	// Install via the official install script.
	installCmd := "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>&1"
	_, _ = runner(ctx, "docker", "exec", container, "sh", "-c", installCmd)

	// Verify.
	out2, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v trivy >/dev/null 2>&1 && echo ok || echo missing")
	return strings.TrimSpace(out2) == "ok", nil
}

// trivyVuln is the minimal JSON shape for one Trivy vulnerability result.
type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	CVSS             map[string]struct {
		V3Score float64 `json:"V3Score"`
		V2Score float64 `json:"V2Score"`
	} `json:"CVSS"`
	References []string `json:"References"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Metadata      struct {
		ImageConfig struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		} `json:"ImageConfig"`
	} `json:"Metadata"`
	Results []trivyResult `json:"Results"`
}

// TrivyFinding is the structured output record, matching ReportCVE layout for
// direct use in write_sast_report.
type TrivyFinding struct {
	CVE              string  `json:"cve"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	CVSS             float64 `json:"cvss"`
	Severity         string  `json:"severity"`
	Description      string  `json:"description"`
	Link             string  `json:"link"`
	Target           string  `json:"target"`
}

func parseTrivyJSON(raw string, cvssThreshold float64) ([]TrivyFinding, string, int, error) {
	// Trivy sometimes emits progress lines before the JSON. Find the first '{'.
	idx := strings.Index(raw, "{")
	if idx < 0 {
		return nil, "", 0, fmt.Errorf("no JSON object in trivy output")
	}
	raw = raw[idx:]

	var report trivyReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return nil, "", 0, fmt.Errorf("unmarshal trivy JSON: %w", err)
	}

	seen := map[string]bool{}
	var findings []TrivyFinding
	skipped := 0

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			cvssScore := bestCVSSScore(v.CVSS)
			if cvssThreshold > 0 && cvssScore < cvssThreshold {
				skipped++
				continue
			}
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true

			desc := strings.TrimSpace(v.Title)
			if desc == "" {
				desc = truncate(strings.TrimSpace(v.Description), 200)
			}

			link := nvdLink(v.VulnerabilityID)
			for _, ref := range v.References {
				if strings.Contains(ref, "nvd.nist.gov") {
					link = ref
					break
				}
			}

			pkg := v.PkgName
			if v.InstalledVersion != "" {
				pkg += "@" + v.InstalledVersion
			}

			findings = append(findings, TrivyFinding{
				CVE:              v.VulnerabilityID,
				Package:          pkg,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				CVSS:             cvssScore,
				Severity:         strings.ToUpper(strings.TrimSpace(v.Severity)),
				Description:      desc,
				Link:             link,
				Target:           result.Target,
			})
		}
	}

	// Sort: CVSS descending.
	sortTrivyFindings(findings)
	return findings, "", skipped, nil
}

func bestCVSSScore(cvss map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) float64 {
	best := 0.0
	for _, scores := range cvss {
		if scores.V3Score > best {
			best = scores.V3Score
		}
		if scores.V2Score > best {
			best = scores.V2Score
		}
	}
	return best
}

func nvdLink(cveID string) string {
	if strings.HasPrefix(cveID, "CVE-") {
		return "https://nvd.nist.gov/vuln/detail/" + cveID
	}
	return ""
}

func sortTrivyFindings(findings []TrivyFinding) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && findings[j].CVSS > findings[j-1].CVSS; j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

// trivySeverityRank returns a numeric rank for sorting (higher = more severe).
func trivySeverityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN":
		return 1
	default:
		return 0
	}
}

// Silence unused warning — trivySeverityRank used by tests.
var _ = trivySeverityRank
var _ = strconv.Itoa
