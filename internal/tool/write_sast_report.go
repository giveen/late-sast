package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// WriteSASTReportTool assembles a normalized, de-duplicated SAST security
// report from structured finding records and writes it to disk.
type WriteSASTReportTool struct{}

// ReportFinding is the structured input for one finding.
type ReportFinding struct {
	ID             string `json:"id"`                   // H1, H2, …
	Title          string `json:"title"`                // e.g. "SSRF — RemoteImageController"
	Location       string `json:"location"`             // "File.cs:158 — FunctionName"
	CWE            int    `json:"cwe"`                  // 918
	AuditorVerdict string `json:"auditor_verdict"`      // CONFIRMED | LIKELY | NEEDS_CONTEXT
	TaintPath      string `json:"taint_path"`           // source → sink
	Severity       string `json:"severity"`             // CRITICAL | HIGH | MEDIUM | LOW
	ExploitStatus  string `json:"exploit_status"`       // EXPLOITED | BLOCKED | UNREACHABLE | INCONCLUSIVE
	ReplayVerdict  string `json:"replay_verdict"`       // from run_exploit_replay (optional)
	Impact         string `json:"impact"`               // one sentence
	Reproduce      string `json:"reproduce"`            // bash command block
	Fix            string `json:"fix"`                  // remediation text
	VulnerableCode string `json:"vulnerable_code"`      // exact lines from source
	CodeLang       string `json:"vulnerable_code_lang"` // go, java, cs, …
	Notes          string `json:"notes"`                // additional context
}

// ReportCVE is one entry in the CVE findings table.
type ReportCVE struct {
	CVE         string  `json:"cve"`
	Package     string  `json:"package"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Link        string  `json:"link"`
	Advisory    string  `json:"advisory"` // optional GHSA link
}

// ScanCoverage records scan metrics for the coverage footer.
type ScanCoverage struct {
	Languages         string `json:"languages"`
	EntryPoints       int    `json:"entry_points"`
	FunctionsAnalysed int    `json:"functions_analysed"`
	AppVersion        string `json:"app_version"`
	GraphNodes        int    `json:"graph_nodes"`
	GraphEdges        int    `json:"graph_edges"`
}

func (t WriteSASTReportTool) Name() string { return "write_sast_report" }

func (t WriteSASTReportTool) Description() string {
	return "Assemble a normalized, de-duplicated SAST security report from structured findings and write it to disk. Enforces consistent section ordering, field casing, and deduplication."
}

func (t WriteSASTReportTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"output_path": {"type": "string", "description": "Absolute path to write the report markdown file"},
			"target": {"type": "string", "description": "Scan target URL or local path"},
			"repo_name": {"type": "string", "description": "Repository short name (used in heading and filename)"},
			"app_version": {"type": "string", "description": "Scanned application version"},
			"analyzer_version": {"type": "string", "description": "late-sast version string"},
			"executive_summary": {"type": "string", "description": "Optional 2-3 sentence executive summary override; auto-generated if omitted"},
			"findings": {
				"type": "array",
				"description": "Structured finding records",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"title": {"type": "string"},
						"location": {"type": "string"},
						"cwe": {"type": "integer"},
						"auditor_verdict": {"type": "string", "enum": ["CONFIRMED","LIKELY","NEEDS_CONTEXT"]},
						"taint_path": {"type": "string"},
						"severity": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW"]},
						"exploit_status": {"type": "string", "enum": ["EXPLOITED","BLOCKED","UNREACHABLE","INCONCLUSIVE"]},
						"replay_verdict": {"type": "string"},
						"impact": {"type": "string"},
						"reproduce": {"type": "string"},
						"fix": {"type": "string"},
						"vulnerable_code": {"type": "string"},
						"vulnerable_code_lang": {"type": "string"},
						"notes": {"type": "string"}
					},
					"required": ["title","location","cwe","auditor_verdict","severity","exploit_status","impact","fix"]
				}
			},
			"cve_findings": {
				"type": "array",
				"description": "CVE table entries",
				"items": {
					"type": "object",
					"properties": {
						"cve": {"type": "string"},
						"package": {"type": "string"},
						"cvss": {"type": "number"},
						"severity": {"type": "string"},
						"description": {"type": "string"},
						"link": {"type": "string"},
						"advisory": {"type": "string"}
					},
					"required": ["cve","package","cvss","severity","description"]
				}
			},
			"informational": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Informational notes (bullet points)"
			},
			"previously_disclosed": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Previously disclosed advisory notes (markdown formatted)"
			},
			"scan_coverage": {
				"type": "object",
				"properties": {
					"languages": {"type": "string"},
					"entry_points": {"type": "integer"},
					"functions_analysed": {"type": "integer"},
					"app_version": {"type": "string"},
					"graph_nodes": {"type": "integer"},
					"graph_edges": {"type": "integer"}
				}
			},
			"remediation_priority": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Ordered remediation steps. Auto-generated from findings if omitted."
			}
		},
		"required": ["output_path","target","repo_name","findings"]
	}`)
}

func (t WriteSASTReportTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t WriteSASTReportTool) CallString(args json.RawMessage) string {
	var p struct {
		RepoName string `json:"repo_name"`
	}
	_ = json.Unmarshal(args, &p)
	return fmt.Sprintf("write_sast_report(repo=%q)", p.RepoName)
}

func (t WriteSASTReportTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		OutputPath          string          `json:"output_path"`
		Target              string          `json:"target"`
		RepoName            string          `json:"repo_name"`
		AppVersion          string          `json:"app_version"`
		AnalyzerVersion     string          `json:"analyzer_version"`
		ExecutiveSummary    string          `json:"executive_summary"`
		Findings            []ReportFinding `json:"findings"`
		CVEFindings         []ReportCVE     `json:"cve_findings"`
		Informational       []string        `json:"informational"`
		PreviouslyDisclosed []string        `json:"previously_disclosed"`
		ScanCoverage        *ScanCoverage   `json:"scan_coverage"`
		RemediationPriority []string        `json:"remediation_priority"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.OutputPath) == "" {
		return "", fmt.Errorf("output_path is required")
	}
	if strings.TrimSpace(p.RepoName) == "" {
		return "", fmt.Errorf("repo_name is required")
	}
	if strings.TrimSpace(p.Target) == "" {
		return "", fmt.Errorf("target is required")
	}

	// Normalize and validate findings.
	findings, validationErrors := normalizeFindings(p.Findings)
	if len(validationErrors) > 0 {
		return "", fmt.Errorf("finding validation errors:\n%s", strings.Join(validationErrors, "\n"))
	}

	// Normalize CVE findings.
	cves := normalizeCVEs(p.CVEFindings)

	// Deduplicate findings.
	findings = deduplicateFindings(findings)

	// Split into active findings and needs-context.
	var active, needsContext []ReportFinding
	for _, f := range findings {
		if f.AuditorVerdict == "NEEDS_CONTEXT" {
			needsContext = append(needsContext, f)
		} else {
			active = append(active, f)
		}
	}

	// Sort active findings: CRITICAL → HIGH → MEDIUM → LOW, then by title.
	sort.SliceStable(active, func(i, j int) bool {
		si := severityRank(active[i].Severity)
		sj := severityRank(active[j].Severity)
		if si != sj {
			return si > sj
		}
		return active[i].Title < active[j].Title
	})

	// Count by severity.
	counts := map[string]int{}
	exploited := 0
	for _, f := range active {
		counts[f.Severity]++
		if f.ExploitStatus == "EXPLOITED" {
			exploited++
		}
	}

	analyzerVer := strings.TrimSpace(p.AnalyzerVersion)
	if analyzerVer == "" {
		analyzerVer = "v1.8.4"
	}

	execSummary := strings.TrimSpace(p.ExecutiveSummary)
	if execSummary == "" {
		execSummary = generateExecutiveSummary(p.RepoName, active, cves, exploited)
	}

	var sb strings.Builder

	// Header.
	fmt.Fprintf(&sb, "# SAST Security Report — %s\n", p.RepoName)
	fmt.Fprintf(&sb, "Date: %s\n", time.Now().Format("2006-01-02"))
	fmt.Fprintf(&sb, "Target: %s\n", strings.TrimSpace(p.Target))
	if strings.TrimSpace(p.AppVersion) != "" {
		fmt.Fprintf(&sb, "Version: %s\n", strings.TrimSpace(p.AppVersion))
	}
	fmt.Fprintf(&sb, "Analyzer: late-sast %s (llm-sast-scanner + live verification)\n", analyzerVer)
	sb.WriteString("\n")

	// Executive Summary.
	sb.WriteString("## Executive Summary\n")
	sb.WriteString(execSummary)
	sb.WriteString("\n\n")

	// Finding sections — only emit non-empty severity blocks.
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		var sevFindings []ReportFinding
		for _, f := range active {
			if f.Severity == sev {
				sevFindings = append(sevFindings, f)
			}
		}
		if len(sevFindings) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "## %s Findings\n\n", capitalize(sev))
		for _, f := range sevFindings {
			writeFinding(&sb, f)
		}
	}

	// Dependency Vulnerabilities (CVE findings with advisory links).
	var highCVEs []ReportCVE
	for _, c := range cves {
		if c.CVSS >= 7.0 {
			highCVEs = append(highCVEs, c)
		}
	}
	if len(highCVEs) > 0 {
		sb.WriteString("## Dependency Vulnerabilities\n\n")
		for _, c := range highCVEs {
			fmt.Fprintf(&sb, "### %s — %s\n", c.CVE, c.Description)
			fmt.Fprintf(&sb, "- **Package:** %s\n", c.Package)
			fmt.Fprintf(&sb, "- **CVSS:** %s (%.1f)\n", c.Severity, c.CVSS)
			fmt.Fprintf(&sb, "- **Severity:** %s\n", c.Severity)
			fmt.Fprintf(&sb, "- **Description:** %s\n", c.Description)
			if c.Link != "" {
				fmt.Fprintf(&sb, "- **Link:** [Advisory](%s)\n", c.Link)
			}
			sb.WriteString("\n")
		}
	}

	// CVE Findings table — all CVEs.
	if len(cves) > 0 {
		sb.WriteString("## CVE Findings\n")
		sb.WriteString("| CVE | Package | CVSS | Severity | Description | Link |\n")
		sb.WriteString("|-----|---------|------|----------|-------------|------|\n")
		for _, c := range cves {
			link := ""
			if c.Link != "" {
				link = fmt.Sprintf("[NVD](%s)", c.Link)
			}
			fmt.Fprintf(&sb, "| %s | %s | %.1f | %s | %s | %s |\n",
				c.CVE, c.Package, c.CVSS, c.Severity, c.Description, link)
		}
		sb.WriteString("\n")
		// Previously disclosed advisories.
		for _, d := range p.PreviouslyDisclosed {
			fmt.Fprintf(&sb, "> %s\n", strings.TrimPrefix(strings.TrimSpace(d), "> "))
		}
		if len(p.PreviouslyDisclosed) > 0 {
			sb.WriteString("\n")
		}
	}

	// Informational.
	if len(p.Informational) > 0 {
		sb.WriteString("## Informational\n")
		for _, note := range p.Informational {
			fmt.Fprintf(&sb, "- %s\n", strings.TrimPrefix(strings.TrimSpace(note), "- "))
		}
		sb.WriteString("\n")
	}

	// Unverifiable findings.
	if len(needsContext) > 0 {
		sb.WriteString("## Unverifiable Findings (NEEDS CONTEXT)\n\n")
		for _, f := range needsContext {
			fmt.Fprintf(&sb, "### %s — %s (NEEDS CONTEXT)\n", f.Title, f.Location)
			if f.Notes != "" {
				fmt.Fprintf(&sb, "- **Missing context:** %s\n", f.Notes)
			}
			if f.Fix != "" {
				fmt.Fprintf(&sb, "- **Recommendation:** %s\n", f.Fix)
			}
			sb.WriteString("\n")
		}
	}

	// Remediation Priority.
	sb.WriteString("## Remediation Priority\n")
	if len(p.RemediationPriority) > 0 {
		for i, step := range p.RemediationPriority {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, strings.TrimSpace(step))
		}
	} else {
		// Auto-generate from sorted active findings.
		for i, f := range active {
			statusNote := ""
			if f.ExploitStatus == "EXPLOITED" {
				statusNote = " (**actively exploitable**)"
			}
			fmt.Fprintf(&sb, "%d. **%s — %s%s:** %s\n", i+1, f.Severity, f.Title, statusNote, f.Fix)
		}
	}
	sb.WriteString("\n")

	// Scan Coverage.
	sb.WriteString("## Scan Coverage\n")
	if p.ScanCoverage != nil {
		c := p.ScanCoverage
		if c.Languages != "" {
			fmt.Fprintf(&sb, "Languages: %s\n", c.Languages)
		}
		if c.EntryPoints > 0 {
			fmt.Fprintf(&sb, "Entry points: %d\n", c.EntryPoints)
		}
		if c.FunctionsAnalysed > 0 {
			fmt.Fprintf(&sb, "Functions analysed: %d\n", c.FunctionsAnalysed)
		}
		appVer := c.AppVersion
		if appVer == "" {
			appVer = strings.TrimSpace(p.AppVersion)
		}
		if appVer != "" {
			fmt.Fprintf(&sb, "App version: %s\n", appVer)
		}
		if c.GraphNodes > 0 || c.GraphEdges > 0 {
			fmt.Fprintf(&sb, "Graph nodes: %d | Edges: %d\n", c.GraphNodes, c.GraphEdges)
		}
	}
	countLine := fmt.Sprintf("Findings: %d critical / %d high / %d medium / %d low",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
	fmt.Fprintf(&sb, "%s\n", countLine)
	fmt.Fprintf(&sb, "Exploited: %d / %d total\n", exploited, len(active))
	sb.WriteString("\n")

	// Footer.
	fmt.Fprintf(&sb, "---\n*Report generated by late-sast %s on %s*\n", analyzerVer, time.Now().Format("2006-01-02"))

	// Write file.
	if err := os.MkdirAll(filepath.Dir(p.OutputPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := os.WriteFile(p.OutputPath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	result := map[string]any{
		"status":        "ok",
		"output_path":   p.OutputPath,
		"findings":      len(active),
		"needs_context": len(needsContext),
		"cve_findings":  len(cves),
		"counts":        counts,
		"exploited":     exploited,
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func writeFinding(sb *strings.Builder, f ReportFinding) {
	cweStr := ""
	if f.CWE > 0 {
		cweStr = fmt.Sprintf(" (CWE-%d)", f.CWE)
	}
	fmt.Fprintf(sb, "### %s%s\n", f.Title, cweStr)

	if f.Location != "" {
		fmt.Fprintf(sb, "- **Location:** `%s`\n", f.Location)
	}
	fmt.Fprintf(sb, "- **Auditor Verdict:** %s\n", f.AuditorVerdict)
	if f.TaintPath != "" {
		fmt.Fprintf(sb, "- **Taint Path:** `%s`\n", f.TaintPath)
	}
	fmt.Fprintf(sb, "- **Severity:** %s\n", f.Severity)
	fmt.Fprintf(sb, "- **Exploit Status:** %s\n", exploitStatusLabel(f.ExploitStatus))
	fmt.Fprintf(sb, "- **Impact:** %s\n", f.Impact)

	if f.VulnerableCode != "" {
		lang := f.CodeLang
		if lang == "" {
			lang = ""
		}
		fmt.Fprintf(sb, "- **Vulnerable code:**\n  ```%s\n%s\n  ```\n", lang, indentBlock(f.VulnerableCode, "  "))
	}

	if f.Reproduce != "" {
		reproduce := strings.TrimSpace(f.Reproduce)
		fmt.Fprintf(sb, "- **Reproduce:**\n  ```bash\n%s\n  ```\n", indentBlock(reproduce, "  "))
	}

	fmt.Fprintf(sb, "- **Fix:** %s\n", f.Fix)
	if f.Notes != "" {
		fmt.Fprintf(sb, "- **Notes:** %s\n", f.Notes)
	}
	sb.WriteString("\n")
}

func normalizeFindings(findings []ReportFinding) ([]ReportFinding, []string) {
	var errs []string
	validSeverities := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	validVerdicts := map[string]bool{"CONFIRMED": true, "LIKELY": true, "NEEDS_CONTEXT": true}
	validStatus := map[string]bool{"EXPLOITED": true, "BLOCKED": true, "UNREACHABLE": true, "INCONCLUSIVE": true}

	// Map replay tool verdicts to exploit status values.
	replayToStatus := map[string]string{
		"exploited":    "EXPLOITED",
		"blocked":      "BLOCKED",
		"unreachable":  "UNREACHABLE",
		"inconclusive": "INCONCLUSIVE",
	}

	out := make([]ReportFinding, 0, len(findings))
	for i, f := range findings {
		ref := fmt.Sprintf("finding[%d] (%s)", i, f.ID)

		// Normalize string fields.
		f.Title = strings.TrimSpace(f.Title)
		f.Location = strings.TrimSpace(f.Location)
		f.AuditorVerdict = strings.ToUpper(strings.TrimSpace(f.AuditorVerdict))
		f.Severity = strings.ToUpper(strings.TrimSpace(f.Severity))
		f.ExploitStatus = strings.ToUpper(strings.TrimSpace(f.ExploitStatus))
		f.ReplayVerdict = strings.ToLower(strings.TrimSpace(f.ReplayVerdict))
		f.Impact = strings.TrimSpace(f.Impact)
		f.Fix = strings.TrimSpace(f.Fix)

		// If replay_verdict is set, it overrides exploit_status (source of truth).
		if mapped, ok := replayToStatus[f.ReplayVerdict]; ok {
			f.ExploitStatus = mapped
		}

		// Validation.
		if f.Title == "" {
			errs = append(errs, fmt.Sprintf("%s: title is required", ref))
		}
		if f.Location == "" {
			errs = append(errs, fmt.Sprintf("%s: location is required", ref))
		}
		if f.CWE <= 0 {
			errs = append(errs, fmt.Sprintf("%s: cwe must be a positive integer", ref))
		}
		if !validSeverities[f.Severity] {
			errs = append(errs, fmt.Sprintf("%s: severity %q is invalid (must be CRITICAL|HIGH|MEDIUM|LOW)", ref, f.Severity))
		}
		if !validVerdicts[f.AuditorVerdict] {
			errs = append(errs, fmt.Sprintf("%s: auditor_verdict %q is invalid (must be CONFIRMED|LIKELY|NEEDS_CONTEXT)", ref, f.AuditorVerdict))
		}
		if !validStatus[f.ExploitStatus] {
			errs = append(errs, fmt.Sprintf("%s: exploit_status %q is invalid (must be EXPLOITED|BLOCKED|UNREACHABLE|INCONCLUSIVE)", ref, f.ExploitStatus))
		}
		if f.Impact == "" {
			errs = append(errs, fmt.Sprintf("%s: impact is required", ref))
		}
		if f.Fix == "" {
			errs = append(errs, fmt.Sprintf("%s: fix is required", ref))
		}

		out = append(out, f)
	}
	return out, errs
}

func normalizeCVEs(cves []ReportCVE) []ReportCVE {
	out := make([]ReportCVE, 0, len(cves))
	seen := map[string]bool{}
	for _, c := range cves {
		c.CVE = strings.TrimSpace(c.CVE)
		c.Severity = strings.ToUpper(strings.TrimSpace(c.Severity))
		if c.CVE == "" || seen[c.CVE] {
			continue
		}
		seen[c.CVE] = true
		out = append(out, c)
	}
	// Sort: CVSS descending.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CVSS > out[j].CVSS
	})
	return out
}

// deduplicateFindings removes findings with the same (location, cwe) pair,
// keeping the one with the highest severity.
func deduplicateFindings(findings []ReportFinding) []ReportFinding {
	type key struct {
		location string
		cwe      int
	}
	seen := map[key]int{}
	result := make([]ReportFinding, 0, len(findings))

	for _, f := range findings {
		k := key{location: strings.ToLower(f.Location), cwe: f.CWE}
		if idx, exists := seen[k]; exists {
			// Keep whichever has higher severity.
			if severityRank(f.Severity) > severityRank(result[idx].Severity) {
				result[idx] = f
			}
			continue
		}
		seen[k] = len(result)
		result = append(result, f)
	}
	return result
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func exploitStatusLabel(s string) string {
	switch s {
	case "EXPLOITED":
		return "EXPLOITED ✓"
	case "BLOCKED":
		return "BLOCKED"
	case "UNREACHABLE":
		return "UNREACHABLE"
	case "INCONCLUSIVE":
		return "INCONCLUSIVE"
	default:
		return s
	}
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return s[0:1] + strings.ToLower(s[1:])
}

func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func generateExecutiveSummary(repoName string, findings []ReportFinding, cves []ReportCVE, exploited int) string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	total := len(findings)
	if total == 0 {
		return fmt.Sprintf("Analysis of the %s codebase found no actionable findings.", repoName)
	}

	var severityParts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if n := counts[sev]; n > 0 {
			severityParts = append(severityParts, fmt.Sprintf("**%d %s**", n, capitalize(sev)))
		}
	}

	// Find highest-severity finding for lead sentence.
	var lead string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		for _, f := range findings {
			if f.Severity == sev {
				lead = f.Title
				break
			}
		}
		if lead != "" {
			break
		}
	}

	summary := fmt.Sprintf("Analysis of the %s codebase identified %s across %d finding(s). "+
		"The most critical vulnerability is **%s**. "+
		"Live replay verification confirmed %d of %d finding(s) as actively exploitable",
		repoName,
		strings.Join(severityParts, " and "),
		total,
		lead,
		exploited,
		total,
	)
	if len(cves) > 0 {
		summary += fmt.Sprintf("; additionally %d CVE finding(s) were identified in project dependencies", len(cves))
	}
	summary += "."
	return summary
}
