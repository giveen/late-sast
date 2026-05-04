package tool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RunSecretsScannerTool runs TruffleHog inside a scan container and returns
// structured secret findings suitable for scanner workflows.
type RunSecretsScannerTool struct {
	Runner setupCommandRunner
}

func (t RunSecretsScannerTool) Name() string { return "run_secrets_scanner" }

func (t RunSecretsScannerTool) Description() string {
	return "Run TruffleHog secrets scan inside a container filesystem and return structured findings. Auto-installs TruffleHog if absent."
}

func (t RunSecretsScannerTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_name": {"type": "string", "description": "Scan container name (docker exec target)"},
			"scan_path": {"type": "string", "description": "Path inside container to scan (default: /app)"},
			"only_verified": {"type": "boolean", "description": "Return only verified secrets (default: false)"},
			"max_findings": {"type": "integer", "description": "Maximum findings to return (default: 100)"},
			"timeout_seconds": {"type": "integer", "description": "Scan timeout in seconds (default: 180, max: 600)"}
		},
		"required": ["container_name"]
	}`)
}

func (t RunSecretsScannerTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t RunSecretsScannerTool) CallString(args json.RawMessage) string {
	var p struct {
		ContainerName string `json:"container_name"`
		ScanPath      string `json:"scan_path"`
	}
	_ = json.Unmarshal(args, &p)
	scanPath := strings.TrimSpace(p.ScanPath)
	if scanPath == "" {
		scanPath = "/app"
	}
	return fmt.Sprintf("run_secrets_scanner(container=%q, path=%q)", p.ContainerName, scanPath)
}

func (t RunSecretsScannerTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		ContainerName string `json:"container_name"`
		ScanPath      string `json:"scan_path"`
		OnlyVerified  *bool  `json:"only_verified"`
		MaxFindings   int    `json:"max_findings"`
		TimeoutSecs   int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.ContainerName) == "" {
		return "", fmt.Errorf("container_name is required")
	}
	if strings.TrimSpace(p.ScanPath) == "" {
		p.ScanPath = "/app"
	}
	if p.MaxFindings <= 0 {
		p.MaxFindings = 100
	}
	if p.TimeoutSecs <= 0 {
		p.TimeoutSecs = 180
	}
	if p.TimeoutSecs > 600 {
		p.TimeoutSecs = 600
	}
	onlyVerified := false
	if p.OnlyVerified != nil {
		onlyVerified = *p.OnlyVerified
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}

	if ok, _ := t.ensureTruffleHog(ctx, runner, p.ContainerName); !ok {
		result := map[string]any{
			"status":    "skipped",
			"reason":    "trufflehog not available and could not be installed",
			"findings":  []any{},
			"total":     0,
			"installed": false,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	verifiedFlag := ""
	if onlyVerified {
		verifiedFlag = " --only-verified"
	}
	cmd := fmt.Sprintf("trufflehog filesystem --json%s --no-update --fail --results=verified,unknown %s 2>/dev/null", verifiedFlag, p.ScanPath)
	raw, err := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", cmd)
	if err != nil && strings.TrimSpace(raw) == "" {
		result := map[string]any{
			"status":   "error",
			"reason":   fmt.Sprintf("trufflehog scan failed: %v", err),
			"findings": []any{},
			"total":    0,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	findings, parseErr := parseTruffleHogJSONL(raw, onlyVerified, p.MaxFindings)
	if parseErr != nil {
		result := map[string]any{
			"status":     "partial",
			"reason":     fmt.Sprintf("parse error: %v", parseErr),
			"raw_output": truncate(strings.TrimSpace(raw), 3000),
			"findings":   []any{},
			"total":      0,
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	counts := map[string]int{"verified": 0, "unverified": 0}
	for _, f := range findings {
		if f.Verified {
			counts["verified"]++
		} else {
			counts["unverified"]++
		}
	}

	result := map[string]any{
		"status":          "ok",
		"container_name":  p.ContainerName,
		"scan_path":       p.ScanPath,
		"only_verified":   onlyVerified,
		"total":           len(findings),
		"counts":          counts,
		"findings":        findings,
		"scanner_backend": "trufflehog",
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func (t RunSecretsScannerTool) ensureTruffleHog(ctx context.Context, runner setupCommandRunner, container string) (bool, error) {
	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v trufflehog >/dev/null 2>&1 && echo ok || echo missing")
	if strings.TrimSpace(out) == "ok" {
		return true, nil
	}

	installCmd := "curl -sfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true"
	_, _ = runner(ctx, "docker", "exec", container, "sh", "-c", installCmd)

	out2, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v trufflehog >/dev/null 2>&1 && echo ok || echo missing")
	return strings.TrimSpace(out2) == "ok", nil
}

// TruffleHogFinding is a normalized secret finding returned by run_secrets_scanner.
type TruffleHogFinding struct {
	Detector string `json:"detector"`
	Verified bool   `json:"verified"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Redacted string `json:"redacted"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

func parseTruffleHogJSONL(raw string, onlyVerified bool, maxFindings int) ([]TruffleHogFinding, error) {
	s := bufio.NewScanner(strings.NewReader(raw))
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 2*1024*1024)

	seen := map[string]bool{}
	findings := make([]TruffleHogFinding, 0)
	parsedAny := false

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		parsedAny = true

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}

		detector := asString(m["DetectorName"])
		if detector == "" {
			detector = asString(m["DetectorType"])
		}
		verified := asBool(m["Verified"])
		if onlyVerified && !verified {
			continue
		}
		file, lineNo := extractTrufflehogLocation(m)
		if file == "" {
			file = "unknown"
		}
		redacted := strings.TrimSpace(asString(m["Redacted"]))
		source := asString(m["SourceType"])
		category := asString(m["DetectorType"])
		if category == "" {
			category = detector
		}

		key := detector + "|" + file + "|" + strconv.Itoa(lineNo) + "|" + redacted
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, TruffleHogFinding{
			Detector: detector,
			Verified: verified,
			File:     file,
			Line:     lineNo,
			Redacted: truncate(redacted, 120),
			Source:   source,
			Category: category,
		})

		if maxFindings > 0 && len(findings) >= maxFindings {
			break
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	if !parsedAny && strings.TrimSpace(raw) != "" {
		return nil, fmt.Errorf("no parseable JSON lines in trufflehog output")
	}

	return findings, nil
}

func extractTrufflehogLocation(m map[string]any) (string, int) {
	sm, _ := m["SourceMetadata"].(map[string]any)
	if sm == nil {
		return "", 0
	}
	data, _ := sm["Data"].(map[string]any)
	if data == nil {
		return "", 0
	}

	if fs, ok := data["Filesystem"].(map[string]any); ok {
		return asString(fs["file"]), asInt(fs["line"])
	}
	if git, ok := data["Git"].(map[string]any); ok {
		file := asString(git["file"])
		line := asInt(git["line"])
		if file != "" || line != 0 {
			return file, line
		}
	}
	if file := asString(data["file"]); file != "" {
		return file, asInt(data["line"])
	}
	return "", 0
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}
