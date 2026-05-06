package sast

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRunSecretsScanner_BasicParsing(t *testing.T) {
	report := `
{"DetectorName":"AWS","DetectorType":"AWS","Verified":true,"Redacted":"AKIA****","SourceType":"filesystem","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/.env","line":12}}}}
{"DetectorName":"Slack","DetectorType":"Slack","Verified":false,"Redacted":"xoxb-****","SourceType":"filesystem","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/config.yml","line":7}}}}
`
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "ok", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected ok status, got %v", result["status"])
	}
	if int(result["total"].(float64)) != 2 {
		t.Fatalf("expected 2 findings, got %v", result["total"])
	}

	findings := result["findings"].([]any)
	first := findings[0].(map[string]any)
	if first["detector"] != "AWS" {
		t.Errorf("unexpected detector: %v", first["detector"])
	}
	if first["file"] != "/app/.env" {
		t.Errorf("unexpected file: %v", first["file"])
	}
	if int(first["line"].(float64)) != 12 {
		t.Errorf("unexpected line: %v", first["line"])
	}
}

func TestRunSecretsScanner_OnlyVerified(t *testing.T) {
	report := `
{"DetectorName":"A","Verified":true,"Redacted":"a","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/a","line":1}}}}
{"DetectorName":"B","Verified":false,"Redacted":"b","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/b","line":2}}}}
`
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "ok", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c", "only_verified": true})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if int(result["total"].(float64)) != 1 {
		t.Fatalf("expected 1 verified finding, got %v", result["total"])
	}
}

func TestRunSecretsScanner_Deduplicates(t *testing.T) {
	report := `
{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/.env","line":3}}}}
{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/.env","line":3}}}}
`
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "ok", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			return report, nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if int(result["total"].(float64)) != 1 {
		t.Fatalf("expected deduped finding count=1, got %v", result["total"])
	}
}

func TestRunSecretsScanner_AutoInstall(t *testing.T) {
	calls := 0
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			calls++
			if calls == 1 {
				return "missing", nil
			}
			return "ok", nil
		}
		if containsStr(joined, "install.sh") {
			return "", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			return "", nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "ok" {
		t.Fatalf("expected ok status after install, got %v", result["status"])
	}
}

func TestRunSecretsScanner_Unavailable(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "missing", nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c"})
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(out), &result)
	if result["status"] != "skipped" {
		t.Fatalf("expected skipped status, got %v", result["status"])
	}
}

func TestRunSecretsScanner_RequiresContainerName(t *testing.T) {
	tool := RunSecretsScannerTool{}
	args, _ := json.Marshal(map[string]any{})
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Fatal("expected error for missing container_name")
	}
}

func TestRunSecretsScanner_AppliesTimeoutSecondsToScan(t *testing.T) {
	var scanCtxHasDeadline bool
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "ok", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			deadline, ok := ctx.Deadline()
			if ok {
				scanCtxHasDeadline = time.Until(deadline) > 0
			}
			return "", nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{"container_name": "c", "timeout_seconds": 2})
	_, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !scanCtxHasDeadline {
		t.Fatal("expected trufflehog scan context to have deadline")
	}
}

func TestRunSecretsScanner_QuotesScanPathInShellCommand(t *testing.T) {
	var scanCmd string
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name
		for _, a := range args {
			joined += " " + a
		}
		if containsStr(joined, "command -v trufflehog") {
			return "ok", nil
		}
		if containsStr(joined, "trufflehog filesystem") {
			if len(args) >= 5 {
				scanCmd = args[4]
			}
			return "", nil
		}
		return "", nil
	}

	tool := RunSecretsScannerTool{Runner: runner}
	args, _ := json.Marshal(map[string]any{
		"container_name": "c",
		"scan_path":      "/app; echo pwned",
	})
	_, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(scanCmd, "'/app; echo pwned'") {
		t.Fatalf("expected scan_path to be shell-quoted, got command: %s", scanCmd)
	}
}

// ---------------------------------------------------------------------------
// asInt unit tests
// ---------------------------------------------------------------------------

func TestAsInt_Float64(t *testing.T) {
	if got := asInt(float64(42)); got != 42 {
		t.Errorf("asInt(float64(42)) = %d, want 42", got)
	}
}

func TestAsInt_Int(t *testing.T) {
	if got := asInt(int(7)); got != 7 {
		t.Errorf("asInt(int(7)) = %d, want 7", got)
	}
}

func TestAsInt_Int64(t *testing.T) {
	if got := asInt(int64(100)); got != 100 {
		t.Errorf("asInt(int64(100)) = %d, want 100", got)
	}
}

func TestAsInt_JSONNumber(t *testing.T) {
	if got := asInt(json.Number("55")); got != 55 {
		t.Errorf("asInt(json.Number(55)) = %d, want 55", got)
	}
}

func TestAsInt_String(t *testing.T) {
	if got := asInt("99"); got != 99 {
		t.Errorf("asInt(string 99) = %d, want 99", got)
	}
}

func TestAsInt_StringWithSpaces(t *testing.T) {
	if got := asInt("  12  "); got != 12 {
		t.Errorf("asInt(padded string) = %d, want 12", got)
	}
}

func TestAsInt_NilReturnsZero(t *testing.T) {
	if got := asInt(nil); got != 0 {
		t.Errorf("asInt(nil) = %d, want 0", got)
	}
}

func TestAsInt_NonNumericStringReturnsZero(t *testing.T) {
	if got := asInt("not-a-number"); got != 0 {
		t.Errorf("asInt(non-numeric) = %d, want 0", got)
	}
}

func TestAsInt_BoolReturnsZero(t *testing.T) {
	if got := asInt(true); got != 0 {
		t.Errorf("asInt(bool) = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// extractTrufflehogLocation unit tests
// ---------------------------------------------------------------------------

func TestExtractTrufflehogLocation_Filesystem(t *testing.T) {
	m := map[string]any{
		"SourceMetadata": map[string]any{
			"Data": map[string]any{
				"Filesystem": map[string]any{
					"file": "/app/.env",
					"line": float64(12),
				},
			},
		},
	}
	file, line := extractTrufflehogLocation(m)
	if file != "/app/.env" {
		t.Errorf("file = %q, want /app/.env", file)
	}
	if line != 12 {
		t.Errorf("line = %d, want 12", line)
	}
}

func TestExtractTrufflehogLocation_Git(t *testing.T) {
	m := map[string]any{
		"SourceMetadata": map[string]any{
			"Data": map[string]any{
				"Git": map[string]any{
					"file": "secrets/key.go",
					"line": float64(7),
				},
			},
		},
	}
	file, line := extractTrufflehogLocation(m)
	if file != "secrets/key.go" {
		t.Errorf("file = %q, want secrets/key.go", file)
	}
	if line != 7 {
		t.Errorf("line = %d, want 7", line)
	}
}

func TestExtractTrufflehogLocation_FlatDataFallback(t *testing.T) {
	m := map[string]any{
		"SourceMetadata": map[string]any{
			"Data": map[string]any{
				"file": "flat/path.go",
				"line": float64(3),
			},
		},
	}
	file, line := extractTrufflehogLocation(m)
	if file != "flat/path.go" {
		t.Errorf("file = %q, want flat/path.go", file)
	}
	if line != 3 {
		t.Errorf("line = %d, want 3", line)
	}
}

func TestExtractTrufflehogLocation_NilSourceMetadata(t *testing.T) {
	m := map[string]any{}
	file, line := extractTrufflehogLocation(m)
	if file != "" || line != 0 {
		t.Errorf("expected empty, got file=%q line=%d", file, line)
	}
}

func TestExtractTrufflehogLocation_NilData(t *testing.T) {
	m := map[string]any{
		"SourceMetadata": map[string]any{},
	}
	file, line := extractTrufflehogLocation(m)
	if file != "" || line != 0 {
		t.Errorf("expected empty, got file=%q line=%d", file, line)
	}
}

func TestExtractTrufflehogLocation_EmptyFilesystemBlock(t *testing.T) {
	m := map[string]any{
		"SourceMetadata": map[string]any{
			"Data": map[string]any{
				"Filesystem": map[string]any{},
			},
		},
	}
	file, line := extractTrufflehogLocation(m)
	// Empty Filesystem block: file is empty string from asString, line is 0.
	if file != "" || line != 0 {
		t.Errorf("expected empty filesystem block to give empty result, got file=%q line=%d", file, line)
	}
}
