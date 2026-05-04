package tool

import (
	"context"
	"encoding/json"
	"testing"
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
