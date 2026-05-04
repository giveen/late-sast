package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBootstrapScanToolchainTool_RequiresContainerName(t *testing.T) {
	tool := BootstrapScanToolchainTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"repo_path":"/repo"}`))
	if err == nil {
		t.Fatal("expected missing container_name error")
	}
	if !strings.Contains(err.Error(), "container_name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBootstrapScanToolchainTool_HappyPath(t *testing.T) {
	tool := BootstrapScanToolchainTool{
		Runner: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "docker" {
				return "", fmt.Errorf("unexpected executable: %s", name)
			}
			cmd := strings.Join(args, " ")

			switch {
			case strings.Contains(cmd, "echo apt"):
				return "apt\n", nil
			case strings.Contains(cmd, "find '/repo'"):
				return "", nil
			case strings.Contains(cmd, "command -v"):
				return "ok\n", nil
			default:
				return "done\n", nil
			}
		},
	}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"container_name":"target"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got: %v", resp["status"])
	}
	if resp["container_name"] != "target" {
		t.Fatalf("unexpected container_name: %v", resp["container_name"])
	}
	if resp["package_manager"] != "apt" {
		t.Fatalf("expected package_manager apt, got: %v", resp["package_manager"])
	}
	availability, ok := resp["availability"].(map[string]any)
	if !ok {
		t.Fatalf("availability map missing: %#v", resp["availability"])
	}
	if availability["trivy"] != "available" {
		t.Fatalf("expected trivy available, got: %v", availability["trivy"])
	}
}

func TestBootstrapScanToolchainTool_UnknownPackageManagerIsPartial(t *testing.T) {
	tool := BootstrapScanToolchainTool{
		Runner: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "docker" {
				return "", nil
			}
			cmd := strings.Join(args, " ")
			if strings.Contains(cmd, "echo apt") {
				return "unknown\n", nil
			}
			if strings.Contains(cmd, "command -v") {
				return "missing\n", nil
			}
			return "", nil
		},
	}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"container_name":"target","repo_path":"/repo"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["status"] != "partial" {
		t.Fatalf("expected partial status, got: %v", resp["status"])
	}
	if !strings.Contains(fmt.Sprint(resp["reason"]), "unknown package manager") {
		t.Fatalf("unexpected reason: %v", resp["reason"])
	}
}
