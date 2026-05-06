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
			// Batch probe: pm + command presence + project markers.
			case strings.Contains(cmd, "java_project"):
				return "pm=apt\nnode=ok\ngo=ok\ncargo=ok\njava_project=no\nnode_project=no\n", nil
			// Batch availability check.
			case strings.Contains(cmd, "cargo_audit"):
				return "curl=available\ngit=available\njq=available\npython3=available\npipx=available\njava=available\nnode=available\ntrivy=available\nsemgrep=available\nchecksec=available\ngosec=available\ncargo_audit=available\n", nil
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
			if strings.Contains(cmd, "java_project") {
				return "pm=unknown\nnode=missing\ngo=missing\ncargo=missing\njava_project=no\nnode_project=no\n", nil
			}
			if strings.Contains(cmd, "cargo_audit") {
				return "curl=missing\ngit=missing\njq=missing\npython3=missing\npipx=missing\njava=missing\nnode=missing\ntrivy=missing\nsemgrep=missing\nchecksec=missing\ngosec=missing\ncargo_audit=missing\n", nil
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
