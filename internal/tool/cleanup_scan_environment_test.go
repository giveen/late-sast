package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCleanupScanEnvironmentTool_RequiresCoreFields(t *testing.T) {
	tool := CleanupScanEnvironmentTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"container":"c"}`))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "container, compose_project, network, and workdir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupScanEnvironmentTool_HappyPath(t *testing.T) {
	tool := CleanupScanEnvironmentTool{
		Runner: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "docker" {
				return "", fmt.Errorf("unexpected executable: %s", name)
			}
			cmd := strings.Join(args, " ")
			switch {
			case strings.Contains(cmd, "ps -aq"):
				return "cid1\ncid2\n", nil
			default:
				return "ok\n", nil
			}
		},
	}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{
		"container":"scan-app",
		"compose_project":"scan-proj",
		"network":"scan-net",
		"workdir":"/tmp/sast-123"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp["status"])
	}
	if resp["image_tag"] != "scan-app-image" {
		t.Fatalf("expected default image tag scan-app-image, got %v", resp["image_tag"])
	}
	if resp["success_count"] != float64(8) {
		t.Fatalf("expected success_count 8, got %v", resp["success_count"])
	}
}

func TestCleanupScanEnvironmentTool_PartialWhenStepsFail(t *testing.T) {
	tool := CleanupScanEnvironmentTool{
		Runner: func(_ context.Context, name string, args ...string) (string, error) {
			cmd := strings.Join(args, " ")
			if strings.Contains(cmd, "network rm") || strings.Contains(cmd, "rmi") {
				return "failed\n", fmt.Errorf("not found")
			}
			if strings.Contains(cmd, "ps -aq") {
				return "\n", nil
			}
			return "ok\n", nil
		},
	}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{
		"container":"scan-app",
		"compose_project":"scan-proj",
		"network":"scan-net",
		"workdir":"/tmp/sast-123",
		"image_tag":"custom-image"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp["status"] != "partial" {
		t.Fatalf("expected status partial, got %v", resp["status"])
	}
	if resp["image_tag"] != "custom-image" {
		t.Fatalf("expected custom image tag, got %v", resp["image_tag"])
	}
}

func TestCleanupScanEnvironmentTool_MountsWorkdirParentForArbitraryPath(t *testing.T) {
	var removeWorkdirCmd string
	tool := CleanupScanEnvironmentTool{
		Runner: func(_ context.Context, _ string, args ...string) (string, error) {
			cmd := strings.Join(args, " ")
			if strings.Contains(cmd, "run --rm") && strings.Contains(cmd, "<workdir-parent>") {
				// not expected in real command path
			}
			if len(args) >= 8 && args[0] == "run" && args[1] == "--rm" && args[2] == "-v" && args[4] == "alpine" {
				if strings.Contains(args[3], "/home/user/work") {
					removeWorkdirCmd = cmd
				}
			}
			if strings.Contains(cmd, "ps -aq") {
				return "\n", nil
			}
			return "ok\n", nil
		},
	}

	_, err := tool.Execute(context.Background(), json.RawMessage(`{
		"container":"scan-app",
		"compose_project":"scan-proj",
		"network":"scan-net",
		"workdir":"/home/user/work/sast-run"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(removeWorkdirCmd, "-v /home/user/work:/home/user/work") {
		t.Fatalf("expected workdir parent mount for arbitrary path, got command: %s", removeWorkdirCmd)
	}
	if !strings.Contains(removeWorkdirCmd, "rm -rf '/home/user/work/sast-run'") {
		t.Fatalf("expected cleanup command to target absolute workdir path, got command: %s", removeWorkdirCmd)
	}
}
