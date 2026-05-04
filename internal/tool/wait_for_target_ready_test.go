package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWaitForTargetReadyTool_ReadyViaHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tool := WaitForTargetReadyTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.State.Status}}" {
			return "running\n", nil
		}
		if len(args) >= 2 && args[0] == "logs" && args[1] == "--tail" {
			return "startup logs", nil
		}
		if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}" {
			return "{}\n", nil
		}
		return "", nil
	}}

	args := json.RawMessage(`{
		"container_name":"sast-app",
		"endpoint":"` + srv.URL + `",
		"max_wait_seconds":5,
		"interval_seconds":1
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"ready"`) {
		t.Fatalf("expected ready status, got: %s", out)
	}
	if !strings.Contains(out, srv.URL) {
		t.Fatalf("expected endpoint in output, got: %s", out)
	}
}

func TestWaitForTargetReadyTool_CrashedWhenContainerNotRunning(t *testing.T) {
	tool := WaitForTargetReadyTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.State.Status}}" {
			return "exited\n", nil
		}
		if len(args) >= 2 && args[0] == "logs" && args[1] == "--tail" {
			return "panic: boot failed", nil
		}
		return "", nil
	}}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"container_name":"sast-app"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"crashed"`) {
		t.Fatalf("expected crashed status, got: %s", out)
	}
	if !strings.Contains(out, "panic: boot failed") {
		t.Fatalf("expected logs in diagnostics, got: %s", out)
	}
}

func TestWaitForTargetReadyTool_NotReadyWithoutEndpointOrPorts(t *testing.T) {
	tool := WaitForTargetReadyTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.State.Status}}" {
			return "running\n", nil
		}
		if len(args) >= 2 && args[0] == "logs" && args[1] == "--tail" {
			return "listening only on unix socket", nil
		}
		if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}" {
			return "{}\n", nil
		}
		return "", nil
	}}

	out, err := tool.Execute(context.Background(), json.RawMessage(`{"container_name":"sast-app"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"not_ready"`) {
		t.Fatalf("expected not_ready status, got: %s", out)
	}
	if !strings.Contains(out, "no endpoint could be derived") {
		t.Fatalf("expected endpoint guidance, got: %s", out)
	}
}
