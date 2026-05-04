package tool

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type setupCall struct {
	name string
	args []string
}

func TestSetupContainerTool_SuccessCreatesNetworkAndInstalls(t *testing.T) {
	calls := make([]setupCall, 0)
	tool := SetupContainerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, setupCall{name: name, args: append([]string{}, args...)})
		if len(args) >= 3 && args[0] == "network" && args[1] == "inspect" {
			return "", errors.New("not found")
		}
		if len(args) >= 2 && args[0] == "exec" {
			return "installed", nil
		}
		return "ok", nil
	}}

	args := json.RawMessage(`{
		"image":"golang:1.23",
		"container_name":"sast-123",
		"network_name":"sast-123-net",
		"workdir":"/tmp/sast-123",
		"install_command":"go install github.com/foo/bar@latest"
	}`)

	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"ok"`) {
		t.Fatalf("expected ok status, got %s", out)
	}

	wantPrefix := []setupCall{
		{name: "docker", args: []string{"network", "inspect", "sast-123-net"}},
		{name: "docker", args: []string{"network", "create", "sast-123-net"}},
		{name: "docker", args: []string{"rm", "-f", "sast-123"}},
	}
	if len(calls) < len(wantPrefix) {
		t.Fatalf("too few calls: got %d", len(calls))
	}
	for i, w := range wantPrefix {
		if calls[i].name != w.name || !reflect.DeepEqual(calls[i].args, w.args) {
			t.Fatalf("call %d mismatch\n got: %s %v\nwant: %s %v", i, calls[i].name, calls[i].args, w.name, w.args)
		}
	}

	foundRun := false
	foundExec := false
	for _, c := range calls {
		if len(c.args) >= 2 && c.args[0] == "run" && c.args[1] == "-d" {
			foundRun = true
		}
		if len(c.args) >= 2 && c.args[0] == "exec" && c.args[1] == "sast-123" {
			foundExec = true
		}
	}
	if !foundRun {
		t.Fatal("expected docker run call")
	}
	if !foundExec {
		t.Fatal("expected docker exec call")
	}
}

func TestSetupContainerTool_NoCreateWhenNetworkExists(t *testing.T) {
	calls := make([]setupCall, 0)
	tool := SetupContainerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, setupCall{name: name, args: append([]string{}, args...)})
		if len(args) >= 2 && args[0] == "exec" {
			return "ok", nil
		}
		return "ok", nil
	}}

	args := json.RawMessage(`{
		"image":"python:3.11-slim",
		"container_name":"sast-1",
		"network_name":"net-1",
		"workdir":"/tmp/sast-1",
		"install_command":"pip install semgrep"
	}`)
	if _, err := tool.Execute(context.Background(), args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range calls {
		if len(c.args) >= 2 && c.args[0] == "network" && c.args[1] == "create" {
			t.Fatal("did not expect network create when inspect succeeds")
		}
	}
}

func TestSetupContainerTool_ValidationError(t *testing.T) {
	tool := SetupContainerTool{}
	_, err := tool.Execute(context.Background(), json.RawMessage(`{"image":"node:20-slim"}`))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestSetupContainerTool_InstallFailure(t *testing.T) {
	tool := SetupContainerTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 1 && args[0] == "exec" {
			return "boom", errors.New("exit status 1")
		}
		return "ok", nil
	}}
	args := json.RawMessage(`{
		"image":"node:20-slim",
		"container_name":"sast-2",
		"network_name":"net-2",
		"workdir":"/tmp/sast-2",
		"install_command":"npm i -g foo"
	}`)
	_, err := tool.Execute(context.Background(), args)
	if err == nil {
		t.Fatal("expected install failure")
	}
	if !strings.Contains(err.Error(), "install command failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
