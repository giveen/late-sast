package tool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type launchCall struct {
	name string
	args []string
}

func TestLaunchDockerTool_NoAssets(t *testing.T) {
	repo := t.TempDir()
	tool := LaunchDockerTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "network" && args[1] == "inspect" {
			return "ok", nil
		}
		return "ok", nil
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net"
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"no_docker_assets"`) {
		t.Fatalf("expected no_docker_assets, got: %s", out)
	}
}

func TestLaunchDockerTool_ComposePreferred(t *testing.T) {
	repo := t.TempDir()
	composePath := filepath.Join(repo, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(repo, "svc"), 0755)
	_ = os.WriteFile(filepath.Join(repo, "svc", "Dockerfile"), []byte("FROM alpine\n"), 0644)

	calls := make([]launchCall, 0)
	tool := LaunchDockerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, launchCall{name: name, args: append([]string{}, args...)})
		if len(args) >= 3 && args[0] == "network" && args[1] == "inspect" {
			return "ok", nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps --services --status running"):
			return "web\nredis\n", nil
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps -q web"):
			return "abc123\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.Name}}":
			return "/myproj-web-1\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}]}` + "\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net",
		"compose_project":"myproj"
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"mode_used":"compose"`) {
		t.Fatalf("expected compose mode, got: %s", out)
	}
	if !strings.Contains(out, `"service":"web"`) {
		t.Fatalf("expected web service, got: %s", out)
	}

	foundComposeUp := false
	for _, c := range calls {
		if c.name == "docker" && len(c.args) >= 1 && c.args[0] == "compose" {
			if strings.Contains(strings.Join(c.args, " "), "up -d") {
				foundComposeUp = true
			}
		}
	}
	if !foundComposeUp {
		t.Fatal("expected docker compose up call")
	}
}

func TestLaunchDockerTool_DockerfileFallback(t *testing.T) {
	repo := t.TempDir()
	dockerfilePath := filepath.Join(repo, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	calls := make([]launchCall, 0)
	tool := LaunchDockerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, launchCall{name: name, args: append([]string{}, args...)})
		if len(args) >= 2 && args[0] == "network" && args[1] == "inspect" {
			return "ok", nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "build -t"):
			return "built", nil
		case len(args) >= 2 && args[0] == "inspect" && args[len(args)-1] == "repo-app":
			return "container-id-1\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return "{}\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net",
		"container_name_prefix":"repo"
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"mode_used":"dockerfile"`) {
		t.Fatalf("expected dockerfile mode, got: %s", out)
	}

	foundBuild := false
	foundRun := false
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "build -t") {
			foundBuild = true
		}
		if strings.Contains(joined, "run -d") {
			foundRun = true
		}
	}
	if !foundBuild || !foundRun {
		t.Fatalf("expected build+run calls, got %+v", calls)
	}
}

func TestLaunchDockerTool_CreateNetworkWhenMissing(t *testing.T) {
	repo := t.TempDir()
	calls := 0
	tool := LaunchDockerTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		calls++
		if len(args) >= 2 && args[0] == "network" && args[1] == "inspect" {
			return "", errors.New("missing")
		}
		if len(args) >= 2 && args[0] == "network" && args[1] == "create" {
			return "created", nil
		}
		return "ok", nil
	}}

	args := json.RawMessage(`{"repo_path":"` + repo + `","network_name":"sast-net"}`)
	if _, err := tool.Execute(context.Background(), args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls == 0 {
		t.Fatal("expected runner to be called")
	}
}

func TestLaunchDockerTool_ComposePortConflictTriggersCleanup(t *testing.T) {
	repo := t.TempDir()
	composePath := filepath.Join(repo, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	calls := make([]launchCall, 0)
	tool := LaunchDockerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, launchCall{name: name, args: append([]string{}, args...)})
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "inspect":
			return "ok", nil
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps --services --status running"):
			return "web\n", nil
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps -q web"):
			return "abc123\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.Name}}":
			return "/conflict-web-1\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}` + "\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net",
		"compose_project":"myproj",
		"recreate":false,
		"reserved_host_ports":[8080]
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"port_conflict"`) {
		t.Fatalf("expected port_conflict, got: %s", out)
	}

	foundConflictCleanup := false
	for _, c := range calls {
		if c.name != "docker" {
			continue
		}
		if strings.Contains(strings.Join(c.args, " "), "compose -p myproj -f "+composePath+" down --remove-orphans") {
			foundConflictCleanup = true
			break
		}
	}
	if !foundConflictCleanup {
		t.Fatal("expected compose down cleanup on reserved port conflict")
	}
}

func TestLaunchDockerTool_DockerfilePortConflictRemovesContainer(t *testing.T) {
	repo := t.TempDir()
	dockerfilePath := filepath.Join(repo, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	calls := make([]launchCall, 0)
	tool := LaunchDockerTool{Runner: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, launchCall{name: name, args: append([]string{}, args...)})
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "inspect":
			return "ok", nil
		case strings.Contains(joined, "build -t"):
			return "built", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}` + "\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net",
		"container_name_prefix":"repo",
		"recreate":false,
		"reserved_host_ports":[8080]
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"status":"port_conflict"`) {
		t.Fatalf("expected port_conflict, got: %s", out)
	}

	removed := false
	for _, c := range calls {
		if c.name == "docker" && len(c.args) >= 3 && c.args[0] == "rm" && c.args[1] == "-f" && c.args[2] == "repo-app" {
			removed = true
			break
		}
	}
	if !removed {
		t.Fatal("expected docker rm -f repo-app on reserved port conflict")
	}
}

func TestLaunchDockerTool_ComposeVariantDetectedInNestedDir(t *testing.T) {
	repo := t.TempDir()
	composePath := filepath.Join(repo, "docker", "compose.dev.yaml")
	if err := os.MkdirAll(filepath.Dir(composePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tool := LaunchDockerTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "inspect":
			return "ok", nil
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps --services --status running"):
			return "web\n", nil
		case strings.Contains(joined, "compose") && strings.Contains(joined, "ps -q web"):
			return "abc123\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{.Name}}":
			return "/myproj-web-1\n", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}]}` + "\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net"
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"mode_used":"compose"`) {
		t.Fatalf("expected compose mode, got: %s", out)
	}
	if !strings.Contains(out, `"compose_path":"`+composePath+`"`) {
		t.Fatalf("expected compose path %s in output, got: %s", composePath, out)
	}
}

func TestLaunchDockerTool_DockerfileVariantDetectedInNestedDir(t *testing.T) {
	repo := t.TempDir()
	dockerfilePath := filepath.Join(repo, "docker", "unified", "Dockerfile.dev")
	if err := os.MkdirAll(filepath.Dir(dockerfilePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tool := LaunchDockerTool{Runner: func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case len(args) >= 2 && args[0] == "network" && args[1] == "inspect":
			return "ok", nil
		case strings.Contains(joined, "build -t"):
			return "built", nil
		case len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" && args[2] == "{{json .NetworkSettings.Ports}}":
			return "{}\n", nil
		default:
			return "ok", nil
		}
	}}

	args := json.RawMessage(`{
		"repo_path":"` + repo + `",
		"network_name":"sast-net",
		"container_name_prefix":"repo"
	}`)
	out, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"mode_used":"dockerfile"`) {
		t.Fatalf("expected dockerfile mode, got: %s", out)
	}
	if !strings.Contains(out, `"dockerfile_path":"`+dockerfilePath+`"`) {
		t.Fatalf("expected dockerfile path %s in output, got: %s", dockerfilePath, out)
	}
}
