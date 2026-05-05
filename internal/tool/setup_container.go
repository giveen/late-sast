package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// setupCommandRunner executes a command and returns combined stdout/stderr.
type setupCommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// SetupContainerTool creates a Docker container and runs a program install
// command inside it in one deterministic tool call.
type SetupContainerTool struct {
	Runner setupCommandRunner
}

func (t SetupContainerTool) Name() string { return "setup_container" }

func (t SetupContainerTool) Description() string {
	return "Create a Docker network/container and run a program installation command inside it in one deterministic call."
}

func (t SetupContainerTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {"type": "string", "description": "Docker image to run (e.g. golang:1.23, python:3.11-slim)"},
			"container_name": {"type": "string", "description": "Container name to create"},
			"network_name": {"type": "string", "description": "Docker network name to attach"},
			"workdir": {"type": "string", "description": "Host work directory to mount at /workdir"},
			"install_command": {"type": "string", "description": "Command to run inside container to install the program"},
			"startup_command": {"type": "string", "description": "Optional container startup command (default: tail -f /dev/null)"},
			"recreate": {"type": "boolean", "description": "Remove existing container with same name before creating (default: true)"}
		},
		"required": ["image", "container_name", "network_name", "workdir", "install_command"]
	}`)
}

func (t SetupContainerTool) RequiresConfirmation(args json.RawMessage) bool { return false }

func (t SetupContainerTool) CallString(args json.RawMessage) string {
	var p struct {
		Image         string `json:"image"`
		ContainerName string `json:"container_name"`
		NetworkName   string `json:"network_name"`
	}
	_ = json.Unmarshal(args, &p)
	if p.Image == "" {
		return "setup_container(...)"
	}
	return fmt.Sprintf("setup_container(image=%q, container=%q, network=%q)", p.Image, p.ContainerName, p.NetworkName)
}

func (t SetupContainerTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Image          string `json:"image"`
		ContainerName  string `json:"container_name"`
		NetworkName    string `json:"network_name"`
		Workdir        string `json:"workdir"`
		InstallCommand string `json:"install_command"`
		StartupCommand string `json:"startup_command"`
		Recreate       *bool  `json:"recreate"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.Image) == "" ||
		strings.TrimSpace(p.ContainerName) == "" ||
		strings.TrimSpace(p.NetworkName) == "" ||
		strings.TrimSpace(p.Workdir) == "" ||
		strings.TrimSpace(p.InstallCommand) == "" {
		return "", fmt.Errorf("image, container_name, network_name, workdir, and install_command are required")
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}

	// Ensure network exists.
	if _, err := runner(ctx, "docker", "network", "inspect", p.NetworkName); err != nil {
		if _, createErr := runner(ctx, "docker", "network", "create", p.NetworkName); createErr != nil {
			return "", fmt.Errorf("failed to create network %q: %w", p.NetworkName, createErr)
		}
	}

	recreate := true
	if p.Recreate != nil {
		recreate = *p.Recreate
	}
	containerExists := false
	if recreate {
		_, _ = runner(ctx, "docker", "rm", "-f", p.ContainerName)
	} else {
		if _, inspectErr := runner(ctx, "docker", "inspect", p.ContainerName); inspectErr == nil {
			containerExists = true
		}
	}

	startup := strings.TrimSpace(p.StartupCommand)
	if startup == "" {
		startup = "tail -f /dev/null"
	}

	if !containerExists {
		if _, err := runner(ctx,
			"docker", "run", "-d",
			"--name", p.ContainerName,
			"--network", p.NetworkName,
			"-v", p.Workdir+":/workdir",
			"-w", "/workdir",
			p.Image,
			"sh", "-lc", startup,
		); err != nil {
			return "", fmt.Errorf("failed to start container %q: %w", p.ContainerName, err)
		}
	} else {
		if runningOut, runErr := runner(ctx, "docker", "inspect", "-f", "{{.State.Running}}", p.ContainerName); runErr != nil {
			return "", fmt.Errorf("failed to inspect running state for container %q: %w", p.ContainerName, runErr)
		} else if strings.TrimSpace(runningOut) != "true" {
			if _, err := runner(ctx, "docker", "start", p.ContainerName); err != nil {
				return "", fmt.Errorf("failed to start existing container %q: %w", p.ContainerName, err)
			}
		}
	}

	installOut, err := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-lc", p.InstallCommand)
	if err != nil {
		return "", fmt.Errorf("install command failed in container %q: %w", p.ContainerName, err)
	}

	result := map[string]any{
		"status":          "ok",
		"container_name":  p.ContainerName,
		"network_name":    p.NetworkName,
		"image":           p.Image,
		"workdir":         p.Workdir,
		"startup_command": startup,
		"install_command": p.InstallCommand,
		"install_output":  truncate(installOut, 4000),
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func runSetupCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}
