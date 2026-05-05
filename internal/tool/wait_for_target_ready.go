package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WaitForTargetReadyTool checks whether a launched container target is ready
// to be scanned, returning deterministic status and diagnostics.
type WaitForTargetReadyTool struct {
	Runner     setupCommandRunner
	HTTPClient *http.Client
}

type readinessCheck struct {
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Success    bool   `json:"success"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func (t WaitForTargetReadyTool) Name() string { return "wait_for_target_ready" }

func (t WaitForTargetReadyTool) Description() string {
	return "Wait for a Dockerized target to become ready with bounded probes and structured diagnostics."
}

func (t WaitForTargetReadyTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_name": {"type": "string", "description": "Main app container name to probe"},
			"endpoint": {"type": "string", "description": "Optional explicit endpoint URL to probe (e.g. http://127.0.0.1:8080/health)"},
			"host": {"type": "string", "description": "Host used for auto-built endpoint probes (default: 127.0.0.1)"},
			"port": {"type": "integer", "description": "Optional preferred container port to probe"},
			"health_paths": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional health paths to probe when endpoint is omitted"
			},
			"max_wait_seconds": {"type": "integer", "description": "Total wait budget in seconds (default: 90, max: 180)"},
			"interval_seconds": {"type": "integer", "description": "Polling interval in seconds (default: 5)"},
			"log_tail_lines": {"type": "integer", "description": "How many container log lines to include in diagnostics (default: 80)"}
		},
		"required": ["container_name"]
	}`)
}

func (t WaitForTargetReadyTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t WaitForTargetReadyTool) CallString(args json.RawMessage) string {
	var p struct {
		ContainerName string `json:"container_name"`
	}
	_ = json.Unmarshal(args, &p)
	if strings.TrimSpace(p.ContainerName) == "" {
		return "wait_for_target_ready(...)"
	}
	return fmt.Sprintf("wait_for_target_ready(container=%q)", p.ContainerName)
}

func (t WaitForTargetReadyTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		ContainerName string   `json:"container_name"`
		Endpoint      string   `json:"endpoint"`
		Host          string   `json:"host"`
		Port          int      `json:"port"`
		HealthPaths   []string `json:"health_paths"`
		MaxWaitSec    int      `json:"max_wait_seconds"`
		IntervalSec   int      `json:"interval_seconds"`
		LogTailLines  int      `json:"log_tail_lines"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.ContainerName) == "" {
		return "", fmt.Errorf("container_name is required")
	}
	if strings.TrimSpace(p.Host) == "" {
		p.Host = "127.0.0.1"
	}
	if p.MaxWaitSec <= 0 {
		p.MaxWaitSec = 90
	}
	if p.MaxWaitSec > 180 {
		p.MaxWaitSec = 180
	}
	if p.IntervalSec <= 0 {
		p.IntervalSec = 5
	}
	if p.IntervalSec > 15 {
		p.IntervalSec = 15
	}
	if p.LogTailLines <= 0 {
		p.LogTailLines = 80
	}
	if p.LogTailLines > 400 {
		p.LogTailLines = 400
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}
	httpClient := t.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}

	status, err := inspectContainerState(ctx, runner, p.ContainerName)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %q: %w", p.ContainerName, err)
	}
	if status != "running" {
		return t.renderStatus(ctx, runner, p, "crashed", "container is not running", nil)
	}

	ports, _ := inspectPortInfo(ctx, runner, p.ContainerName)["raw"].(map[string][]map[string]string)
	endpoints, chosenPort := buildProbeEndpoints(p.Endpoint, p.Host, p.Port, p.HealthPaths, ports)
	if len(endpoints) == 0 {
		return t.renderStatus(ctx, runner, p, "not_ready", "no endpoint could be derived from container ports; provide endpoint or port", nil)
	}

	checks := make([]readinessCheck, 0, 32)
	deadline := time.Now().Add(time.Duration(p.MaxWaitSec) * time.Second)
	interval := time.Duration(p.IntervalSec) * time.Second

	for {
		stateStart := time.Now()
		state, stateErr := inspectContainerState(ctx, runner, p.ContainerName)
		stateCheck := readinessCheck{
			Kind:       "container_state",
			Target:     p.ContainerName,
			Success:    stateErr == nil && state == "running",
			DurationMS: time.Since(stateStart).Milliseconds(),
		}
		if stateErr != nil {
			stateCheck.Detail = stateErr.Error()
			checks = append(checks, stateCheck)
			return t.renderStatus(ctx, runner, p, "not_ready", "failed to read container state during probe", checks)
		}
		stateCheck.Detail = state
		checks = append(checks, stateCheck)
		if state != "running" {
			return t.renderStatus(ctx, runner, p, "crashed", "container exited during readiness probe", checks)
		}

		for _, ep := range endpoints {
			tcpStart := time.Now()
			tcpOK, tcpDetail := probeTCP(ep)
			checks = append(checks, readinessCheck{
				Kind:       "tcp",
				Target:     ep,
				Success:    tcpOK,
				Detail:     tcpDetail,
				DurationMS: time.Since(tcpStart).Milliseconds(),
			})

			httpStart := time.Now()
			httpOK, httpDetail := probeHTTP(ctx, httpClient, ep)
			checks = append(checks, readinessCheck{
				Kind:       "http",
				Target:     ep,
				Success:    httpOK,
				Detail:     httpDetail,
				DurationMS: time.Since(httpStart).Milliseconds(),
			})

			if httpOK {
				resp := map[string]any{
					"status":         "ready",
					"container_name": p.ContainerName,
					"endpoint":       ep,
					"port":           chosenPort,
					"checks":         checks,
					"recommendation": "proceed with scanner and exploit verification",
				}
				out, _ := json.Marshal(resp)
				return string(out), nil
			}
		}

		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}

	return t.renderStatus(ctx, runner, p, "not_ready", "readiness timeout exceeded before successful HTTP probe", checks)
}

func (t WaitForTargetReadyTool) renderStatus(
	ctx context.Context,
	runner setupCommandRunner,
	p struct {
		ContainerName string   `json:"container_name"`
		Endpoint      string   `json:"endpoint"`
		Host          string   `json:"host"`
		Port          int      `json:"port"`
		HealthPaths   []string `json:"health_paths"`
		MaxWaitSec    int      `json:"max_wait_seconds"`
		IntervalSec   int      `json:"interval_seconds"`
		LogTailLines  int      `json:"log_tail_lines"`
	},
	status, reason string,
	checks []readinessCheck,
) (string, error) {
	logs, _ := runner(ctx, "docker", "logs", "--tail", strconv.Itoa(p.LogTailLines), p.ContainerName)
	resp := map[string]any{
		"status":         status,
		"container_name": p.ContainerName,
		"endpoint":       strings.TrimSpace(p.Endpoint),
		"checks":         checks,
		"diagnostics": map[string]any{
			"reason": reason,
			"logs":   truncate(strings.TrimSpace(logs), 4000),
		},
		"recommendation": recommendationForStatus(status),
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

func inspectContainerState(ctx context.Context, runner setupCommandRunner, container string) (string, error) {
	out, err := runner(ctx, "docker", "inspect", "-f", "{{.State.Status}}", container)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func buildProbeEndpoints(explicitEndpoint, host string, preferredPort int, healthPaths []string, ports map[string][]map[string]string) ([]string, string) {
	if strings.TrimSpace(explicitEndpoint) != "" {
		return []string{strings.TrimSpace(explicitEndpoint)}, strconv.Itoa(preferredPort)
	}
	if len(healthPaths) == 0 {
		healthPaths = []string{"/health", "/healthz", "/ready", "/", "/ping"}
	}

	hostPort := ""
	containerPort := ""
	if preferredPort > 0 {
		containerPort = strconv.Itoa(preferredPort)
		for k, binds := range ports {
			if strings.HasPrefix(k, containerPort+"/") && len(binds) > 0 {
				hostPort = binds[0]["HostPort"]
				break
			}
		}
		if hostPort == "" {
			hostPort = containerPort
		}
	} else {
		keys := make([]string, 0, len(ports))
		for k := range ports {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			li := strings.SplitN(keys[i], "/", 2)[0]
			lj := strings.SplitN(keys[j], "/", 2)[0]
			pi, errI := strconv.Atoi(li)
			pj, errJ := strconv.Atoi(lj)
			if errI == nil && errJ == nil {
				if pi != pj {
					return pi < pj
				}
				return keys[i] < keys[j]
			}
			if errI == nil {
				return true
			}
			if errJ == nil {
				return false
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			binds := ports[k]
			parts := strings.Split(k, "/")
			if len(parts) > 0 {
				containerPort = parts[0]
			}
			if len(binds) > 0 {
				hostPort = binds[0]["HostPort"]
				break
			}
		}
	}
	if hostPort == "" {
		return nil, containerPort
	}

	base := "http://" + host + ":" + hostPort
	endpoints := make([]string, 0, len(healthPaths))
	for _, p := range healthPaths {
		path := strings.TrimSpace(p)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		endpoints = append(endpoints, base+path)
	}
	return endpoints, containerPort
}

func probeTCP(endpoint string) (bool, string) {
	u := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	host := strings.Split(u, "/")[0]
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, "connected"
}

func probeHTTP(ctx context.Context, client *http.Client, endpoint string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return true, fmt.Sprintf("status=%d", resp.StatusCode)
	}
	return false, fmt.Sprintf("status=%d", resp.StatusCode)
}

func recommendationForStatus(status string) string {
	switch status {
	case "ready":
		return "proceed with scanner and exploit verification"
	case "crashed":
		return "container crashed; inspect logs, fix startup command, then relaunch via launch_docker or setup_container"
	default:
		return "target is not ready yet; inspect logs and retry with endpoint override or increased max_wait_seconds"
	}
}
