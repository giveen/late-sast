package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LaunchDockerTool detects docker assets in a repository and launches them in a
// deterministic way: compose first, then Dockerfile.
type LaunchDockerTool struct {
	Runner            setupCommandRunner
	ReservedHostPorts []int
}

func (t LaunchDockerTool) Name() string { return "launch_docker" }

func (t LaunchDockerTool) Description() string {
	return "Auto-detect and launch Docker assets for a repository (docker-compose first, then Dockerfile)."
}

func (t LaunchDockerTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"repo_path": {"type": "string", "description": "Absolute path to repository root"},
			"network_name": {"type": "string", "description": "Docker network name to ensure/use"},
			"compose_project": {"type": "string", "description": "Compose project name (optional)"},
			"container_name_prefix": {"type": "string", "description": "Container name prefix for Dockerfile mode (optional)"},
			"prefer_service_dir": {"type": "string", "description": "Preferred service subdirectory for monorepos (optional)"},
			"max_depth": {"type": "integer", "description": "Max search depth for docker files (default: 8)"},
			"compose_file": {"type": "string", "description": "Explicit compose file path override (optional)"},
			"dockerfile": {"type": "string", "description": "Explicit Dockerfile path override (optional)"},
			"patch_network": {"type": "boolean", "description": "Patch compose to join network (default: true)"},
			"recreate": {"type": "boolean", "description": "Recreate containers/project before launch (default: true)"},
			"reserved_host_ports": {"type": "array", "items": {"type": "integer"}, "description": "Host ports that must not be occupied by the launched target"},
			"cleanup_on_port_conflict": {"type": "boolean", "description": "Stop launched target immediately if a reserved host port is detected (default: true)"}
		},
		"required": ["repo_path", "network_name"]
	}`)
}

func (t LaunchDockerTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t LaunchDockerTool) CallString(args json.RawMessage) string {
	var p struct {
		RepoPath    string `json:"repo_path"`
		NetworkName string `json:"network_name"`
	}
	_ = json.Unmarshal(args, &p)
	return fmt.Sprintf("launch_docker(repo=%q, network=%q)", p.RepoPath, p.NetworkName)
}

func (t LaunchDockerTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		RepoPath            string `json:"repo_path"`
		NetworkName         string `json:"network_name"`
		ComposeProject      string `json:"compose_project"`
		ContainerNamePrefix string `json:"container_name_prefix"`
		PreferServiceDir    string `json:"prefer_service_dir"`
		MaxDepth            int    `json:"max_depth"`
		ComposeFile         string `json:"compose_file"`
		Dockerfile          string `json:"dockerfile"`
		PatchNetwork        *bool  `json:"patch_network"`
		Recreate            *bool  `json:"recreate"`
		ReservedHostPorts   []int  `json:"reserved_host_ports"`
		CleanupOnConflict   *bool  `json:"cleanup_on_port_conflict"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.RepoPath) == "" || strings.TrimSpace(p.NetworkName) == "" {
		return "", fmt.Errorf("repo_path and network_name are required")
	}

	repoPath := filepath.Clean(p.RepoPath)
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return "", fmt.Errorf("repo_path %q does not exist or is not a directory", repoPath)
	}

	if p.MaxDepth <= 0 {
		p.MaxDepth = 8
	}
	if strings.TrimSpace(p.ContainerNamePrefix) == "" {
		p.ContainerNamePrefix = sanitizeName(filepath.Base(repoPath))
	}
	if strings.TrimSpace(p.ComposeProject) == "" {
		p.ComposeProject = p.ContainerNamePrefix
	}
	patchNetwork := true
	if p.PatchNetwork != nil {
		patchNetwork = *p.PatchNetwork
	}
	recreate := true
	if p.Recreate != nil {
		recreate = *p.Recreate
	}
	cleanupOnConflict := true
	if p.CleanupOnConflict != nil {
		cleanupOnConflict = *p.CleanupOnConflict
	}
	reservedHostPorts := p.ReservedHostPorts
	if len(reservedHostPorts) == 0 {
		reservedHostPorts = append(reservedHostPorts, t.ReservedHostPorts...)
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}

	if err := ensureDockerNetwork(ctx, runner, p.NetworkName); err != nil {
		return "", err
	}

	composeCandidates := []string{}
	dockerfileCandidates := []string{}

	composeFile := strings.TrimSpace(p.ComposeFile)
	dockerfile := strings.TrimSpace(p.Dockerfile)
	if composeFile == "" && dockerfile == "" {
		var err error
		composeCandidates, dockerfileCandidates, err = detectDockerAssets(repoPath, p.MaxDepth)
		if err != nil {
			return "", err
		}
		composeFile = chooseCandidate(composeCandidates, p.PreferServiceDir)
		dockerfile = chooseCandidate(dockerfileCandidates, p.PreferServiceDir)
	}

	if composeFile == "" && dockerfile == "" {
		out, _ := json.Marshal(map[string]any{
			"status":                "no_docker_assets",
			"repo_path":             repoPath,
			"compose_candidates":    composeCandidates,
			"dockerfile_candidates": dockerfileCandidates,
		})
		return string(out), nil
	}

	if composeFile != "" {
		return launchCompose(
			ctx,
			runner,
			repoPath,
			composeFile,
			p.ComposeProject,
			p.NetworkName,
			patchNetwork,
			recreate,
			reservedHostPorts,
			cleanupOnConflict,
		)
	}
	return launchDockerfile(
		ctx,
		runner,
		repoPath,
		dockerfile,
		p.ContainerNamePrefix,
		p.NetworkName,
		recreate,
		reservedHostPorts,
		cleanupOnConflict,
	)
}

func ensureDockerNetwork(ctx context.Context, runner setupCommandRunner, networkName string) error {
	if _, err := runner(ctx, "docker", "network", "inspect", networkName); err != nil {
		if _, createErr := runner(ctx, "docker", "network", "create", networkName); createErr != nil {
			return fmt.Errorf("failed to create network %q: %w", networkName, createErr)
		}
	}
	return nil
}

func launchCompose(
	ctx context.Context,
	runner setupCommandRunner,
	repoPath, composeFile, composeProject, networkName string,
	patchNetwork, recreate bool,
	reservedHostPorts []int,
	cleanupOnConflict bool,
) (string, error) {
	composeFile = filepath.Clean(composeFile)
	if !filepath.IsAbs(composeFile) {
		composeFile = filepath.Join(repoPath, composeFile)
	}

	if patchNetwork {
		raw, err := os.ReadFile(composeFile)
		if err != nil {
			return "", fmt.Errorf("cannot read compose file %q: %w", composeFile, err)
		}
		patched, _, err := patchComposeNetwork(raw, networkName)
		if err != nil {
			return "", fmt.Errorf("failed to patch compose file %q: %w", composeFile, err)
		}
		if err := os.WriteFile(composeFile, patched, 0644); err != nil {
			return "", fmt.Errorf("cannot write patched compose file %q: %w", composeFile, err)
		}
	}

	composeArgs := []string{"compose", "-p", composeProject, "-f", composeFile}
	if recreate {
		_, _ = runner(ctx, "docker", append(composeArgs, "down", "--remove-orphans")...)
	}
	if _, err := runner(ctx, "docker", append(composeArgs, "up", "-d")...); err != nil {
		return "", fmt.Errorf("docker compose up failed: %w", err)
	}

	servicesOut, err := runner(ctx, "docker", append(composeArgs, "ps", "--services", "--status", "running")...)
	if err != nil {
		return "", fmt.Errorf("docker compose ps failed: %w", err)
	}
	services := splitLines(servicesOut)
	service := chooseAppService(services)

	containerID := ""
	containerName := ""
	portInfo := map[string]any{}
	if service != "" {
		idOut, err := runner(ctx, "docker", append(composeArgs, "ps", "-q", service)...)
		if err == nil {
			containerID = strings.TrimSpace(idOut)
		}
	}
	if containerID != "" {
		nameOut, err := runner(ctx, "docker", "inspect", "-f", "{{.Name}}", containerID)
		if err == nil {
			containerName = strings.TrimPrefix(strings.TrimSpace(nameOut), "/")
		}
		portInfo = inspectPortInfo(ctx, runner, containerID)
	}
	if hostPort, ok := extractHostPort(portInfo); ok && isReservedPort(hostPort, reservedHostPorts) {
		if cleanupOnConflict {
			_, _ = runner(ctx, "docker", append(composeArgs, "down", "--remove-orphans")...)
		}
		result := map[string]any{
			"status":              "port_conflict",
			"mode_used":           "compose",
			"compose_path":        composeFile,
			"compose_project":     composeProject,
			"service":             service,
			"container_id":        containerID,
			"container_name":      containerName,
			"ports":               portInfo,
			"conflict_host_port":  hostPort,
			"reserved_host_ports": reservedHostPorts,
			"cleanup_on_conflict": cleanupOnConflict,
			"conflict_reason":     "launched target claimed a reserved host port",
			"recommendation":      "launch target with a different host port mapping",
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	result := map[string]any{
		"status":          "ok",
		"mode_used":       "compose",
		"compose_path":    composeFile,
		"compose_project": composeProject,
		"service":         service,
		"container_id":    containerID,
		"container_name":  containerName,
		"ports":           portInfo,
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func launchDockerfile(
	ctx context.Context,
	runner setupCommandRunner,
	repoPath, dockerfile, prefix, networkName string,
	recreate bool,
	reservedHostPorts []int,
	cleanupOnConflict bool,
) (string, error) {
	dockerfile = filepath.Clean(dockerfile)
	if !filepath.IsAbs(dockerfile) {
		dockerfile = filepath.Join(repoPath, dockerfile)
	}
	contextDir := filepath.Dir(dockerfile)
	imageTag := prefix + "-image"
	containerName := prefix + "-app"

	if recreate {
		_, _ = runner(ctx, "docker", "rm", "-f", containerName)
	}

	if _, err := runner(ctx, "docker", "build", "-t", imageTag, "-f", dockerfile, contextDir); err != nil {
		return "", fmt.Errorf("docker build failed: %w", err)
	}
	if _, err := runner(ctx,
		"docker", "run", "-d",
		"--name", containerName,
		"--network", networkName,
		"-v", repoPath+":/app",
		"-w", "/app",
		imageTag,
	); err != nil {
		return "", fmt.Errorf("docker run failed: %w", err)
	}

	idOut, _ := runner(ctx, "docker", "inspect", "-f", "{{.Id}}", containerName)
	containerID := strings.TrimSpace(idOut)
	portInfo := inspectPortInfo(ctx, runner, containerName)
	if hostPort, ok := extractHostPort(portInfo); ok && isReservedPort(hostPort, reservedHostPorts) {
		if cleanupOnConflict {
			_, _ = runner(ctx, "docker", "rm", "-f", containerName)
		}
		result := map[string]any{
			"status":              "port_conflict",
			"mode_used":           "dockerfile",
			"dockerfile_path":     dockerfile,
			"context_dir":         contextDir,
			"image_tag":           imageTag,
			"container_id":        containerID,
			"container_name":      containerName,
			"ports":               portInfo,
			"conflict_host_port":  hostPort,
			"reserved_host_ports": reservedHostPorts,
			"cleanup_on_conflict": cleanupOnConflict,
			"conflict_reason":     "launched target claimed a reserved host port",
			"recommendation":      "launch target with a different host port mapping",
		}
		out, _ := json.Marshal(result)
		return string(out), nil
	}

	result := map[string]any{
		"status":          "ok",
		"mode_used":       "dockerfile",
		"dockerfile_path": dockerfile,
		"context_dir":     contextDir,
		"image_tag":       imageTag,
		"container_id":    containerID,
		"container_name":  containerName,
		"ports":           portInfo,
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func detectDockerAssets(repoPath string, maxDepth int) ([]string, []string, error) {
	var composeCandidates []string
	var dockerfileCandidates []string

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(repoPath, path)
		if relErr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = strings.Count(filepath.ToSlash(rel), "/")
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			if depth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > maxDepth {
			return nil
		}
		base := filepath.Base(path)
		if isComposeCandidate(base) {
			composeCandidates = append(composeCandidates, path)
		}
		if isDockerfileCandidate(base) {
			dockerfileCandidates = append(dockerfileCandidates, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan repo for docker assets: %w", err)
	}

	sort.Slice(composeCandidates, func(i, j int) bool {
		return candidateScore(composeCandidates[i]) < candidateScore(composeCandidates[j])
	})
	sort.Slice(dockerfileCandidates, func(i, j int) bool {
		return candidateScore(dockerfileCandidates[i]) < candidateScore(dockerfileCandidates[j])
	})
	return composeCandidates, dockerfileCandidates, nil
}

func isComposeCandidate(base string) bool {
	b := strings.ToLower(strings.TrimSpace(base))
	if b == "" {
		return false
	}
	if b == "docker-compose.yml" || b == "docker-compose.yaml" || b == "compose.yml" || b == "compose.yaml" {
		return true
	}
	if strings.HasPrefix(b, "docker-compose") && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")) {
		return true
	}
	if strings.HasPrefix(b, "compose") && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")) {
		return true
	}
	return false
}

func isDockerfileCandidate(base string) bool {
	b := strings.ToLower(strings.TrimSpace(base))
	if b == "" {
		return false
	}
	if b == "dockerfile" || b == "containerfile" {
		return true
	}
	if strings.HasPrefix(b, "dockerfile.") || strings.HasPrefix(b, "containerfile.") {
		return true
	}
	return false
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", "target", ".next", "coverage":
		return true
	default:
		return false
	}
}

func candidateScore(path string) int {
	return strings.Count(filepath.ToSlash(path), "/")*1000 + len(path)
}

func chooseCandidate(candidates []string, preferServiceDir string) string {
	if len(candidates) == 0 {
		return ""
	}
	prefer := strings.TrimSpace(filepath.ToSlash(preferServiceDir))
	if prefer == "" {
		return candidates[0]
	}
	for _, c := range candidates {
		if strings.Contains(filepath.ToSlash(c), prefer) {
			return c
		}
	}
	return candidates[0]
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func chooseAppService(services []string) string {
	if len(services) == 0 {
		return ""
	}
	for _, s := range services {
		if !isInfraService(s) {
			return s
		}
	}
	return services[0]
}

func isInfraService(service string) bool {
	s := strings.ToLower(service)
	infra := []string{"postgres", "mysql", "mariadb", "redis", "mongo", "rabbit", "kafka", "elastic", "db"}
	for _, kw := range infra {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func inspectPortInfo(ctx context.Context, runner setupCommandRunner, target string) map[string]any {
	out, err := runner(ctx, "docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", target)
	if err != nil {
		return map[string]any{}
	}
	raw := strings.TrimSpace(out)
	if raw == "" || raw == "null" {
		return map[string]any{}
	}
	ports := make(map[string][]map[string]string)
	if err := json.Unmarshal([]byte(raw), &ports); err != nil {
		return map[string]any{"raw": truncate(raw, 500)}
	}
	for k, binds := range ports {
		containerPort := strings.Split(k, "/")[0]
		cp, _ := strconv.Atoi(containerPort)
		if len(binds) > 0 {
			hp, _ := strconv.Atoi(binds[0]["HostPort"])
			return map[string]any{
				"container_port": cp,
				"host_port":      hp,
				"raw":            ports,
			}
		}
		return map[string]any{
			"container_port": cp,
			"raw":            ports,
		}
	}
	return map[string]any{"raw": ports}
}

func extractHostPort(portInfo map[string]any) (int, bool) {
	v, ok := portInfo["host_port"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case string:
		hp, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return hp, true
	default:
		return 0, false
	}
}

func isReservedPort(port int, reserved []int) bool {
	if port <= 0 {
		return false
	}
	for _, p := range reserved {
		if p > 0 && p == port {
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	if s == "" {
		return "sast"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "sast"
	}
	return out
}
