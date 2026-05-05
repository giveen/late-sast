package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CleanupScanEnvironmentTool consolidates SAST teardown logic into one
// deterministic call.
type CleanupScanEnvironmentTool struct {
	Runner setupCommandRunner
}

func (t CleanupScanEnvironmentTool) Name() string { return "cleanup_scan_environment" }

func (t CleanupScanEnvironmentTool) Description() string {
	return "Cleanup scan docker resources (container, compose stack, sidecars, network, image, and temp workdir) in one deterministic call."
}

func (t CleanupScanEnvironmentTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container": {"type": "string", "description": "Primary container name"},
			"compose_project": {"type": "string", "description": "Compose project name"},
			"network": {"type": "string", "description": "Docker network name"},
			"workdir": {"type": "string", "description": "Host workdir to remove"},
			"image_tag": {"type": "string", "description": "Custom image tag to remove (optional)"}
		},
		"required": ["container", "compose_project", "network", "workdir"]
	}`)
}

func (t CleanupScanEnvironmentTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t CleanupScanEnvironmentTool) CallString(args json.RawMessage) string {
	var p struct {
		Container string `json:"container"`
	}
	_ = json.Unmarshal(args, &p)
	if strings.TrimSpace(p.Container) == "" {
		return "cleanup_scan_environment(...)"
	}
	return fmt.Sprintf("cleanup_scan_environment(container=%q)", p.Container)
}

func (t CleanupScanEnvironmentTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		Container      string `json:"container"`
		ComposeProject string `json:"compose_project"`
		Network        string `json:"network"`
		Workdir        string `json:"workdir"`
		ImageTag       string `json:"image_tag"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.Container) == "" ||
		strings.TrimSpace(p.ComposeProject) == "" ||
		strings.TrimSpace(p.Network) == "" ||
		strings.TrimSpace(p.Workdir) == "" {
		return "", fmt.Errorf("container, compose_project, network, and workdir are required")
	}

	runner := t.Runner
	if runner == nil {
		runner = runSetupCommand
	}

	steps := make([]map[string]any, 0, 10)
	appendStep := func(name, command string, out string, err error) {
		step := map[string]any{
			"step":    name,
			"command": command,
			"ok":      err == nil,
			"output":  truncate(strings.TrimSpace(out), 500),
		}
		if err != nil {
			step["error"] = truncate(err.Error(), 200)
		}
		steps = append(steps, step)
	}

	// Stop/remove primary container.
	out, err := runner(ctx, "docker", "rm", "-f", p.Container)
	appendStep("remove_container", fmt.Sprintf("docker rm -f %s", p.Container), out, err)

	// Bring down compose stack.
	out, err = runner(ctx, "docker", "compose", "-p", p.ComposeProject, "down", "-v", "--remove-orphans")
	appendStep("compose_down", fmt.Sprintf("docker compose -p %s down -v --remove-orphans", p.ComposeProject), out, err)

	// Fallback: discover compose files under workdir and tear them down directly.
	composeFiles := findComposeFiles(p.Workdir, 4)
	if len(composeFiles) > 0 {
		okCount := 0
		var outputParts []string
		for _, cf := range composeFiles {
			cfOut, cfErr := runner(ctx, "docker", "compose", "-f", cf, "down", "-v", "--remove-orphans")
			if cfErr == nil {
				okCount++
			}
			msg := fmt.Sprintf("%s: %s", cf, truncate(strings.TrimSpace(cfOut), 150))
			if cfErr != nil {
				msg += " (err: " + truncate(cfErr.Error(), 120) + ")"
			}
			outputParts = append(outputParts, msg)
		}
		var downErr error
		if okCount == 0 {
			downErr = fmt.Errorf("compose fallback down failed for %d file(s)", len(composeFiles))
		}
		appendStep("compose_down_discovered", "docker compose -f <discovered> down -v --remove-orphans", strings.Join(outputParts, "\n"), downErr)
	} else {
		appendStep("compose_down_discovered", "docker compose -f <discovered> down -v --remove-orphans", "no compose files discovered", nil)
	}

	// Remove sidecars/leaked containers discovered by multiple filters.
	idSet := map[string]struct{}{}
	var filterNotes []string
	collectIDs := func(filterType, filterValue string) {
		idsOut, listErr := runner(ctx, "docker", "ps", "-aq", "--filter", filterType+"="+filterValue)
		if listErr != nil {
			filterNotes = append(filterNotes, fmt.Sprintf("%s=%s err: %s", filterType, filterValue, truncate(listErr.Error(), 120)))
			return
		}
		ids := splitLines(idsOut)
		filterNotes = append(filterNotes, fmt.Sprintf("%s=%s matched=%d", filterType, filterValue, len(ids)))
		for _, id := range ids {
			idSet[id] = struct{}{}
		}
	}
	collectIDs("name", p.Container+"-")
	collectIDs("network", p.Network)
	collectIDs("label", "com.docker.compose.project="+p.ComposeProject)

	var ids []string
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		args := append([]string{"rm", "-f"}, ids...)
		rmOut, rmErr := runner(ctx, "docker", args...)
		appendStep("remove_sidecars", "docker rm -f <filtered sidecars>", strings.TrimSpace(strings.Join(filterNotes, "\n")+"\n"+rmOut), rmErr)
	} else {
		appendStep("remove_sidecars", "docker rm -f <filtered sidecars>", strings.Join(filterNotes, "\n"), nil)
	}

	// Remove network.
	out, err = runner(ctx, "docker", "network", "rm", p.Network)
	appendStep("remove_network", fmt.Sprintf("docker network rm %s", p.Network), out, err)

	// Remove custom image tag when provided.
	imageTag := strings.TrimSpace(p.ImageTag)
	if imageTag == "" {
		imageTag = p.Container + "-image"
	}
	out, err = runner(ctx, "docker", "rmi", imageTag)
	appendStep("remove_image", fmt.Sprintf("docker rmi %s", imageTag), out, err)

	// Cleanup host workdir by mounting its parent directory into the helper container.
	absWorkdir, absErr := filepath.Abs(p.Workdir)
	if absErr != nil {
		appendStep("remove_workdir", "docker run --rm -v <workdir-parent>:<workdir-parent> alpine sh -lc <cleanup>", "", fmt.Errorf("resolve absolute workdir: %w", absErr))
	} else {
		parentDir := filepath.Dir(absWorkdir)
		cleanupWorkdirCmd := fmt.Sprintf("rm -rf %s", shQuote(absWorkdir))
		out, err = runner(ctx, "docker", "run", "--rm", "-v", parentDir+":"+parentDir, "alpine", "sh", "-lc", cleanupWorkdirCmd)
		appendStep("remove_workdir", "docker run --rm -v <workdir-parent>:<workdir-parent> alpine sh -lc <cleanup>", out, err)
	}

	// Cleanup temp sast-skill artifacts under /tmp.
	out, err = runner(ctx, "docker", "run", "--rm", "-v", "/tmp:/tmp", "alpine", "sh", "-lc", "rm -rf /tmp/sast-skill")
	appendStep("remove_temp_files", "docker run --rm -v /tmp:/tmp alpine sh -lc <cleanup>", out, err)

	successes := 0
	for _, s := range steps {
		if ok, _ := s["ok"].(bool); ok {
			successes++
		}
	}

	status := "ok"
	if successes < len(steps) {
		status = "partial"
	}

	resp := map[string]any{
		"status":          status,
		"container":       p.Container,
		"compose_project": p.ComposeProject,
		"network":         p.Network,
		"workdir":         p.Workdir,
		"image_tag":       imageTag,
		"steps":           steps,
		"success_count":   successes,
		"step_count":      len(steps),
	}
	outJSON, _ := json.Marshal(resp)
	return string(outJSON), nil
}

func findComposeFiles(root string, maxDepth int) []string {
	trimmed := strings.TrimSpace(root)
	if trimmed == "" {
		return nil
	}
	info, err := os.Stat(trimmed)
	if err != nil || !info.IsDir() {
		return nil
	}
	composeNames := map[string]bool{
		"docker-compose.yml":  true,
		"docker-compose.yaml": true,
		"compose.yml":         true,
		"compose.yaml":        true,
	}
	var out []string
	root = filepath.Clean(trimmed)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = strings.Count(filepath.ToSlash(rel), "/") + 1
		}
		if d.IsDir() {
			name := d.Name()
			if depth > maxDepth || shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > maxDepth {
			return nil
		}
		if composeNames[strings.ToLower(d.Name())] {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}
