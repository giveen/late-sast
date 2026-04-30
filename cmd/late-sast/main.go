package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"late/internal/agent"
	"late/internal/assets"
	"late/internal/assets/sast"
	"late/internal/client"
	appconfig "late/internal/config"
	"late/internal/common"
	"late/internal/mcp"
	"late/internal/orchestrator"
	"late/internal/pathutil"
	"late/internal/session"
	"late/internal/tool"
	"late/internal/tui"

	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
)

func main() {
	targetReq := flag.String("target", "", "GitHub URL of the repository to audit")
	outputReq := flag.String("output", "", "Directory to write the SAST report (default: current directory)")
	timeoutReq := flag.Duration("timeout", 0, "Wall-clock scan timeout (e.g. 90m, 2h). 0 = no limit")
	versionReq := flag.Bool("version", false, "Show version")
	subagentMaxTurns := flag.Int("subagent-max-turns", 500, "Maximum turns per subagent")
	gemmaThinkingReq := flag.Bool("gemma-thinking", false, "Prepend <|think|> token for Gemma 4 models")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: late-sast [flags]\n\n")
		fmt.Fprintf(os.Stderr, "  late-sast https://github.com/owner/repo\n")
		fmt.Fprintf(os.Stderr, "  late-sast --output ~/reports https://github.com/owner/repo\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionReq {
		fmt.Printf("late-sast %s\n", common.Version)
		return
	}

	// Accept positional URL as an alternative to --target
	target := *targetReq
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	// Reap stale containers from any previous crashed run that share the "sast-" prefix.
	// This prevents "name already in use" errors on subsequent runs.
	if out, err := exec.Command("docker", "ps", "-aq", "--filter", "name=sast-").Output(); err == nil {
		if ids := strings.Fields(string(out)); len(ids) > 0 {
			args := append([]string{"rm", "-f"}, ids...)
			if rmErr := exec.Command("docker", args...).Run(); rmErr == nil {
				fmt.Printf("[late-sast] Reaped %d stale container(s) from previous run.\n", len(ids))
			}
		}
	}
	// Remove stale docker networks from previous runs.
	if out, err := exec.Command("docker", "network", "ls", "--filter", "name=sast-", "-q").Output(); err == nil {
		for _, netID := range strings.Fields(string(out)) {
			exec.Command("docker", "network", "rm", netID).Run() //nolint:errcheck
		}
	}

	// Extract embedded SAST skill files to /tmp/sast-skill so the agent can read them
	if err := extractSASTSkill("/tmp/sast-skill"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to extract SAST skill files: %v\n", err)
	}

	// Load SAST system prompt
	content, err := assets.PromptsFS.ReadFile("prompts/instruction-sast.md")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading SAST system prompt: %v\n", err)
		os.Exit(1)
	}
	systemPrompt := string(content)

	// Container name and workdir are unique per session — no parallel run collisions.
	// All three placeholders are resolved via the standard ${{}} mechanism.
	cwd, _ := os.Getwd()
	containerName := "sast-" + time.Now().Format("20060102-150405")
	workDir := "/tmp/" + containerName
	networkName := containerName + "-net"
	composeProject := containerName
	// Derive repo name from the last path segment of the target URL (e.g. "llama-swap").
	repoName := "repo"
	if target != "" {
		if parts := strings.Split(strings.TrimRight(target, "/"), "/"); len(parts) > 0 {
			if last := parts[len(parts)-1]; last != "" {
				repoName = last
			}
		}
	}
	// Resolve output directory: flag > cwd. Create it if it doesn't exist.
	outputDir := *outputReq
	if outputDir == "" {
		outputDir = cwd
	} else {
		outputDir = filepath.Clean(outputDir)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}
	systemPrompt = common.ReplacePlaceholders(systemPrompt, map[string]string{
		"${{CWD}}":             cwd,
		"${{CONTAINER_NAME}}":  containerName,
		"${{WORKDIR}}":         workDir,
		"${{REPO_NAME}}":       repoName,
		"${{OUTPUT_DIR}}":      outputDir,
		"${{NETWORK_NAME}}":    networkName,
		"${{COMPOSE_PROJECT}}": composeProject,
	})

	if *gemmaThinkingReq {
		systemPrompt = "<|think|>" + systemPrompt
	}

	// Build initial audit message
	var initialMessage string
	if target != "" {
		initialMessage = fmt.Sprintf("Perform a complete security audit of: %s", target)
	}

	fmt.Println("Starting late-sast...")
	fmt.Printf("[late-sast] Report will be written to: %s/sast_report_%s.md\n", outputDir, repoName)

	// Session setup (non-persistent for audit runs)
	sessionsDir, err := session.SessionDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get session directory: %v\n", err)
		os.Exit(1)
	}
	sessionID := fmt.Sprintf("sast-%s", time.Now().Format("20060102-150405"))

	// Register cleanup: stop+remove the Docker container on exit (Ctrl-C, Ctrl-Q, or normal exit).
	cleanupDone := make(chan struct{})
	cleanupOnce := make(chan struct{}, 1)
	cleanupOnce <- struct{}{}
	cleanupContainer := func() {
		select {
		case <-cleanupOnce:
			defer close(cleanupDone)
			fmt.Printf("\n[late-sast] Cleaning up container %s...\n", containerName)
			exec.Command("docker", "stop", "-t", "5", containerName).Run() //nolint:errcheck
			exec.Command("docker", "rm", "-f", containerName).Run()        //nolint:errcheck
			// Tear down any docker-compose services for this project
			exec.Command("docker", "compose", "-p", composeProject, "down", "-v", "--remove-orphans").Run() //nolint:errcheck
			// Remove any manually-started sidecar containers (named sast-<ts>-*)
			if out, err := exec.Command("docker", "ps", "-aq", "--filter", "name="+containerName+"-").Output(); err == nil {
				if ids := strings.Fields(string(out)); len(ids) > 0 {
					args := append([]string{"rm", "-f"}, ids...)
					exec.Command("docker", args...).Run() //nolint:errcheck
				}
			}
			// Remove the shared docker network
			exec.Command("docker", "network", "rm", networkName).Run() //nolint:errcheck
			fmt.Printf("[late-sast] Container %s removed.\n", containerName)
			// Docker installs packages as root inside the container, leaving root-owned
			// files in the bind-mounted workdir. Use a throwaway alpine container
			// (which has root) to delete them reliably without requiring sudo.
			removeAsRoot := func(path string) {
				err := exec.Command("docker", "run", "--rm",
					"-v", "/tmp:/tmp",
					"alpine", "rm", "-rf", path).Run()
				if err != nil {
					// Fallback: best-effort with the current user
					os.RemoveAll(path) //nolint:errcheck
				}
			}
			removeAsRoot("/tmp/sast-skill")
			removeAsRoot(workDir)
			fmt.Printf("[late-sast] Workdir %s removed.\n", workDir)
		default:
			<-cleanupDone // already running, wait for it
		}
	}

	// Handle OS signals (Ctrl-C = SIGINT, kill = SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanupContainer()
		os.Exit(0)
	}()

	// Wall-clock timeout: if --timeout is set, fire cleanup and exit when it expires.
	if *timeoutReq > 0 {
		go func() {
			<-time.After(*timeoutReq)
			fmt.Fprintf(os.Stderr, "\n[late-sast] Scan timeout (%s) reached — aborting.\n", *timeoutReq)
			cleanupContainer()
			os.Exit(2)
		}()
	}
	historyPath := filepath.Join(sessionsDir, sessionID+".json")

	// Load app config — prefer ~/.config/late-sast/, fall back to ~/.config/late/
	sastCfgDir, _ := pathutil.LateSASTConfigDir()
	appConfig, _ := appconfig.LoadConfigFromDir(sastCfgDir)
	enabledTools := make(map[string]bool)
	if appConfig != nil {
		for k, v := range appConfig.EnabledTools {
			enabledTools[k] = v
		}
	}
	// SAST always needs bash, read_file, write_file
	enabledTools["bash"] = true
	enabledTools["read_file"] = true
	enabledTools["write_file"] = true

	// OpenAI client setup
	resolvedOpenAI := appconfig.ResolveOpenAISettings(appConfig)
	c := client.NewClient(client.Config{
		BaseURL: resolvedOpenAI.BaseURL,
		APIKey:  resolvedOpenAI.APIKey,
		Model:   resolvedOpenAI.Model,
	})
	c.DiscoverBackend(context.Background())

	resolvedSubagent := appconfig.ResolveSubagentSettings(appConfig, resolvedOpenAI)
	subagentClient := c
	if resolvedSubagent.Model != "" {
		subagentClient = client.NewClient(client.Config{
			BaseURL: resolvedSubagent.BaseURL,
			APIKey:  resolvedSubagent.APIKey,
			Model:   resolvedSubagent.Model,
		})
		subagentClient.DiscoverBackend(context.Background())
	}

	// Ensure codebase-memory-mcp is available, downloading if needed
	if cbmPath, cbmErr := ensureCBM(); cbmErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: codebase-memory-mcp unavailable (%v) — graph intelligence disabled\n", cbmErr)
	} else {
		// Add its directory to PATH so the MCP config can find it by name
		cbmDir := filepath.Dir(cbmPath)
		if cur := os.Getenv("PATH"); !strings.Contains(cur, cbmDir) {
			os.Setenv("PATH", cbmDir+string(os.PathListSeparator)+cur)
		}
	}

	// MCP client
	mcpClient := mcp.NewClient()
	defer mcpClient.Close()

	mcpConfig, err := mcp.LoadMCPConfigFromDir(sastCfgDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load MCP config: %v\n", err)
	}
	if mcpConfig != nil && len(mcpConfig.McpServers) > 0 {
		fmt.Println("Connecting to MCP servers...")
		if err := mcpClient.ConnectFromConfig(context.Background(), mcpConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: MCP connection error: %v\n", err)
		}
	}

	// Session + tool registration
	sess := session.New(c, historyPath, []client.ChatMessage{}, systemPrompt, true)

	// Register SAST tool set — permissive ShellTool, no path restrictions.
	// 2-minute timeout prevents curl/docker exec from blocking the agent indefinitely.
	sess.Registry.Register(&tool.ShellTool{
		Analyzer:     &tool.SASTBashAnalyzer{},
		SkipSafePath: true,
		Timeout:      2 * time.Minute,
	})
	sess.Registry.Register(tool.NewReadFileTool())
	sess.Registry.Register(tool.WriteFileTool{})

	// CVE lookup tools (native Go — no external dependencies)
	sess.Registry.Register(tool.VulVendorProductCVETool{})
	sess.Registry.Register(tool.VulCVESearchTool{})
	sess.Registry.Register(tool.VulVendorProductsTool{})
	sess.Registry.Register(tool.VulLastCVEsTool{})

	// Register MCP tools
	for _, t := range mcpClient.GetTools() {
		if enabled, exists := enabledTools[t.Name()]; exists && !enabled {
			continue
		}
		sess.Registry.Register(t)
	}

	// TUI renderer
	renderer, _ := glamour.NewTermRenderer(
		glamour.WithStylesFromJSONBytes(tui.LateTheme),
		glamour.WithWordWrap(80),
		glamour.WithPreservedNewLines(),
	)

	// Root orchestrator
	rootAgent := orchestrator.NewBaseOrchestrator("main", sess, nil, 0)
	model := tui.NewModel(rootAgent, renderer)
	p := tea.NewProgram(model)

	go func() {
		p.Send(tui.SetMessengerMsg{Messenger: p})

		// SAST runs fully unsupervised — no prompts
		ctx := context.WithValue(context.Background(), common.InputProviderKey, tui.NewTUIInputProvider(p))
		ctx = context.WithValue(ctx, common.SkipConfirmationKey, true)
		ctx = context.WithValue(ctx, common.ToolApprovalKey, true)
		rootAgent.SetContext(ctx)

		rootAgent.SetMiddlewares([]common.ToolMiddleware{
			tui.TUIConfirmMiddleware(p, sess.Registry),
		})

		ForwardOrchestratorEvents(p, rootAgent)

		// Auto-submit the initial audit task if a target was provided
		if initialMessage != "" {
			// Small delay to let the TUI render its first frame
			time.Sleep(300 * time.Millisecond)
			p.Send(tui.AutoSubmitMsg{Text: initialMessage})
		}
	}()

	// Subagent support
	runner := func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
		child, err := agent.NewSubagentOrchestrator(
			subagentClient, goal, ctxFiles, agentType,
			enabledTools, true, *gemmaThinkingReq,
			*subagentMaxTurns, rootAgent, p,
		)
		if err != nil {
			return "", err
		}
		res, err := child.Execute("")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Subagent completed. Result:\n\n%s", res), nil
	}
	sess.Registry.Register(tool.SpawnSubagentTool{Runner: runner})

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		cleanupContainer()
		os.Exit(1)
	}

	// Normal exit (Ctrl-Q or agent finished) — clean up too.
	cleanupContainer()
}

// ensureCBM ensures codebase-memory-mcp is available on the system.
// When built with -tags cbm_embedded the binary is extracted from the baked-in
// cbmBinaryData; otherwise it is downloaded from GitHub Releases.
func ensureCBM() (string, error) {
	const binaryName = "codebase-memory-mcp"

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	localBin := filepath.Join(home, ".local", "bin", binaryName)

	// 0. Embedded binary — extract if not already present or size differs.
	if len(cbmBinaryData) > 0 {
		stat, statErr := os.Stat(localBin)
		if statErr != nil || stat.Size() != int64(len(cbmBinaryData)) {
			if err := os.MkdirAll(filepath.Dir(localBin), 0755); err != nil {
				return "", fmt.Errorf("mkdir ~/.local/bin: %w", err)
			}
			if err := os.WriteFile(localBin, cbmBinaryData, 0755); err != nil {
				return "", fmt.Errorf("write embedded codebase-memory-mcp: %w", err)
			}
			fmt.Printf("[late-sast] Extracted embedded codebase-memory-mcp to %s\n", localBin)
		}
		return localBin, nil
	}

	// 1. Already on PATH?
	if path, err := exec.LookPath(binaryName); err == nil {
		return path, nil
	}

	// 2. In ~/.local/bin?
	if _, err := os.Stat(localBin); err == nil {
		return localBin, nil
	}

	// 3. Download from GitHub releases
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	// GitHub release naming: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64
	archMap := map[string]string{"amd64": "amd64", "arm64": "arm64"}
	arch, ok := archMap[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
	assetName := fmt.Sprintf("%s-%s-%s", binaryName, goos, arch)
	tarURL := fmt.Sprintf(
		"https://github.com/DeusData/codebase-memory-mcp/releases/latest/download/%s.tar.gz",
		assetName,
	)

	fmt.Printf("[late-sast] Downloading codebase-memory-mcp (%s/%s)...\n", goos, arch)

	//nolint:gosec // URL is constructed from a fixed base and runtime constants only
	resp, err := http.Get(tarURL) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d for %s", resp.StatusCode, tarURL)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(filepath.Dir(localBin), 0755); err != nil {
		return "", fmt.Errorf("mkdir ~/.local/bin: %w", err)
	}

	tr := tar.NewReader(gz)
	installed := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar read: %w", err)
		}
		// Match the bare binary name (archives may contain e.g. "codebase-memory-mcp" or "./codebase-memory-mcp")
		base := filepath.Base(hdr.Name)
		if base != binaryName {
			continue
		}
		f, err := os.OpenFile(localBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return "", fmt.Errorf("create binary: %w", err)
		}
		if _, err := io.Copy(f, tr); err != nil { //nolint:gosec
			f.Close()
			return "", fmt.Errorf("write binary: %w", err)
		}
		f.Close()
		installed = true
		break
	}

	if !installed {
		return "", fmt.Errorf("binary %q not found inside archive %s", binaryName, tarURL)
	}

	fmt.Printf("[late-sast] Installed codebase-memory-mcp to %s\n", localBin)
	return localBin, nil
}

// extractSASTSkill writes the embedded llm-sast-scanner skill files to destDir.
func extractSASTSkill(destDir string) error {
	return fs.WalkDir(sast.SASTSkillFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(destDir, path)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		data, err := sast.SASTSkillFS.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0644)
	})
}

// ForwardOrchestratorEvents streams orchestrator events into the TUI.
func ForwardOrchestratorEvents(p *tea.Program, o common.Orchestrator) {
	go func() {
		for event := range o.Events() {
			p.Send(tui.OrchestratorEventMsg{Event: event})
			if added, ok := event.(common.ChildAddedEvent); ok {
				ForwardOrchestratorEvents(p, added.Child)
			}
		}
	}()
}
