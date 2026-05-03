package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
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
	"late/internal/common"
	appconfig "late/internal/config"
	"late/internal/debug"
	"late/internal/executor"
	"late/internal/gui"
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
	// Fyne's locale parser rejects the "C" pseudo-locale.
	// Normalise to a well-formed BCP-47 tag before Fyne initialises.
	if lc := os.Getenv("LANG"); lc == "" || lc == "C" || lc == "POSIX" {
		os.Setenv("LANG", "en_US.UTF-8")
	}

	targetReq := flag.String("target", "", "GitHub URL of the repository to audit")
	outputReq := flag.String("output", "", "Directory to write the SAST report (default: current directory)")
	timeoutReq := flag.Duration("timeout", 0, "Wall-clock scan timeout (e.g. 90m, 2h). 0 = no limit")
	versionReq := flag.Bool("version", false, "Show version")
	subagentMaxTurns := flag.Int("subagent-max-turns", 300, "Maximum turns per subagent")
	subagentTimeout := flag.Duration("subagent-timeout", 45*time.Minute, "Wall-clock timeout per subagent run (e.g. 30m, 1h)")
	gemmaThinkingReq := flag.Bool("gemma-thinking", false, "Prepend <|think|> token for Gemma 4 models")

	pathReq := flag.String("path", "", "Path to a local repository to audit (alternative to a GitHub URL)")
	retestReq := flag.String("retest", "", "Path to a previous SAST report — retests all confirmed findings to check if they have been fixed")
	useTUIReq := flag.Bool("tui", false, "Use terminal UI instead of the graphical interface")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: late-sast [flags]\n\n")
		fmt.Fprintf(os.Stderr, "  late-sast https://github.com/owner/repo\n")
		fmt.Fprintf(os.Stderr, "  late-sast --output ~/reports https://github.com/owner/repo\n")
		fmt.Fprintf(os.Stderr, "  late-sast --path /path/to/local/repo\n")
		fmt.Fprintf(os.Stderr, "  late-sast --retest ./sast_report_myrepo.md\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionReq {
		fmt.Printf("late-sast %s\n", common.Version)
		return
	}

	// GUI mode: redirect stdout and stderr to a log file so the terminal the
	// user launched from stays clean. Logs go to ~/.cache/late-sast/late-sast.log.
	// syscall.Dup2 redirects at the fd level, so Fyne internals, C libraries,
	// and child processes (docker) all write to the same log file.
	if !*useTUIReq {
		if cacheDir, err := pathutil.LateSASTCacheDir(); err == nil {
			os.MkdirAll(cacheDir, 0700) //nolint:errcheck
			logPath := filepath.Join(cacheDir, "late-sast.log")
			_ = redirectStdoutStderrToFile(logPath)
		}
	}

	// Accept positional URL as an alternative to --target
	target := *targetReq
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	// --retest: mutually exclusive with --target, --path, and positional URL
	retestPath := *retestReq
	if retestPath != "" && (target != "" || *pathReq != "") {
		fmt.Fprintf(os.Stderr, "Error: --retest cannot be combined with --target or --path\n")
		os.Exit(1)
	}
	if retestPath != "" {
		abs, err := filepath.Abs(retestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving --retest path: %v\n", err)
			os.Exit(1)
		}
		if _, err := os.Stat(abs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: --retest %q does not exist\n", abs)
			os.Exit(1)
		}
		retestPath = abs
	}

	// --path: local repository path (mutually exclusive with a GitHub URL target)
	localPath := *pathReq
	if localPath != "" && target != "" {
		fmt.Fprintf(os.Stderr, "Error: --path and a GitHub URL target are mutually exclusive\n")
		os.Exit(1)
	}
	if localPath != "" {
		abs, err := filepath.Abs(localPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving --path: %v\n", err)
			os.Exit(1)
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: --path %q does not exist or is not a directory\n", abs)
			os.Exit(1)
		}
		localPath = abs
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

	// Container name and workdir are unique per session — no parallel run collisions.
	cwd, _ := os.Getwd()
	containerName := "sast-" + time.Now().Format("20060102-150405")
	workDir := "/tmp/" + containerName
	networkName := containerName + "-net"
	composeProject := containerName
	// Resolve output directory from flag; picker may override for GUI mode.
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

	resolvedAuditor := appconfig.ResolveAuditorSettings(appConfig, resolvedOpenAI)
	auditorClient := subagentClient
	if resolvedAuditor.Model != "" {
		auditorClient = client.NewClient(client.Config{
			BaseURL: resolvedAuditor.BaseURL,
			APIKey:  resolvedAuditor.APIKey,
			Model:   resolvedAuditor.Model,
		})
		auditorClient.DiscoverBackend(context.Background())
	}

	// Ensure codebase-memory-mcp is available, downloading if needed.
	// Capture the path so we can auto-inject it into the MCP config below.
	var cbmBinPath string
	if cbmPath, cbmErr := ensureCBM(); cbmErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: codebase-memory-mcp unavailable (%v) — graph intelligence disabled\n", cbmErr)
	} else {
		cbmBinPath = cbmPath
		// Add its directory to PATH so any user-configured MCP entry that
		// references "codebase-memory-mcp" by name can resolve it.
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
	if mcpConfig == nil {
		mcpConfig = &mcp.MCPConfig{McpServers: make(map[string]mcp.MCPServer)}
	}
	// Auto-inject codebase-memory-mcp when ensureCBM succeeded and the user
	// has not explicitly configured it. This wires up the 14 graph tools
	// (index_repository, get_architecture, search_graph, …) automatically
	// without requiring any manual mcp_config.json edits.
	if cbmBinPath != "" {
		if _, exists := mcpConfig.McpServers["codebase-memory-mcp"]; !exists {
			mcpConfig.McpServers["codebase-memory-mcp"] = mcp.MCPServer{
				Command: cbmBinPath,
				Args:    []string{},
			}
		}
	}
	if len(mcpConfig.McpServers) > 0 {
		fmt.Println("Connecting to MCP servers...")
		if err := mcpClient.ConnectFromConfig(context.Background(), mcpConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: MCP connection error: %v\n", err)
		}
	}

	// buildScan constructs the system prompt, session, tools, and root
	// orchestrator for a given target. It is called either directly (TUI path)
	// or from the GUI picker callback (GUI mode).
	type sessionResult struct {
		sess       *session.Session
		rootAgent  *orchestrator.BaseOrchestrator
		initialMsg string
		debugLog   *debug.Logger
	}
	buildScan := func(pickedTarget, pickedLocalPath, pickedOutputDir, pickedRetestPath string) sessionResult {
		activeRetestPath := retestPath
		if pickedRetestPath != "" {
			activeRetestPath = pickedRetestPath
		}
		if activeRetestPath != "" {
			abs, err := filepath.Abs(activeRetestPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving retest path: %v\n", err)
				os.Exit(1)
			}
			if _, err := os.Stat(abs); err != nil {
				fmt.Fprintf(os.Stderr, "Error: retest report %q does not exist\n", abs)
				os.Exit(1)
			}
			activeRetestPath = abs
		}

		if pickedOutputDir == "" {
			pickedOutputDir = outputDir
		}

		// Derive repo name from the chosen target/path.
		repoName := "repo"
		if pickedLocalPath != "" {
			if base := filepath.Base(pickedLocalPath); base != "" && base != "." {
				repoName = base
			}
		} else if pickedTarget != "" {
			if parts := strings.Split(strings.TrimRight(pickedTarget, "/"), "/"); len(parts) > 0 {
				if last := parts[len(parts)-1]; last != "" {
					repoName = last
				}
			}
		}

		// Load SAST system prompt — retest uses a different prompt.
		promptFile := "prompts/instruction-sast.md"
		if activeRetestPath != "" {
			promptFile = "prompts/instruction-sast-retest.md"
		}
		content, err := assets.PromptsFS.ReadFile(promptFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading SAST system prompt: %v\n", err)
			os.Exit(1)
		}
		systemPrompt := string(content)

		// In retest mode: extract the original target and repo name from the report.
		if activeRetestPath != "" {
			reportBytes, readErr := os.ReadFile(activeRetestPath)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "Error reading retest report: %v\n", readErr)
				os.Exit(1)
			}
			parsedTarget, parsedRepo := parseReportHeader(string(reportBytes))
			if parsedTarget == "" {
				fmt.Fprintf(os.Stderr, "Error: could not find a 'Target:' line in %s\n", activeRetestPath)
				os.Exit(1)
			}
			pickedTarget = parsedTarget
			if parsedRepo != "" {
				repoName = parsedRepo
			}
		}

		// Ensure output dir exists.
		if err := os.MkdirAll(pickedOutputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}

		systemPrompt = common.ReplacePlaceholders(systemPrompt, map[string]string{
			"${{CWD}}":             cwd,
			"${{CONTAINER_NAME}}":  containerName,
			"${{WORKDIR}}":         workDir,
			"${{REPO_NAME}}":       repoName,
			"${{OUTPUT_DIR}}":      pickedOutputDir,
			"${{NETWORK_NAME}}":    networkName,
			"${{COMPOSE_PROJECT}}": composeProject,
			"${{VERSION}}":         common.Version,
		})

		if *gemmaThinkingReq {
			systemPrompt = "<|think|>" + systemPrompt
		}

		// Build initial audit message.
		var initialMessage string
		switch {
		case activeRetestPath != "":
			initialMessage = fmt.Sprintf("Retest the confirmed and likely findings from the previous SAST report.\nPrevious report: %s\nTarget: %s", activeRetestPath, pickedTarget)
		case pickedLocalPath != "":
			initialMessage = fmt.Sprintf("Perform a complete security audit of the local repository at: %s", pickedLocalPath)
		case pickedTarget != "":
			initialMessage = fmt.Sprintf("Perform a complete security audit of: %s", pickedTarget)
		}

		reportLabel := fmt.Sprintf("sast_report_%s.md", repoName)
		if activeRetestPath != "" {
			reportLabel = fmt.Sprintf("sast_retest_%s.md", repoName)
		}
		fmt.Println("Starting late-sast...")
		fmt.Printf("[late-sast] Report will be written to: %s/%s\n", pickedOutputDir, reportLabel)

		// Session + tool registration.
		sess := session.New(c, historyPath, []client.ChatMessage{}, systemPrompt, true)

		// Re-read config at scan time so settings changes (e.g. debug toggle) take
		// effect without requiring a restart of the application.
		var debugLog *debug.Logger
		if latestCfg, err := appconfig.LoadConfigFromDir(sastCfgDir); err == nil && latestCfg != nil && latestCfg.DebugLogging {
			debugLog = debug.New(pickedOutputDir)
			sess.SetDebugLogger(debugLog)
			if debugLog.Enabled() {
				fmt.Printf("[late-sast] Debug logging enabled → %s\n", debugLog.FilePath())
			}
		}

		sess.Registry.Register(&tool.ShellTool{
			Analyzer:     &tool.SASTBashAnalyzer{},
			SkipSafePath: true,
			Timeout:      5 * time.Minute,
		})
		sess.Registry.Register(tool.NewReadFileTool())
		sess.Registry.Register(tool.WriteFileTool{})

		sess.Registry.Register(tool.VulVendorProductCVETool{})
		sess.Registry.Register(tool.VulCVESearchTool{})
		sess.Registry.Register(tool.VulVendorProductsTool{})
		sess.Registry.Register(tool.VulLastCVEsTool{})

		sess.Registry.Register(tool.PatchComposeNetworkTool{})

		if docsClient, docsErr := tool.NewProContextClient(); docsErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: ProContext registry unavailable (%v) — docs_resolve/read/search disabled\n", docsErr)
		} else {
			sess.Registry.Register(tool.DocsResolveTool{Client: docsClient})
			sess.Registry.Register(tool.DocsReadTool{Client: docsClient})
			sess.Registry.Register(tool.DocsSearchTool{Client: docsClient})
		}

		ctxIdx := tool.NewContextIndex()
		indexSASTReferences(ctxIdx, "/tmp/sast-skill")
		semgrepCacheDir := func() string {
			if d, err := pathutil.LateSASTCacheDir(); err == nil {
				return filepath.Join(d, "semgrep-skills")
			}
			return "/tmp/semgrep-skills"
		}()
		if err := fetchAndIndexSemgrepSkills(context.Background(), ctxIdx, semgrepCacheDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: semgrep code-security skills unavailable (%v) — skipping\n", err)
		}
		sess.Registry.Register(tool.CtxIndexTool{Index: ctxIdx})
		sess.Registry.Register(tool.CtxSearchTool{Index: ctxIdx})
		sess.Registry.Register(tool.CtxFetchAndIndexTool{Index: ctxIdx})
		sess.Registry.Register(tool.CtxIndexFileTool{Index: ctxIdx})

		for _, t := range mcpClient.GetTools() {
			if enabled, exists := enabledTools[t.Name()]; exists && !enabled {
				continue
			}
			sess.Registry.Register(t)
		}

		rootAgent := orchestrator.NewBaseOrchestrator("main", sess, nil, 0)
		rootAgent.SetCoordinator(executor.GlobalGPU)
		return sessionResult{sess: sess, rootAgent: rootAgent, initialMsg: initialMessage, debugLog: debugLog}
	}

	if *useTUIReq {
		// ── TUI path — old behaviour, completely unchanged ───────────────────
		sr := buildScan(target, localPath, outputDir, retestPath)
		sess, rootAgent, initialMessage, debugLog := sr.sess, sr.rootAgent, sr.initialMsg, sr.debugLog

		renderer, _ := glamour.NewTermRenderer(
			glamour.WithStylesFromJSONBytes(tui.LateTheme),
			glamour.WithWordWrap(80),
			glamour.WithPreservedNewLines(),
		)
		model := tui.NewModel(rootAgent, renderer)
		p := tea.NewProgram(model)

		go func() {
			p.Send(tui.SetMessengerMsg{Messenger: p})

			ctx := context.WithValue(context.Background(), common.InputProviderKey, tui.NewTUIInputProvider(p))
			ctx = context.WithValue(ctx, common.SkipConfirmationKey, true)
			ctx = context.WithValue(ctx, common.ToolApprovalKey, true)
			rootAgent.SetContext(ctx)
			rootAgent.SetMiddlewares([]common.ToolMiddleware{
				tui.TUIConfirmMiddleware(p, sess.Registry),
			})
			ForwardOrchestratorEvents(p, rootAgent)

			if initialMessage != "" {
				time.Sleep(300 * time.Millisecond)
				p.Send(tui.AutoSubmitMsg{Text: initialMessage})
			}
		}()

		sess.Registry.Register(tool.SpawnSubagentTool{
			Runner: func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
				agentClient := subagentClient
				if agentType == "auditor" {
					agentClient = auditorClient
				}
				child, err := agent.NewSubagentOrchestrator(
					agentClient, goal, ctxFiles, agentType,
					enabledTools, true, *gemmaThinkingReq,
					*subagentMaxTurns, rootAgent,
					func(reg *common.ToolRegistry) []common.ToolMiddleware {
						return []common.ToolMiddleware{tui.TUIConfirmMiddleware(p, reg)}
					},
					debugLog,
				)
				if err != nil {
					return "", err
				}
				res, err := child.Execute("")
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("Subagent completed. Result:\n\n%s", res), nil
			},
			DefaultTimeout:    *subagentTimeout,
			HeartbeatInterval: 30 * time.Second,
			Heartbeat: func(agentType, goal string, elapsed time.Duration) {
				if debugLog != nil && debugLog.Enabled() {
					debugLog.LogEvent("SUBAGENT_HEARTBEAT", "Subagent is still running", map[string]interface{}{
						"agent_type":   agentType,
						"elapsed_ms":   elapsed.Milliseconds(),
						"goal_preview": truncateForLog(goal, 120),
					})
				}
			},
		})

		if _, err := p.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			cleanupContainer()
			os.Exit(1)
		}
	} else {
		// ── GUI path — shows target picker when no target supplied via CLI ────
		guiApp := gui.NewApp()
		guiApp.SetConfigDir(sastCfgDir)
		guiApp.SetOnQuit(cleanupContainer)

		setupFn := func(res gui.SASTPickerResult) (common.Orchestrator, string) {
			sr := buildScan(res.URL, res.LocalPath, res.OutputDir, res.RetestReportPath)
			sess, rootAgent, debugLog := sr.sess, sr.rootAgent, sr.debugLog

			baseCtx := context.WithValue(context.Background(), common.SkipConfirmationKey, true)
			baseCtx = context.WithValue(baseCtx, common.ToolApprovalKey, true)
			rootAgent.SetContext(baseCtx)
			rootAgent.SetMiddlewares([]common.ToolMiddleware{
				guiApp.ConfirmMiddleware(sess.Registry, true),
			})

			sess.Registry.Register(tool.SpawnSubagentTool{
				Runner: func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
					agentClient := subagentClient
					if agentType == "auditor" {
						agentClient = auditorClient
					}
					child, err := agent.NewSubagentOrchestrator(
						agentClient, goal, ctxFiles, agentType,
						enabledTools, true, *gemmaThinkingReq,
						*subagentMaxTurns, rootAgent,
						func(reg *common.ToolRegistry) []common.ToolMiddleware {
							return []common.ToolMiddleware{guiApp.ConfirmMiddleware(reg, true)}
						},
						debugLog,
					)
					if err != nil {
						return "", err
					}
					res, err := child.Execute("")
					if err != nil {
						return "", err
					}
					return fmt.Sprintf("Subagent completed. Result:\n\n%s", res), nil
				},
				DefaultTimeout:    *subagentTimeout,
				HeartbeatInterval: 30 * time.Second,
				Heartbeat: func(agentType, goal string, elapsed time.Duration) {
					if debugLog != nil && debugLog.Enabled() {
						debugLog.LogEvent("SUBAGENT_HEARTBEAT", "Subagent is still running", map[string]interface{}{
							"agent_type":   agentType,
							"elapsed_ms":   elapsed.Milliseconds(),
							"goal_preview": truncateForLog(goal, 120),
						})
					}
				},
			})

			return rootAgent, sr.initialMsg
		}

		guiApp.RunSAST(target, localPath, retestPath, outputDir, setupFn)
	}

	// Normal exit — clean up Docker resources.
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

// fetchAndIndexSemgrepSkills downloads the semgrep/skills code-security zip
// (if not already cached at the persistent cache dir), extracts it, and indexes
// all rule markdown files into the BM25 index. Non-fatal — caller logs the error.
func fetchAndIndexSemgrepSkills(ctx context.Context, idx *tool.ContextIndex, destDir string) error {
	const zipURL = "https://github.com/semgrep/skills/raw/main/skills/code-security.zip"
	rulesDir := filepath.Join(destDir, "code-security", "rules")

	// Already extracted from a previous run — just index.
	if _, err := os.Stat(rulesDir); err == nil {
		return indexRulesDir(idx, rulesDir)
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	// Download with a bounded timeout so startup never hangs indefinitely.
	dlCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, zipURL, nil)
	if err != nil {
		return fmt.Errorf("build semgrep skills request: %w", err)
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download semgrep skills: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download semgrep skills: HTTP %d", resp.StatusCode)
	}

	// Read zip into memory (file is ~60 KB)
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read semgrep skills zip: %w", err)
	}

	// Extract — guard against Zip Slip by verifying every entry stays inside destDir.
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("open semgrep skills zip: %w", err)
	}
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve destDir: %w", err)
	}
	for _, f := range zr.File {
		// Reject absolute paths and clean the name before joining.
		name := filepath.Clean(f.Name)
		if filepath.IsAbs(name) {
			continue
		}
		dest := filepath.Join(absDestDir, name)
		// Ensure the resolved path is still inside destDir.
		if !strings.HasPrefix(dest+string(filepath.Separator), absDestDir+string(filepath.Separator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(dest, 0755) //nolint:errcheck
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		os.WriteFile(dest, data, 0644) //nolint:errcheck
	}

	fmt.Printf("[late-sast] Indexed %d semgrep code-security rules\n",
		countMDFiles(rulesDir))
	return indexRulesDir(idx, rulesDir)
}

func indexRulesDir(idx *tool.ContextIndex, rulesDir string) error {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rulesDir, e.Name()))
		if err != nil {
			continue
		}
		source := "semgrep/" + strings.TrimSuffix(e.Name(), ".md")
		idx.IndexText(source, string(data))
	}
	return nil
}

// parseReportHeader extracts the Target URL and repo name from the header of a
// SAST report generated by late-sast.  It looks for:
//   - "Target: <url-or-path>"          → target
//   - "# SAST Security Report — <name>" → repoName
func parseReportHeader(content string) (target, repoName string) {
	for _, line := range strings.SplitN(content, "\n", 20) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Target: ") {
			target = strings.TrimSpace(strings.TrimPrefix(line, "Target: "))
		}
		if strings.HasPrefix(line, "# SAST Security Report — ") {
			repoName = strings.TrimSpace(strings.TrimPrefix(line, "# SAST Security Report — "))
		}
		if target != "" && repoName != "" {
			return
		}
	}
	return
}

func countMDFiles(dir string) int {
	entries, _ := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			n++
		}
	}
	return n
}

func truncateForLog(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// indexSASTReferences pre-loads the SAST vulnerability reference library into
// the shared BM25 index so the scanner subagent never needs to read these files
// into its conversation context (~128 KB for a typical scan).
func indexSASTReferences(idx *tool.ContextIndex, dir string) {
	// Index SKILL.md (Judge protocol + vulnerability class list)
	if b, err := os.ReadFile(filepath.Join(dir, "SKILL.md")); err == nil {
		idx.IndexText("SKILL", string(b))
	}
	// Index every reference markdown file
	entries, err := os.ReadDir(filepath.Join(dir, "references"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "references", e.Name()))
		if err != nil {
			continue
		}
		source := strings.TrimSuffix(e.Name(), ".md")
		idx.IndexText(source, string(b))
	}
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
