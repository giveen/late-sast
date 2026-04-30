package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	"late/internal/skill"
	"late/internal/tool"
	"late/internal/tui"

	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
)

func main() {
	targetReq := flag.String("target", "", "GitHub URL of the repository to audit")
	versionReq := flag.Bool("version", false, "Show version")
	subagentMaxTurns := flag.Int("subagent-max-turns", 500, "Maximum turns per subagent")
	gemmaThinkingReq := flag.Bool("gemma-thinking", false, "Prepend <|think|> token for Gemma 4 models")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: late-sast [flags]\n\n")
		fmt.Fprintf(os.Stderr, "  late-sast --target https://github.com/owner/repo\n\n")
		fmt.Fprintf(os.Stderr, "  Alternatively, provide the URL as a positional argument:\n")
		fmt.Fprintf(os.Stderr, "  late-sast https://github.com/owner/repo\n\n")
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

	// Inject CWD
	cwd, _ := os.Getwd()
	if cwd != "" {
		systemPrompt = common.ReplacePlaceholders(systemPrompt, map[string]string{
			"${{CWD}}": cwd,
		})
	}

	if *gemmaThinkingReq {
		systemPrompt = "<|think|>" + systemPrompt
	}

	// Build initial audit message
	var initialMessage string
	if target != "" {
		initialMessage = fmt.Sprintf("Perform a complete security audit of: %s", target)
	}

	fmt.Println("Starting late-sast...")

	// Session setup (non-persistent for audit runs)
	sessionsDir, err := session.SessionDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get session directory: %v\n", err)
		os.Exit(1)
	}
	sessionID := fmt.Sprintf("sast-%s", time.Now().Format("20060102-150405"))
	historyPath := filepath.Join(sessionsDir, sessionID+".json")

	// Load app config
	appConfig, _ := appconfig.LoadConfig()
	enabledTools := make(map[string]bool)
	if appConfig != nil {
		for k, v := range appConfig.EnabledTools {
			enabledTools[k] = v
		}
	}
	// SAST always needs bash, read_file, write_file, target_edit
	enabledTools["bash"] = true
	enabledTools["read_file"] = true
	enabledTools["write_file"] = true
	enabledTools["target_edit"] = true

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

	// MCP client
	mcpClient := mcp.NewClient()
	defer mcpClient.Close()

	mcpConfig, err := mcp.LoadMCPConfig()
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

	// Register SAST tool set — permissive ShellTool, no path restrictions
	sess.Registry.Register(&tool.ShellTool{
		Analyzer:     &tool.SASTBashAnalyzer{},
		SkipSafePath: true,
	})
	sess.Registry.Register(tool.NewReadFileTool())
	sess.Registry.Register(tool.WriteFileTool{})
	sess.Registry.Register(tool.NewTargetEditTool())

	// Register skills (project + user directories)
	skillDirs := []string{}
	if userSkillsDir, err := pathutil.LateSkillsDir(); err == nil {
		skillDirs = append(skillDirs, userSkillsDir)
	}
	skillDirs = append(skillDirs, pathutil.LateProjectSkillsDir())
	if skills, err := skill.DiscoverSkills(skillDirs); err == nil && len(skills) > 0 {
		skillMap := make(map[string]*skill.Skill)
		for _, s := range skills {
			skillMap[s.Metadata.Name] = s
		}
		sess.Registry.Register(tool.ActivateSkillTool{Skills: skillMap, Reg: sess.Registry})
	}

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
		os.Exit(1)
	}
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
