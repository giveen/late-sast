package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"late/internal/assets"
	"late/internal/client"
	"late/internal/common"
	"late/internal/debug"
	"late/internal/executor"
	"late/internal/orchestrator"
	"late/internal/session"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func setupBootstrapFirstMiddleware() common.ToolMiddleware {
	needsReadiness := false

	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			if needsReadiness && tc.Function.Name != "wait_for_target_ready" {
				return "", fmt.Errorf("setup agent must call 'wait_for_target_ready' immediately after successful launch/setup before '%s'", tc.Function.Name)
			}

			out, err := next(ctx, tc)
			if err != nil {
				return out, err
			}

			if tc.Function.Name == "setup_container" || (tc.Function.Name == "launch_docker" && launchDockerActuallyStarted(out)) {
				needsReadiness = true
			}

			if needsReadiness && tc.Function.Name == "wait_for_target_ready" {
				needsReadiness = false
			}

			return out, nil
		}
	}
}

func launchDockerActuallyStarted(out string) bool {
	var payload struct {
		Status   string `json:"status"`
		ModeUsed string `json:"mode_used"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return false
	}
	return payload.Status == "ok" && payload.ModeUsed != ""
}

var urlInShellRe = regexp.MustCompile("https?://[^\\s\"'`]+")

func scannerExploitReplayMiddleware() common.ToolMiddleware {
	attemptedCandidates := map[string]bool{}

	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			switch tc.Function.Name {
			case "run_exploit_replay":
				candidate, ok := replayCandidateFromArgs(tc.Function.Arguments)
				if !ok {
					return "", fmt.Errorf("run_exploit_replay must include endpoint or path/port so candidate matching can be enforced")
				}
				attemptedCandidates[candidate] = true
				return next(ctx, tc)

			case "bash":
				command, ok := bashCommandFromArgs(tc.Function.Arguments)
				if !ok {
					return next(ctx, tc)
				}
				isRawPoC, candidate := rawExploitCandidateFromCommand(command)
				if !isRawPoC {
					return next(ctx, tc)
				}
				if candidate == "" {
					return "", fmt.Errorf("raw exploit shell PoC blocked: unable to derive finding candidate from command; run run_exploit_replay first")
				}
				if !attemptedCandidates[candidate] {
					return "", fmt.Errorf("raw exploit shell PoC blocked for candidate %q: run run_exploit_replay for this finding first", candidate)
				}
				return next(ctx, tc)
			default:
				return next(ctx, tc)
			}
		}
	}
}

func scannerSecretsFirstMiddleware() common.ToolMiddleware {
	secretsScanned := false

	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			if tc.Function.Name == "trace_path" && !secretsScanned {
				return "", fmt.Errorf("scanner should call 'run_secrets_scanner' before taint tracing with 'trace_path'")
			}

			out, err := next(ctx, tc)
			if err != nil {
				return out, err
			}
			if tc.Function.Name == "run_secrets_scanner" {
				secretsScanned = true
			}
			return out, nil
		}
	}
}

func cleanupToolPreferredMiddleware() common.ToolMiddleware {
	cleanupUsed := false

	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			switch tc.Function.Name {
			case "cleanup_scan_environment":
				out, err := next(ctx, tc)
				if err == nil {
					cleanupUsed = true
				}
				return out, err
			case "bash":
				if cleanupUsed {
					return next(ctx, tc)
				}
				command, ok := bashCommandFromArgs(tc.Function.Arguments)
				if !ok {
					return next(ctx, tc)
				}
				if looksLikeAdHocCleanup(command) {
					return "", fmt.Errorf("prefer 'cleanup_scan_environment' over ad-hoc docker cleanup commands")
				}
				return next(ctx, tc)
			default:
				return next(ctx, tc)
			}
		}
	}
}

func looksLikeAdHocCleanup(command string) bool {
	c := strings.ToLower(command)
	if !strings.Contains(c, "docker") {
		return false
	}

	if strings.Contains(c, "docker compose") && strings.Contains(c, " down") {
		return true
	}
	if strings.Contains(c, "docker network rm") {
		return true
	}
	if strings.Contains(c, "docker rmi") {
		return true
	}
	if strings.Contains(c, "docker rm -f") {
		return true
	}
	if strings.Contains(c, "/tmp/sast-skill") || strings.Contains(c, "rm -rf /tmp/sast") {
		return true
	}

	return false
}

// CleanupToolPreferredMiddleware nudges agents toward the deterministic
// cleanup_scan_environment tool instead of ad-hoc bash teardown commands.
func CleanupToolPreferredMiddleware() common.ToolMiddleware {
	return cleanupToolPreferredMiddleware()
}

func replayCandidateFromArgs(rawArgs string) (string, bool) {
	var p struct {
		Endpoint string            `json:"endpoint"`
		Path     string            `json:"path"`
		Query    map[string]string `json:"query"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &p); err != nil {
		return "", false
	}
	if c, ok := candidateFromURL(p.Endpoint); ok {
		return c, true
	}
	path := normalizePath(p.Path)
	if path == "" {
		return "", false
	}
	u := url.URL{Path: path}
	if len(p.Query) > 0 {
		q := url.Values{}
		for k, v := range p.Query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return candidateFromParsedURL(&u), true
}

func bashCommandFromArgs(rawArgs string) (string, bool) {
	var p struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &p); err != nil {
		return "", false
	}
	cmd := p.Command
	if cmd == "" {
		return "", false
	}
	return cmd, true
}

func rawExploitCandidateFromCommand(command string) (bool, string) {
	cmdLower := strings.ToLower(command)
	if !strings.Contains(cmdLower, "docker exec") {
		return false, ""
	}
	if !strings.Contains(cmdLower, "wget") && !strings.Contains(cmdLower, "curl") {
		return false, ""
	}
	for _, hit := range urlInShellRe.FindAllString(command, -1) {
		u, err := url.Parse(hit)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h != "localhost" && h != "127.0.0.1" {
			continue
		}
		if c := candidateFromParsedURL(u); c != "" {
			return true, c
		}
	}
	return true, ""
}

func candidateFromURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	c := candidateFromParsedURL(u)
	if c == "" {
		return "", false
	}
	return c, true
}

func candidateFromParsedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	path := normalizePath(u.Path)
	if path == "" {
		return ""
	}
	if u.RawQuery == "" {
		return path
	}
	return path + "?" + u.Query().Encode()
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func promptPathForAgentType(agentType string) (string, error) {
	switch agentType {
	case "coder":
		return "prompts/instruction-coding.md", nil
	case "scanner":
		return "prompts/instruction-sast-scanner.md", nil
	case "binary-scanner":
		return "prompts/instruction-sast-scanner-binary.md", nil
	case "auditor":
		return "prompts/instruction-sast-auditor.md", nil
	case "setup":
		return "prompts/instruction-sast-setup.md", nil
	case "strategist":
		return "prompts/instruction-sast-strategist.md", nil
	case "explorer":
		return "prompts/instruction-sast-explorer.md", nil
	case "executor":
		return "prompts/instruction-sast-executor.md", nil
	default:
		return "", fmt.Errorf("unknown agent type: %s", agentType)
	}
}

func allowToolForAgentType(agentType, toolName string) bool {
	switch agentType {
	case "strategist":
		return toolName == "read_file"
	case "explorer":
		switch toolName {
		case "search_graph", "trace_path", "get_code_snippet", "query_graph", "read_file":
			return true
		default:
			return false
		}
	case "executor":
		switch toolName {
		case "bash", "read_file":
			return true
		default:
			return false
		}
	case "auditor":
		return toolName == "read_file"
	default:
		return true
	}
}

// MiddlewareFactory creates middlewares bound to a specific tool registry.
// Used to wire confirm-middleware (GUI) to the child's own registry.
type MiddlewareFactory func(registry *common.ToolRegistry) []common.ToolMiddleware

func buildSubagentMiddlewares(
	parent common.Orchestrator,
	registry *common.ToolRegistry,
	agentType string,
	middlewareFactory MiddlewareFactory,
) []common.ToolMiddleware {
	// Default behavior is to inherit parent middlewares.
	base := parent.Middlewares()

	// If a factory is provided, it intentionally replaces inherited middlewares.
	// This avoids carrying parent-scoped confirm middleware bound to a different
	// registry into child subagents.
	if middlewareFactory != nil {
		base = middlewareFactory(registry)
	}

	if agentType == "setup" {
		return append([]common.ToolMiddleware{setupBootstrapFirstMiddleware(), cleanupToolPreferredMiddleware()}, base...)
	}
	if agentType == "scanner" || agentType == "binary-scanner" {
		return append([]common.ToolMiddleware{scannerSecretsFirstMiddleware(), scannerExploitReplayMiddleware()}, base...)
	}

	return base
}

// NewSubagentOrchestrator creates a new BaseOrchestrator for a subagent.
func NewSubagentOrchestrator(
	c *client.Client,
	goal string,
	ctxFiles []string,
	agentType string,
	enabledTools map[string]bool,
	injectCWD bool,
	gemmaThinking bool,
	maxTurns int,
	parent common.Orchestrator,
	middlewareFactory MiddlewareFactory,
	debugLogger *debug.Logger,
) (common.Orchestrator, error) {
	if parent == nil {
		return nil, fmt.Errorf("parent orchestrator is required")
	}

	// 1. Determine System Prompt
	promptPath, err := promptPathForAgentType(agentType)
	if err != nil {
		return nil, err
	}
	content, err := assets.PromptsFS.ReadFile(promptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded prompt for agent %q: %w", agentType, err)
	}
	systemPrompt := string(content)

	if agentType == "coder" && injectCWD {
		cwd, cwdErr := os.Getwd()
		if cwdErr == nil {
			systemPrompt = common.ReplacePlaceholders(systemPrompt, map[string]string{
				"${{CWD}}": cwd,
			})
		}
	}

	if gemmaThinking {
		systemPrompt = "<|think|>" + systemPrompt
	}

	// 2. Create Session
	// Subagents should not persist their history to the sessions directory
	sess := session.New(c, "", []client.ChatMessage{}, systemPrompt, true)

	// Set debug logger if provided
	if debugLogger != nil {
		sess.SetDebugLogger(debugLogger)
	}

	// Auditor is a small 7B model — give it extra generation budget so it can
	// complete all hotspot verdicts without truncating mid-JSON.
	// Also set a repeat_penalty so the model does not enter a repetition loop
	// on long reasoning chains (common failure mode for sub-10B models).
	if agentType == "auditor" {
		sess.SetMaxTokens(8192)
		sess.SetExtraBody(map[string]any{
			"repeat_penalty": 1.15,
			"repeat_last_n":  512,
		})
	}
	// Inherit all tools from parent (including MCP tools)
	if parent.Registry() != nil {
		for _, t := range parent.Registry().All() {
			// Skip spawn_subagent and write_implementation_plan to prevent recursion/confusion
			name := t.Name()
			if name == "spawn_subagent" || name == "write_implementation_plan" {
				continue
			}
			if !allowToolForAgentType(agentType, name) {
				continue
			}
			sess.Registry.Register(t)
		}
	}

	// Always ensure coder subagents have the full toolset (not just planning tools)
	if agentType == "coder" {
		executor.RegisterTools(sess.Registry, enabledTools, false)
	}

	// 3. Construct Initial Context
	initialMsg := fmt.Sprintf("Goal: %s\n\n", goal)
	if len(ctxFiles) > 0 {
		initialMsg += "Context Files:\n"
		for _, f := range ctxFiles {
			content, err := os.ReadFile(f)
			if err == nil {
				initialMsg += fmt.Sprintf("- %s:\n```\n%s\n```\n", f, string(content))
			}
		}
	}

	if err := sess.AddUserMessage(initialMsg); err != nil {
		return nil, fmt.Errorf("failed to add initial message: %w", err)
	}

	// 4. Create Orchestrator
	id := fmt.Sprintf("subagent-%d", len(parent.Children()))
	mws := buildSubagentMiddlewares(parent, sess.Registry, agentType, middlewareFactory)

	child := orchestrator.NewBaseOrchestrator(id, sess, mws, maxTurns)
	child.SetContext(parent.Context())

	if p, ok := parent.(*orchestrator.BaseOrchestrator); ok {
		p.AddChild(child, agentType)
		if coord := p.Coordinator(); coord != nil {
			child.SetCoordinator(coord)
		}
	}

	return child, nil
}

func FormatToolConfirmPrompt(tc client.ToolCall) string {
	var jsonObj map[string]interface{}
	args := tc.Function.Arguments
	if err := json.Unmarshal([]byte(args), &jsonObj); err == nil {
		pretty, _ := json.MarshalIndent(jsonObj, "", "  ")
		args = string(pretty)
	}
	return fmt.Sprintf("Execute **%s**:\n\n```json\n%s\n```", tc.Function.Name, args)
}
