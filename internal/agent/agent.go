package agent

import (
	"encoding/json"
	"fmt"
	"late/internal/assets"
	"late/internal/client"
	"late/internal/common"
	"late/internal/debug"
	"late/internal/executor"
	"late/internal/orchestrator"
	"late/internal/session"
	"os"
)

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
// Used to wire confirm-middleware (TUI or GUI) to the child's own registry.
type MiddlewareFactory func(registry *common.ToolRegistry) []common.ToolMiddleware

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
	if parent != nil && parent.Registry() != nil {
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
	mws := parent.Middlewares()

	if middlewareFactory != nil {
		mws = middlewareFactory(sess.Registry)
	}

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
