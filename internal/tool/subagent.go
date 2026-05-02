package tool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SubagentRunner func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error)

type SpawnSubagentTool struct {
	Runner            SubagentRunner
	DefaultTimeout    time.Duration
	TimeoutByAgent    map[string]time.Duration
	HeartbeatInterval time.Duration
	Heartbeat         func(agentType, goal string, elapsed time.Duration)
}

func (t SpawnSubagentTool) Name() string { return "spawn_subagent" }
func (t SpawnSubagentTool) Description() string {
	return "Spawn a specialist subagent to perform a complex task. Use this to isolate heavy work (scanning, analysis, coding) from the main context."
}
func (t SpawnSubagentTool) Parameters() json.RawMessage {
	// TODO: add reviewer, committer
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"goal": { "type": "string", "description": "The specific goal or instruction for the subagent" },
			"ctx_files": { 
				"type": "array", 
				"items": { "type": "string" },
				"description": "List of file paths to provide as context to the subagent" 
			},
			"agent_type": { 
				"type": "string", 
				"enum": ["coder", "scanner", "binary-scanner", "auditor", "setup"],
				"description": "The type of subagent to spawn. 'coder' for writing/modifying code. 'setup' for cloning/building/launching a target app. 'scanner' for SAST vulnerability analysis. 'binary-scanner' for compiled binary analysis. 'auditor' for deep security taint-chain analysis of hotspots (uses VulnLLM-R-7B)."
			}
		},
		"required": ["goal", "agent_type"]
	}`)
}

func (t SpawnSubagentTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	if t.Runner == nil {
		return "", fmt.Errorf("subagent runner not configured")
	}

	var params struct {
		Goal      string   `json:"goal"`
		CtxFiles  []string `json:"ctx_files"`
		AgentType string   `json:"agent_type"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %v", err)
	}

	timeout := t.resolveTimeout(params.AgentType)
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	heartbeatEvery := t.resolveHeartbeatInterval()
	start := time.Now()

	type subagentResult struct {
		output string
		err    error
	}
	resultCh := make(chan subagentResult, 1)
	go func() {
		out, err := t.Runner(runCtx, params.Goal, params.CtxFiles, params.AgentType)
		resultCh <- subagentResult{output: out, err: err}
	}()

	var ticker *time.Ticker
	if heartbeatEvery > 0 {
		ticker = time.NewTicker(heartbeatEvery)
		defer ticker.Stop()
	}

	for {
		select {
		case res := <-resultCh:
			if t.Heartbeat != nil {
				t.Heartbeat(params.AgentType, params.Goal, time.Since(start))
			}
			// If the runner returned no error but also no output, the subagent
			// stalled (context overflow, unexpected stop, etc.). Return a
			// descriptive string so the orchestrator can see what happened and
			// avoid treating silence as "no findings".
			if res.err == nil && strings.TrimSpace(res.output) == "" {
				return fmt.Sprintf("subagent '%s' completed but returned empty output — possible context window overflow or unexpected termination", params.AgentType), nil
			}
			return res.output, res.err
		case <-runCtx.Done():
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return "", fmt.Errorf("subagent '%s' timed out after %s", params.AgentType, timeout)
			}
			return "", runCtx.Err()
		case <-tickerC(ticker):
			if t.Heartbeat != nil {
				t.Heartbeat(params.AgentType, params.Goal, time.Since(start))
			}
		}
	}

}

func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func (t SpawnSubagentTool) resolveTimeout(agentType string) time.Duration {
	if len(t.TimeoutByAgent) > 0 {
		if d, ok := t.TimeoutByAgent[agentType]; ok {
			return d
		}
	}
	if t.DefaultTimeout > 0 {
		return t.DefaultTimeout
	}

	switch agentType {
	case "auditor":
		return 20 * time.Minute
	case "scanner", "binary-scanner", "setup":
		return 15 * time.Minute
	default:
		return 10 * time.Minute
	}
}

func (t SpawnSubagentTool) resolveHeartbeatInterval() time.Duration {
	if t.HeartbeatInterval > 0 {
		return t.HeartbeatInterval
	}
	return 30 * time.Second
}

func (t SpawnSubagentTool) RequiresConfirmation(args json.RawMessage) bool { return false }

func (t SpawnSubagentTool) CallString(args json.RawMessage) string {
	goal := getToolParam(args, "goal")
	if goal == "" {
		goal = "unknown goal"
	}
	return fmt.Sprintf("Spawning subagent for: %s", truncate(goal, 50))
}
