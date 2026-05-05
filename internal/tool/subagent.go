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
type SubagentRetryLogger func(eventType string, message string, fields map[string]interface{})

type SpawnSubagentTool struct {
	Runner            SubagentRunner
	DefaultTimeout    time.Duration
	TimeoutByAgent    map[string]time.Duration
	HeartbeatInterval time.Duration
	// HeartbeatThrottle controls how often the Heartbeat callback is invoked.
	// A value of N means the callback fires every Nth tick (default: 10).
	HeartbeatThrottle int
	Heartbeat         func(agentType, goal string, elapsed time.Duration)
	MaxEmptyRetries   int
	EmptyRetryBackoff time.Duration
	RetryLog          SubagentRetryLogger
}

func (t SpawnSubagentTool) Name() string { return "spawn_subagent" }
func (t SpawnSubagentTool) Description() string {
	return "Spawn a specialist subagent to perform a complex task. Use this to isolate heavy work (scanning, analysis, coding) from the main context."
}
func (t SpawnSubagentTool) Parameters() json.RawMessage {
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
					"enum": ["coder", "scanner", "binary-scanner", "auditor", "setup", "strategist", "explorer", "executor"],
					"description": "The type of subagent to spawn. 'coder' for writing/modifying code. 'setup' for cloning/building/launching a target app. 'scanner' for SAST vulnerability analysis. 'binary-scanner' for compiled binary analysis. 'auditor' for deep security taint-chain analysis of hotspots (uses VulnLLM-R-7B). 'strategist' for hypothesis planning and constraints. 'explorer' for graph-first codebase navigation. 'executor' for sandbox PoC execution and raw outcome reporting."
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

	maxRetries := t.resolveMaxEmptyRetries()
	backoff := t.resolveEmptyRetryBackoff()

	for attempt := 0; attempt <= maxRetries; attempt++ {
		t.emitRetryLog("SUBAGENT_RETRY_ATTEMPT", "Subagent attempt started", map[string]interface{}{
			"agent_type":       params.AgentType,
			"attempt":          attempt + 1,
			"max_attempts":     maxRetries + 1,
			"retry_backoff_ms": backoff.Milliseconds(),
		})

		goal := params.Goal
		ctxFiles := params.CtxFiles
		if attempt > 0 {
			goal = retryGoal(goal, attempt)
			ctxFiles = reduceCtxFiles(ctxFiles)
		}

		out, err := t.runAttempt(ctx, goal, ctxFiles, params.AgentType)
		if err == nil && strings.TrimSpace(out) != "" {
			t.emitRetryLog("SUBAGENT_RETRY_FINAL", "Subagent completed", map[string]interface{}{
				"agent_type":   params.AgentType,
				"attempt":      attempt + 1,
				"max_attempts": maxRetries + 1,
				"outcome":      "success",
			})
			return out, nil
		}

		if !isEmptyStreamLike(out, err) {
			outcome := "error"
			if err == nil {
				outcome = "completed_non_retryable"
			}
			t.emitRetryLog("SUBAGENT_RETRY_FINAL", "Subagent completed without retry fallback", map[string]interface{}{
				"agent_type":   params.AgentType,
				"attempt":      attempt + 1,
				"max_attempts": maxRetries + 1,
				"outcome":      outcome,
				"error":        safeErr(err),
			})
			if err != nil {
				return "", err
			}
			return out, nil
		}

		if attempt == maxRetries {
			t.emitRetryLog("SUBAGENT_RETRY_FINAL", "Subagent retries exhausted", map[string]interface{}{
				"agent_type":   params.AgentType,
				"attempt":      attempt + 1,
				"max_attempts": maxRetries + 1,
				"outcome":      "retry_exhausted",
				"error":        safeErr(err),
			})
			if err != nil {
				return "", fmt.Errorf("subagent '%s' failed after %d attempts due to empty-stream behavior: %w", params.AgentType, maxRetries+1, err)
			}
			return fmt.Sprintf("subagent '%s' returned empty output after %d attempts (empty-stream retries exhausted)", params.AgentType, maxRetries+1), nil
		}

		t.emitRetryLog("SUBAGENT_RETRY_BACKOFF", "Scheduling subagent retry after empty-stream behavior", map[string]interface{}{
			"agent_type":       params.AgentType,
			"attempt":          attempt + 1,
			"next_attempt":     attempt + 2,
			"max_attempts":     maxRetries + 1,
			"retry_backoff_ms": (backoff * time.Duration(attempt+1)).Milliseconds(),
			"trigger":          emptyLikeTrigger(out, err),
		})

		select {
		case <-ctx.Done():
			t.emitRetryLog("SUBAGENT_RETRY_FINAL", "Subagent retry canceled by context", map[string]interface{}{
				"agent_type":   params.AgentType,
				"attempt":      attempt + 1,
				"max_attempts": maxRetries + 1,
				"outcome":      "canceled",
				"error":        ctx.Err().Error(),
			})
			return "", ctx.Err()
		case <-time.After(backoff * time.Duration(attempt+1)):
		}
	}

	return "", fmt.Errorf("unexpected subagent retry state")
}

func (t SpawnSubagentTool) runAttempt(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
	timeout := t.resolveTimeout(agentType)
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	heartbeatEvery := t.resolveHeartbeatInterval()
	throttle := t.resolveHeartbeatThrottle()
	start := time.Now()
	var stallWarned bool
	var tickCount int

	type subagentResult struct {
		output string
		err    error
	}
	resultCh := make(chan subagentResult, 1)
	go func() {
		out, err := t.Runner(runCtx, goal, ctxFiles, agentType)
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
				t.Heartbeat(agentType, goal, time.Since(start))
			}
			return res.output, res.err
		case <-runCtx.Done():
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return "", fmt.Errorf("subagent '%s' timed out after %s", agentType, timeout)
			}
			return "", runCtx.Err()
		case <-tickerC(ticker):
			tickCount++
			elapsed := time.Since(start)
			if t.Heartbeat != nil && tickCount%throttle == 0 {
				t.Heartbeat(agentType, goal, elapsed)
			}
			// Emit a stall warning once when the subagent approaches its timeout
			// threshold. This helps diagnose agents that are spinning without
			// making visible progress.
			if !stallWarned && timeout > 0 && elapsed > timeout*4/5 {
				t.emitRetryLog("SUBAGENT_STALL_WARNING", "Subagent approaching timeout threshold", map[string]interface{}{
					"agent_type":  agentType,
					"elapsed_ms":  elapsed.Milliseconds(),
					"timeout_ms":  timeout.Milliseconds(),
					"pct_elapsed": int(elapsed * 100 / timeout),
				})
				stallWarned = true
			}
		}
	}
}

func isEmptyStreamLike(out string, err error) bool {
	if err == nil {
		return strings.TrimSpace(out) == ""
	}

	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"empty response",
		"empty stream",
		"early termination",
		"no finish_reason and no content",
		"context limit",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}

	return false
}

func emptyLikeTrigger(out string, err error) string {
	if err == nil {
		return "empty_output"
	}

	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"empty response",
		"empty stream",
		"early termination",
		"no finish_reason and no content",
		"context limit",
	} {
		if strings.Contains(msg, needle) {
			return needle
		}
	}

	return "error"
}

func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func retryGoal(goal string, attempt int) string {
	return fmt.Sprintf("%s\n\nRetry attempt %d: previous run ended with an empty stream/response. Continue from partial progress and return a concise non-empty final output.", goal, attempt+1)
}

func reduceCtxFiles(ctxFiles []string) []string {
	const maxFiles = 32
	if len(ctxFiles) <= maxFiles {
		return ctxFiles
	}
	trimmed := make([]string, maxFiles)
	copy(trimmed, ctxFiles[:maxFiles])
	return trimmed
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
	case "scanner", "binary-scanner", "setup", "strategist", "explorer", "executor":
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

func (t SpawnSubagentTool) resolveHeartbeatThrottle() int {
	if t.HeartbeatThrottle > 0 {
		return t.HeartbeatThrottle
	}
	return 10 // emit every 10th tick by default
}

func (t SpawnSubagentTool) resolveMaxEmptyRetries() int {
	if t.MaxEmptyRetries > 0 {
		return t.MaxEmptyRetries
	}
	return 1
}

func (t SpawnSubagentTool) resolveEmptyRetryBackoff() time.Duration {
	if t.EmptyRetryBackoff > 0 {
		return t.EmptyRetryBackoff
	}
	return 1 * time.Second
}

func (t SpawnSubagentTool) emitRetryLog(eventType string, message string, fields map[string]interface{}) {
	if t.RetryLog != nil {
		t.RetryLog(eventType, message, fields)
	}
}

func (t SpawnSubagentTool) RequiresConfirmation(args json.RawMessage) bool { return false }

func (t SpawnSubagentTool) CallString(args json.RawMessage) string {
	goal := getToolParam(args, "goal")
	if goal == "" {
		goal = "unknown goal"
	}
	return fmt.Sprintf("Spawning subagent for: %s", truncate(goal, 50))
}
