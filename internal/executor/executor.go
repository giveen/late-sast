package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"late/internal/client"
	"late/internal/common"
	"late/internal/debug"
	"late/internal/pathutil"
	"late/internal/session"
	"late/internal/skill"
	"late/internal/tool"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// --- Stream Accumulator ---

// execHTMLTagRe strips known HTML formatting tags that models sometimes emit into
// their output. Preserves generic angle-bracket constructs (C++ templates, XML
// snippets, generic type params).
var execHTMLTagRe = regexp.MustCompile(`(?i)</?(?:pre|code|br|p|li|ol|ul|details|summary|div|span|h[1-6]|blockquote|hr|table|thead|tbody|tr|th|td|em|strong|b|i|a|img|figure|figcaption|section|article|aside|header|footer|nav|main|form|input|button|select|option|textarea|label|script|style|html|head|body)(?:\s[^>]*)?>|</>`)

// sanitizeContent strips HTML tags and collapses repeated-line loops before the
// assistant message is committed to session history. This keeps runaway model
// output (hundreds of </pre> tags) from inflating the context window.
func sanitizeContent(s string) string {
	if s == "" {
		return s
	}
	const maxRep = 3
	s = execHTMLTagRe.ReplaceAllString(s, "")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	var lastLine string
	repCount := 0
	consecBlank := 0
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			consecBlank++
			if consecBlank <= 1 {
				out = append(out, l)
			}
			continue
		}
		consecBlank = 0
		if trimmed == lastLine {
			repCount++
			if repCount >= maxRep {
				continue
			}
		} else {
			repCount = 0
			lastLine = trimmed
		}
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// StreamAccumulator collects streaming deltas into coherent content.
// This replaces the duplicated accumulation logic in tui/state.go (GenerationState.Append)
// and agent/agent.go (manual accumulation loop).
type StreamAccumulator struct {
	Content      string
	Reasoning    string
	ToolCalls    []client.ToolCall
	Usage        client.Usage
	FinishReason string
}

// Append merges a single streaming delta into the accumulated state.
func (a *StreamAccumulator) Append(res common.StreamResult) {
	a.Content += res.Content
	a.Reasoning += res.ReasoningContent

	if res.Usage.TotalTokens > 0 {
		a.Usage = res.Usage
	}

	if res.FinishReason != "" {
		a.FinishReason = res.FinishReason
	}

	for _, delta := range res.ToolCalls {
		index := delta.Index
		if index < len(a.ToolCalls) {
			a.ToolCalls[index].Function.Arguments += delta.Function.Arguments
			if delta.Function.Name != "" {
				a.ToolCalls[index].Function.Name = delta.Function.Name
			}
			if delta.ID != "" {
				a.ToolCalls[index].ID = delta.ID
			}
		} else {
			a.ToolCalls = append(a.ToolCalls, delta)
		}
	}
}

// Reset clears all accumulated state.
func (a *StreamAccumulator) Reset() {
	a.Content = ""
	a.Reasoning = ""
	a.ToolCalls = nil
	a.FinishReason = ""
}

// --- Tool Execution ---

const (
	maxToolCallsPerTurn     = 24
	maxDuplicateToolTurns   = 2
	maxToolExecutionPerTurn = 5 * time.Minute
)

// ToolExecutionStats captures aggregate tool outcomes for a single turn.
type ToolExecutionStats struct {
	Total      int
	Failures   int
	Blocked    int
	TimedOut   int
	DurationMS int64
}

// ExecuteToolCallsWithStats runs a slice of tool calls and returns execution stats.
// cache may be nil; when provided, idempotent tool results are served from cache.
func ExecuteToolCallsWithStats(
	ctx context.Context,
	sess *session.Session,
	toolCalls []client.ToolCall,
	middlewares []common.ToolMiddleware,
	onToolState func(toolName string, running bool),
	cache *ToolResultCache,
) (ToolExecutionStats, error) {
	stats := ToolExecutionStats{}

	turnCtx := ctx
	if maxToolExecutionPerTurn > 0 {
		var cancel context.CancelFunc
		turnCtx, cancel = context.WithTimeout(ctx, maxToolExecutionPerTurn)
		defer cancel()
	}

	started := time.Now()

	// Base execution logic
	baseRunner := func(ctx context.Context, tc client.ToolCall) (string, error) {
		t := sess.Registry.Get(tc.Function.Name)
		if t == nil {
			return fmt.Sprintf("Error: tool '%s' not found", tc.Function.Name), nil
		}
		return sess.ExecuteTool(ctx, tc)
	}

	// Wrap with middlewares (in reverse order so first middleware is outermost)
	runner := baseRunner
	for i := len(middlewares) - 1; i >= 0; i-- {
		runner = middlewares[i](common.ToolRunner(runner))
	}

	for _, tc := range toolCalls {
		stats.Total++

		// Fail-closed: if no confirmation middleware is provided, do not
		// execute shell commands (they must be explicitly approved by a
		// confirmation middleware).
		if len(middlewares) == 0 {
			if t := sess.Registry.Get(tc.Function.Name); t != nil {
				if _, ok := t.(*tool.ShellTool); ok {
					result := "shell command requires explicit approval before execution"
					stats.Blocked++
					if err := sess.AddToolResultMessage(tc.ID, result); err != nil {
						return stats, err
					}
					continue
				}
			}
		}

		// Serve from cache when possible (idempotent tools only).
		if cache != nil {
			if cached, hit := cache.Get(tc.Function.Name, tc.Function.Arguments); hit {
				sess.LogEvent("TOOL_CACHE_HIT", "Returning cached tool result", map[string]interface{}{
					"tool": tc.Function.Name,
					"id":   tc.ID,
				})
				sess.LogDebugToolResult(tc.Function.Name, tc.ID, cached, nil, 0)
				if err := sess.AddToolResultMessage(tc.ID, cached); err != nil {
					return stats, err
				}
				continue
			}
		}

		toolStart := time.Now()
		if onToolState != nil {
			onToolState(tc.Function.Name, true)
		}
		// spawn_subagent manages its own timeout internally; use the parent context
		// so the per-turn deadline doesn't kill a long-running subagent early.
		// All other tools get an optional per-tool timeout layered on top of the
		// per-turn deadline.
		var toolCancel context.CancelFunc
		callCtx := turnCtx
		if tc.Function.Name == "spawn_subagent" {
			callCtx = ctx
		} else if td := toolTimeoutFor(tc.Function.Name); td > 0 {
			callCtx, toolCancel = context.WithTimeout(turnCtx, td)
		}
		result, runErr := runner(callCtx, tc)
		if toolCancel != nil {
			toolCancel()
		}
		if runErr != nil {
			if callCtx.Err() == context.DeadlineExceeded {
				stats.TimedOut++
			} else {
				stats.Failures++
			}
			result = fmt.Sprintf("Error executing tool %s: %v", tc.Function.Name, runErr)
		} else {
			if strings.Contains(result, "requires explicit approval") || strings.Contains(result, "Tool execution cancelled by user") {
				stats.Blocked++
			}
			if strings.HasPrefix(result, "Command failed with exit code") || strings.HasPrefix(result, "Error executing command:") {
				stats.Failures++
			}
			// Populate cache for successful idempotent tools.
			if cache != nil {
				cache.Set(tc.Function.Name, tc.Function.Arguments, result)
			}
		}
		// Log the final result (after error-wrapping) so the debug log matches what the LLM receives.
		sess.LogDebugToolResult(tc.Function.Name, tc.ID, result, runErr, time.Since(toolStart))
		if err := sess.AddToolResultMessage(tc.ID, result); err != nil {
			if onToolState != nil {
				onToolState(tc.Function.Name, false)
			}
			return stats, err
		}
		if onToolState != nil {
			onToolState(tc.Function.Name, false)
		}
	}

	stats.DurationMS = time.Since(started).Milliseconds()
	return stats, nil
}

// ExecuteToolCalls runs a slice of tool calls against the session.
// Results are added to the session history.
func ExecuteToolCalls(ctx context.Context, sess *session.Session, toolCalls []client.ToolCall, middlewares []common.ToolMiddleware) error {
	_, err := ExecuteToolCallsWithStats(ctx, sess, toolCalls, middlewares, nil, nil)
	return err
}

// --- Tool Registration ---

// RegisterTools registers the common tool set on a session's registry.
// If isPlanning is true, it only registers read-only tools and the planning tool.
// Otherwise, it registers the full set of coding tools.
// configuredSkillsDir is optional; when provided, its skills are discovered
// additively alongside default skill directories.
func RegisterTools(reg *tool.Registry, enabledTools map[string]bool, isPlanning bool, configuredSkillsDir ...string) {
	if enabledTools == nil {
		enabledTools = make(map[string]bool)
	}

	// Always register read-only and base tools
	if enabledTools["read_file"] {
		reg.Register(tool.NewReadFileTool())
	}
	if enabledTools["bash"] {
		reg.Register(&tool.ShellTool{})
	}

	if isPlanning {
		// Planning-only tools
		reg.Register(tool.WriteImplementationPlanTool{})
	} else {
		// Coding-only tools
		if enabledTools["write_file"] {
			reg.Register(tool.WriteFileTool{})
		}
		if enabledTools["target_edit"] {
			reg.Register(tool.NewTargetEditTool())
		}
	}

	// Register Skills. This is additive: configured dir (if any) + defaults.
	// Precedence is controlled by directory order because later duplicate names
	// overwrite earlier entries in skillMap.
	skillDirs := buildSkillDirs(configuredSkillsDir...)

	skills, err := skill.DiscoverSkills(skillDirs)
	if err == nil && len(skills) > 0 {
		skillMap := make(map[string]*skill.Skill)
		for _, s := range skills {
			skillMap[s.Metadata.Name] = s
		}
		reg.Register(tool.ActivateSkillTool{
			Skills: skillMap,
			Reg:    reg,
		})
	}
}

func buildSkillDirs(configuredSkillsDir ...string) []string {
	var dirs []string
	seen := make(map[string]struct{})

	addDir := func(dir string) {
		d := strings.TrimSpace(dir)
		if d == "" {
			return
		}
		d = filepath.Clean(d)
		if _, exists := seen[d]; exists {
			return
		}
		seen[d] = struct{}{}
		dirs = append(dirs, d)
	}

	if len(configuredSkillsDir) > 0 {
		addDir(configuredSkillsDir[0])
	}
	if userSkillsDir, err := pathutil.LateSkillsDir(); err == nil {
		addDir(userSkillsDir)
	}
	addDir(pathutil.LateProjectSkillsDir())

	return dirs
}

// --- Consume Stream ---

// ConsumeStream drains a stream channel pair into a StreamAccumulator.
// It calls onChunk (if non-nil) for each delta, enabling real-time UI updates.
// Returns the final accumulated state or an error.
func ConsumeStream(
	ctx context.Context,
	outCh <-chan common.StreamResult,
	errCh <-chan error,
	onChunk func(common.StreamResult),
) (*StreamAccumulator, error) {
	acc := &StreamAccumulator{}

	for res := range outCh {
		acc.Append(res)
		if onChunk != nil {
			onChunk(res)
		}

		// Check for context cancellation (stop request)
		select {
		case <-ctx.Done():
			// Context cancelled - stop streaming but return accumulated data
			return acc, nil
		default:
			// Continue streaming
		}
	}

	// Check for stream error
	select {
	case err, ok := <-errCh:
		if ok && err != nil {
			return acc, fmt.Errorf("stream error: %w", err)
		}
	default:
	}

	return acc, nil
}

// --- Full Run Loop (Blocking) ---

// RunLoop handles the core, blocking event loop for autonomous agents.
// It forces the sequence: inference stream -> verifiable accumulation -> history commit -> safe tool execution.
// If the deterministic tool extraction yields zero calls, the loop securely collapses and returns execution control.
//
// When coordinator is non-nil the GPU lock is held only for the duration of
// the HTTP stream (StartStream → ConsumeStream). The lock is released before
// tool execution so that other agents can "Think" while this agent "Works".
// The optional callbacks fire at each state transition:
//
//   - onStartTurn    — called before attempting to acquire the GPU lock (→ "queued")
//   - onGPUAcquired  — called immediately after the GPU lock is obtained (→ "thinking")
//   - onGPUReleased  — called immediately after the GPU lock is released (→ "working")
func RunLoop(
	ctx context.Context,
	sess *session.Session,
	maxTurns int,
	extraBody map[string]any,
	onStartTurn func(),
	onEndTurn func(),
	onStreamChunk func(common.StreamResult),
	middlewares []common.ToolMiddleware,
	coordinator *ResourceCoordinator,
	onGPUAcquired func(),
	onGPUReleased func(),
	onToolState func(toolName string, running bool),
	sharedCache *ToolResultCache,
) (string, error) {
	var lastContent string
	var previousToolSig string
	duplicateToolTurns := 0
	cache := sharedCache
	if cache == nil {
		cache = NewToolResultCache()
	}

	for i := 0; maxTurns <= 0 || i < maxTurns; i++ {
		if onStartTurn != nil {
			onStartTurn()
		}

		if coordinator != nil {
			if err := coordinator.AcquireGPULock(ctx); err != nil {
				return "", err
			}
			if onGPUAcquired != nil {
				onGPUAcquired()
			}
		}

		streamCh, errCh := sess.StartStream(ctx, extraBody)
		acc, err := ConsumeStream(ctx, streamCh, errCh, onStreamChunk)

		if coordinator != nil {
			coordinator.ReleaseGPULock()
			// onGPUReleased ("working") is deferred to just before tool execution
			// so the status only appears when the agent is actually running tools,
			// not on stream errors or turns that end without tool calls.
		}

		if err != nil {
			return "", err
		}

		if acc.FinishReason == "length" {
			// Distinguish between hitting n_predict (output budget, recoverable) vs n_ctx
			// (context window full, unrecoverable). Refresh the context size from the backend
			// and compare against total tokens used. A 5-token margin accounts for rounding.
			sess.Client().RefreshContextSize(ctx)
			nCtx := sess.Client().ContextSize()
			isContextFull := nCtx > 0 && acc.Usage.TotalTokens >= nCtx-5

			// Either way, filter out any truncated (invalid JSON) tool calls.
			var validCalls []client.ToolCall
			for _, tc := range acc.ToolCalls {
				if json.Valid([]byte(tc.Function.Arguments)) {
					validCalls = append(validCalls, tc)
				}
			}
			acc.ToolCalls = validCalls

			if isContextFull || (len(validCalls) == 0 && acc.Content == "") {
				sess.LogEvent("CONTEXT_LIMIT", "Context window full — unrecoverable", map[string]interface{}{
					"turn":              i + 1,
					"total_tokens":      acc.Usage.TotalTokens,
					"prompt_tokens":     acc.Usage.PromptTokens,
					"completion_tokens": acc.Usage.CompletionTokens,
					"n_ctx":             nCtx,
				})
				return "", fmt.Errorf("exceeds the available context size")
			}
			// Recoverable: hit n_predict output budget, not the context window.
			sess.LogEvent("OUTPUT_BUDGET_HIT", "finish_reason=length but context not full — hit n_predict budget", map[string]interface{}{
				"turn":              i + 1,
				"total_tokens":      acc.Usage.TotalTokens,
				"prompt_tokens":     acc.Usage.PromptTokens,
				"completion_tokens": acc.Usage.CompletionTokens,
				"n_ctx":             nCtx,
				"valid_tool_calls":  len(validCalls),
			})
		}

		// If stopped, the last tool call might be partially streamed and thus invalid JSON.
		// We shouldn't save corrupted tool calls to the session history.
		if ctx.Err() != nil {
			var filtered []client.ToolCall
			for _, tc := range acc.ToolCalls {
				// A simple check: if the arguments are valid JSON, keeping it is probably safe.
				// Otherwise, it was cut off mid-stream.
				if json.Valid([]byte(tc.Function.Arguments)) {
					filtered = append(filtered, tc)
				}
			}
			acc.ToolCalls = filtered
		}

		// Report token usage to session so compaction can gate on context pressure.
		if acc.Usage.TotalTokens > 0 {
			sess.SetLastTokenCount(acc.Usage.TotalTokens)
		} else if acc.Usage.PromptTokens > 0 {
			sess.SetLastTokenCount(acc.Usage.PromptTokens)
		}

		// AddAssistantMessageWithTools returns only the calls saved to history
		// (filtering any with malformed JSON). We execute exactly those calls so
		// every tool result message has a matching assistant tool_call entry.
		validCalls, err := sess.AddAssistantMessageWithTools(sanitizeContent(acc.Content), acc.Reasoning, acc.ToolCalls)
		if err != nil {
			return "", fmt.Errorf("failed to save history: %w", err)
		}

		if onEndTurn != nil {
			onEndTurn()
		}

		if len(validCalls) == 0 {
			// Detect model stall: empty finish reason with no content means the model
			// ended without yielding content (stream failure, early termination, or
			// a context limit edge case) and without a proper stop signal.
			// Return an error so the caller can surface it rather than silently
			// treating a stalled response as "no findings".
			if acc.FinishReason == "" && acc.Content == "" {
				nCtxAtStall := sess.Client().ContextSize()
				sess.LogTurnSummary(debug.TurnSummary{
					TurnIndex:        i + 1,
					FinishReason:     "empty",
					ReasoningChars:   len(acc.Reasoning),
					PromptTokens:     acc.Usage.PromptTokens,
					CompletionTokens: acc.Usage.CompletionTokens,
					TotalTokens:      acc.Usage.TotalTokens,
					NCtx:             nCtxAtStall,
				})
				sess.LogEvent("EMPTY_STREAM", "Model returned empty response — no finish_reason and no content", map[string]interface{}{
					"turn":              i + 1,
					"total_tokens":      acc.Usage.TotalTokens,
					"prompt_tokens":     acc.Usage.PromptTokens,
					"completion_tokens": acc.Usage.CompletionTokens,
					"n_ctx":             nCtxAtStall,
					"reasoning_chars":   len(acc.Reasoning),
				})
				return "", fmt.Errorf("model returned empty response on turn %d (possible empty stream, early termination, or context limit)", i+1)
			}
			sess.LogTurnSummary(debug.TurnSummary{
				TurnIndex:          i + 1,
				FinishReason:       acc.FinishReason,
				ToolCalls:          0,
				DuplicateToolTurns: duplicateToolTurns,
				ContentChars:       len(acc.Content),
				ReasoningChars:     len(acc.Reasoning),
				PromptTokens:       acc.Usage.PromptTokens,
				CompletionTokens:   acc.Usage.CompletionTokens,
				TotalTokens:        acc.Usage.TotalTokens,
				NCtx:               sess.Client().ContextSize(),
			})
			return acc.Content, nil
		}

		if len(validCalls) > maxToolCallsPerTurn {
			return "", fmt.Errorf("tool call budget exceeded for turn %d: %d > %d", i+1, len(validCalls), maxToolCallsPerTurn)
		}

		toolSig := toolCallSignature(validCalls)
		if toolSig != "" && toolSig == previousToolSig {
			duplicateToolTurns++
		} else {
			duplicateToolTurns = 0
		}
		previousToolSig = toolSig

		if duplicateToolTurns >= maxDuplicateToolTurns {
			return "", fmt.Errorf("repeated identical tool-call plan detected for %d consecutive turns", duplicateToolTurns+1)
		}

		lastContent = acc.Content

		// If a stop was requested, break the loop before executing tools
		select {
		case <-ctx.Done():
			return lastContent + "\n\n(Stopped by user)", nil
		default:
		}

		// Emit "working" now: the GPU lock was already released, and the agent is
		// actually about to run tool calls (not just finishing a no-tool turn).
		if onGPUReleased != nil {
			onGPUReleased()
		}

		stats, err := ExecuteToolCallsWithStats(ctx, sess, validCalls, middlewares, onToolState, cache)
		if err != nil {
			return "", err
		}

		// If the previous turn had failures, timeouts, or policy blocks, reset
		// the duplicate counter. This allows legitimate retries after transient
		// errors or blocked commands without triggering the duplicate-loop
		// blocker. Only count as duplicate if the plan repeats AFTER a fully
		// successful turn.
		if stats.Failures > 0 || stats.TimedOut > 0 || stats.Blocked > 0 {
			duplicateToolTurns = 0
		}

		sess.LogTurnSummary(debug.TurnSummary{
			TurnIndex:          i + 1,
			FinishReason:       acc.FinishReason,
			ToolCalls:          len(validCalls),
			DuplicateToolTurns: duplicateToolTurns,
			ContentChars:       len(acc.Content),
			ReasoningChars:     len(acc.Reasoning),
			ToolExecDurationMS: stats.DurationMS,
			ToolFailures:       stats.Failures,
			ToolBlocked:        stats.Blocked,
			ToolTimedOut:       stats.TimedOut,
			PromptTokens:       acc.Usage.PromptTokens,
			CompletionTokens:   acc.Usage.CompletionTokens,
			TotalTokens:        acc.Usage.TotalTokens,
			NCtx:               sess.Client().ContextSize(),
		})

		// Also check after tool execution in case user requested stop during a long tool
		select {
		case <-ctx.Done():
			return lastContent + "\n\n(Stopped by user)", nil
		default:
		}
	}

	return lastContent + "\n\n(Terminated due to max turns limit)", nil
}

func toolCallSignature(calls []client.ToolCall) string {
	if len(calls) == 0 {
		return ""
	}
	h := sha256.New()
	for _, tc := range calls {
		h.Write([]byte(tc.Function.Name))
		h.Write([]byte("\x00"))
		h.Write([]byte(tc.Function.Arguments))
		h.Write([]byte("\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
